#Requires -Version 5.1
<#
.SYNOPSIS
    CSV logging helper for the AD Global Reader deployer.
.DESCRIPTION
    Appends a structured log entry to the deployment CSV log.
    Creates the log file with headers if it does not yet exist.
    File writes are serialised with a named Win32 mutex derived from the log
    path, so concurrent deployer instances targeting the same file do not
    interleave rows. The mutex is acquired with a 5-second timeout; if the
    timeout expires the write proceeds anyway rather than silently dropping
    the log entry.
#>

function Write-GRLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [ValidateSet(
            'ACE_Added','ACE_Exists_Skipping','ACE_Removed','ACE_NotFound_Skipping',
            'Group_Created','Group_Exists_Skipping','Group_Removed','Group_NotFound_Skipping',
            'AdminSDHolder_ACE_Added','AdminSDHolder_ACE_Removed',
            'AdminSDHolder_ACE_Exists_Skipping','AdminSDHolder_ACE_NotFound_Skipping',
            'PreFlight_OK','PreFlight_Warning','PreFlight_Error',
            'WhatIf_Active',
            'Error'
        )]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Principal,

        [Parameter(Mandatory)]
        [string]$Details
    )

    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        TargetDN  = $TargetDN
        Action    = $Action
        Principal = $Principal
        Details   = $Details
    }

    # Use .NET I/O directly so that PowerShell's $WhatIfPreference does not suppress
    # log writes. Out-File honours ShouldProcess in PS5.1, which means -WhatIf on
    # the caller propagates through and silently drops every log entry.
    # [System.IO.File] methods are not affected by $WhatIfPreference.
    $logDir = Split-Path -Parent $LogPath
    [System.IO.Directory]::CreateDirectory($logDir) | Out-Null

    # Named mutex — one per unique log path, scoped to the local machine.
    $safeName  = 'Local\GR-Log-' + ($LogPath -replace '[\\/:*?"<>|]', '_')
    $mutex     = [System.Threading.Mutex]::new($false, $safeName)
    $acquired  = $false
    try {
        $acquired = $mutex.WaitOne(5000)   # 5-second timeout

        # Write header if file is new
        if (-not [System.IO.File]::Exists($LogPath)) {
            [System.IO.File]::WriteAllText(
                $LogPath,
                "Timestamp,TargetDN,Action,Principal,Details`r`n",
                [System.Text.Encoding]::UTF8
            )
        }

        # Escape commas/quotes in fields for valid CSV
        $row = ($entry.Timestamp, $entry.TargetDN, $entry.Action, $entry.Principal, $entry.Details) |
            ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }
        [System.IO.File]::AppendAllText(
            $LogPath,
            ($row -join ',') + "`r`n",
            [System.Text.Encoding]::UTF8
        )
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }

    # Mirror to console with colour coding
    $colour = switch ($Action) {
        'Error'                            { 'Red' }
        'PreFlight_Error'                  { 'Red' }
        'PreFlight_Warning'                { 'Yellow' }
        'ACE_Added'                        { 'Green' }
        'AdminSDHolder_ACE_Added'          { 'Green' }
        'Group_Created'                    { 'Green' }
        'ACE_Removed'                      { 'Yellow' }
        'AdminSDHolder_ACE_Removed'        { 'Yellow' }
        'Group_Removed'                    { 'Yellow' }
        'WhatIf_Active'                    { 'Magenta' }
        default                            { 'Cyan' }
    }
    Write-Host "[$($entry.Timestamp)] [$Action] $TargetDN :: $Details" -ForegroundColor $colour
}
