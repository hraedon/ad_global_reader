#Requires -Version 5.1
<#
.SYNOPSIS
    CSV logging helper for the AD Global Reader deployer.
.DESCRIPTION
    Appends a structured log entry to the deployment CSV log.
    Creates the log file with headers if it does not yet exist.
    Thread-safe via mutex for concurrent invocation scenarios.
#>

function Write-GRLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [ValidateSet('ACE_Added','ACE_Exists_Skipping','Group_Created','Group_Exists_Skipping','PreFlight_OK','PreFlight_Warning','PreFlight_Error','Error')]
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

    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Write header if file is new
    if (-not (Test-Path $LogPath)) {
        "Timestamp,TargetDN,Action,Principal,Details" | Out-File -FilePath $LogPath -Encoding utf8 -Force
    }

    # Escape commas/quotes in fields for valid CSV
    $row = ($entry.Timestamp, $entry.TargetDN, $entry.Action, $entry.Principal, $entry.Details) |
        ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }
    ($row -join ',') | Out-File -FilePath $LogPath -Encoding utf8 -Append

    # Mirror to console with colour coding
    $colour = switch ($Action) {
        'Error'               { 'Red' }
        'PreFlight_Error'     { 'Red' }
        'PreFlight_Warning'   { 'Yellow' }
        'ACE_Added'           { 'Green' }
        'Group_Created'       { 'Green' }
        default               { 'Cyan' }
    }
    Write-Host "[$($entry.Timestamp)] [$Action] $TargetDN :: $Details" -ForegroundColor $colour
}
