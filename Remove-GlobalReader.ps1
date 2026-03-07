#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes the AD Global Reader role from the domain.

.DESCRIPTION
    Reverses the deployment performed by Deploy-GlobalReader.ps1.
    Removes the Global Reader ACE from the target container (domain root by default)
    and optionally removes the AdminSDHolder ACE and the security group itself.

    All operations are idempotent: safe to re-run if already removed.
    Uses -WhatIf for dry-run simulation.

    WHAT IS REMOVED (by default):
      - The explicit Allow ACE (ReadProperty|ListChildren|ListObject) from the target
        container. Child objects lose the inherited read access via normal propagation.

    ADDITIONAL REMOVALS (opt-in):
      - -RemoveAdminSDHolder : removes the ACE from AdminSDHolder; SDProp will
        propagate the removal to protected accounts within 60 minutes.
      - -RemoveGroup         : deletes the GS-Global-Readers security group after
        removing the ACE. Clears ProtectedFromAccidentalDeletion first.
        Warning: if the group has members, they are also removed implicitly.

.PARAMETER IdentityName
    Name of the Global Reader security group.
    Default: GS-Global-Readers

.PARAMETER TargetOU
    Distinguished Name of the container from which to remove the ACE.
    If omitted, the domain root DN is used.

.PARAMETER RemoveAdminSDHolder
    Also removes the Global Reader ACE from the AdminSDHolder object.
    SDProp will propagate the removal to protected accounts within 60 minutes.
    To force immediate propagation, trigger SDProp manually (see Set-GR-AdminSDHolder.ps1).

.PARAMETER RemoveGroup
    Also removes the GS-Global-Readers security group from AD.
    ProtectedFromAccidentalDeletion is cleared automatically before deletion.
    If the group has members, issue a warning but continue.

.PARAMETER LogPath
    Full path to the output CSV log file.
    Default: .\Logs\GR-Remove-<timestamp>.csv

.PARAMETER WhatIf
    Simulate all actions without making changes. Logs are still written.

.EXAMPLE
    # Remove only the ACE from domain root (reversible, leaves group intact)
    .\Remove-GlobalReader.ps1

.EXAMPLE
    # Remove ACE + AdminSDHolder ACE (dry run first)
    .\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -WhatIf
    .\Remove-GlobalReader.ps1 -RemoveAdminSDHolder

.EXAMPLE
    # Full teardown: ACE + AdminSDHolder + group
    .\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -RemoveGroup

.NOTES
    Version : 2.0
    Author  : AD-GR Deployer (Claude Code / Anthropic)
    Companion to Deploy-GlobalReader.ps1

    To re-deploy after removal, simply run Deploy-GlobalReader.ps1 again.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$IdentityName      = 'GS-Global-Readers',
    [string]$TargetOU          = '',
    [switch]$RemoveAdminSDHolder,
    [switch]$RemoveGroup,
    [switch]$TriggerSDProp,             # Trigger immediate SDProp after AdminSDHolder removal
    [string]$LogPath           = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# 0. Bootstrap
# ============================================================================
$scriptRoot = $PSScriptRoot

if (-not $LogPath) {
    $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $LogPath = Join-Path $scriptRoot "Logs\GR-Remove-$stamp.csv"
}

. (Join-Path $scriptRoot 'Helpers\Write-GRLog.ps1')
. (Join-Path $scriptRoot 'Helpers\Test-GRPreFlight.ps1')
. (Join-Path $scriptRoot 'Modules\Remove-GR-Delegation.ps1')
. (Join-Path $scriptRoot 'Modules\Remove-GR-AdminSDHolder.ps1')

# ============================================================================
# 1. Resolve domain context
# ============================================================================
try {
    $domain     = Get-ADDomain -ErrorAction Stop
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    Write-Error "FATAL: Cannot retrieve domain information. Error: $_"
    exit 1
}

$TargetDN        = if ($TargetOU) { $TargetOU } else { $DomainDN }
$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"

Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host '  AD Global Reader Removal  v2.0' -ForegroundColor Cyan
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host "  Domain             : $DomainFQDN" -ForegroundColor White
Write-Host "  Target DN          : $TargetDN" -ForegroundColor White
Write-Host "  Group              : $IdentityName" -ForegroundColor White
Write-Host "  Log                : $LogPath" -ForegroundColor White
if ($RemoveAdminSDHolder) { Write-Host '  RemoveAdminSDHolder: YES' -ForegroundColor Yellow }
if ($RemoveGroup)         { Write-Host '  RemoveGroup        : YES (group will be deleted)' -ForegroundColor Yellow }
if ($WhatIfPreference)    { Write-Host '  MODE               : WhatIf (no changes will be made)' -ForegroundColor Yellow }
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host ''

# ============================================================================
# 2. WhatIf marker
# ============================================================================
if ($WhatIfPreference) {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action WhatIf_Active `
        -Principal ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -Details "WhatIf mode active. No changes will be made to Active Directory. Log entries below reflect what WOULD have happened."
}

# ============================================================================
# 3. Pre-flight
# ============================================================================
Write-Host '[Step 1] Running pre-flight checks...' -ForegroundColor DarkCyan

$preFlightOK = Test-GRPreFlight -TargetDN $TargetDN -LogPath $LogPath

if (-not $preFlightOK) {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
        -Principal ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -Details 'Pre-flight validation failed. Removal aborted.'
    Write-Error 'Pre-flight validation failed. Review the log for details.'
    exit 1
}
Write-Host '[Step 1] Pre-flight checks passed.' -ForegroundColor Green

# ============================================================================
# 3. Remove the domain root ACE
# ============================================================================
Write-Host "[Step 2] Removing Global Reader ACE from '$TargetDN'..." -ForegroundColor DarkCyan

try {
    Remove-GRDelegation -TargetDN $TargetDN -IdentityName $IdentityName `
        -LogPath $LogPath -WhatIf:$WhatIfPreference
    Write-Host '[Step 2] Domain root ACE removal complete.' -ForegroundColor Green
}
catch {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
        -Principal $IdentityName -Details "ACE removal failed: $_"
    Write-Error "ACE removal failed. See log: $LogPath"
    exit 1
}

# ============================================================================
# 4. Remove AdminSDHolder ACE (opt-in)
# ============================================================================
if ($RemoveAdminSDHolder) {
    Write-Host '[Step 3] Removing Global Reader ACE from AdminSDHolder...' -ForegroundColor DarkCyan
    try {
        Remove-GRAdminSDHolder -IdentityName $IdentityName `
            -LogPath $LogPath -TriggerSDProp:$TriggerSDProp -WhatIf:$WhatIfPreference
        Write-Host '[Step 3] AdminSDHolder ACE removal complete. SDProp propagates within 60 minutes.' -ForegroundColor Green
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action Error `
            -Principal $IdentityName -Details "AdminSDHolder ACE removal failed: $_"
        Write-Error "AdminSDHolder ACE removal failed. See log: $LogPath"
        exit 1
    }
}

# ============================================================================
# 5. Remove the security group (opt-in)
# ============================================================================
if ($RemoveGroup) {
    Write-Host "[Step 4] Removing security group '$IdentityName'..." -ForegroundColor DarkCyan
    try {
        $group = Get-ADGroup -Filter { Name -eq $IdentityName } -ErrorAction SilentlyContinue

        if (-not $group) {
            Write-GRLog -LogPath $LogPath -TargetDN $DomainDN -Action Group_NotFound_Skipping `
                -Principal $IdentityName `
                -Details "Group '$IdentityName' not found in AD. Nothing to remove."
            Write-Host '[Step 4] Group not found - skipping.' -ForegroundColor Yellow
        }
        else {
            # Warn if group has members
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
            if ($members -and $members.Count -gt 0) {
                Write-Host "  WARNING: Group has $($members.Count) member(s). They will lose the Global Reader role." -ForegroundColor Yellow
                Write-GRLog -LogPath $LogPath -TargetDN $group.DistinguishedName -Action PreFlight_Warning `
                    -Principal $IdentityName `
                    -Details "Group '$IdentityName' has $($members.Count) member(s) that will lose the Global Reader role upon group deletion."
            }

            if ($PSCmdlet.ShouldProcess($group.DistinguishedName, "Remove security group '$IdentityName'")) {
                # Must clear ProtectedFromAccidentalDeletion before Remove-ADGroup will succeed
                Set-ADObject -Identity $group.DistinguishedName `
                    -ProtectedFromAccidentalDeletion $false -ErrorAction Stop

                Remove-ADGroup -Identity $group.DistinguishedName -Confirm:$false -ErrorAction Stop

                Write-GRLog -LogPath $LogPath -TargetDN $group.DistinguishedName -Action Group_Removed `
                    -Principal ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
                    -Details "Group '$IdentityName' removed. ProtectedFromAccidentalDeletion was cleared first."
                Write-Host '[Step 4] Group removed.' -ForegroundColor Green
            }
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $DomainDN -Action Error `
            -Principal $IdentityName -Details "Group removal failed: $_"
        Write-Error "Group removal failed. See log: $LogPath"
        exit 1
    }
}

# ============================================================================
# 6. Summary
# ============================================================================
Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host '  Removal complete.' -ForegroundColor Green
Write-Host "  Log written to: $LogPath" -ForegroundColor White
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host ''
