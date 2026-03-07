#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Deploys the AD Global Reader role to an Active Directory domain.

.DESCRIPTION
    Orchestrates the creation of the GS-Global-Readers security group and
    the application of a read-only ACE (ReadProperty | ListChildren | ListObject)
    to the specified target container (defaults to domain root).

    Safe to re-run: all operations are idempotent.
    Does NOT grant ControlAccess, Write, Modify, or Delete of any kind.
    Does NOT alter existing ACEs — purely additive.

.PARAMETER IdentityName
    Name of the security group to create/use as the Global Reader principal.
    Default: GS-Global-Readers

.PARAMETER TargetOU
    Distinguished Name of the container to receive the ACE.
    If omitted, the domain root DN is used.

.PARAMETER GroupOU
    Distinguished Name of the OU in which to create the security group.
    If omitted, the domain's default Users container is used.

.PARAMETER LogPath
    Full path to the output CSV log file.
    Default: .\Logs\GR-Deploy-<timestamp>.csv

.PARAMETER ApplyAdminSDHolder
    Also applies the Global Reader ACE to the AdminSDHolder object, which causes
    SDProp to propagate read access to all admin-protected accounts (Domain Admins,
    Schema Admins, etc.) within 60 minutes.

    This deliberately expands read scope. Review Set-GR-AdminSDHolder.ps1 for full
    security implications. Requires -Force to proceed.

.PARAMETER Force
    Required when -ApplyAdminSDHolder is specified, to acknowledge the security
    implications of modifying AdminSDHolder.

.PARAMETER WhatIf
    Simulate actions without making changes. Logs are still written.

.EXAMPLE
    # Deploy with all defaults against the local domain
    .\Deploy-GlobalReader.ps1

.EXAMPLE
    # Target a specific OU; place the group in a custom OU; custom log path
    .\Deploy-GlobalReader.ps1 `
        -IdentityName  'GS-Global-Readers' `
        -TargetOU      'OU=Servers,DC=ad,DC=hraedon,DC=com' `
        -GroupOU       'OU=SecurityGroups,DC=ad,DC=hraedon,DC=com' `
        -LogPath       'C:\Logs\GR-Deploy.csv'

.EXAMPLE
    # Deploy including AdminSDHolder coverage (closes the AdminSDHolder Gap)
    .\Deploy-GlobalReader.ps1 -ApplyAdminSDHolder -Force

.EXAMPLE
    # Dry-run
    .\Deploy-GlobalReader.ps1 -WhatIf

.NOTES
    Execution context: must be run as Domain Admin or an account with
    Modify Permissions (WriteDacl) on the target container.

    Out of scope (by design):
      - Deleted Objects container
      - SAMR / restricted-group policy
      - Auditing pre-existing permissive ACEs

    Version : 2.0
    Author  : AD-GR Deployer (Claude Code / Anthropic)
    Domain  : Derived at runtime — no hardcoded values
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$IdentityName       = 'GS-Global-Readers',
    [string]$TargetOU           = '',   # Empty = domain root
    [string]$GroupOU            = '',   # Empty = domain Users container
    [string]$LogPath            = '',   # Empty = auto-generated in .\Logs\
    [switch]$ApplyAdminSDHolder,        # Also apply ACE to AdminSDHolder object
    [switch]$Force,                     # Required when -ApplyAdminSDHolder is set
    [switch]$TriggerSDProp              # Trigger immediate SDProp after AdminSDHolder change
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# 0. Bootstrap — resolve paths and dot-source helpers/modules
# ============================================================================
$scriptRoot = $PSScriptRoot

# Auto-generate log path if not provided
if (-not $LogPath) {
    $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $LogPath = Join-Path $scriptRoot "Logs\GR-Deploy-$stamp.csv"
}

# Dot-source helpers first (Write-GRLog must be available before anything else)
. (Join-Path $scriptRoot 'Helpers\Write-GRLog.ps1')
. (Join-Path $scriptRoot 'Helpers\Test-GRPreFlight.ps1')

# Dot-source modules
. (Join-Path $scriptRoot 'Modules\New-GR-Group.ps1')
. (Join-Path $scriptRoot 'Modules\Set-GR-Delegation.ps1')
. (Join-Path $scriptRoot 'Modules\Set-GR-AdminSDHolder.ps1')

# ============================================================================
# 1. Resolve domain context at runtime — NO hardcoded values
# ============================================================================
try {
    $domain     = Get-ADDomain -ErrorAction Stop
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    Write-Error "FATAL: Cannot retrieve domain information. Ensure the ActiveDirectory module is installed and this machine is domain-joined. Error: $_"
    exit 1
}

# Resolve target DN
$TargetDN = if ($TargetOU) { $TargetOU } else { $DomainDN }

Write-Host ""
Write-Host "========================================================" -ForegroundColor DarkCyan
Write-Host "  AD Global Reader Deployer  v2.0" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor DarkCyan
Write-Host "  Domain             : $DomainFQDN" -ForegroundColor White
Write-Host "  Target DN          : $TargetDN" -ForegroundColor White
Write-Host "  Group              : $IdentityName" -ForegroundColor White
Write-Host "  Log                : $LogPath" -ForegroundColor White
if ($ApplyAdminSDHolder) { Write-Host '  ApplyAdminSDHolder : YES' -ForegroundColor Yellow }
if ($WhatIfPreference)   { Write-Host '  MODE               : WhatIf (no changes will be made)' -ForegroundColor Yellow }
Write-Host "========================================================" -ForegroundColor DarkCyan
Write-Host ""

# ============================================================================
# 2. WhatIf marker (logged before any operations so the CSV is always stamped)
# ============================================================================
if ($WhatIfPreference) {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action WhatIf_Active `
        -Principal ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -Details "WhatIf mode active. No changes will be made to Active Directory. Log entries below reflect what WOULD have happened."
}

# ============================================================================
# 3. Pre-flight validation
# ============================================================================
Write-Host "[Step 1/3] Running pre-flight checks..." -ForegroundColor DarkCyan

$preFlightOK = Test-GRPreFlight -TargetDN $TargetDN -LogPath $LogPath

if (-not $preFlightOK) {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
        -Principal ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -Details 'Pre-flight validation failed. Deployment aborted.'
    Write-Error 'Pre-flight validation failed. Review the log for details.'
    exit 1
}

Write-Host "[Step 1/3] Pre-flight checks passed." -ForegroundColor Green

# ============================================================================
# 4. Module 1 — Create the Global Reader security group
# ============================================================================
Write-Host "[Step 2/3] Ensuring Global Reader group exists..." -ForegroundColor DarkCyan

$groupParams = @{
    IdentityName = $IdentityName
    LogPath      = $LogPath
}
if ($GroupOU) { $groupParams['GroupOU'] = $GroupOU }

try {
    $grGroup = New-GRGroup @groupParams -WhatIf:$WhatIfPreference
    Write-Host "[Step 2/3] Group ready: $($grGroup.DistinguishedName)" -ForegroundColor Green
}
catch {
    $groupErrTarget = if ($GroupOU) { $GroupOU } else { $domain.UsersContainer }
    Write-GRLog -LogPath $LogPath -TargetDN $groupErrTarget `
        -Action Error `
        -Principal $IdentityName `
        -Details "Group creation failed: $_"
    Write-Error "Group creation failed. See log: $LogPath"
    exit 1
}

# ============================================================================
# 4. Module 2 — Apply the Global Reader ACE
# ============================================================================
Write-Host "[Step 3/3] Applying Global Reader ACE to '$TargetDN'..." -ForegroundColor DarkCyan

try {
    Set-GRDelegation -TargetDN $TargetDN -IdentityName $IdentityName -LogPath $LogPath -WhatIf:$WhatIfPreference
    Write-Host "[Step 3/3] ACL delegation complete." -ForegroundColor Green
}
catch {
    Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
        -Principal $IdentityName `
        -Details "ACL delegation failed: $_"
    Write-Error "ACL delegation failed. See log: $LogPath"
    exit 1
}

# ============================================================================
# 5. Module 3 (optional) — Apply ACE to AdminSDHolder
# ============================================================================
if ($ApplyAdminSDHolder) {
    Write-Host "[Step 4/4] Applying Global Reader ACE to AdminSDHolder..." -ForegroundColor DarkCyan

    try {
        Set-GRAdminSDHolder -IdentityName $IdentityName -LogPath $LogPath `
            -Force:$Force -TriggerSDProp:$TriggerSDProp -WhatIf:$WhatIfPreference
        Write-Host "[Step 4/4] AdminSDHolder ACE applied. SDProp propagates within 60 minutes." -ForegroundColor Green
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN "CN=AdminSDHolder,CN=System,$DomainDN" -Action Error `
            -Principal $IdentityName `
            -Details "AdminSDHolder ACE failed: $_"
        Write-Error "AdminSDHolder ACE failed. See log: $LogPath"
        exit 1
    }
}

# ============================================================================
# 6. Summary
# ============================================================================
Write-Host ""
Write-Host "========================================================" -ForegroundColor DarkCyan
Write-Host "  Deployment complete." -ForegroundColor Green
Write-Host "  Log written to: $LogPath" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor DarkCyan
Write-Host ""

Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
    -Principal $IdentityName `
    -Details "Deployment finished successfully. Group: '$IdentityName', Target: '$TargetDN', Domain: '$DomainFQDN'."
