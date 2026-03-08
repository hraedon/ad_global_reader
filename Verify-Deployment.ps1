#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Verifies the Global Reader role is deployed correctly and runs an idempotency test.

.DESCRIPTION
    Human-facing companion to the integration tests. Checks:
      1. Security group exists in AD
      2. Explicit ReadProperty ACE is present on the target DN
      3. AdminSDHolder ACE status (informational - optional via -CheckAdminSDHolder)
      4. Idempotency: re-runs Deploy-GlobalReader.ps1 and confirms only skip actions

    For automated/pipeline validation use Tests\Bootstrap.ps1 -Tags Integration.
    This script is intended for operator spot-checks after deployment.

.PARAMETER IdentityName
    Name of the Global Reader security group to verify.
    Default: GS-Global-Readers

.PARAMETER TargetDN
    Distinguished Name of the container where the ACE should be present.
    If omitted, the domain root DN is used.

.PARAMETER CheckAdminSDHolder
    If set, also checks whether the AdminSDHolder ACE is present and reports
    its status. AdminSDHolder coverage is optional (deployed with -ApplyAdminSDHolder);
    its absence is reported as informational, not a failure.

.EXAMPLE
    # Verify defaults
    .\Verify-Deployment.ps1

.EXAMPLE
    # Verify with AdminSDHolder check
    .\Verify-Deployment.ps1 -CheckAdminSDHolder

.EXAMPLE
    # Verify a custom group and target
    .\Verify-Deployment.ps1 -IdentityName 'GS-SIEM-Readers' `
        -TargetDN 'OU=Servers,DC=ad,DC=example,DC=com' -CheckAdminSDHolder
#>

[CmdletBinding()]
param(
    [string]$IdentityName      = 'GS-Global-Readers',
    [string]$TargetDN          = '',
    [switch]$CheckAdminSDHolder
)

. (Join-Path $PSScriptRoot 'Helpers\Find-GRAce.ps1')

# ---- Resolve domain context ------------------------------------------------
$domain = Get-ADDomain -ErrorAction Stop
if (-not $TargetDN) {
    $TargetDN = $domain.DistinguishedName
}
$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"

$overallOK = $true

Write-Host ''
Write-Host '=== AD Global Reader - Deployment Verification ===' -ForegroundColor Cyan
Write-Host "    Domain : $($domain.DNSRoot)" -ForegroundColor White
Write-Host "    Group  : $IdentityName" -ForegroundColor White
Write-Host "    Target : $TargetDN" -ForegroundColor White
Write-Host ''

# ============================================================================
# Check 1: Security group exists
# ============================================================================
Write-Host '[Check 1] Security group' -ForegroundColor DarkCyan

$group = Get-ADGroup -Filter { Name -eq $IdentityName } `
           -Properties ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue

if (-not $group) {
    Write-Host "  FAIL : Group '$IdentityName' not found in AD." -ForegroundColor Red
    $overallOK = $false
}
else {
    Write-Host "  OK   : '$($group.DistinguishedName)'" -ForegroundColor Green
    Write-Host "         SID: $($group.SID.Value)" -ForegroundColor Gray
    Write-Host "         ProtectedFromAccidentalDeletion: $($group.ProtectedFromAccidentalDeletion)" -ForegroundColor Gray
}

# ============================================================================
# Check 2: ACE on target DN
# ============================================================================
Write-Host ''
Write-Host '[Check 2] Domain root ACE' -ForegroundColor DarkCyan

if ($group) {
    $groupSidValue = $group.SID.Value
    $targetAcl = $null
    try { $targetAcl = Get-Acl -Path "AD:\$TargetDN" -ErrorAction Stop } catch {}

    $grAce = if ($targetAcl) { Find-GRAce -Acl $targetAcl -SidValue $groupSidValue -IdentityName $IdentityName } else { $null }

    if ($grAce) {
        Write-Host "  OK   : Explicit ReadProperty ACE found on '$TargetDN'." -ForegroundColor Green
        Write-Host "         Rights: $($grAce.ActiveDirectoryRights)" -ForegroundColor Gray
        Write-Host "         Inherited: $($grAce.IsInherited) | InheritanceType: $($grAce.InheritanceType)" -ForegroundColor Gray
    }
    else {
        Write-Host "  FAIL : No explicit ReadProperty ACE for '$IdentityName' found on '$TargetDN'." -ForegroundColor Red
        $overallOK = $false
    }
}
else {
    Write-Host '  SKIP : Cannot check ACE - group not found.' -ForegroundColor Yellow
    $overallOK = $false
}

# ============================================================================
# Check 3: AdminSDHolder ACE (informational, opt-in)
# ============================================================================
if ($CheckAdminSDHolder) {
    Write-Host ''
    Write-Host '[Check 3] AdminSDHolder ACE' -ForegroundColor DarkCyan

    if ($group) {
        $ashAcl = $null
        try { $ashAcl = Get-Acl -Path "AD:\$adminSDHolderDN" -ErrorAction Stop } catch {}
        $ashAce = if ($ashAcl) { Find-GRAce -Acl $ashAcl -SidValue $groupSidValue -IdentityName $IdentityName } else { $null }

        if ($ashAce) {
            Write-Host '  OK   : AdminSDHolder ACE is present.' -ForegroundColor Green
            Write-Host "         Rights: $($ashAce.ActiveDirectoryRights)" -ForegroundColor Gray
            Write-Host '         Protected accounts (adminCount=1) will receive read access via SDProp.' -ForegroundColor Gray
        }
        else {
            Write-Host '  INFO : AdminSDHolder ACE is NOT present (AdminSDHolder Gap active).' -ForegroundColor Yellow
            Write-Host '         Protected accounts (Domain Admins, etc.) are not covered.' -ForegroundColor Yellow
            Write-Host '         To close the gap: .\Deploy-GlobalReader.ps1 -ApplyAdminSDHolder -Force' -ForegroundColor Yellow
            # Not setting $overallOK = $false -- AdminSDHolder coverage is optional
        }
    }
    else {
        Write-Host '  SKIP : Cannot check AdminSDHolder ACE - group not found.' -ForegroundColor Yellow
    }
}

# ============================================================================
# Check 4: Idempotency test
# ============================================================================
Write-Host ''
Write-Host '[Check 4] Idempotency test (re-run deployer, expect only skip actions)' -ForegroundColor DarkCyan

$stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$logPath = Join-Path $PSScriptRoot "Logs\GR-Verify-$stamp.csv"

& (Join-Path $PSScriptRoot 'Deploy-GlobalReader.ps1') `
    -IdentityName $IdentityName `
    -TargetOU     $TargetDN `
    -LogPath      $logPath

if (Test-Path $logPath) {
    $log    = Import-Csv $logPath
    $skips  = @($log | Where-Object { $_.Action -in @('ACE_Exists_Skipping','Group_Exists_Skipping') })
    $errors = @($log | Where-Object { $_.Action -eq 'Error' })

    if ($errors.Count -gt 0) {
        Write-Host '  FAIL : Errors found in idempotency run:' -ForegroundColor Red
        $errors | Format-Table -AutoSize
        $overallOK = $false
    }
    elseif ($skips.Count -ge 2) {
        Write-Host '  OK   : Deployer skipped existing group and ACE (idempotency confirmed).' -ForegroundColor Green
    }
    else {
        Write-Host "  WARN : Expected at least 2 skip actions but found $($skips.Count). Review log: $logPath" -ForegroundColor Yellow
        $log | Format-Table Action, TargetDN, Details -AutoSize
    }
}
else {
    Write-Host '  WARN : Log file not found after idempotency run.' -ForegroundColor Yellow
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ''
Write-Host '==================================================' -ForegroundColor Cyan
if ($overallOK) {
    Write-Host '  Result: PASS - Deployment verified.' -ForegroundColor Green
}
else {
    Write-Host '  Result: FAIL - One or more checks failed. See above.' -ForegroundColor Red
}
Write-Host '==================================================' -ForegroundColor Cyan
Write-Host ''

if (-not $overallOK) {
    exit 1
}
