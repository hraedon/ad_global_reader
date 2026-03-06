#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Verifies the Global Reader ACE is present and runs an idempotency test.
    This script is used for post-deployment validation only.
#>

$TargetDN     = (Get-ADDomain).DistinguishedName
$IdentityName = 'GS-Global-Readers'

Write-Host ''
Write-Host '=== ACE Verification ===' -ForegroundColor Cyan

# 1. Confirm group exists
$group = Get-ADGroup -Filter { Name -eq $IdentityName } -ErrorAction SilentlyContinue
if (-not $group) {
    Write-Host "FAIL: Group '$IdentityName' not found in AD." -ForegroundColor Red
    exit 1
}
Write-Host "OK  : Group '$($group.DistinguishedName)' exists." -ForegroundColor Green
Write-Host "      SID: $($group.SID.Value)"

# 2. Check ACE on domain root
$acl      = Get-Acl -Path "AD:\$TargetDN"
$groupSid = $group.SID.Value

$grAces = @($acl.Access | Where-Object {
    $aceSid = $null
    try { $aceSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
    $aceSid -eq $groupSid
})

if ($grAces.Count -gt 0) {
    Write-Host "OK  : Found $($grAces.Count) ACE(s) for '$IdentityName' on '$TargetDN':" -ForegroundColor Green
    $grAces | Format-List IdentityReference, ActiveDirectoryRights, AccessControlType, IsInherited, InheritanceType
}
else {
    Write-Host "FAIL: No ACE found for '$IdentityName' (SID: $groupSid) on '$TargetDN'." -ForegroundColor Red
    Write-Host 'First 5 ACEs on target for reference:' -ForegroundColor Yellow
    $acl.Access | Select-Object -First 5 | Format-List IdentityReference, ActiveDirectoryRights, IsInherited
    exit 1
}

# 3. Idempotency test -- re-run deployer; expect ACE_Exists_Skipping and Group_Exists_Skipping
Write-Host ''
Write-Host '=== Idempotency Test ===' -ForegroundColor Cyan
$stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$logPath = Join-Path $PSScriptRoot "Logs\GR-Idempotency-$stamp.csv"

& (Join-Path $PSScriptRoot 'Deploy-GlobalReader.ps1') -LogPath $logPath

$log    = Import-Csv $logPath
$skips  = @($log | Where-Object { $_.Action -in @('ACE_Exists_Skipping','Group_Exists_Skipping') })
$errors = @($log | Where-Object { $_.Action -eq 'Error' })

if ($errors.Count -gt 0) {
    Write-Host 'FAIL: Errors found in idempotency run:' -ForegroundColor Red
    $errors | Format-Table -AutoSize
    exit 1
}

if ($skips.Count -ge 2) {
    Write-Host 'OK  : Idempotency confirmed -- deployer correctly skipped existing group and ACE.' -ForegroundColor Green
}
else {
    Write-Host "WARN: Expected 2 skip actions but found $($skips.Count). Review log: $logPath" -ForegroundColor Yellow
    $log | Format-Table -AutoSize
}

Write-Host ''
Write-Host '=== Verification complete ===' -ForegroundColor Cyan
