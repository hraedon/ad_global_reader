#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Generates an audit and health report for the AD Global Reader role.

.DESCRIPTION
    Produces a structured report covering:
      1. Role Health    - Group existence, ACE on domain root, ACE on AdminSDHolder
      2. Membership     - All members with last logon and enabled status
      3. AdminSDHolder Gap Analysis - Protected accounts (adminCount=1) and
                          whether Global Readers can see them
      4. Inheritance Check - Spot-checks inherited ACE presence on sampled OUs

    Output formats: HTML report and/or CSV summary.
    Exits with code 1 if critical health checks fail (useful for scheduled monitoring).

.PARAMETER IdentityName
    Name of the Global Reader security group.
    Default: GS-Global-Readers

.PARAMETER TargetDN
    Distinguished Name of the container expected to have the ACE.
    If omitted, the domain root DN is used.

.PARAMETER OutputPath
    Directory for report output files.
    Default: .\Logs\Reports\

.PARAMETER Format
    Output format: HTML, CSV, or Both.
    Default: Both

.PARAMETER CheckInheritance
    If set, spot-checks a sample of OUs to verify the inherited ACE is flowing.
    Slightly slower due to additional Get-Acl calls.

.PARAMETER FailOnMissingAce
    If set, exits with code 1 when the domain root ACE is missing.
    Useful for scheduled monitoring / alerting pipelines.

.EXAMPLE
    .\Get-GRReport.ps1

.EXAMPLE
    .\Get-GRReport.ps1 -CheckInheritance -FailOnMissingAce -Format HTML

.NOTES
    Version : 2.0
    Author  : AD-GR Deployer (Claude Code / Anthropic)
#>

[CmdletBinding()]
param(
    [string]$IdentityName    = 'GS-Global-Readers',
    [string]$TargetDN        = '',
    [string]$OutputPath      = '',
    [ValidateSet('HTML','CSV','Both')]
    [string]$Format          = 'Both',
    [switch]$CheckInheritance,
    [switch]$FailOnMissingAce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot  = $PSScriptRoot
$reportStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')

if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptRoot "Logs\Reports"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# ============================================================================
# Helper: find explicit ACE for our group on a given AD path
# ============================================================================
function Find-GRAce {
    param(
        [string]$ADPath,
        [string]$GroupSidValue,
        [string]$GroupName
    )
    try {
        $acl            = Get-Acl -Path $ADPath -ErrorAction Stop
        $candidateAces  = $acl.Access | Where-Object {
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -ne 0
        }
        foreach ($ace in $candidateAces) {
            $aceSid = $null
            try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $aceSid = $null }
            if ($aceSid -and $aceSid -eq $GroupSidValue)             { return $ace }
            if ($ace.IdentityReference.Value -like "*$GroupName*")   { return $ace }
        }
    }
    catch { }
    return $null
}

# ============================================================================
# 1. Domain context
# ============================================================================
$domain     = Get-ADDomain -ErrorAction Stop
$DomainFQDN = $domain.DNSRoot
$DomainDN   = $domain.DistinguishedName

if (-not $TargetDN) { $TargetDN = $DomainDN }

$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$DomainDN"

Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host '  AD Global Reader Report' -ForegroundColor Cyan
Write-Host "  Domain : $DomainFQDN" -ForegroundColor White
Write-Host "  Group  : $IdentityName" -ForegroundColor White
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host ''

# ============================================================================
# 2. Role Health Check
# ============================================================================
Write-Host '[Section 1] Role Health Check' -ForegroundColor DarkCyan

$healthRows = [System.Collections.Generic.List[PSObject]]::new()

# --- 2a. Group existence ---
$group     = Get-ADGroup -Filter { Name -eq $IdentityName } `
               -Properties Description,Created,ProtectedFromAccidentalDeletion `
               -ErrorAction SilentlyContinue

if ($group) {
    $memberCount = (Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue | Measure-Object).Count
    $groupStatus = 'OK'
    $groupDetail = "DN: $($group.DistinguishedName) | SID: $($group.SID.Value) | Members: $memberCount | Protected: $($group.ProtectedFromAccidentalDeletion)"
    Write-Host "  [OK]   Group '$IdentityName' exists. Members: $memberCount" -ForegroundColor Green
}
else {
    $groupStatus = 'MISSING'
    $groupDetail = "Group '$IdentityName' not found in AD."
    Write-Host "  [FAIL] Group '$IdentityName' not found." -ForegroundColor Red
}

$healthRows.Add([PSCustomObject]@{
    Check   = 'Group Exists'
    Status  = $groupStatus
    Detail  = $groupDetail
})

# --- 2b. Domain root ACE ---
$domainRootAceStatus = 'MISSING'
$domainRootAceDetail = 'ACE not found.'
$groupSidValue       = $null

if ($group) {
    $groupSidValue = $group.SID.Value
    $rootAce = Find-GRAce -ADPath "AD:\$TargetDN" -GroupSidValue $groupSidValue -GroupName $IdentityName
    if ($rootAce) {
        $domainRootAceStatus = 'OK'
        $domainRootAceDetail = "Rights: $($rootAce.ActiveDirectoryRights) | Inherited: $($rootAce.IsInherited) | InheritanceType: $($rootAce.InheritanceType)"
        Write-Host "  [OK]   ACE present on target DN '$TargetDN'." -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] ACE missing on target DN '$TargetDN'." -ForegroundColor Red
    }
}
else {
    $domainRootAceDetail = 'Cannot check ACE - group not found.'
}

$healthRows.Add([PSCustomObject]@{
    Check   = 'Domain Root ACE'
    Status  = $domainRootAceStatus
    Detail  = $domainRootAceDetail
})

# --- 2c. AdminSDHolder ACE ---
$adminSDHolderAceStatus = 'NOT_APPLIED'
$adminSDHolderAceDetail = 'ACE not present on AdminSDHolder. Protected accounts (adminCount=1) are NOT covered by Global Readers.'

if ($group) {
    $ashAce = Find-GRAce -ADPath "AD:\$adminSDHolderDN" -GroupSidValue $groupSidValue -GroupName $IdentityName
    if ($ashAce) {
        $adminSDHolderAceStatus = 'OK'
        $adminSDHolderAceDetail = "ACE present on AdminSDHolder. SDProp propagates to protected accounts. Rights: $($ashAce.ActiveDirectoryRights)"
        Write-Host "  [OK]   AdminSDHolder ACE present (protected accounts covered)." -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] AdminSDHolder ACE not applied (protected accounts not covered - AdminSDHolder Gap active)." -ForegroundColor Yellow
    }
}

$healthRows.Add([PSCustomObject]@{
    Check   = 'AdminSDHolder ACE'
    Status  = $adminSDHolderAceStatus
    Detail  = $adminSDHolderAceDetail
})

# ============================================================================
# 3. Group Membership
# ============================================================================
Write-Host ''
Write-Host '[Section 2] Group Membership' -ForegroundColor DarkCyan

$memberRows = [System.Collections.Generic.List[PSObject]]::new()

if ($group) {
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue

    if ($members -and $members.Count -gt 0) {
        foreach ($m in $members) {
            $memberDetail = $null
            try {
                if ($m.objectClass -eq 'user') {
                    $u = Get-ADUser -Identity $m.distinguishedName `
                           -Properties LastLogonDate,Enabled,Description -ErrorAction SilentlyContinue
                    if ($u) {
                        $memberDetail = [PSCustomObject]@{
                            Name            = $u.Name
                            SAMAccountName  = $u.SamAccountName
                            ObjectClass     = 'user'
                            Enabled         = $u.Enabled
                            LastLogonDate   = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                            Description     = $u.Description
                            DN              = $u.DistinguishedName
                        }
                    }
                }
                elseif ($m.objectClass -eq 'group') {
                    $g = Get-ADGroup -Identity $m.distinguishedName `
                           -Properties Description -ErrorAction SilentlyContinue
                    if ($g) {
                        $memberDetail = [PSCustomObject]@{
                            Name            = $g.Name
                            SAMAccountName  = $g.SamAccountName
                            ObjectClass     = 'group'
                            Enabled         = 'N/A'
                            LastLogonDate   = 'N/A'
                            Description     = $g.Description
                            DN              = $g.DistinguishedName
                        }
                    }
                }
                elseif ($m.objectClass -eq 'computer') {
                    $memberDetail = [PSCustomObject]@{
                        Name            = $m.Name
                        SAMAccountName  = $m.SamAccountName
                        ObjectClass     = 'computer'
                        Enabled         = 'N/A'
                        LastLogonDate   = 'N/A'
                        Description     = ''
                        DN              = $m.distinguishedName
                    }
                }
            }
            catch { }

            if ($memberDetail) {
                $memberRows.Add($memberDetail)
            }
        }
        Write-Host "  Found $($memberRows.Count) member(s)." -ForegroundColor White
        $memberRows | Format-Table Name, SAMAccountName, ObjectClass, Enabled, LastLogonDate -AutoSize
    }
    else {
        Write-Host '  Group has no members.' -ForegroundColor Yellow
    }
}
else {
    Write-Host '  Cannot enumerate members - group not found.' -ForegroundColor Red
}

# ============================================================================
# 4. AdminSDHolder Gap Analysis
# ============================================================================
Write-Host ''
Write-Host '[Section 3] AdminSDHolder Gap Analysis' -ForegroundColor DarkCyan

$protectedRows = [System.Collections.Generic.List[PSObject]]::new()

try {
    $protectedObjects = Get-ADObject -Filter { adminCount -eq 1 } `
        -Properties adminCount, objectClass, distinguishedName, name `
        -ErrorAction SilentlyContinue

    if ($protectedObjects) {
        $protectedCount = ($protectedObjects | Measure-Object).Count
        Write-Host "  Found $protectedCount objects with adminCount=1 (SDProp-protected)." -ForegroundColor White

        $gapNote = if ($adminSDHolderAceStatus -eq 'OK') {
            'COVERED - AdminSDHolder ACE present; SDProp propagates read access.'
        }
        else {
            'GAP - AdminSDHolder ACE not present; Global Readers cannot see these accounts.'
        }
        Write-Host "  Status: $gapNote" -ForegroundColor $(if ($adminSDHolderAceStatus -eq 'OK') { 'Green' } else { 'Yellow' })

        foreach ($obj in $protectedObjects) {
            $protectedRows.Add([PSCustomObject]@{
                Name            = $obj.Name
                ObjectClass     = $obj.objectClass
                DN              = $obj.distinguishedName
                GlobalReaderAccess = if ($adminSDHolderAceStatus -eq 'OK') { 'Covered (via AdminSDHolder)' } else { 'GAP - Not covered' }
            })
        }
    }
    else {
        Write-Host '  No objects with adminCount=1 found (unusual).' -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  Unable to query adminCount objects: $_" -ForegroundColor Red
}

# ============================================================================
# 5. Inheritance Check (optional)
# ============================================================================
$inheritanceRows = [System.Collections.Generic.List[PSObject]]::new()

if ($CheckInheritance -and $group) {
    Write-Host ''
    Write-Host '[Section 4] Inheritance Spot-Check' -ForegroundColor DarkCyan

    $sampleOUs = @(Get-ADOrganizationalUnit -Filter * -ResultSetSize 5 `
                    -Properties DistinguishedName -ErrorAction SilentlyContinue)

    foreach ($ou in $sampleOUs) {
        $inheritedAce = Find-GRAce -ADPath "AD:\$($ou.DistinguishedName)" `
                            -GroupSidValue $groupSidValue -GroupName $IdentityName
        $inherited    = if ($inheritedAce -and $inheritedAce.IsInherited) { 'YES' }
                        elseif ($inheritedAce)                            { 'EXPLICIT' }
                        else                                              { 'NOT_FOUND' }

        $colour = if ($inherited -eq 'NOT_FOUND') { 'Red' } else { 'Green' }
        Write-Host "  [$inherited] $($ou.DistinguishedName)" -ForegroundColor $colour

        $inheritanceRows.Add([PSCustomObject]@{
            OU             = $ou.DistinguishedName
            InheritedACE   = $inherited
        })
    }
}

# ============================================================================
# 6. Export
# ============================================================================
Write-Host ''
Write-Host '[Section 5] Exporting Report' -ForegroundColor DarkCyan

$reportTitle  = "AD Global Reader Role Report - $DomainFQDN - $reportStamp"
$htmlBase     = Join-Path $OutputPath "GR-Report-$reportStamp.html"
$csvBase      = Join-Path $OutputPath "GR-Report-$reportStamp"

$cssStyle = @"
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; background: #f4f4f4; color: #222; }
  h1    { background: #1a3a5c; color: #fff; padding: 12px 20px; margin: 0; }
  h2    { background: #2e6da4; color: #fff; padding: 8px 16px; margin: 20px 0 4px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background: #fff; }
  th    { background: #2e6da4; color: #fff; padding: 8px 12px; text-align: left; }
  td    { padding: 6px 12px; border-bottom: 1px solid #ddd; }
  tr:nth-child(even) td { background: #f0f5ff; }
  .ok   { color: green; font-weight: bold; }
  .fail { color: red; font-weight: bold; }
  .warn { color: #b86e00; font-weight: bold; }
  .meta { padding: 8px 20px; font-size: 12px; color: #555; background: #e8eef5; }
</style>
"@

if ($Format -in 'HTML','Both') {
    $htmlSections = [System.Text.StringBuilder]::new()
    $null = $htmlSections.Append("<h1>$reportTitle</h1>")
    $null = $htmlSections.Append("<div class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') | Domain: $DomainFQDN | Group: $IdentityName</div>")

    # Health
    $null = $htmlSections.Append('<h2>Role Health</h2>')
    $null = $htmlSections.Append(($healthRows | ConvertTo-Html -Fragment))

    # Members
    $null = $htmlSections.Append('<h2>Group Membership</h2>')
    if ($memberRows.Count -gt 0) {
        $null = $htmlSections.Append(($memberRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(No members)</p>')
    }

    # Protected accounts
    $null = $htmlSections.Append('<h2>AdminSDHolder-Protected Objects</h2>')
    if ($protectedRows.Count -gt 0) {
        $null = $htmlSections.Append(($protectedRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(None found)</p>')
    }

    # Inheritance
    if ($CheckInheritance -and $inheritanceRows.Count -gt 0) {
        $null = $htmlSections.Append('<h2>Inheritance Spot-Check</h2>')
        $null = $htmlSections.Append(($inheritanceRows | ConvertTo-Html -Fragment))
    }

    $html = ConvertTo-Html -Head $cssStyle -Body $htmlSections.ToString() -Title $reportTitle
    $html | Out-File -FilePath $htmlBase -Encoding utf8 -Force
    Write-Host "  HTML: $htmlBase" -ForegroundColor White
}

if ($Format -in 'CSV','Both') {
    $healthRows   | Export-Csv -Path "${csvBase}-Health.csv"   -NoTypeInformation -Encoding utf8 -Force
    $memberRows   | Export-Csv -Path "${csvBase}-Members.csv"  -NoTypeInformation -Encoding utf8 -Force
    $protectedRows | Export-Csv -Path "${csvBase}-Protected.csv" -NoTypeInformation -Encoding utf8 -Force
    Write-Host "  CSV: ${csvBase}-Health.csv / -Members.csv / -Protected.csv" -ForegroundColor White
}

# ============================================================================
# 7. Summary and exit
# ============================================================================
Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
$criticalOK = ($domainRootAceStatus -eq 'OK') -and ($groupStatus -eq 'OK')
if ($criticalOK) {
    Write-Host '  Health: OK - Role is deployed and active.' -ForegroundColor Green
}
else {
    Write-Host '  Health: DEGRADED - See report for details.' -ForegroundColor Red
}
Write-Host "  Output: $OutputPath" -ForegroundColor White
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host ''

if ($FailOnMissingAce -and -not $criticalOK) {
    exit 1
}
