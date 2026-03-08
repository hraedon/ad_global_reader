#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Generates an audit and health report for the AD Global Reader role.

.DESCRIPTION
    Produces a structured report covering:
      1. Role Health        - Group existence, ACE on domain root, ACE on AdminSDHolder
      2. Group Membership   - All members with last logon and enabled status
      3. Membership Alerts  - Baseline compare; warns and writes to event log on delta
      4. Logon Activity     - Security event log query (4624) for group members,
                              or SIEM endpoint stub if -SiemEndpoint is supplied
      5. AdminSDHolder Gap  - Protected accounts (adminCount=1) and coverage status
      6. Inheritance Check  - Spot-checks inherited ACE presence on sampled OUs

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

.PARAMETER SiemEndpoint
    Optional. URI of a SIEM API endpoint (Splunk, Sentinel, Elastic, etc.).
    When supplied, the Logon Activity section displays a stub query that a real
    integration would execute, rather than attempting a local event log query.
    Example: 'https://splunk.example.com:8089'

.PARAMETER RefreshBaseline
    Update the stored membership baseline to the current group membership.
    Use this after intentional membership changes to silence the delta alert.
    Without this switch the baseline is created automatically on first run but
    never updated automatically thereafter.

.EXAMPLE
    .\Get-GRReport.ps1

.EXAMPLE
    .\Get-GRReport.ps1 -CheckInheritance -FailOnMissingAce -Format HTML

.EXAMPLE
    .\Get-GRReport.ps1 -SiemEndpoint 'https://splunk.corp.example.com:8089'

.EXAMPLE
    .\Get-GRReport.ps1 -RefreshBaseline

.NOTES
    Version : 2.5
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
    [switch]$FailOnMissingAce,
    [string]$SiemEndpoint    = '',
    [switch]$RefreshBaseline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot  = $PSScriptRoot
$reportStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')

. (Join-Path $scriptRoot 'Helpers\Find-GRAce.ps1')

if (-not $OutputPath) {
    $OutputPath = Join-Path $scriptRoot 'Logs\Reports'
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$logsRoot = Join-Path $scriptRoot 'Logs'
if (-not (Test-Path $logsRoot)) {
    New-Item -ItemType Directory -Path $logsRoot -Force | Out-Null
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

# --- Group existence ---
$group = Get-ADGroup -Filter { Name -eq $IdentityName } `
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
    Check  = 'Group Exists'
    Status = $groupStatus
    Detail = $groupDetail
})

# --- Domain root ACE ---
$domainRootAceStatus = 'MISSING'
$domainRootAceDetail = 'ACE not found.'
$groupSidValue       = $null

if ($group) {
    $groupSidValue = $group.SID.Value
    $rootAcl = $null
    try { $rootAcl = Get-Acl -Path "AD:\$TargetDN" -ErrorAction Stop } catch {}
    $rootAce = if ($rootAcl) { Find-GRAce -Acl $rootAcl -SidValue $groupSidValue -IdentityName $IdentityName } else { $null }

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
    Check  = 'Domain Root ACE'
    Status = $domainRootAceStatus
    Detail = $domainRootAceDetail
})

# --- AdminSDHolder ACE ---
$adminSDHolderAceStatus = 'NOT_APPLIED'
$adminSDHolderAceDetail = 'ACE not present on AdminSDHolder. Protected accounts (adminCount=1) are NOT covered by Global Readers.'

if ($group) {
    $ashAcl = $null
    try { $ashAcl = Get-Acl -Path "AD:\$adminSDHolderDN" -ErrorAction Stop } catch {}
    $ashAce = if ($ashAcl) { Find-GRAce -Acl $ashAcl -SidValue $groupSidValue -IdentityName $IdentityName } else { $null }

    if ($ashAce) {
        $adminSDHolderAceStatus = 'OK'
        $adminSDHolderAceDetail = "ACE present on AdminSDHolder. SDProp propagates to protected accounts. Rights: $($ashAce.ActiveDirectoryRights)"
        Write-Host "  [OK]   AdminSDHolder ACE present (protected accounts covered)." -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] AdminSDHolder ACE not applied (AdminSDHolder Gap active -- protected accounts not covered)." -ForegroundColor Yellow
    }
}

$healthRows.Add([PSCustomObject]@{
    Check  = 'AdminSDHolder ACE'
    Status = $adminSDHolderAceStatus
    Detail = $adminSDHolderAceDetail
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
                            Name           = $u.Name
                            SAMAccountName = $u.SamAccountName
                            ObjectClass    = 'user'
                            Enabled        = $u.Enabled
                            LastLogonDate  = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                            Description    = $u.Description
                            DN             = $u.DistinguishedName
                        }
                    }
                }
                elseif ($m.objectClass -eq 'group') {
                    $g = Get-ADGroup -Identity $m.distinguishedName `
                           -Properties Description -ErrorAction SilentlyContinue
                    if ($g) {
                        $memberDetail = [PSCustomObject]@{
                            Name           = $g.Name
                            SAMAccountName = $g.SamAccountName
                            ObjectClass    = 'group'
                            Enabled        = 'N/A'
                            LastLogonDate  = 'N/A'
                            Description    = $g.Description
                            DN             = $g.DistinguishedName
                        }
                    }
                }
                elseif ($m.objectClass -eq 'computer') {
                    $memberDetail = [PSCustomObject]@{
                        Name           = $m.Name
                        SAMAccountName = $m.SamAccountName
                        ObjectClass    = 'computer'
                        Enabled        = 'N/A'
                        LastLogonDate  = 'N/A'
                        Description    = ''
                        DN             = $m.distinguishedName
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
# 4. Membership Change Alert (baseline compare)
# ============================================================================
Write-Host ''
Write-Host '[Section 3] Membership Change Alert' -ForegroundColor DarkCyan

$safeGroupName  = $IdentityName -replace '[\\/:*?"<>|]', '_'
$baselineFile   = Join-Path $logsRoot "GR-Baseline-$safeGroupName.csv"
$memberAlertRows = [System.Collections.Generic.List[PSObject]]::new()

if ($group) {
    $currentSams = @($memberRows | Select-Object -ExpandProperty SAMAccountName)

    if ((Test-Path $baselineFile) -and -not $RefreshBaseline) {
        $baseline     = @(Import-Csv $baselineFile)
        $baselineSams = @($baseline | Select-Object -ExpandProperty SAMAccountName)

        $added   = @($currentSams | Where-Object { $baselineSams -notcontains $_ })
        $removed = @($baselineSams | Where-Object { $currentSams -notcontains $_ })

        if ($added.Count -gt 0 -or $removed.Count -gt 0) {
            $addedStr   = if ($added.Count   -gt 0) { $added   -join ', ' } else { '(none)' }
            $removedStr = if ($removed.Count -gt 0) { $removed -join ', ' } else { '(none)' }
            $alertMsg   = "AD Global Reader group '$IdentityName' membership changed. Added: $addedStr. Removed: $removedStr."

            Write-Warning $alertMsg

            # Write to Application event log
            $eventSource = 'AD-Global-Reader'
            try {
                if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                    New-EventLog -LogName Application -Source $eventSource -ErrorAction Stop
                }
                Write-EventLog -LogName Application -Source $eventSource `
                    -EventId 8650 -EntryType Warning -Message $alertMsg
                Write-Host "  [ALERT] Membership delta written to Application event log (EventId 8650)." -ForegroundColor Yellow
            }
            catch {
                Write-Host "  [ALERT] Membership delta detected but could not write to event log: $_" -ForegroundColor Yellow
            }

            foreach ($sam in $added)   { $memberAlertRows.Add([PSCustomObject]@{ SAMAccountName = $sam; Delta = 'ADDED';   BaselineDate = (Get-Item $baselineFile).LastWriteTimeUtc.ToString('yyyy-MM-dd') }) }
            foreach ($sam in $removed) { $memberAlertRows.Add([PSCustomObject]@{ SAMAccountName = $sam; Delta = 'REMOVED'; BaselineDate = (Get-Item $baselineFile).LastWriteTimeUtc.ToString('yyyy-MM-dd') }) }
        }
        else {
            Write-Host "  No membership changes detected since baseline ($($( (Get-Item $baselineFile).LastWriteTimeUtc.ToString('yyyy-MM-dd') )))." -ForegroundColor Green
        }
    }
    elseif (Test-Path $baselineFile) {
        # -RefreshBaseline was specified
        Write-Host '  Baseline refresh requested.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  No baseline found -- creating on this run.' -ForegroundColor Yellow
    }

    # Create or refresh baseline
    if (-not (Test-Path $baselineFile) -or $RefreshBaseline) {
        $memberRows | Select-Object SAMAccountName, ObjectClass, DN |
            Export-Csv -Path $baselineFile -NoTypeInformation -Encoding utf8 -Force
        $action = if ($RefreshBaseline) { 'refreshed' } else { 'created' }
        Write-Host "  Membership baseline $action`: $baselineFile" -ForegroundColor Green
        Write-Host "  Re-run without -RefreshBaseline to detect future deltas." -ForegroundColor White
    }
}
else {
    Write-Host '  Cannot run baseline check - group not found.' -ForegroundColor Red
}

# ============================================================================
# 5. Logon Activity (SIEM stub / local Security event log)
# ============================================================================
Write-Host ''
Write-Host '[Section 4] Logon Activity' -ForegroundColor DarkCyan

$logonRows      = [System.Collections.Generic.List[PSObject]]::new()
$memberUserSams = @($memberRows | Where-Object { $_.ObjectClass -eq 'user' } |
                    Select-Object -ExpandProperty SAMAccountName)

if ($SiemEndpoint) {
    # STUB: document the query a real SIEM integration would execute.
    # Replace this block with an API call to your SIEM when integrating.
    $sampleNames = if ($memberUserSams.Count -gt 0) {
        ($memberUserSams | Select-Object -First 5) -join ', '
    } else { '(no user members)' }

    Write-Host "  [STUB] SIEM endpoint: $SiemEndpoint" -ForegroundColor Yellow
    Write-Host '  A real implementation would execute a query similar to:' -ForegroundColor Yellow
    Write-Host "    Splunk SPL  : index=wineventlog EventCode=4624 LogonType IN (3,10) TargetUserName IN ($sampleNames, ...)" -ForegroundColor DarkGray
    Write-Host "    KQL/Sentinel: SecurityEvent | where EventID==4624 and LogonType in (3,10) and TargetUserName in ($sampleNames, ...)" -ForegroundColor DarkGray
    Write-Host "    Elastic EQL : sequence [authentication where event.code == '4624' and winlog.event_data.TargetUserName in ($sampleNames, ...)]" -ForegroundColor DarkGray

    $logonRows.Add([PSCustomObject]@{
        Status    = 'STUB_CONFIGURED'
        Endpoint  = $SiemEndpoint
        QueryNote = "Not implemented. Integrate with SIEM API at $SiemEndpoint. Query: EventCode=4624 LogonType IN (3,10) TargetUserName IN ($($memberUserSams -join ', '))"
    })
}
elseif ($memberUserSams.Count -eq 0) {
    Write-Host '  No user members -- no logon events to query.' -ForegroundColor Yellow
    $logonRows.Add([PSCustomObject]@{ Status = 'NO_USER_MEMBERS'; QueryNote = 'Group has no user members. Add members and re-run, or configure -SiemEndpoint.' })
}
else {
    # Attempt local query of the PDC Emulator Security event log.
    # Requires: WinRM enabled on PDC, and caller is member of Event Log Readers on DCs.
    $pdcFqdn   = $domain.PDCEmulator
    $queryDays = 7
    Write-Host "  Querying Security event log on '$pdcFqdn' (last $queryDays days, up to 200 events)..." -ForegroundColor White

    # Limit filter to 10 accounts to keep the XML filter manageable.
    # Use -SiemEndpoint for full-coverage queries against all members.
    $filterSams = $memberUserSams | Select-Object -First 10
    $userFilter = ($filterSams | ForEach-Object { "Data[@Name='TargetUserName']='$_'" }) -join ' or '

    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4624] and EventData[$userFilter]]
    </Select>
  </Query>
</QueryList>
"@

    try {
        $events = Get-WinEvent -ComputerName $pdcFqdn -FilterXml $filterXml `
                      -MaxEvents 200 -ErrorAction Stop

        foreach ($evt in $events) {
            $evtXml  = [xml]$evt.ToXml()
            $evtData = @{}
            foreach ($d in $evtXml.Event.EventData.Data) {
                $evtData[$d.Name] = $d.'#text'
            }
            $logonRows.Add([PSCustomObject]@{
                TimeCreated     = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                TargetUserName  = $evtData['TargetUserName']
                LogonType       = $evtData['LogonType']
                WorkstationName = $evtData['WorkstationName']
                IpAddress       = $evtData['IpAddress']
            })
        }

        if ($logonRows.Count -gt 0) {
            Write-Host "  Found $($logonRows.Count) logon event(s) for monitored accounts in the last $queryDays days." -ForegroundColor Green
        }
        else {
            Write-Host "  No matching logon events found in the last $queryDays days." -ForegroundColor Yellow
        }

        if ($memberUserSams.Count -gt 10) {
            Write-Host "  NOTE: Filter limited to first 10 of $($memberUserSams.Count) user members. Use -SiemEndpoint for full-scope queries." -ForegroundColor Yellow
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "  [NOT CONFIGURED] Access denied to Security event log on '$pdcFqdn'." -ForegroundColor Yellow
        Write-Host '  To enable: add the running account to Event Log Readers on DCs, or use -SiemEndpoint.' -ForegroundColor Yellow
        $logonRows.Add([PSCustomObject]@{
            Status    = 'ACCESS_DENIED'
            QueryNote = "Access denied to Security event log on $pdcFqdn. Add account to 'Event Log Readers' group on DCs, or configure -SiemEndpoint."
        })
    }
    catch {
        Write-Host "  [NOT CONFIGURED] Could not query Security event log: $_" -ForegroundColor Yellow
        Write-Host '  Ensure WinRM is enabled on DCs, or use -SiemEndpoint for SIEM integration.' -ForegroundColor Yellow
        $logonRows.Add([PSCustomObject]@{
            Status    = 'NOT_AVAILABLE'
            QueryNote = "Security event log query failed: $_. Ensure WinRM is enabled on DCs, or configure -SiemEndpoint."
        })
    }
}

# ============================================================================
# 6. AdminSDHolder Gap Analysis
# ============================================================================
Write-Host ''
Write-Host '[Section 5] AdminSDHolder Gap Analysis' -ForegroundColor DarkCyan

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
        $gapColour = if ($adminSDHolderAceStatus -eq 'OK') { 'Green' } else { 'Yellow' }
        Write-Host "  Status: $gapNote" -ForegroundColor $gapColour

        foreach ($obj in $protectedObjects) {
            $protectedRows.Add([PSCustomObject]@{
                Name               = $obj.Name
                ObjectClass        = $obj.objectClass
                DN                 = $obj.distinguishedName
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
# 7. Inheritance Check (optional)
# ============================================================================
$inheritanceRows = [System.Collections.Generic.List[PSObject]]::new()

if ($CheckInheritance -and $group) {
    Write-Host ''
    Write-Host '[Section 6] Inheritance Spot-Check' -ForegroundColor DarkCyan

    $sampleOUs = @(Get-ADOrganizationalUnit -Filter * -ResultSetSize 5 `
                    -Properties DistinguishedName -ErrorAction SilentlyContinue)

    foreach ($ou in $sampleOUs) {
        $ouAcl = $null
        try { $ouAcl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction SilentlyContinue } catch {}
        $inheritedAce = if ($ouAcl) { Find-GRAce -Acl $ouAcl -SidValue $groupSidValue -IdentityName $IdentityName } else { $null }

        $inherited = if ($inheritedAce -and $inheritedAce.IsInherited) { 'YES' }
                     elseif ($inheritedAce)                            { 'EXPLICIT' }
                     else                                              { 'NOT_FOUND' }

        $colour = if ($inherited -eq 'NOT_FOUND') { 'Red' } else { 'Green' }
        Write-Host "  [$inherited] $($ou.DistinguishedName)" -ForegroundColor $colour

        $inheritanceRows.Add([PSCustomObject]@{
            OU           = $ou.DistinguishedName
            InheritedACE = $inherited
        })
    }
}

# ============================================================================
# 8. Export
# ============================================================================
Write-Host ''
Write-Host '[Section 7] Exporting Report' -ForegroundColor DarkCyan

$reportTitle = "AD Global Reader Role Report - $DomainFQDN - $reportStamp"
$htmlBase    = Join-Path $OutputPath "GR-Report-$reportStamp.html"
$csvBase     = Join-Path $OutputPath "GR-Report-$reportStamp"

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

    $null = $htmlSections.Append('<h2>Role Health</h2>')
    $null = $htmlSections.Append(($healthRows | ConvertTo-Html -Fragment))

    $null = $htmlSections.Append('<h2>Group Membership</h2>')
    if ($memberRows.Count -gt 0) {
        $null = $htmlSections.Append(($memberRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(No members)</p>')
    }

    $null = $htmlSections.Append('<h2>Membership Change Alert</h2>')
    if ($memberAlertRows.Count -gt 0) {
        $null = $htmlSections.Append(($memberAlertRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(No membership changes detected)</p>')
    }

    $null = $htmlSections.Append('<h2>Logon Activity</h2>')
    if ($logonRows.Count -gt 0) {
        $null = $htmlSections.Append(($logonRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(No logon events found or query not available)</p>')
    }

    $null = $htmlSections.Append('<h2>AdminSDHolder-Protected Objects</h2>')
    if ($protectedRows.Count -gt 0) {
        $null = $htmlSections.Append(($protectedRows | ConvertTo-Html -Fragment))
    }
    else {
        $null = $htmlSections.Append('<p>(None found)</p>')
    }

    if ($CheckInheritance -and $inheritanceRows.Count -gt 0) {
        $null = $htmlSections.Append('<h2>Inheritance Spot-Check</h2>')
        $null = $htmlSections.Append(($inheritanceRows | ConvertTo-Html -Fragment))
    }

    $html = ConvertTo-Html -Head $cssStyle -Body $htmlSections.ToString() -Title $reportTitle
    $html | Out-File -FilePath $htmlBase -Encoding utf8 -Force
    Write-Host "  HTML: $htmlBase" -ForegroundColor White
}

if ($Format -in 'CSV','Both') {
    $healthRows    | Export-Csv -Path "${csvBase}-Health.csv"    -NoTypeInformation -Encoding utf8 -Force
    $memberRows    | Export-Csv -Path "${csvBase}-Members.csv"   -NoTypeInformation -Encoding utf8 -Force
    $protectedRows | Export-Csv -Path "${csvBase}-Protected.csv" -NoTypeInformation -Encoding utf8 -Force
    if ($memberAlertRows.Count -gt 0) {
        $memberAlertRows | Export-Csv -Path "${csvBase}-MemberAlerts.csv" -NoTypeInformation -Encoding utf8 -Force
    }
    if ($logonRows.Count -gt 0) {
        $logonRows | Export-Csv -Path "${csvBase}-LogonActivity.csv" -NoTypeInformation -Encoding utf8 -Force
    }
    Write-Host "  CSV: ${csvBase}-Health.csv / -Members.csv / -Protected.csv" -ForegroundColor White
}

# ============================================================================
# 9. Summary and exit
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
