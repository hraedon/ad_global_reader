# AD Global Reader Deployer — v2

Idempotent PowerShell deployer that creates a **read-only Active Directory role** for SIEM ingestion, auditing, and security posture management.

The deployer creates a security group (`GS-Global-Readers` by default) and applies a single ACE to the target container granting:

```
Allow | ReadProperty, ListChildren, ListObject | Inheritance: All
```

`ControlAccess` is intentionally omitted, meaning confidential attributes (LAPS passwords, `ms-PKI-DPAPIMasterKeys`, etc., flagged with `searchFlags` bit 128) remain inaccessible even though `ReadProperty` is granted.

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later |
| RSAT module | `ActiveDirectory` (included in RSAT on Windows Server; install via `Add-WindowsCapability` on workstations) |
| Execution context | Domain Admin, or an account with **WriteDacl** on the target container |
| Pester | v5+ (required for tests; auto-installed by `Tests\Bootstrap.ps1`) |

---

## File structure

```
ad_global_reader/
  Deploy-GlobalReader.ps1       # Orchestrator: create group + apply ACE
  Remove-GlobalReader.ps1       # Orchestrator: remove ACE (and optionally group)
  Get-GRReport.ps1              # Audit and reporting
  Verify-Deployment.ps1         # Post-deploy verification (v1; see note below)
  Modules/
    New-GR-Group.ps1            # Security group creation
    Set-GR-Delegation.ps1       # ACL delegation
    Remove-GR-Delegation.ps1    # ACL removal
    Set-GR-AdminSDHolder.ps1    # AdminSDHolder ACE application
    Remove-GR-AdminSDHolder.ps1 # AdminSDHolder ACE removal
  Helpers/
    Write-GRLog.ps1             # CSV + console logging
    Test-GRPreFlight.ps1        # Pre-flight checks
    Sign-GRScripts.ps1          # Authenticode signing for AllSigned environments
  Tests/
    Bootstrap.ps1               # Pester v5 installer and test runner
    New-GR-Group.Tests.ps1      # Unit tests
    Set-GR-Delegation.Tests.ps1 # Unit tests
    Remove-GR-Delegation.Tests.ps1 # Unit tests
    Integration.Tests.ps1       # Integration tests (requires domain-joined session)
  Docs/
    V2-Decisions.md             # Design decisions and rationale for v2
    DSC-Evaluation.md           # Evaluation of DSC for role drift remediation
  Logs/                         # Runtime CSV logs (git-ignored)
  Logs/Reports/                 # Get-GRReport HTML/CSV output (git-ignored)
```

---

## Deploy

### Deploy with defaults

Targets the domain root. Creates `GS-Global-Readers` in `CN=Users`.

```powershell
.\Deploy-GlobalReader.ps1
```

### Deploy to a specific OU

```powershell
.\Deploy-GlobalReader.ps1 `
    -TargetOU 'OU=Servers,DC=ad,DC=example,DC=com'
```

### Custom group name and group placement OU

```powershell
.\Deploy-GlobalReader.ps1 `
    -IdentityName 'GS-SIEM-Readers' `
    -TargetOU     'DC=ad,DC=example,DC=com' `
    -GroupOU      'OU=SecurityGroups,OU=Admin,DC=ad,DC=example,DC=com'
```

### Deploy with AdminSDHolder coverage

Closes the AdminSDHolder gap so that domain-protected accounts (Domain Admins, Schema Admins, etc.) are also readable. Requires `-Force` to acknowledge the security implication.

```powershell
.\Deploy-GlobalReader.ps1 -ApplyAdminSDHolder -Force
```

To immediately propagate via SDProp (rather than waiting up to 60 minutes):

```powershell
.\Deploy-GlobalReader.ps1 -ApplyAdminSDHolder -Force -TriggerSDProp
```

### Dry run

All operations are simulated. No changes are made to AD. A CSV log is still written with a `WhatIf_Active` marker row so the simulated run is auditable.

```powershell
.\Deploy-GlobalReader.ps1 -WhatIf
```

### Custom log path

```powershell
.\Deploy-GlobalReader.ps1 -LogPath 'C:\Logs\GR-Deploy.csv'
```

---

## Deploy parameters

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Name of the security group to create or use |
| `-TargetOU` | Domain root DN | DN of the container to receive the ACE |
| `-GroupOU` | Domain `CN=Users` container | DN of the OU in which to create the group |
| `-ApplyAdminSDHolder` | `$false` | Also apply the ACE to `CN=AdminSDHolder,CN=System,...` |
| `-Force` | `$false` | Required when `-ApplyAdminSDHolder` is specified |
| `-TriggerSDProp` | `$false` | Trigger immediate SDProp propagation after AdminSDHolder change |
| `-LogPath` | `.\Logs\GR-Deploy-<timestamp>.csv` | Output path for the structured deployment log |
| `-WhatIf` | — | Simulate all operations; log is still written with `WhatIf_Active` marker |

---

## Remove

Removes the domain root ACE. By default the security group is preserved, making re-deployment a single command.

```powershell
.\Remove-GlobalReader.ps1
```

### Remove AdminSDHolder ACE as well

```powershell
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder
```

To trigger immediate SDProp propagation after removal:

```powershell
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -TriggerSDProp
```

### Remove the group too

Warns if the group has members. Clears `ProtectedFromAccidentalDeletion` before deleting.

```powershell
.\Remove-GlobalReader.ps1 -RemoveGroup
```

### Dry run

```powershell
.\Remove-GlobalReader.ps1 -WhatIf
```

---

## Remove parameters

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Name of the security group |
| `-TargetOU` | Domain root DN | DN from which to remove the ACE |
| `-RemoveAdminSDHolder` | `$false` | Also remove the ACE from AdminSDHolder |
| `-RemoveGroup` | `$false` | Delete the security group after removing ACEs |
| `-TriggerSDProp` | `$false` | Trigger immediate SDProp propagation after AdminSDHolder change |
| `-LogPath` | `.\Logs\GR-Remove-<timestamp>.csv` | Output path for the removal log |
| `-WhatIf` | — | Simulate all operations; log is still written with `WhatIf_Active` marker |

All removal operations are idempotent. Re-running when the ACE or group is already absent logs a `_Skipping` action and exits cleanly.

---

## AdminSDHolder gap

Without AdminSDHolder coverage, `GS-Global-Readers` cannot read accounts protected by SDProp (`Domain Admins`, `Schema Admins`, `Enterprise Admins`, `Administrators`, Account Operators, etc.). SDProp runs every 60 minutes on the PDC Emulator and overwrites the DACL on those accounts, stripping any inherited ACE from the domain root delegation.

Applying the ACE to `CN=AdminSDHolder,CN=System,<DomainDN>` causes SDProp to propagate it forward to all protected accounts. This is opt-in (`-ApplyAdminSDHolder -Force`) and reversible (`Remove-GlobalReader.ps1 -RemoveAdminSDHolder`).

**SDProp timing:** Changes take effect within the next SDProp cycle (up to 60 minutes) unless `-TriggerSDProp` is used, which writes `runProtectAdminGroupsTask=1` to the PDC Emulator's RootDSE for immediate propagation.

---

## Audit and reporting

`Get-GRReport.ps1` produces an HTML and/or CSV report without modifying any AD objects.

```powershell
# Default: HTML + CSV report, current domain
.\Get-GRReport.ps1

# Specify output path and format
.\Get-GRReport.ps1 -OutputPath 'C:\Reports' -Format HTML

# Check inherited ACE presence on sampled OUs
.\Get-GRReport.ps1 -CheckInheritance

# Use in a monitoring pipeline: exits 1 if health is degraded
.\Get-GRReport.ps1 -FailOnMissingAce

# SIEM logon activity stub (documents what query to run against your SIEM)
.\Get-GRReport.ps1 -SiemEndpoint 'https://splunk.corp.example.com:8089'

# Acknowledge a legitimate membership change and reset the baseline
.\Get-GRReport.ps1 -RefreshBaseline
```

**Report sections:**

1. **Role Health** — group existence, domain root ACE, AdminSDHolder ACE
2. **Group Membership** — members with `LastLogonDate` and enabled status
3. **Membership Change Alert** — compares current membership against a stored baseline CSV; writes to the Windows Application event log (EventId 8650) and emits a console warning on delta. Baseline auto-created on first run; update with `-RefreshBaseline` after intentional changes.
4. **Logon Activity** — queries the PDC Emulator Security event log for event 4624 (network/remote logons) for group member accounts. If access is denied or WinRM is unavailable, surfaces a clear "not configured" notice with remediation steps. When `-SiemEndpoint` is provided, displays sample Splunk/Sentinel/Elastic queries instead.
5. **AdminSDHolder Gap Analysis** — all `adminCount=1` objects and whether they are covered
6. **Inheritance Spot-Check** *(optional, `-CheckInheritance`)* — samples up to 5 OUs and verifies inherited ACE presence

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Group name |
| `-TargetDN` | Domain root DN | DN expected to carry the ACE |
| `-OutputPath` | `.\Logs\Reports\` | Output directory |
| `-Format` | `Both` | `HTML`, `CSV`, or `Both` |
| `-CheckInheritance` | — | Enable OU inheritance spot-check |
| `-FailOnMissingAce` | — | Exit 1 when role health is degraded |
| `-SiemEndpoint` | — | SIEM URI; activates query stub instead of local event log query |
| `-RefreshBaseline` | — | Update membership baseline to current state |

---

## Pre-flight checks

Before making any changes the deployer verifies:

1. **AD module** — `ActiveDirectory` is imported or can be imported.
2. **Domain connectivity** — `Get-ADDomain` returns a valid domain object.
3. **Privilege** — Enumerates all SIDs in the current Windows token and walks the target object's DACL for a matching `WriteDacl` or `GenericAll` Allow ACE. Logs a warning (not a hard stop) if none is found; `Set-Acl` will surface the real error if rights are insufficient.
4. **Protected containers** — Warns if the target DN is under `CN=System`, `CN=Configuration`, or `CN=Schema`, where inheritance may be blocked on child objects.

---

## Idempotency

Every operation is safe to re-run:

| Operation | Already done | Action |
|---|---|---|
| Group creation | Group exists | `Group_Exists_Skipping` logged; existing object returned |
| ACE application | ACE present | `ACE_Exists_Skipping` logged; `Set-Acl` not called |
| ACE removal | ACE absent | `ACE_NotFound_Skipping` logged; exits cleanly |
| Group removal | Group absent | `Group_NotFound_Skipping` logged; exits cleanly |
| AdminSDHolder apply | ACE present | `AdminSDHolder_ACE_Exists_Skipping` logged |
| AdminSDHolder remove | ACE absent | `AdminSDHolder_ACE_NotFound_Skipping` logged |

---

## Verification

`Verify-Deployment.ps1` is a human-facing spot-check tool. It confirms the group exists, the domain root ACE is in place, and re-runs the deployer to verify idempotency.

```powershell
# Basic verification
.\Verify-Deployment.ps1

# Include AdminSDHolder ACE check
.\Verify-Deployment.ps1 -CheckAdminSDHolder

# Custom group / target
.\Verify-Deployment.ps1 -IdentityName 'GS-SIEM-Readers' `
    -TargetDN 'OU=Servers,DC=ad,DC=example,DC=com' -CheckAdminSDHolder
```

The AdminSDHolder check is informational (`INFO`) — its absence is not treated as a failure since AdminSDHolder coverage is opt-in. Exits with code 1 if the group or domain root ACE is missing, or if the idempotency run produces errors.

---

## Testing

Tests require Pester v5. `Bootstrap.ps1` installs it automatically from PSGallery if needed.

```powershell
# Unit tests only (no AD required)
.\Tests\Bootstrap.ps1 -Tags Unit

# Integration tests (requires Domain Admin session)
.\Tests\Bootstrap.ps1 -Tags Integration
```

**Unit tests:** 22 tests covering `New-GR-Group`, `Set-GR-Delegation`, and `Remove-GR-Delegation` across happy-path, idempotency, WhatIf, and error contexts. All AD and ACL calls are mocked.

**Integration tests:** 29 tests in five phases executed against a real domain:
1. Deploy (group + ACE creation)
2. Idempotency (re-run produces only skip actions)
3. Remove (WhatIf first, then real; WhatIf log verified)
4. Restore (re-deploy after removal)
5. AdminSDHolder (real apply + remove with SDProp trigger)

---

## Log format

All operations write a UTF-8 CSV at `$LogPath`. Logs are written even under `-WhatIf`; a `WhatIf_Active` marker row is prepended so simulated runs are clearly distinguishable in audit trails.

| Field | Description |
|---|---|
| `Timestamp` | UTC time (`yyyy-MM-ddTHH:mm:ssZ`) |
| `TargetDN` | DN of the object where the action occurred |
| `Action` | See action codes below |
| `Principal` | Group name or executing user |
| `Details` | Human-readable result or exception message |

**Action codes**

| Code | Meaning |
|---|---|
| `WhatIf_Active` | First row in any WhatIf run; confirms log is a simulation |
| `Group_Created` | Group was created successfully |
| `Group_Exists_Skipping` | Group already existed; no change made |
| `Group_Removed` | Group was deleted successfully |
| `Group_NotFound_Skipping` | Group already absent; removal skipped |
| `ACE_Added` | ACE was applied via `Set-Acl` |
| `ACE_Exists_Skipping` | ACE already present; `Set-Acl` not called |
| `ACE_Removed` | ACE was removed via `Set-Acl` |
| `ACE_NotFound_Skipping` | ACE already absent; removal skipped |
| `AdminSDHolder_ACE_Added` | ACE applied to AdminSDHolder |
| `AdminSDHolder_ACE_Exists_Skipping` | AdminSDHolder ACE already present; skipped |
| `AdminSDHolder_ACE_Removed` | ACE removed from AdminSDHolder |
| `AdminSDHolder_ACE_NotFound_Skipping` | AdminSDHolder ACE already absent; skipped |
| `PreFlight_OK` | Pre-flight check passed |
| `PreFlight_Warning` | Pre-flight check produced a non-fatal warning |
| `PreFlight_Error` | Pre-flight check failed (deployment aborted) |
| `Error` | Unexpected error; see `Details` for the exception |

---

## Security design

### What this role grants

- **ReadProperty** on all attributes of all objects (subject to schema `searchFlags`)
- **ListChildren** — enumerate child objects in a container
- **ListObject** — see that objects exist (required when `List Object` mode is enabled)
- Inheritance scope: **This object and all descendant objects**

### What this role explicitly does NOT grant

- `ControlAccess` — no Extended Rights of any kind, including *Read Password*, *Return Property*, *DS-Replication-Get-Changes*
- `WriteProperty`, `WriteDacl`, `WriteOwner`, `Delete`, `DeleteTree`
- Access to **confidential attributes** (`searchFlags` bit 128 in the schema, e.g., LAPS `ms-LAPS-Password`, `ms-PKI-DPAPIMasterKeys`) — these require an explicit `ControlAccess` delegation that this deployer never grants

---

## Code signing (AllSigned environments)

Environments that enforce an `AllSigned` execution policy via GPO require every `.ps1` file to carry a valid Authenticode signature — including dot-sourced helpers and modules, not just the entry-point scripts.

`Helpers\Sign-GRScripts.ps1` handles this in one pass.

```powershell
# Sign all production scripts
.\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...'

# With an RFC 3161 timestamp (recommended for production)
.\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...' `
    -TimestampServer 'http://timestamp.digicert.com'

# Also sign test scripts (if running Pester in an AllSigned session)
.\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...' `
    -TimestampServer 'http://timestamp.digicert.com' -IncludeTests
```

The certificate must carry the Code Signing EKU (`1.3.6.1.5.5.7.3.3`) and resolve to a trusted root on the target machine. The script validates both before signing.

**Invoke workaround — do not use in production:**
A common bypass for unsigned scripts is to read the file content and execute it as a ScriptBlock:
```powershell
# These bypass ExecutionPolicy but also bypass Authenticode verification entirely
& ([ScriptBlock]::Create((Get-Content $path -Raw)))
Invoke-Expression (Get-Content $path -Raw)
```
PowerShell's `AllSigned` policy applies to script *files*, not ScriptBlock literals. These patterns defeat the security purpose of code signing. Sign all constituent scripts with `Sign-GRScripts.ps1` instead.

For development sessions without AllSigned, a per-process bypass is safe:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# Reverts automatically when the session ends; does not modify machine or user policy
```

**Re-signing after edits:** `Set-AuthenticodeSignature` appends a signature block to the file. Any edit — even a single character — invalidates the signature. Re-run `Sign-GRScripts.ps1` after every change before deploying to an AllSigned environment.

---

## DSC evaluation

See [`Docs/DSC-Evaluation.md`](Docs/DSC-Evaluation.md) for a full evaluation of using the `ActiveDirectoryDsc` module (`ADObjectPermissionEntry`, `ADGroup`) to keep the role healthy via drift remediation. Short summary: a scheduled task running `Deploy-GlobalReader.ps1` is simpler and equally effective for most environments; DSC is recommended only where DSC infrastructure is already in place.

---

## Out of scope

- Deleted Objects container (requires specialized rights)
- Restricted groups / SAMR policy
- Auditing pre-existing permissive ACEs that may make this role redundant
- Cross-domain / forest-wide deployment (v3 candidate; see `Docs/V2-Decisions.md`)
