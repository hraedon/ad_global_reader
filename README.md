# AD Global Reader Deployer

PowerShell scripts that create a **read-only Active Directory role** for SIEM ingestion, auditing, and security posture management. You can run them again safely at any time. They only ever add or remove the one group and the one access entry they manage.

Scripts report version 2.0 (deploy and remove) and 2.5 (report). There are no tagged releases. See [CHANGELOG.md](CHANGELOG.md).

**Who it is for:** a Windows / Active Directory administrator who needs to give a SIEM service account or an auditor read access to the directory without handing out Domain Admin.

**What it does:** creates a security group (`GS-Global-Readers` by default) and puts one access control entry (ACE) for that group on a target container (the domain root by default):

```
Allow | ReadProperty, ListChildren, ListObject | Inheritance: All
```

`ControlAccess` is deliberately left out. Attributes the schema marks as confidential (`searchFlags` bit 128) therefore stay unreadable even though `ReadProperty` is granted. See [SECURITY.md](SECURITY.md) for the full list of what the role can and cannot do.

**What it does not do:**

- It does not add anyone to the group. You manage membership yourself.
- It does not grant write, delete, `ControlAccess`, replication or any other right.
- It does not touch the Deleted Objects container, restricted-group/SAMR policy, or existing permissive ACEs.
- It does not deploy across several domains or a whole forest (a v3 candidate, see `Docs/V2-Decisions.md`).
- The SIEM integration is a stub. It prints example queries; it does not call any SIEM API.

---

## Contents

- [Requirements](#requirements)
- [File structure](#file-structure)
- [Quickstart](#quickstart)
- [Deploy](#deploy)
- [Remove (rollback)](#remove)
- [AdminSDHolder gap](#adminsdholder-gap)
- [Audit and reporting](#audit-and-reporting)
- [Pre-flight checks](#pre-flight-checks)
- [Idempotency](#idempotency)
- [Verification](#verification)
- [Behaviour notes and known issues](#behaviour-notes-and-known-issues)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Log format](#log-format)
- [Security design](#security-design)
- [Code signing (AllSigned environments)](#code-signing-allsigned-environments)
- [DSC evaluation](#dsc-evaluation)
- [Out of scope](#out-of-scope)
- [For maintainers (handover)](#for-maintainers-handover)

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later. Use Windows PowerShell 5.1 for `Get-GRReport.ps1`: the membership alert uses `New-EventLog` / `Write-EventLog`, which PowerShell 7 does not include (inferred from the cmdlets used; not tested on 7). |
| RSAT module | `ActiveDirectory` (included in RSAT on Windows Server; install via `Add-WindowsCapability` on workstations). Every script has `#Requires -Modules ActiveDirectory`. |
| Execution context | Run from a machine joined to the target domain, in a session authenticated as Domain Admin, or as an account with **WriteDacl** on the target container. No `-Credential` parameters exist; the scripts use your current Windows session. |
| Pester | v5 or later, only for tests. `Tests\Bootstrap.ps1` installs it from PSGallery if missing. |

Rights each action needs (from what the code does; the smallest delegated set was not tested, so Domain Admin is the documented context):

| Action | What the code does | Right it implies |
|---|---|---|
| Create the group | `New-ADGroup` in `-GroupOU` (default `CN=Users`), then `Set-ADObject -ProtectedFromAccidentalDeletion` | Create group objects in that container; write to the new object |
| Apply or remove the ACE | `Get-Acl` / `Set-Acl` on `AD:\<TargetDN>` | Read and write the DACL (WriteDacl) on the target |
| `-ApplyAdminSDHolder` / `-RemoveAdminSDHolder` | `Set-Acl` on `CN=AdminSDHolder,CN=System,<domain DN>` | WriteDacl on AdminSDHolder |
| `-TriggerSDProp` | Writes `runProtectAdminGroupsTask=1` to the PDC Emulator's RootDSE | Permission to do that on the PDC Emulator. If it fails, a warning is logged and the ACE change still stands |
| `-RemoveGroup` | Clears `ProtectedFromAccidentalDeletion`, then `Remove-ADGroup` | Delete the group |
| `Get-GRReport.ps1` | Reads AD; queries the PDC Emulator Security log; may register an event source | Read AD. Optional: Event Log Readers on the PDC Emulator; local administrator to register the `AD-Global-Reader` event source |

---

## File structure

```
ad_global_reader/
  Deploy-GlobalReader.ps1       # Orchestrator: create group + apply ACE
  Remove-GlobalReader.ps1       # Orchestrator: remove ACE (and optionally group)
  Get-GRReport.ps1              # Audit and reporting (read-only)
  Verify-Deployment.ps1         # Post-deploy verification (re-runs the deployer; see Verification)
  Modules/
    New-GR-Group.ps1            # Security group creation
    Set-GR-Delegation.ps1       # ACL delegation
    Remove-GR-Delegation.ps1    # ACL removal
    Set-GR-AdminSDHolder.ps1    # AdminSDHolder ACE application
    Remove-GR-AdminSDHolder.ps1 # AdminSDHolder ACE removal
  Helpers/
    Write-GRLog.ps1             # CSV + console logging
    Test-GRPreFlight.ps1        # Pre-flight checks
    Find-GRAce.ps1              # Shared ACE-matching helper (used by all ACE lookups)
    Sign-GRScripts.ps1          # Authenticode signing for AllSigned environments
  Tests/
    Bootstrap.ps1               # Pester v5 installer and test runner
    Find-GRAce.Tests.ps1        # Unit tests
    New-GR-Group.Tests.ps1      # Unit tests
    Set-GR-Delegation.Tests.ps1 # Unit tests
    Remove-GR-Delegation.Tests.ps1 # Unit tests
    Integration.Tests.ps1       # Integration tests (requires domain-joined session)
  Docs/
    V2-Decisions.md             # Design decisions and rationale for v2 (dated 2026-03-07)
    DSC-Evaluation.md           # Evaluation of DSC for role drift remediation
  Logs/                         # Runtime CSV logs and membership baseline (git-ignored)
  Logs/Reports/                 # Get-GRReport HTML/CSV output (git-ignored)
```

---

## Quickstart

Always preview first. From the repository folder, in an elevated session on a domain-joined machine:

```powershell
# 1. Preview. Nothing is written to AD; a CSV log is still written.
.\Deploy-GlobalReader.ps1 -WhatIf

# 2. Deploy to the domain root with defaults
.\Deploy-GlobalReader.ps1

# 3. Confirm
.\Verify-Deployment.ps1

# 4. Add your SIEM service account to GS-Global-Readers (not done by this tool)
Add-ADGroupMember -Identity 'GS-Global-Readers' -Members '<siem-service-account>'
```

Read [Behaviour notes and known issues](#behaviour-notes-and-known-issues) before relying on `-WhatIf` for a first deployment.

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

To propagate immediately through SDProp (rather than waiting up to 60 minutes):

```powershell
.\Deploy-GlobalReader.ps1 -ApplyAdminSDHolder -Force -TriggerSDProp
```

### Dry run

Every change is simulated. No changes are made to AD. A CSV log is still written, with a `WhatIf_Active` marker row so the simulated run is auditable.

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
| `-LogPath` | `.\Logs\GR-Deploy-<timestamp>.csv` | Output path for the structured deployment log (the default is relative to the script folder, timestamp in UTC) |
| `-WhatIf` | — | Simulate all operations; log is still written with `WhatIf_Active` marker |

---

## Remove

Removal is also the rollback. It removes the ACE from the target (domain root by default). By default the security group is kept, so re-deployment is a single command.

```powershell
.\Remove-GlobalReader.ps1
```

Pass the same `-IdentityName` and `-TargetOU` you used to deploy. If you deployed with `-ApplyAdminSDHolder`, also pass `-RemoveAdminSDHolder`.

### Remove AdminSDHolder ACE as well

```powershell
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder
```

To trigger immediate SDProp propagation after removal:

```powershell
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -TriggerSDProp
```

Protected accounts keep read access until the next SDProp cycle (up to 60 minutes), even after the AdminSDHolder ACE is gone.

### Remove the group too

Warns if the group has members. Clears `ProtectedFromAccidentalDeletion` before deleting. The group is deleted after the ACE steps, so remove the ACEs and the group in the same run (see the re-run caveat under [Behaviour notes](#behaviour-notes-and-known-issues)).

```powershell
.\Remove-GlobalReader.ps1 -RemoveGroup
```

### Full rollback

```powershell
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -RemoveGroup -WhatIf   # preview
.\Remove-GlobalReader.ps1 -RemoveAdminSDHolder -RemoveGroup
```

Then confirm with `.\Verify-Deployment.ps1` (it should report FAIL: group and ACE absent) or the manual checks under [Verification](#verification). Removing the group deletes it. Recreating it later gives a new SID; any other permissions that referenced the old group are not restored.

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

Removal skips steps whose target is already gone: if the ACE is absent it logs `ACE_NotFound_Skipping`, and if the group is absent it logs `Group_NotFound_Skipping` (only in the `-RemoveGroup` step). One exception is described in [Behaviour notes](#behaviour-notes-and-known-issues): the ACE steps need the group to still exist.

---

## AdminSDHolder gap

Without AdminSDHolder coverage, `GS-Global-Readers` cannot read accounts protected by SDProp (`Domain Admins`, `Schema Admins`, `Enterprise Admins`, `Administrators`, Account Operators, etc.). SDProp runs every 60 minutes on the PDC Emulator and overwrites the DACL on those accounts, stripping any inherited ACE from the domain root delegation.

Applying the ACE to `CN=AdminSDHolder,CN=System,<DomainDN>` causes SDProp to copy it to all protected accounts. This is opt-in (`-ApplyAdminSDHolder -Force`) and reversible (`Remove-GlobalReader.ps1 -RemoveAdminSDHolder`).

**SDProp timing:** Changes take effect within the next SDProp cycle (up to 60 minutes) unless `-TriggerSDProp` is used, which writes `runProtectAdminGroupsTask=1` to the PDC Emulator's RootDSE to start propagation immediately. Propagation is still asynchronous and can take a few seconds.

**Decide deliberately.** This step extends read access to every privileged account in the domain. The reasoning behind the `-Force` requirement is in [SECURITY.md](SECURITY.md).

---

## Audit and reporting

`Get-GRReport.ps1` produces an HTML and/or CSV report without modifying any AD objects. (It can write one Application event log entry and local files; see below.)

```powershell
# Default: HTML + CSV report, current domain
.\Get-GRReport.ps1

# Specify output path and format
.\Get-GRReport.ps1 -OutputPath 'C:\Reports' -Format HTML

# Check inherited ACE presence on sampled OUs (see known issue: the result is unreliable)
.\Get-GRReport.ps1 -CheckInheritance

# Use in a monitoring pipeline: exits 1 if the group or the target ACE is missing
.\Get-GRReport.ps1 -FailOnMissingAce

# SIEM logon activity stub (documents what query to run against your SIEM)
.\Get-GRReport.ps1 -SiemEndpoint 'https://splunk.corp.example.com:8089'

# Acknowledge a legitimate membership change and reset the baseline
.\Get-GRReport.ps1 -RefreshBaseline
```

**Report sections:**

1. **Role Health** — group existence, target (domain root by default) ACE, AdminSDHolder ACE (`NOT_APPLIED` is informational, not a failure)
2. **Group Membership** — members with `LastLogonDate` and enabled status
3. **Membership Change Alert** — compares current membership against a stored baseline CSV, `Logs\GR-Baseline-<group>.csv`. On a difference it prints a warning and tries to write to the Windows Application event log (Source `AD-Global-Reader`, EventId 8650, Warning), registering the source if needed. If the event log write fails, it prints that and continues. The baseline is created on the first run and is never updated automatically; update it with `-RefreshBaseline` after intentional changes.
4. **Logon Activity** — queries the PDC Emulator Security event log for event 4624 for up to the first 10 user members of the group, up to 200 events. The query does not filter by logon type, and its XML filter has no time range even though the console text says "last 7 days" (code check; see known issues). If access is denied or the remote query fails, the section shows a "not configured" notice with remediation steps (add the account to Event Log Readers on the DCs, or use `-SiemEndpoint`). When `-SiemEndpoint` is given, it prints sample Splunk, Sentinel and Elastic queries (logon types 3 and 10) instead and calls no API.
5. **AdminSDHolder Gap Analysis** — all `adminCount=1` objects and whether they are covered
6. **Inheritance Spot-Check** *(optional, `-CheckInheritance`)* — samples up to 5 OUs and looks for the ACE

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Group name |
| `-TargetDN` | Domain root DN | DN expected to carry the ACE |
| `-OutputPath` | `.\Logs\Reports\` | Output directory |
| `-Format` | `Both` | `HTML`, `CSV`, or `Both` |
| `-CheckInheritance` | — | Enable OU inheritance spot-check |
| `-FailOnMissingAce` | — | Exit 1 when the group or the target ACE is missing |
| `-SiemEndpoint` | — | SIEM URI; activates query stub instead of local event log query |
| `-RefreshBaseline` | — | Update membership baseline to current state |

Output files: `GR-Report-<timestamp>.html`, and CSV files with the suffixes `-Health`, `-Members`, `-Protected`, plus `-MemberAlerts` and `-LogonActivity` when those sections have rows.

---

## Pre-flight checks

Before making any changes the deployer and remover verify:

1. **AD module** — `ActiveDirectory` is imported or can be imported.
2. **Domain connectivity** — `Get-ADDomain` returns a valid domain object.
3. **Privilege** — Enumerates all SIDs in the current Windows token and walks the target object's DACL for a matching `WriteDacl` or `GenericAll` Allow ACE. Logs a warning (not a hard stop) if none is found; `Set-Acl` will surface the real error if rights are insufficient. Deny ACEs and ACE order are not evaluated. Only the target container is checked, not AdminSDHolder.
4. **Protected containers** — Warns if the target DN is under `CN=System`, `CN=Configuration`, or `CN=Schema`, where inheritance may be blocked on child objects.

A failed check 1, 2, or an unreadable target DACL stops the run (exit 1).

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

"ACE present" means a looser test than "my exact ACE is there". See the matching rules in [Behaviour notes](#behaviour-notes-and-known-issues).

---

## Verification

`Verify-Deployment.ps1` is a human-facing spot-check tool. It confirms the group exists, the target ACE is in place, and re-runs the deployer to check idempotency. **That re-run is a real deployment, not a dry run.** If the group or ACE is missing, the re-run creates it.

```powershell
# Basic verification
.\Verify-Deployment.ps1

# Include AdminSDHolder ACE check
.\Verify-Deployment.ps1 -CheckAdminSDHolder

# Custom group / target
.\Verify-Deployment.ps1 -IdentityName 'GS-SIEM-Readers' `
    -TargetDN 'OU=Servers,DC=ad,DC=example,DC=com' -CheckAdminSDHolder
```

The AdminSDHolder check is informational (`INFO`): its absence is not a failure, since AdminSDHolder coverage is opt-in. The script exits with code 1 if the group or target ACE is missing, or if the idempotency run produces errors. Its log is `Logs\GR-Verify-<timestamp>.csv`. (Check 1 and 2 run before the re-run, so a missing group or ACE is still reported as FAIL even though the re-run then repairs it.)

Manual checks, independent of these scripts:

```powershell
Get-ADGroup 'GS-Global-Readers' -Properties ProtectedFromAccidentalDeletion
(Get-Acl 'AD:\DC=ad,DC=example,DC=com').Access |
    Where-Object { $_.IdentityReference -like '*GS-Global-Readers*' } |
    Format-List IdentityReference, ActiveDirectoryRights, AccessControlType, InheritanceType, IsInherited
```

Expect one `Allow` entry with `ReadProperty, ListChildren, ListObject`, `InheritanceType` `All`, `IsInherited` `False`.

---

## Behaviour notes and known issues

These were found by reading the code. None was run against a live domain here (no AD available), so treat the first two as likely rather than confirmed.

1. **`-WhatIf` on a first deployment may stop early.** In a preview, the group is not created. The next step looks the group up with `Get-ADGroup -Identity` and throws if it does not exist, so the ACE step of a first-ever preview probably fails. Once the group exists, `-WhatIf` runs completely. Not yet confirmed against a live domain.
2. **Final log row says success under `-WhatIf`.** The last row (`PreFlight_OK`, "Deployment finished successfully") is written even in preview mode. Read it together with the `WhatIf_Active` row. `ACE_Added` / `Group_Created` rows are not written in preview mode.
3. **ACE matching is loose.** `Find-GRAce` counts any explicit, non-inherited **Allow** ACE that includes `ReadProperty` and either resolves to the group's SID or has an identity string that contains the group name (`-like "*<name>*"`). It does not check the other rights, the inheritance scope or the object type. Consequences: a narrower pre-existing ACE for the group makes the deployer skip; a group named `GS-Global-Readers-2` also matches `GS-Global-Readers`; and `Remove-GlobalReader.ps1` removes the first matching ACE it finds, which may not be the one this tool created. Do not hand-add other explicit read ACEs for this group on the target.
4. **`-ApplyAdminSDHolder` without `-Force` fails late.** The group and the target ACE are created first; only then does the AdminSDHolder step refuse and throw (the run exits 1). Pass `-Force` from the start.
5. **Re-running removal after the group was deleted fails.** The ACE steps resolve the group first and throw if it no longer exists. If you delete the group in one run and need to repeat the ACE removal, the tool cannot do it. Remove the leftover ACE entries (they show as an unresolved SID) by hand.
6. **The inheritance spot-check cannot report `YES`.** It uses the same matcher, which ignores inherited ACEs, so a correctly inherited ACE is reported `NOT_FOUND`, and only explicit ACEs are reported (`EXPLICIT`). Do not use `-CheckInheritance` output as proof of a problem or of success until this is fixed. Use the manual check above on a sample OU instead, and look for `IsInherited` `True`.
7. **Logon-activity query has no time range** (see report section 4). Expect the 200 most recent matching events returned by the PDC Emulator, not a fixed 7-day window.
8. **Unit tests need the `ActiveDirectory` module** and, for the delegation tests, a domain-joined machine. See [Testing](#testing).
9. **Signing helper does not sign `Tests\Find-GRAce.Tests.ps1`** when `-IncludeTests` is used (it is missing from the list in `Sign-GRScripts.ps1`).
10. **No license file.** The repository has no `LICENSE`. The owner has not chosen one. Confirm terms with the owner before redistributing outside your organisation.

---

## Troubleshooting

| Symptom | Likely cause / action |
|---|---|
| `FATAL: Cannot retrieve domain information` | Not domain-joined, RSAT not installed, or no DC reachable. Run `Get-ADDomain` by hand. |
| `PreFlight_Error` in the log, run aborted | AD module cannot be imported, domain unreachable, or the target DN's DACL cannot be read. Check the `Details` column. |
| `PreFlight_Warning`: no WriteDacl/GenericAll ACE found | Warning only. Rights inherited via groups such as Builtin\Administrators may not appear as explicit ACEs. If `Set-Acl` then fails, the account lacks WriteDacl. |
| `Group creation failed` | The account cannot create groups in `-GroupOU`, the OU DN is wrong, or the name clashes with another object. |
| `ACL delegation failed` | No WriteDacl on the target, or the target DN is wrong. |
| `-Force is required to apply the AdminSDHolder ACE` | You used `-ApplyAdminSDHolder` without `-Force`. |
| SDProp trigger failed (`PreFlight_Warning`) | The ACE change succeeded. Protected accounts update on the next SDProp cycle (up to 60 minutes). |
| Protected accounts still unreadable after enabling AdminSDHolder | Wait for the SDProp cycle, or re-run with `-TriggerSDProp`; propagation takes a few seconds even then. |
| Logon Activity shows `ACCESS_DENIED` / `NOT_AVAILABLE` | Add the account to Event Log Readers on the DCs, check remote event log access to the PDC Emulator, or use `-SiemEndpoint`. |
| Membership alert shows but no event log entry | Registering the `AD-Global-Reader` source needs an elevated session. The console text says the event log write failed. |
| `Integration.Tests.ps1` leaves things behind | It runs real deploy and remove cycles against the live domain. Re-run `Deploy-GlobalReader.ps1` to restore. |

Logs are the first stop: every action is a row in the CSV (see [Log format](#log-format)).

---

## Testing

Tests require Pester v5. `Bootstrap.ps1` installs it automatically from PSGallery if needed.

```powershell
# Unit tests (default tag)
.\Tests\Bootstrap.ps1 -Tags Unit

# Integration tests (requires Domain Admin session)
.\Tests\Bootstrap.ps1 -Tags Integration
```

**Unit tests:** 34 `It` blocks in total: 22 covering `New-GR-Group`, `Set-GR-Delegation` and `Remove-GR-Delegation` (happy path, idempotency, WhatIf, errors) and 12 for `Find-GRAce`. All AD and ACL calls are mocked, but the files still require the `ActiveDirectory` module (`#Requires`), and the delegation tests resolve the real group name through `NTAccount.Translate()`, so they expect a domain-joined machine where `GS-Global-Readers` resolves. They are not runnable on a machine without RSAT.

**Integration tests:** 29 tests in five phases executed against a real domain:
1. Deploy (group + ACE creation)
2. Idempotency (re-run produces only skip actions)
3. Remove (WhatIf first, then real; WhatIf log verified)
4. Restore (re-deploy after removal)
5. AdminSDHolder (real apply + remove with SDProp trigger)

**Static checks run for this documentation pass (PowerShell 7.6.6 on Linux, no AD):** every `.ps1` file parses with no syntax errors. `Find-GRAce.Tests.ps1`: 10 of 12 pass; the 2 failures create real ACL objects, which Linux does not support. The other unit test files and the integration tests cannot load without the `ActiveDirectory` module. PSScriptAnalyzer 1.25.0 with default rules reports no errors; warnings are mostly `PSAvoidUsingWriteHost` (177), plus a few empty catch blocks, missing BOM on 8 files and `ShouldProcess` notes. There is no PSScriptAnalyzer settings file and no CI configuration in the repository.

---

## Log format

All operations write a UTF-8 CSV at `$LogPath`. Logs are written even under `-WhatIf`; a `WhatIf_Active` marker row is written first so simulated runs are clearly distinguishable in audit trails.

| Field | Description |
|---|---|
| `Timestamp` | UTC time (`yyyy-MM-ddTHH:mm:ssZ`) |
| `TargetDN` | DN of the object where the action occurred |
| `Action` | See action codes below |
| `Principal` | Group name or executing user |
| `Details` | Human-readable result or exception message |

Writes are serialised with a named mutex (5-second wait; if it times out the row is written anyway).

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
| `PreFlight_OK` | Pre-flight check passed (also used for the final success row and a successful SDProp trigger) |
| `PreFlight_Warning` | Non-fatal warning (also the missing-`-Force` notice and a failed SDProp trigger) |
| `PreFlight_Error` | Pre-flight check failed (run aborted) |
| `Error` | Unexpected error; see `Details` for the exception |

---

## Security design

### What this role grants

- **ReadProperty** on all attributes of all objects under the target (subject to schema `searchFlags`)
- **ListChildren** — enumerate child objects in a container
- **ListObject** — see that objects exist (required when `List Object` mode is enabled)
- Inheritance scope: **This object and all descendant objects**

In raw terms the ACE is an Allow entry with access mask `0x94` (`ReadProperty` 0x10, `ListChildren` 0x4, `ListObject` 0x80), no object-type restriction, inheritance flags `All`.

### What this role explicitly does NOT grant

- `ControlAccess` — no Extended Rights of any kind, including *Read Password*, *Return Property*, *DS-Replication-Get-Changes*
- `WriteProperty`, `WriteDacl`, `WriteOwner`, `Delete`, `DeleteTree`
- Access to **confidential attributes** (`searchFlags` bit 128 in the schema, for example the LAPS password attributes) — these require an explicit `ControlAccess` delegation that this deployer never grants. The code comments also name `ms-PKI-DPAPIMasterKeys`; verify that attribute's flags in your own schema.

This protection applies only to attributes the schema flags as confidential. Review which sensitive attributes in your forest are not flagged before granting the role. Details and recommendations: [SECURITY.md](SECURITY.md).

---

## Code signing (AllSigned environments)

Environments that enforce an `AllSigned` execution policy via GPO require every `.ps1` file to carry a valid Authenticode signature, including dot-sourced helpers and modules, not just the entry-point scripts.

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

**Re-signing after edits:** `Set-AuthenticodeSignature` appends a signature block to the file. Any edit, even a single character, invalidates the signature. Re-run `Sign-GRScripts.ps1` after every change before deploying to an AllSigned environment. Obtaining and protecting the signing certificate is the operator's job; the repository does not provide one.

---

## DSC evaluation

See [`Docs/DSC-Evaluation.md`](Docs/DSC-Evaluation.md) for a full evaluation of using the `ActiveDirectoryDsc` module (`ADObjectPermissionEntry`, `ADGroup`) to keep the role healthy via drift remediation. Short summary: a scheduled task running `Deploy-GlobalReader.ps1` is simpler and equally effective for most environments; DSC is recommended only where DSC infrastructure is already in place. The repository does not ship a scheduled task definition; "Not yet documented: a ready-made scheduled-task setup."

---

## Out of scope

- Deleted Objects container (requires specialized rights)
- Restricted groups / SAMR policy
- Auditing pre-existing permissive ACEs that may make this role redundant
- Cross-domain / forest-wide deployment (v3 candidate; see `Docs/V2-Decisions.md`)

---

## For maintainers (handover)

**Architecture in one page.** Three entry scripts (`Deploy-GlobalReader.ps1`, `Remove-GlobalReader.ps1`, `Get-GRReport.ps1`) plus `Verify-Deployment.ps1`. Each dot-sources its helpers and modules from its own folder, derives the domain at runtime (no hard-coded domain values), and logs every action through `Write-GRLog`. The deployer runs: pre-flight, then `New-GRGroup`, then `Set-GRDelegation`, then optionally `Set-GRAdminSDHolder`. The remover runs the mirror image: `Remove-GRDelegation`, optionally `Remove-GRAdminSDHolder`, optionally group deletion (inline in the script). All ACE lookups go through `Helpers\Find-GRAce.ps1`, so a change to matching rules changes deploy, remove, verify and report together. Everything is additive: no existing ACE is modified.

**Where things live.**

| Topic | Location |
|---|---|
| The ACE definition (rights, inheritance) | `Modules\Set-GR-Delegation.ps1` and, identically, `Modules\Set-GR-AdminSDHolder.ps1` (keep the two in step) |
| ACE matching | `Helpers\Find-GRAce.ps1` |
| Log action names | `ValidateSet` in `Helpers\Write-GRLog.ps1` (add a code there before using a new one) |
| Pre-flight | `Helpers\Test-GRPreFlight.ps1` |
| Design decisions | `Docs\V2-Decisions.md` (dated record, 2026-03-07; some statements are older than the code, for example the "last 7 days" logon query and the integration tests' lab domain) |

**Build, test, release.** There is no build. Run the unit tests as described under [Testing](#testing) on a machine with RSAT; run the integration tests only against a domain you can afford to change. There is no CI and no release process: history shows version bumps by commit message only. If you ship to an AllSigned environment, re-sign after every edit.

**Conventions.** Every state-changing function uses `SupportsShouldProcess` and must keep honouring `-WhatIf`; new log codes go into the `ValidateSet`; keep the rights in the two `Set-*` modules identical; keep scripts compatible with Windows PowerShell 5.1 (`#Requires -Version 5.1`).

**Known gaps and debts.** The list under [Behaviour notes and known issues](#behaviour-notes-and-known-issues) is the current debt list. Also open: the `-SiemEndpoint` integration is a stub; no least-privilege delegation set for the operator is documented; the contact for security reports is not yet documented (see [SECURITY.md](SECURITY.md)).

**Depends on.** The `ActiveDirectory` RSAT module; a reachable writable DC and PDC Emulator; Pester v5 (tests); a code-signing certificate (AllSigned environments only).
