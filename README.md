# AD Global Reader Deployer

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

---

## File structure

```
ad_global_reader/
  Deploy-GlobalReader.ps1       # Orchestrator — run this
  Verify-Deployment.ps1         # Post-deploy verification and idempotency test
  Modules/
    New-GR-Group.ps1            # Security group creation
    Set-GR-Delegation.ps1       # ACL delegation
  Helpers/
    Write-GRLog.ps1             # CSV + console logging
    Test-GRPreFlight.ps1        # Pre-flight checks
  Logs/                         # Runtime CSV logs (git-ignored)
```

---

## Usage

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

### Dry run (no changes made)

```powershell
.\Deploy-GlobalReader.ps1 -WhatIf
```

### Custom log path

```powershell
.\Deploy-GlobalReader.ps1 -LogPath 'C:\Logs\GR-Deploy.csv'
```

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Name of the security group to create or use |
| `-TargetOU` | Domain root DN | DN of the container to receive the ACE |
| `-GroupOU` | Domain `CN=Users` container | DN of the OU in which to create the group |
| `-LogPath` | `.\Logs\GR-Deploy-<timestamp>.csv` | Output path for the structured deployment log |
| `-WhatIf` | — | Simulate all operations without making changes |

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

- **Group**: checked by name before creation. If it exists, `Group_Exists_Skipping` is logged and the existing object is returned.
- **ACE**: before calling `Set-Acl`, the deployer reads the current DACL and looks for an explicit (non-inherited) Allow ACE for the group SID that includes `ReadProperty`. If found, `ACE_Exists_Skipping` is logged and `Set-Acl` is not called.

---

## Verification

After deployment, run `Verify-Deployment.ps1` to confirm the ACE is present and re-run the deployer to confirm idempotency:

```powershell
# Verify defaults
.\Verify-Deployment.ps1

# Verify a custom group on a specific OU
.\Verify-Deployment.ps1 `
    -IdentityName 'GS-SIEM-Readers' `
    -TargetDN     'OU=Servers,DC=ad,DC=example,DC=com'
```

| Parameter | Default | Description |
|---|---|---|
| `-IdentityName` | `GS-Global-Readers` | Group name to verify |
| `-TargetDN` | Domain root DN | DN to check for the ACE |

---

## Log format

All operations are written to a UTF-8 CSV at `$LogPath`.

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
| `Group_Created` | Group was created successfully |
| `Group_Exists_Skipping` | Group already existed; no change made |
| `ACE_Added` | ACE was applied via `Set-Acl` |
| `ACE_Exists_Skipping` | ACE already present; `Set-Acl` not called |
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

### AdminSDHolder gap

This role does **not** provide read access to accounts protected by AdminSDHolder (`Domain Admins`, `Schema Admins`, `Enterprise Admins`, `Administrators`, etc.). The SDProp process runs every 60 minutes and overwrites the DACL on protected accounts, stripping inherited ACEs. Delegating read access to those accounts requires a separate ACE on the AdminSDHolder object itself, which is explicitly out of scope.

---

## Out of scope

- Deleted Objects container (requires specialized rights)
- AdminSDHolder modifications
- Restricted groups / SAMR policy
- Auditing pre-existing permissive ACEs that may make this role redundant
