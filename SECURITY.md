# Security

This document says what rights the deployer grants, to whom, and how to report a problem.

## What the role grants

`Deploy-GlobalReader.ps1` creates one Global/Security group (`GS-Global-Readers` by default) and adds one **Allow** ACE for it on the target container (the domain root by default):

| Item | Value |
|---|---|
| Rights | `ReadProperty`, `ListChildren`, `ListObject` (access mask `0x94`) |
| Applies to | The target object and all descendant objects, all object types |
| Principal | The group only. The group is created empty |
| Optional second ACE | The same ACE on `CN=AdminSDHolder,CN=System,<domain DN>` (needs `-ApplyAdminSDHolder -Force`) |

**Who receives the rights:** every member of the group, including nested members, once added. The deployer never adds members. Whoever can change the group's membership can therefore grant read access to the whole directory. Protect the group (restrict who can modify it) and watch it (`Get-GRReport.ps1` compares membership with a baseline and writes Application event log EventId 8650, Source `AD-Global-Reader`, when it changes).

**Not granted:** `ControlAccess` (no extended rights, including read-password and replication rights), any write right, `WriteDacl`, `WriteOwner`, `Delete`, `DeleteTree`.

## Limits of the confidentiality protection

Leaving out `ControlAccess` keeps attributes that the schema flags as confidential (`searchFlags` bit 128) unreadable. That is Active Directory behaviour, and the code relies on it. It protects only flagged attributes. Everything else under the target is readable by group members, including attributes you may consider sensitive. Before granting the role, review your schema and the attributes you care about. The code comments name the LAPS password attributes and `ms-PKI-DPAPIMasterKeys` as examples; confirm each in your own forest (not verified here).

## AdminSDHolder

`-ApplyAdminSDHolder -Force` extends read access to every account and group that SDProp protects (Domain Admins, Schema Admins, Enterprise Admins, Administrators, Account Operators and others). It is off by default because it is a deliberate security decision, and `-Force` is required to confirm you have made it. Removal needs no `-Force`. Protected accounts keep the access for up to 60 minutes after removal (until the next SDProp cycle).

## What the scripts change

| Script | Writes to AD | Other writes |
|---|---|---|
| `Deploy-GlobalReader.ps1` | Creates the group (and sets protection from accidental deletion); adds the ACE on the target; optionally the ACE on AdminSDHolder; optionally writes `runProtectAdminGroupsTask=1` to the PDC Emulator RootDSE | CSV log in `Logs\` |
| `Remove-GlobalReader.ps1` | Removes the ACE on the target; optionally on AdminSDHolder; optionally deletes the group | CSV log |
| `Verify-Deployment.ps1` | Nothing directly, but it **re-runs the deployer for real**, so it can create a missing group or ACE | CSV log |
| `Get-GRReport.ps1` | Nothing | Report files; membership baseline `Logs\GR-Baseline-<group>.csv`; may register an event source and write an Application event |

The scripts never modify or remove an ACE they did not match. The matching is loose (see the README, "Behaviour notes and known issues", item 3), so avoid creating other explicit read ACEs for the same group on the target.

## Running the scripts safely

- They use your current Windows session; no credentials are stored or accepted as parameters.
- Run them from an administrative workstation, not from a server that hosts other workloads.
- Always preview with `-WhatIf` first and keep the CSV log as a change record.
- Under an `AllSigned` policy, sign the scripts (`Helpers\Sign-GRScripts.ps1`). Do not use the `Invoke-Expression` / ScriptBlock workaround in production; it bypasses signature checks.
- The CSV log is a plain file in the script folder. It is not tamper-proof. Deployment actions are not written to the Windows event log (only the membership alert is).

## Reporting a vulnerability

Not yet documented: the monitored contact and process for security reports. Until the owning teams fill this in, report privately to the repository owner or your internal security team. Do not open a public issue.
