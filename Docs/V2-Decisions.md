# AD Global Reader v2 - Design Decisions and Rationale

**Date:** 2026-03-07
**Author:** AD-GR Deployer (Claude Code / Anthropic)

---

## Goal 1: Undo Logic

**Decision: Separate `Remove-GlobalReader.ps1` script (not a flag on the deployer)**

Rationale: A distinct script makes the undo operation explicit and harder to trigger accidentally. The deployer and remover share identical parameter names for consistency, but separating them provides clear intent at invocation time and a distinct log filename (`GR-Remove-*` vs `GR-Deploy-*`).

**Architecture of removal:**
- Default behavior: remove only the domain root ACE. Group is left in place (idempotent re-deployment is easy).
- `-RemoveAdminSDHolder`: removes AdminSDHolder ACE (opt-in; SDProp propagates removal within 60 min).
- `-RemoveGroup`: removes the security group (opt-in; warns on non-empty membership; clears `ProtectedFromAccidentalDeletion` first).

**Idempotency:** All removal operations check for existence before acting. Re-running when already removed logs `ACE_NotFound_Skipping` / `Group_NotFound_Skipping` and exits cleanly.

---

## Goal 2: AdminSDHolder Support

**Decision: Optional flag on both deploy and remove (`-ApplyAdminSDHolder -Force` / `-RemoveAdminSDHolder`)**

Rationale: AdminSDHolder modification is a deliberate security posture decision, not a default. Requiring `-Force` on deploy ensures the operator has acknowledged the implications. The undo path (`-RemoveAdminSDHolder` on remove) does not require `-Force` because removing an ACE is less dangerous than adding one.

**ACE applied to AdminSDHolder:** Identical rights to the domain root ACE (`ReadProperty | ListChildren | ListObject`, Inheritance=All, Type=Allow). This ensures consistent behavior across the directory.

**SDProp propagation timing:** Changes to AdminSDHolder are not immediate — SDProp runs every 60 minutes by default on the PDC Emulator. The scripts log this prominently. A code snippet for forcing SDProp is documented in both module files.

**AdminSDHolder Gap clarification:** The `CN=AdminSDHolder,CN=System,DC=...` object itself is what receives the ACE. SDProp then copies AdminSDHolder's DACL to all `adminCount=1` objects. The gap exists because SDProp *replaces* DACLs on protected objects, removing any inherited ACEs from the domain root delegation.

---

## Goal 3: Pester Tests

**Decision: Pester v5 (not the inbox Pester 3.4.0)**

Rationale: Pester v3 is end-of-life and lacks `Should -Invoke`, `BeforeAll`, and `New-MockObject`. Pester v5 is the current standard. `Bootstrap.ps1` auto-installs Pester v5 from PSGallery if needed.

**Unit test mocking approach:**
- `Write-GRLog` is mocked to avoid file I/O in unit tests.
- `Get-ADGroup` returns a `PSCustomObject` with the expected shape.
- `Get-Acl` returns either a real `ActiveDirectorySecurity` object (empty, for testing the "add ACE" path) or a `PSCustomObject` with a mocked `Access` array (for testing the "skip" path).
- `Set-Acl` is mocked to prevent real ACL modifications.
- The SID translation fallback in `Set-GRDelegation` / `Remove-GRDelegation` (string comparison `$ace.IdentityReference.Value -like "*$IdentityName*"`) is exploited by unit tests to avoid needing real `NTAccount.Translate()` calls.

**Integration tests** (`Integration.Tests.ps1`) run against the real `ad.hraedon.com` lab and execute the full deploy → verify → remove → verify → restore cycle. They are tagged `Integration` to separate them from unit tests.

**Known test limitation:** The `Remove-GRDelegation` unit tests for the "ACE found and removed" path are somewhat indirect because `RemoveAccessRule` is a method on `ActiveDirectorySecurity` that cannot be called on a `PSCustomObject`. The integration tests cover this path against real AD.

---

## Goal 4: DSC Evaluation

**Decision: Document and recommend, implement as a scheduled task for simplicity**

Key findings (full details in `DSC-Evaluation.md`):
- `ActiveDirectoryDsc` module's `ADObjectPermissionEntry` resource is the right DSC primitive.
- DSC adds operational complexity (credential management, MOF compilation, LCM configuration).
- The deployer is already idempotent, making a scheduled task a simpler and equally effective drift-remediation tool.
- DSC is recommended only for environments with existing DSC infrastructure investment.

---

## Goal 5: Audit and Reporting

**Decision: `Get-GRReport.ps1` as a standalone script, not integrated into the deployer**

Rationale: Reporting is a read-only, observability concern. Keeping it separate from the deployer prevents accidental modifications during a report run.

**Report sections:**
1. **Role Health** — group existence, domain root ACE, AdminSDHolder ACE (three distinct checks)
2. **Group Membership** — users with LastLogonDate, enabled status; groups and computers also handled
3. **AdminSDHolder Gap Analysis** — queries all `adminCount=1` objects; shows whether they are covered
4. **Inheritance Spot-Check** (optional, `-CheckInheritance`) — samples up to 5 OUs and verifies inherited ACE presence

**Output:** HTML (styled with inline CSS) and CSV, both auto-named with UTC timestamp. `-FailOnMissingAce` flag for use in monitoring pipelines (exits 1 if health degraded).

---

## Write-GRLog ValidateSet Expansion

New action types added (v2):

| Action | When Used |
|---|---|
| `ACE_Removed` | After successful removal of domain root or custom target ACE |
| `ACE_NotFound_Skipping` | Undo idempotency: ACE already gone |
| `Group_Removed` | After successful group deletion |
| `Group_NotFound_Skipping` | Undo idempotency: group already gone |
| `AdminSDHolder_ACE_Added` | After AdminSDHolder ACE application |
| `AdminSDHolder_ACE_Removed` | After AdminSDHolder ACE removal |
| `AdminSDHolder_ACE_Exists_Skipping` | AdminSDHolder deploy idempotency |
| `AdminSDHolder_ACE_NotFound_Skipping` | AdminSDHolder remove idempotency |

---

---

## V2.1 Additions (2026-03-07 — end-to-end testing pass)

### WhatIf Logging Fixed

**Problem identified during testing:** `Write-GRLog` used `Out-File` and `New-Item -ItemType Directory`, both of which honour `$WhatIfPreference` in PS5.1. When an orchestrator was run with `-WhatIf`, all CSV writes were silently suppressed, producing no log file. This was the opposite of the documented behaviour ("Logs are still written").

**Fix:** Replaced all file I/O in `Write-GRLog` with `[System.IO.File]` and `[System.IO.Directory]` .NET methods. These are not subject to PowerShell's ShouldProcess machinery and write unconditionally regardless of `$WhatIfPreference`.

**WhatIf marker rows:** Orchestrators now write a `WhatIf_Active` action row as the very first log entry when running in WhatIf mode. This stamps the CSV so any reader immediately knows the log represents a simulation, not a real deployment. Colour on console: Magenta.

### -TriggerSDProp Added to AdminSDHolder Modules

**Problem identified from user feedback:** After removing the AdminSDHolder ACE, callers had no way to initiate SDProp propagation programmatically. The guidance was buried in code comments and docs. Validating removal from protected accounts in an automated test was impossible without either waiting 60 minutes or triggering SDProp.

**Fix:** Added `-TriggerSDProp` switch to both `Set-GR-AdminSDHolder` and `Remove-GR-AdminSDHolder`. When set, the function writes `runProtectAdminGroupsTask=1` to the PDC Emulator's RootDSE immediately after the ACE change. SDProp begins propagation asynchronously within seconds.

**Async validation limitation documented explicitly:** The log, the help block, and the integration tests all now clearly state that:
- ACE removal from AdminSDHolder itself is **synchronous** — verifiable immediately.
- ACE removal from individual protected accounts is **asynchronous** — requires a brief wait after TriggerSDProp before querying.
- The integration tests test what is reliably verifiable (AdminSDHolder object) and include a documentation test that explicitly names the async limitation.

**Thought process:** The temptation was to add a `Start-Sleep` in the integration test and then verify a protected account. I rejected this because: (a) sleep durations in tests are fragile and environment-dependent, (b) it would make the test suite noticeably slower, (c) the meaningful assertion (ACE gone from AdminSDHolder) is already synchronous and reliable. The limitation is better surfaced as documentation than papered over with a sleep.

### Integration Test Robustness

**Problem:** The original Phase 1 test checked `$LASTEXITCODE | Should -BeNullOrEmpty`, which fails when `$LASTEXITCODE` is 0 (set by any previous external process) rather than null. PS scripts invoked with `&` do not reset `$LASTEXITCODE` to null on success — they either leave it unchanged (if no `exit` call) or set it to the exit code.

**Fix:** Replaced exit-code assertions with `{ ... } | Should -Not -Throw` wrappers and removed fragile exit-code checks where the subsequent state-verification tests (group exists, ACE exists, log action present) provide more meaningful signal. The integration tests now express intent through AD state assertions, not process exit codes.

## Known Limitations (carried forward or newly identified)

1. **WhatIf + log writing:** When `-WhatIf` is set, `$WhatIfPreference` propagates to `Out-File` in `Write-GRLog`, suppressing CSV file creation. This is a PS5.1 behavior and was present in v1. Workaround: use `-WhatIf` for a preview, then run without it to generate logs.

2. **AdminSDHolder Gap timing:** Even after removing the AdminSDHolder ACE, protected accounts retain read access until the next SDProp cycle (up to 60 minutes). This is expected AD behavior, not a bug.

3. **Pester 3.4.0 inbox version:** Unit tests require Pester v5. `Bootstrap.ps1` handles installation automatically.

4. **RemoveAccessRule on mocked ACL:** Unit tests for ACE removal cannot fully mock `RemoveAccessRule` on a `PSCustomObject`. Integration tests cover this path.
