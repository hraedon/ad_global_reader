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

---

## Code Signing (delivered post-v2)

**Background:** Signing was flagged as a v3 candidate in the project reflection. It was promoted to an immediate deliverable when the source project (`AD Landing Zone deployer`) already contained a signing helper (`Sign-LZScripts.ps1`) that could be adapted.

**Decision: `Helpers\Sign-GRScripts.ps1`, adapted from Sign-LZScripts.ps1**

The LZ signing script was a clean, direct template: certificate resolution from CurrentUser/LocalMachine stores, EKU validation, expiry warning, per-file `Set-AuthenticodeSignature` with optional RFC 3161 timestamp, and a signed/skipped/failed summary. The adaptation required only updating the file manifest and synopsis.

**Key design choice — `-IncludeTests` switch:**
Test scripts are development artifacts. In most production environments running `AllSigned`, the test suite is never executed on the production machine, so signing test files is unnecessary overhead. The default manifest covers only the 12 production scripts. `-IncludeTests` opts in for the 5 Pester files when tests must run in an AllSigned session.

**Invoke workaround documentation:**
The `ScriptBlock::Create` / `Invoke-Expression` bypass pattern was explicitly documented in the script's `.DESCRIPTION` and in the README. This pattern is commonly found in operator runbooks as a quick fix for unsigned scripts; it circumvents both `ExecutionPolicy` and Authenticode verification and must not be used where AllSigned is a security control rather than a convenience setting.

**Dot-source coverage note:**
A non-obvious requirement is that every file the deployer dot-sources (`. (Join-Path $PSScriptRoot 'Modules\...')`) must be individually signed. PowerShell validates each file at load time, not just the entry-point script. This is why `Sign-GRScripts.ps1` signs all 12 files in the tree rather than just the two orchestrators. This was called out explicitly in the script `.DESCRIPTION` to prevent operators from partially signing the tree and hitting a confusing mid-run policy error.

**Re-signing after edits:**
`Set-AuthenticodeSignature` appends a signature block to the file. Any subsequent edit invalidates it. Operators must re-run `Sign-GRScripts.ps1` after every change to any file in the tree before deploying to an `AllSigned` environment. This is documented in the README.

---

## V2.5 Additions

### Goal 5: Shared ACE-matching helper (`Helpers\Find-GRAce.ps1`)

**Problem:** The ACE-matching loop (pre-filter to non-inherited Allow+ReadProperty ACEs, SID translate with string-fallback) was duplicated verbatim in four modules:
`Set-GR-Delegation`, `Remove-GR-Delegation`, `Set-GR-AdminSDHolder`, `Remove-GR-AdminSDHolder`.
A fifth variant also existed inside `Get-GRReport.ps1` as a local function. This violated DRY and, more importantly, each copy called `NTAccount.Translate()` internally, making the ACE-matching step inseparable from its AD dependency.

**Decision: separate SID resolution from ACE matching.**
`Find-GRAce` in `Helpers\Find-GRAce.ps1` accepts a pre-resolved `$SidValue` string (the caller's responsibility), an `$Acl` object (also the caller's), and `$IdentityName` (string fallback). It performs no AD calls — pure ACL inspection. This makes the function independently testable with any SID string and any ACL object, including PSCustomObject mocks.

**Module pattern:** Each module dot-sources `Find-GRAce.ps1` at the script level (not inside its function body), using its own `$PSScriptRoot` to locate the relative path `'..\Helpers\Find-GRAce.ps1'`. This makes each module self-contained: whether loaded by an orchestrator or directly by a test's dot-source, `Find-GRAce` is guaranteed available before the function is called.

**Unit test coverage:** `Tests\Find-GRAce.Tests.ps1` tests the ACE-matching logic in complete isolation using PSCustomObject mock ACEs — no live AD, no NTAccount.Translate(). This provides the "mockable without AD" benefit that was the stated goal of the refactoring.

**Get-GRReport.ps1 alignment:** The local `Find-GRAce` function was removed and replaced with the shared helper (dot-sourced at the top of the script). The three call sites that previously passed `$ADPath` now call `Get-Acl` inline and pass the result to `Find-GRAce`. Slightly more verbose at call sites; significantly cleaner overall.

---

### Goal 3 (fix): `$domain` scope risk in `Set-GR-AdminSDHolder.ps1`

**Problem:** The `$TriggerSDProp` block used `$domain.PDCEmulator` where `$domain` was assigned at function entry. If the module is dot-sourced into a session that already has a `$domain` variable from a different cmdlet or script, the TriggerSDProp block would use a stale or wrong value.

**Fix:** Replace `$domain.PDCEmulator` in the TriggerSDProp block with `(Get-ADDomain -ErrorAction Stop).PDCEmulator`. This is a fresh, self-contained resolution that doesn't depend on any outer-scope variable. `Remove-GR-AdminSDHolder` already used this pattern correctly.

---

### Goal 4: `Verify-Deployment.ps1` updated for v2

**Changes:**
- Added AdminSDHolder ACE check (Check 3), enabled via `-CheckAdminSDHolder`. Reported as informational (`INFO`) rather than `FAIL` since AdminSDHolder coverage is opt-in.
- Updated to use the shared `Find-GRAce` helper for all ACE lookups (domain root and AdminSDHolder), replacing the previous ad-hoc inline Where-Object filter.
- Added `-CheckAdminSDHolder` parameter with guidance on how to enable coverage if the gap is active.
- Summary line now exits with code 1 on failure (consistent with integration test behavior).
- Added `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` blocks to align with v2 style.

**Kept:** The idempotency test (re-run Deploy-GlobalReader.ps1, expect skip actions) — this is the key human-facing validation that distinguishes Verify-Deployment from the Pester integration tests.

---

### Goal 1: Event-log integration in `Get-GRReport.ps1`

**Decision: stub with local DC event log fallback, not a full SIEM integration.**

A `-SiemEndpoint` parameter was added. When provided, the Logon Activity section displays sample queries for Splunk (SPL), Microsoft Sentinel (KQL), and Elastic (EQL) rather than making a real API call. The stub explicitly documents what a real integration would execute and prompts the operator to implement the API call for their specific SIEM.

When `-SiemEndpoint` is NOT provided, the section attempts to query the PDC Emulator's Security event log for event ID 4624 events matching group member usernames (last 7 days, up to 200 events, first 10 members used in the XML filter). Access-denied and WinRM-unavailable failures are caught and surfaced as a "not configured" notice with actionable guidance, rather than silently omitting the section.

**Key design choices:**
- Local event log query is limited to 10 members to keep the FilterXml manageable. Operators with large groups should use `-SiemEndpoint`.
- The section is always present in the report (never silently skipped), per the spec requirement to surface a clear notice when data is unavailable.
- Event 4624 is filtered by `LogonType` 3 (Network) and 10 (RemoteInteractive) in the SIEM stub queries; the local XML filter queries all 4624 events for the named users (LogonType filtering would require an additional XML condition and was kept simple).

---

### Goal 2: Membership change alerting in `Get-GRReport.ps1`

**Decision: automatic baseline compare on every report run, Windows Application event log on delta.**

A baseline CSV is stored at `Logs\GR-Baseline-<GroupName>.csv`. On the first run, it is created automatically from the current membership. On every subsequent run, the current membership is compared against the baseline:
- Additions and removals are surfaced as a `Write-Warning` to the console.
- A Windows Application event log entry is written (EventId 8650, Source `AD-Global-Reader`) for each delta run. The source is registered automatically if not present.
- Delta details are included in the HTML and CSV report output.

The baseline is NOT updated automatically after a delta run. Operators acknowledge membership changes by re-running with `-RefreshBaseline`. This is a deliberate design choice: auto-updating the baseline would make the alert self-clearing and defeat the purpose of drift detection. The operator must explicitly confirm that a membership change was intentional before the alert is silenced.

**Why Application log over Security log:** Writing to the Security log requires `SeAuditPrivilege`, which domain admin sessions don't always have. The Application log write succeeds in any elevated session and is more broadly monitored in SIEM pipelines.
