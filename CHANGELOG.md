# Changelog

All notable changes are listed here, newest first. The repository has no release tags. Entries before "Unreleased" are reconstructed from the commit history (dates are commit dates, 2026) and the version strings in the scripts; treat them as approximate.

## Unreleased

### Documentation
- Rewrote the README in plain language: scope and non-goals, quickstart, rights each action needs, rollback, manual verification, troubleshooting, test status, maintainer handover.
- Added `SECURITY.md` (what the role grants and to whom, limits, what each script writes).
- Added this changelog.
- Documented, without changing code, these known issues: loose ACE matching, `-WhatIf` on a first deployment, late failure of `-ApplyAdminSDHolder` without `-Force`, removal re-run after group deletion, inheritance spot-check that cannot report `YES`, logon query without a time range, `Verify-Deployment.ps1` performing a real deploy, unit tests needing the ActiveDirectory module. See the README section "Behaviour notes and known issues".

## 2.5 (commit 8d30bd4, 2026-03-07)
- Added `-SiemEndpoint` stub to `Get-GRReport.ps1` (prints sample Splunk, Sentinel and Elastic queries; no API call).
- Added membership-change alerting with a baseline CSV and Application event log entry (EventId 8650, Source `AD-Global-Reader`); added `-RefreshBaseline`.
- Added the shared `Helpers\Find-GRAce.ps1` ACE matcher with unit tests; updated `Verify-Deployment.ps1` (`-CheckAdminSDHolder`).

## 2.x signing helper (commit 5795adf, 2026-03-07)
- Added `Helpers\Sign-GRScripts.ps1` for AllSigned environments.

## 2.0 (commit 17fe555, 2026-03-07)
- Added `Remove-GlobalReader.ps1` (rollback), AdminSDHolder support (`-ApplyAdminSDHolder -Force`, `-RemoveAdminSDHolder`, `-TriggerSDProp`), `-WhatIf` support with logging, `Get-GRReport.ps1`, Pester unit and integration tests, and the DSC evaluation.

## 1.2 (commit c4d36c3, 2026-03-05)
- `Write-GRLog` serialises writes with a named mutex.

## 1.1 and 1.0 (commits f0899b8, c33e567, c3374b9, 2026-03-05)
- Initial deployer: group creation and read-only ACE on the domain root; code-review fixes; parameterised `Verify-Deployment.ps1` and first README.
