# DSC Evaluation: Keeping the Global Reader Role Healthy

**Goal 4 of AD-GR v2** — Evaluate how to enable management via DSC to keep the role healthy.

---

## Summary Verdict

DSC is **viable** for steady-state enforcement of the Global Reader role but adds meaningful operational complexity. For most environments, the recommended approach is a **scheduled task running `Deploy-GlobalReader.ps1`** (simpler, idempotent by design), with DSC reserved for environments that already have a DSC infrastructure investment.

---

## What "Keeping the Role Healthy" Means

The two conditions that could degrade the Global Reader role:

| Drift Scenario | Cause | Detection | Remediation |
|---|---|---|---|
| Group deleted | Manual deletion, accidental | Group not found in AD | Re-create via deployer |
| Domain root ACE removed | Explicit removal, DACL reset | ACE missing on target DN | Re-apply via deployer |
| AdminSDHolder ACE removed | Explicit removal | ACE missing on AdminSDHolder | Re-apply via deployer |
| Group membership changed | Authorized or unauthorized | Member count delta | Alert only (out of scope) |

---

## Option 1: Scheduled Task (Recommended for Most Environments)

Run `Deploy-GlobalReader.ps1` on a schedule from the PDC Emulator or any DC. Because the script is fully idempotent, re-runs are safe and zero-impact when no drift has occurred.

```powershell
# Register a daily scheduled task (run from an elevated session on a DC)
$action  = New-ScheduledTaskAction `
               -Execute 'powershell.exe' `
               -Argument '-NonInteractive -NoProfile -File "C:\Tools\ad_global_reader\Deploy-GlobalReader.ps1"'
$trigger = New-ScheduledTaskTrigger -Daily -At '03:00'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName 'AD-GlobalReader-Healthcheck' `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description 'Ensures the AD Global Reader ACE and group remain present.'
```

**Pros:** Simple, uses existing deployer, no new dependencies, logs to CSV.
**Cons:** Reactive (remediates on next scheduled run, not immediately); relies on Task Scheduler reliability.

---

## Option 2: DSC with ActiveDirectoryDsc Module

### Overview

The **[ActiveDirectoryDsc](https://github.com/dsccommunity/ActiveDirectoryDsc)** community module (PowerShell Gallery) provides two resources directly applicable to this role:

| Resource | Purpose |
|---|---|
| `ADGroup` | Ensure the security group exists with the correct properties |
| `ADObjectPermissionEntry` | Ensure a specific ACE exists on an AD object |

The DSC engine (Local Configuration Manager, LCM) can run in **ApplyAndAutoCorrect** mode, checking and remediating drift on a configurable interval (default: 30 minutes).

### Sample Configuration

```powershell
Configuration GlobalReaderRole {
    param(
        [string]$DomainDN        = 'DC=ad,DC=hraedon,DC=com',
        [string]$DomainNetBIOS   = 'HRAENET',
        [string]$GroupName       = 'GS-Global-Readers',
        [string]$UsersContainer  = "CN=Users,DC=ad,DC=hraedon,DC=com"
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc

    Node 'mvmdc03.ad.hraedon.com' {

        # Ensure the security group exists
        ADGroup GlobalReaderGroup {
            GroupName   = $GroupName
            GroupScope  = 'Global'
            Category    = 'Security'
            Path        = $UsersContainer
            Description = 'Read-only visibility across the directory for SIEM and audit.'
            Ensure      = 'Present'
        }

        # Ensure the ACE exists on the domain root
        ADObjectPermissionEntry DomainRootReadAccess {
            Path                               = $DomainDN
            IdentityReference                  = "$DomainNetBIOS\$GroupName"
            ActiveDirectoryRights              = 'ReadProperty, ListChildren, ListObject'
            AccessControlType                  = 'Allow'
            ObjectType                         = '00000000-0000-0000-0000-000000000000'
            ActiveDirectorySecurityInheritance = 'All'
            InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
            Ensure                             = 'Present'
            DependsOn                          = '[ADGroup]GlobalReaderGroup'
        }
    }
}

# Compile to MOF
GlobalReaderRole -OutputPath 'C:\DSC\GlobalReaderRole'

# Apply (run on the target node or push via Start-DscConfiguration)
Start-DscConfiguration -Path 'C:\DSC\GlobalReaderRole' -Wait -Verbose -Force
```

### Enabling Continuous Drift Remediation (ApplyAndAutoCorrect)

```powershell
[DscLocalConfigurationManager()]
Configuration LCMConfig {
    Node 'mvmdc03.ad.hraedon.com' {
        Settings {
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 30
            RebootNodeIfNeeded             = $false
        }
    }
}
LCMConfig -OutputPath 'C:\DSC\LCM'
Set-DscLocalConfigurationManager -Path 'C:\DSC\LCM' -Verbose
```

---

## Challenges and Limitations

### 1. Hardcoded Domain Values in MOF Files

DSC configurations are compiled to MOF files, which are essentially static. The domain DN (`DC=ad,DC=hraedon,DC=com`) and NetBIOS name (`HRAENET`) must be embedded at compile time. This is workable but means the config cannot be domain-agnostic the way the imperative scripts are.

**Mitigation:** Parameterize the `Configuration` block and compile per-domain during CI/CD or initial setup.

### 2. Credential Management

`ADGroup` and `ADObjectPermissionEntry` resources require a credential with WriteDacl on the target. In DSC, credentials in MOF files must be encrypted (requires a certificate on the target node) or the LCM must be configured with a service account. This is non-trivial to set up correctly.

**Mitigation:** Use a Group Managed Service Account (gMSA) for the LCM service account, or implement MOF encryption with a certificate.

### 3. ADObjectPermissionEntry Resource Maturity

As of ActiveDirectoryDsc 6.x, `ADObjectPermissionEntry` can manage individual ACEs. However:
- It manages ACEs as **exact matches** on all properties. If the rights string format differs slightly from what's in the ACL, it may not detect the existing ACE correctly.
- The resource does not support `WhatIf` natively (though `Test-DscConfiguration` provides a read-only check).
- The resource adds ACEs but does not clean up others (no "deny all others" mode), which is consistent with our additive-only principle.

**Mitigation:** Validate the resource's ACE detection against your domain before relying on it for production remediation.

### 4. DSC Node Requirement

The LCM must run on a Windows node with the ActiveDirectory module available. Running DSC on a DC is supported but requires careful LCM configuration (the LCM service account needs enough privilege).

**Mitigation:** Run DSC on the PDC Emulator or a management server with RSAT and the AD module.

### 5. AdminSDHolder Not Supported

`ADObjectPermissionEntry` does not have special handling for AdminSDHolder. It would manage the AdminSDHolder ACE like any other object, which is functionally correct, but the SDProp propagation delay is not modeled. DSC would not "know" that AdminSDHolder changes take 60 minutes to affect protected accounts.

---

## Comparison Table

| Criterion | Scheduled Task | DSC (ApplyAndAutoCorrect) |
|---|---|---|
| Setup complexity | Low | Medium-High |
| Drift detection interval | Configurable (cron) | 15-30 min (LCM) |
| Remediation speed | Next scheduled run | Next LCM cycle |
| Audit trail | CSV logs (existing) | DSC event log + CSV |
| Credential handling | Task account | gMSA or MOF encryption |
| Domain-agnostic | Yes (runtime) | No (compile-time MOF) |
| WhatIf / dry-run | Native (-WhatIf) | Test-DscConfiguration |
| Existing AD tooling | Leverages all | Requires DSC module |
| AdminSDHolder support | Yes (Set-GR-AdminSDHolder) | Indirect only |

---

## Recommendation

For the `ad.hraedon.com` lab and similar single-domain environments:

1. **Short term:** Use a scheduled task calling `Deploy-GlobalReader.ps1` daily. This leverages the existing, tested idempotent deployer with zero new dependencies.

2. **Medium term / if DSC infrastructure exists:** Add a `ADObjectPermissionEntry` DSC resource configuration compiled as part of your domain baseline. The `ActiveDirectoryDsc` module provides all needed resources. This gives you LCM-driven remediation within 30 minutes of drift.

3. **Both options benefit from `Get-GRReport.ps1`** running on a schedule to surface health status and membership changes to the security team.

---

## Prerequisites for DSC Path

If you choose to implement DSC:

```powershell
# On the management/DSC server:
Install-Module -Name ActiveDirectoryDsc -Force
# Verify ADObjectPermissionEntry resource is available:
Get-DscResource -Module ActiveDirectoryDsc | Where-Object { $_.Name -eq 'ADObjectPermissionEntry' }
```

Minimum required: `ActiveDirectoryDsc` v6.0.0 or later.

---

*Document version: 2.0 | Author: AD-GR Deployer (Claude Code / Anthropic)*
