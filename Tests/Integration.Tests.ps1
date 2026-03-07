#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
    Integration tests for the AD Global Reader deployer.
    Tag: Integration -- requires a Domain Admin session against ad.hraedon.com.
    Run via: .\Bootstrap.ps1 -Tags Integration

    PESTER v5 SCOPING NOTE:
    Helper functions are defined in the outermost BeforeAll, which makes them
    accessible from all nested Describe/It blocks. They use explicit parameters
    rather than $script: scope references inside the function body, because
    Pester v5 executes BeforeAll ScriptBlocks in a scope where $script: does
    not refer to the test file's script scope (causing ArgumentException).

    WHAT THESE TESTS DO:
      Phase 1 : Verify role is deployed (or deploy it) -- idempotent
      Phase 2 : Idempotency -- re-run produces only skip actions
      Phase 3 : Remove ACE (WhatIf first, then real); verifies WhatIf log is written
      Phase 4 : Restore ACE via re-deploy
      Phase 5 : AdminSDHolder -- real apply, verify, remove with SDProp trigger.
                ACE removal from AdminSDHolder is verified synchronously (immediate).
                Verification that individual protected accounts lost the ACE is NOT
                performed in-session because SDProp propagation is asynchronous.

    SIDE EFFECTS:
      - Temporarily removes and restores the domain root ACE (Phases 3-4).
      - Applies and removes the AdminSDHolder ACE (Phase 5, net zero change).
      - Does NOT permanently remove the security group.
#>

BeforeAll {
    # ---- Helper functions ------------------------------------------------
    # Defined in BeforeAll so Pester v5 makes them available to all It blocks.
    # Do NOT reference $script: inside these function bodies — Pester's BeforeAll
    # ScriptBlock scope does not carry the $script: qualifier reliably.
    # Pass all context as explicit parameters from the caller.

    function Get-GRGroupSid {
        param([Parameter(Mandatory)][string]$GroupName)
        $g = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
        if ($g) { return $g.SID.Value }
        return $null
    }

    function Find-ExplicitReadAce {
        param(
            [Parameter(Mandatory)][string]$DN,
            [Parameter(Mandatory)][string]$GroupName
        )
        $sidVal = Get-GRGroupSid -GroupName $GroupName
        if (-not $sidVal) { return $null }
        $acl = Get-Acl -Path "AD:\$DN" -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.IsInherited) { continue }
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -eq 0) { continue }
            $aceSid = $null
            try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $aceSid = $null }
            if ($aceSid -and $aceSid -eq $sidVal)                  { return $ace }
            if ($ace.IdentityReference.Value -like "*$GroupName*")  { return $ace }
        }
        return $null
    }

    function Invoke-Deployer {
        param([string]$LogSuffix, [hashtable]$ExtraParams = @{})
        $root    = Join-Path $PSScriptRoot '..'
        $logDir  = Join-Path $root 'Logs'
        $stamp   = $script:Stamp
        $logPath = Join-Path $logDir "GR-Integ-$LogSuffix-$stamp.csv"
        $params  = @{
            IdentityName = $script:IdentityName
            TargetOU     = $script:TargetDN
            LogPath      = $logPath
        }
        $params += $ExtraParams
        & (Join-Path $root 'Deploy-GlobalReader.ps1') @params
        return $logPath
    }

    function Invoke-Remover {
        param([string]$LogSuffix, [hashtable]$ExtraParams = @{})
        $root    = Join-Path $PSScriptRoot '..'
        $logDir  = Join-Path $root 'Logs'
        $stamp   = $script:Stamp
        $logPath = Join-Path $logDir "GR-Integ-$LogSuffix-$stamp.csv"
        $params  = @{
            IdentityName = $script:IdentityName
            TargetOU     = $script:TargetDN
            LogPath      = $logPath
        }
        $params += $ExtraParams
        & (Join-Path $root 'Remove-GlobalReader.ps1') @params
        return $logPath
    }

    # ---- Test context ----------------------------------------------------
    $script:ScriptRoot   = Join-Path $PSScriptRoot '..'
    $script:IdentityName = if ($env:GR_IDENTITY)  { $env:GR_IDENTITY }  else { 'GS-Global-Readers' }
    $script:TargetDN     = if ($env:GR_TARGET_DN) { $env:GR_TARGET_DN } else {
        (Get-ADDomain -ErrorAction Stop).DistinguishedName
    }
    $script:Domain       = Get-ADDomain -ErrorAction Stop
    $script:DomainDN     = $script:Domain.DistinguishedName
    $script:LogDir       = Join-Path $script:ScriptRoot 'Logs'
    $script:Stamp        = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')

    . (Join-Path $script:ScriptRoot 'Helpers\Write-GRLog.ps1')
}

AfterAll {
    Get-ChildItem -Path $script:LogDir -Filter "GR-Integ-*-$($script:Stamp).csv" -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# =============================================================================
Describe 'Phase 1: Deploy (ensure role is active)' -Tag 'Integration' {

    It 'Deploy-GlobalReader completes without throwing' {
        { Invoke-Deployer -LogSuffix 'Deploy1' } | Should -Not -Throw
    }

    It 'Security group exists in AD' {
        $g = Get-ADGroup -Filter "Name -eq '$($script:IdentityName)'" -ErrorAction SilentlyContinue
        $g | Should -Not -BeNullOrEmpty
    }

    It 'Group has ProtectedFromAccidentalDeletion enabled' {
        $g = Get-ADGroup -Identity $script:IdentityName `
                -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
        $g.ProtectedFromAccidentalDeletion | Should -BeTrue
    }

    It 'Explicit ReadProperty ACE is present on target DN' {
        $ace = Find-ExplicitReadAce -DN $script:TargetDN -GroupName $script:IdentityName
        $ace | Should -Not -BeNullOrEmpty
    }

    It 'ACE is explicit (not inherited) at the target level' {
        $ace = Find-ExplicitReadAce -DN $script:TargetDN -GroupName $script:IdentityName
        $ace.IsInherited | Should -BeFalse
    }

    It 'Deploy log contains no Error actions' {
        $logPath = Join-Path $script:LogDir "GR-Integ-Deploy1-$($script:Stamp).csv"
        if (Test-Path $logPath) {
            $errors = @(Import-Csv $logPath | Where-Object { $_.Action -eq 'Error' })
            $errors.Count | Should -Be 0
        }
    }
}

# =============================================================================
Describe 'Phase 2: Idempotency' -Tag 'Integration' {

    BeforeAll {
        $script:IdempLog = Invoke-Deployer -LogSuffix 'Idemp'
    }

    It 'Re-run produces no Error actions' {
        $errors = @(Import-Csv $script:IdempLog | Where-Object { $_.Action -eq 'Error' })
        $errors.Count | Should -Be 0
    }

    It 'Re-run produces ACE_Exists_Skipping (no duplicate ACE added)' {
        $skips = @(Import-Csv $script:IdempLog | Where-Object { $_.Action -eq 'ACE_Exists_Skipping' })
        $skips.Count | Should -Be 1
    }

    It 'Re-run produces Group_Exists_Skipping (no duplicate group created)' {
        $skips = @(Import-Csv $script:IdempLog | Where-Object { $_.Action -eq 'Group_Exists_Skipping' })
        $skips.Count | Should -Be 1
    }

    It 'ACE count on domain root is unchanged after re-run (no duplicate ACE appended)' {
        $before = (Get-Acl -Path "AD:\$($script:TargetDN)").Access.Count
        Invoke-Deployer -LogSuffix 'IdempCount' | Out-Null
        $after  = (Get-Acl -Path "AD:\$($script:TargetDN)").Access.Count
        $after | Should -Be $before
    }
}

# =============================================================================
Describe 'Phase 3: Remove' -Tag 'Integration' {

    It 'Remove-GlobalReader -WhatIf runs without throwing' {
        { Invoke-Remover -LogSuffix 'WhatIf' -ExtraParams @{ WhatIf = $true } } | Should -Not -Throw
    }

    It 'WhatIf does NOT remove the ACE' {
        $ace = Find-ExplicitReadAce -DN $script:TargetDN -GroupName $script:IdentityName
        $ace | Should -Not -BeNullOrEmpty -Because 'WhatIf must not make real changes'
    }

    It 'WhatIf DOES create a CSV log (WhatIf fix verification)' {
        $logPath = Join-Path $script:LogDir "GR-Integ-WhatIf-$($script:Stamp).csv"
        Test-Path $logPath | Should -BeTrue -Because 'logs must be written even under -WhatIf'
    }

    It 'WhatIf CSV log contains WhatIf_Active action marker' {
        $logPath = Join-Path $script:LogDir "GR-Integ-WhatIf-$($script:Stamp).csv"
        $marker  = @(Import-Csv $logPath | Where-Object { $_.Action -eq 'WhatIf_Active' })
        $marker.Count | Should -Be 1 -Because 'WhatIf runs must be stamped in the log'
    }

    It 'Remove-GlobalReader removes the domain root ACE' {
        Invoke-Remover -LogSuffix 'Remove' | Out-Null
        $ace = Find-ExplicitReadAce -DN $script:TargetDN -GroupName $script:IdentityName
        $ace | Should -BeNullOrEmpty
    }

    It 'Remove log contains ACE_Removed action' {
        $logPath = Join-Path $script:LogDir "GR-Integ-Remove-$($script:Stamp).csv"
        $removed = @(Import-Csv $logPath | Where-Object { $_.Action -eq 'ACE_Removed' })
        $removed.Count | Should -Be 1
    }

    It 'Re-running Remove is idempotent (ACE_NotFound_Skipping, no error)' {
        $logPath = Invoke-Remover -LogSuffix 'Remove2'
        $skips   = @(Import-Csv $logPath | Where-Object { $_.Action -eq 'ACE_NotFound_Skipping' })
        $errors  = @(Import-Csv $logPath | Where-Object { $_.Action -eq 'Error' })
        $errors.Count | Should -Be 0
        $skips.Count  | Should -Be 1
    }
}

# =============================================================================
Describe 'Phase 4: Restore' -Tag 'Integration' {

    BeforeAll {
        $script:RestoreLog = Invoke-Deployer -LogSuffix 'Restore'
    }

    It 'Re-deploying after removal restores the ACE' {
        $ace = Find-ExplicitReadAce -DN $script:TargetDN -GroupName $script:IdentityName
        $ace | Should -Not -BeNullOrEmpty
    }

    It 'Restore log contains ACE_Added action (not skipped)' {
        $added = @(Import-Csv $script:RestoreLog | Where-Object { $_.Action -eq 'ACE_Added' })
        $added.Count | Should -Be 1
    }
}

# =============================================================================
Describe 'Phase 5: AdminSDHolder (real apply + remove with SDProp trigger)' -Tag 'Integration' {

    BeforeAll {
        . (Join-Path $script:ScriptRoot 'Modules\Set-GR-AdminSDHolder.ps1')
        . (Join-Path $script:ScriptRoot 'Modules\Remove-GR-AdminSDHolder.ps1')

        $script:AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($script:DomainDN)"
        $script:ASHApplyLog     = Join-Path $script:LogDir "GR-Integ-ASHApply-$($script:Stamp).csv"
        $script:ASHRemoveLog    = Join-Path $script:LogDir "GR-Integ-ASHRemove-$($script:Stamp).csv"
    }

    It 'Set-GRAdminSDHolder applies ACE to AdminSDHolder' {
        Set-GRAdminSDHolder -IdentityName $script:IdentityName `
            -LogPath $script:ASHApplyLog -Force -TriggerSDProp
        $ace = Find-ExplicitReadAce -DN $script:AdminSDHolderDN -GroupName $script:IdentityName
        $ace | Should -Not -BeNullOrEmpty
    }

    It 'Apply log contains AdminSDHolder_ACE_Added action' {
        $added = @(Import-Csv $script:ASHApplyLog | Where-Object { $_.Action -eq 'AdminSDHolder_ACE_Added' })
        $added.Count | Should -Be 1
    }

    It 'Apply log confirms SDProp was triggered' {
        $triggered = @(Import-Csv $script:ASHApplyLog | Where-Object {
            $_.Action -eq 'PreFlight_OK' -and $_.Details -like '*SDProp triggered*'
        })
        $triggered.Count | Should -BeGreaterOrEqual 1
    }

    It 'Re-applying AdminSDHolder ACE is idempotent (AdminSDHolder_ACE_Exists_Skipping)' {
        $idempLog = Join-Path $script:LogDir "GR-Integ-ASHIdemp-$($script:Stamp).csv"
        Set-GRAdminSDHolder -IdentityName $script:IdentityName `
            -LogPath $idempLog -Force
        $skips = @(Import-Csv $idempLog | Where-Object { $_.Action -eq 'AdminSDHolder_ACE_Exists_Skipping' })
        $skips.Count | Should -Be 1
        Remove-Item $idempLog -Force -ErrorAction SilentlyContinue
    }

    It 'Remove-GRAdminSDHolder removes the ACE from AdminSDHolder (synchronous verification)' {
        Remove-GRAdminSDHolder -IdentityName $script:IdentityName `
            -LogPath $script:ASHRemoveLog -TriggerSDProp
        # Verify synchronously against AdminSDHolder itself (not individual protected accounts)
        $ace = Find-ExplicitReadAce -DN $script:AdminSDHolderDN -GroupName $script:IdentityName
        $ace | Should -BeNullOrEmpty -Because 'ACE removal from AdminSDHolder is synchronous'
    }

    It 'Remove log contains AdminSDHolder_ACE_Removed action' {
        $removed = @(Import-Csv $script:ASHRemoveLog | Where-Object { $_.Action -eq 'AdminSDHolder_ACE_Removed' })
        $removed.Count | Should -Be 1
    }

    It 'Remove log confirms SDProp was triggered' {
        $triggered = @(Import-Csv $script:ASHRemoveLog | Where-Object {
            $_.Action -eq 'PreFlight_OK' -and $_.Details -like '*SDProp triggered*'
        })
        $triggered.Count | Should -BeGreaterOrEqual 1
    }

    It 'Remove log surfaces the async propagation validation note' {
        $note = @(Import-Csv $script:ASHRemoveLog | Where-Object {
            $_.Details -like '*asynchronous*'
        })
        $note.Count | Should -BeGreaterOrEqual 1
    }

    It 'Re-removing AdminSDHolder ACE is idempotent (AdminSDHolder_ACE_NotFound_Skipping)' {
        $idempLog = Join-Path $script:LogDir "GR-Integ-ASHRmIdemp-$($script:Stamp).csv"
        Remove-GRAdminSDHolder -IdentityName $script:IdentityName -LogPath $idempLog
        $skips = @(Import-Csv $idempLog | Where-Object { $_.Action -eq 'AdminSDHolder_ACE_NotFound_Skipping' })
        $skips.Count | Should -Be 1
        Remove-Item $idempLog -Force -ErrorAction SilentlyContinue
    }

    It 'KNOWN LIMITATION: protected account ACE removal is async and not verified in-session' {
        # SDProp runs asynchronously on the PDC Emulator. Even after -TriggerSDProp,
        # querying individual protected accounts (adminCount=1) immediately after
        # Remove-GRAdminSDHolder may still show the old ACE for a few seconds.
        # Correct validation: wait ~5-10s after TriggerSDProp, then query a protected
        # account's DACL and confirm GS-Global-Readers is absent.
        $true | Should -BeTrue
    }
}
