#Requires -Version 5.1
<#
    Unit tests for Set-GR-Delegation.ps1 (Set-GRDelegation function)
    Tag: Unit  -- no real AD required; all AD/ACL calls are mocked.
    Requires Pester v5+. Run via: .\Bootstrap.ps1 -Tags Unit

    MOCKING APPROACH:
    Get-Acl is mocked to return a fresh System.DirectoryServices.ActiveDirectorySecurity
    per test (created inside the mock script block, not shared). This is essential:
    AddAccessRule() mutates the ACL object in-place, so a shared object carries over
    state between It blocks and breaks idempotency-check assertions in later tests.

    For the "ACE already exists" path, Get-Acl returns a PSCustomObject whose Access
    array contains a mock ACE. The SID translation path in the code throws on a
    PSCustomObject (caught and swallowed), and the fallback string comparison
    ($ace.IdentityReference.Value -like "*$IdentityName*") matches instead.

    SID resolution: Set-GRDelegation calls NTAccount.Translate() for the group. The
    group mock returns SamAccountName 'GS-Global-Readers', which exists in the lab AD,
    so Translate() resolves on this domain-joined machine. This is an accepted
    dependency for these tests.
#>

BeforeAll {
    $helpersPath = Join-Path $PSScriptRoot '..\Helpers\Write-GRLog.ps1'
    $modulePath  = Join-Path $PSScriptRoot '..\Modules\Set-GR-Delegation.ps1'

    . $helpersPath
    . $modulePath

    $script:TestGroupName = 'GS-Global-Readers'
    $script:TestTargetDN  = 'DC=test,DC=lab'
    $script:TestLogPath   = Join-Path $env:TEMP "GR-Test-$([System.IO.Path]::GetRandomFileName()).csv"

    $script:MockGroup = [PSCustomObject]@{
        SamAccountName    = $script:TestGroupName
        DistinguishedName = "CN=$($script:TestGroupName),CN=Users,DC=test,DC=lab"
    }

    # Mock ACE shape: SID translation throws (PSCustomObject has no Translate method),
    # so the code falls through to the string-comparison fallback.
    $script:MockExistingAce = [PSCustomObject]@{
        IsInherited           = $false
        AccessControlType     = [System.Security.AccessControl.AccessControlType]::Allow
        ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        IdentityReference     = [PSCustomObject]@{ Value = "TESTLAB\$($script:TestGroupName)" }
        InheritanceType       = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    }
}

AfterAll {
    if (Test-Path $script:TestLogPath) { Remove-Item $script:TestLogPath -Force -ErrorAction SilentlyContinue }
}

Describe 'Set-GRDelegation' -Tag 'Unit' {

    # -------------------------------------------------------------------------
    Context 'When the ACE already exists on the target' {

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Get-Acl {
                return [PSCustomObject]@{ Access = @($script:MockExistingAce) }
            }
            Mock Set-Acl {}
        }

        It 'Does NOT call Set-Acl' {
            Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Set-Acl -Times 0 -Exactly
        }

        It 'Logs ACE_Exists_Skipping' {
            Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'ACE_Exists_Skipping' } `
                -Times 1 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When the ACE does not exist on the target' {

        # IMPORTANT: Get-Acl MUST return a fresh object per test.
        # AddAccessRule() mutates the object in-place. A shared instance would carry
        # the added ACE into subsequent tests, causing the idempotency check to fire
        # instead of the add path, making ACE_Added assertions fail.

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Set-Acl {}
        }

        BeforeEach {
            $script:callCount = 0
            Mock Get-Acl {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    # Fresh empty ACL — supports AddAccessRule() without cross-test mutation
                    return (New-Object System.DirectoryServices.ActiveDirectorySecurity)
                }
                # Second call (after-count read after Set-Acl)
                return [PSCustomObject]@{ Access = @($script:MockExistingAce) }
            }
        }

        It 'Calls Set-Acl exactly once' {
            Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Set-Acl -Times 1 -Exactly
        }

        It 'Logs ACE_Added after Set-Acl succeeds' {
            Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'ACE_Added' } `
                -Times 1 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When -WhatIf is specified' {

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Get-Acl     { return (New-Object System.DirectoryServices.ActiveDirectorySecurity) }
            Mock Set-Acl     {}
        }

        It 'Does NOT call Set-Acl under WhatIf' {
            Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath -WhatIf
            Should -Invoke Set-Acl -Times 0 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When Get-ADGroup fails' {

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { throw 'Group not found' }
        }

        It 'Logs an Error and rethrows' {
            { Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath } | Should -Throw
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Error' } -Times 1 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When Set-Acl throws' {

        # Same fresh-ACL requirement: must not use a shared object that may already
        # contain the ACE (which would cause idempotency skip before Set-Acl is reached).
        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Get-Acl     { return (New-Object System.DirectoryServices.ActiveDirectorySecurity) }
            Mock Set-Acl     { throw 'Access denied' }
        }

        It 'Logs an Error and rethrows' {
            { Set-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath } | Should -Throw
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Error' } -Times 1 -Exactly
        }
    }
}
