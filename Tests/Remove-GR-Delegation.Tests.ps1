#Requires -Version 5.1
<#
    Unit tests for Remove-GR-Delegation.ps1 (Remove-GRDelegation function)
    Tag: Unit  -- mostly no real AD required; all AD/ACL calls are mocked.
    Requires Pester v5+. Run via: .\Bootstrap.ps1 -Tags Unit

    MOCKING APPROACH:
    "ACE exists" path: Get-Acl returns a real ActiveDirectorySecurity with a real ACE
    for the GS-Global-Readers group (constructed via ActiveDirectoryAccessRule). This is
    required because Remove-GRDelegation calls $acl.RemoveAccessRule($ace), which is a
    CLR method that only exists on the real type. NTAccount.Translate() inside the code
    resolves the real group SID — GS-Global-Readers must exist in the lab AD.

    "ACE not found" path: Get-Acl returns a PSCustomObject with an empty or unrelated
    Access array. ShouldProcess is never reached, so no CLR method calls are needed.

    "WhatIf" path: Get-Acl returns a PSCustomObject with our mock ACE. The code finds
    the ACE via string fallback, but ShouldProcess returns false, so RemoveAccessRule
    is never called — the PSCustomObject is safe here.
#>

BeforeAll {
    $helpersPath = Join-Path $PSScriptRoot '..\Helpers\Write-GRLog.ps1'
    $modulePath  = Join-Path $PSScriptRoot '..\Modules\Remove-GR-Delegation.ps1'

    . $helpersPath
    . $modulePath

    $script:TestGroupName = 'GS-Global-Readers'
    $script:TestTargetDN  = 'DC=test,DC=lab'
    $script:TestLogPath   = Join-Path $env:TEMP "GR-Test-$([System.IO.Path]::GetRandomFileName()).csv"

    $script:MockGroup = [PSCustomObject]@{
        SamAccountName    = $script:TestGroupName
        DistinguishedName = "CN=$($script:TestGroupName),CN=Users,DC=test,DC=lab"
    }

    # PSCustomObject ACE — safe for paths where RemoveAccessRule is never called
    $script:MockReadAce = [PSCustomObject]@{
        IsInherited           = $false
        AccessControlType     = [System.Security.AccessControl.AccessControlType]::Allow
        ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        IdentityReference     = [PSCustomObject]@{ Value = "TESTLAB\$($script:TestGroupName)" }
    }

    # An unrelated ACE that should never match our group
    $script:OtherAce = [PSCustomObject]@{
        IsInherited           = $false
        AccessControlType     = [System.Security.AccessControl.AccessControlType]::Allow
        ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        IdentityReference     = [PSCustomObject]@{ Value = 'TESTLAB\SomeOtherGroup' }
    }

    # Helper: build a real ActiveDirectorySecurity with one ACE for our group.
    # Uses NTAccount resolution — requires GS-Global-Readers to exist in AD.
    function New-RealAclWithGroupAce {
        $realAcl   = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $ntAccount = New-Object System.Security.Principal.NTAccount($script:TestGroupName)
        $rights    = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        $aceType   = [System.Security.AccessControl.AccessControlType]::Allow
        $inherit   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        $emptyGuid = [Guid]::Empty
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $ntAccount, $rights, $aceType, $emptyGuid, $inherit, $emptyGuid
        )
        $realAcl.AddAccessRule($ace)
        return $realAcl
    }
}

AfterAll {
    if (Test-Path $script:TestLogPath) { Remove-Item $script:TestLogPath -Force -ErrorAction SilentlyContinue }
}

Describe 'Remove-GRDelegation' -Tag 'Unit' {

    # -------------------------------------------------------------------------
    Context 'When the target ACE exists' {

        # Requires a real ACL object so that $acl.RemoveAccessRule() succeeds.
        # A fresh real ACL is created per test to avoid cross-test state leakage.

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Set-Acl     {}
        }

        BeforeEach {
            $script:callCount = 0
            Mock Get-Acl {
                $script:callCount++
                if ($script:callCount -eq 1) {
                    return (New-RealAclWithGroupAce)
                }
                # Second call: after-count read (post-removal)
                return [PSCustomObject]@{ Access = @() }
            }
        }

        It 'Calls Set-Acl exactly once' {
            Remove-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Set-Acl -Times 1 -Exactly
        }

        It 'Logs ACE_Removed' {
            Remove-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'ACE_Removed' } `
                -Times 1 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When the target ACE does not exist' {

        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Get-Acl {
                return [PSCustomObject]@{ Access = @($script:OtherAce) }
            }
            Mock Set-Acl {}
        }

        It 'Does NOT call Set-Acl' {
            Remove-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Set-Acl -Times 0 -Exactly
        }

        It 'Logs ACE_NotFound_Skipping' {
            Remove-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'ACE_NotFound_Skipping' } `
                -Times 1 -Exactly
        }
    }

    # -------------------------------------------------------------------------
    Context 'When -WhatIf is specified and ACE is present' {

        # PSCustomObject is safe here: ShouldProcess returns false under WhatIf,
        # so RemoveAccessRule is never called on the mock object.
        BeforeAll {
            Mock Write-GRLog {}
            Mock Get-ADGroup { return $script:MockGroup }
            Mock Get-Acl {
                return [PSCustomObject]@{ Access = @($script:MockReadAce) }
            }
            Mock Set-Acl {}
        }

        It 'Does NOT call Set-Acl under WhatIf' {
            Remove-GRDelegation -TargetDN $script:TestTargetDN `
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
            { Remove-GRDelegation -TargetDN $script:TestTargetDN `
                -IdentityName $script:TestGroupName -LogPath $script:TestLogPath } | Should -Throw
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Error' } -Times 1 -Exactly
        }
    }
}
