#Requires -Version 5.1
<#
    Unit tests for New-GR-Group.ps1 (New-GRGroup function)
    Tag: Unit  -- no real AD required; all AD calls are mocked.
    Requires Pester v5+. Run via: .\Bootstrap.ps1 -Tags Unit
#>

BeforeAll {
    # Dot-source dependencies in the correct order
    $helpersPath = Join-Path $PSScriptRoot '..\Helpers\Write-GRLog.ps1'
    $modulePath  = Join-Path $PSScriptRoot '..\Modules\New-GR-Group.ps1'

    . $helpersPath
    . $modulePath

    # Shared test data
    $script:TestGroup = [PSCustomObject]@{
        Name              = 'GS-Global-Readers'
        SamAccountName    = 'GS-Global-Readers'
        DistinguishedName = 'CN=GS-Global-Readers,CN=Users,DC=test,DC=lab'
        SID               = [PSCustomObject]@{ Value = 'S-1-5-21-999-1234' }
    }
    $script:TestLogPath = Join-Path $env:TEMP "GR-Test-$([System.IO.Path]::GetRandomFileName()).csv"
    $script:TestGroupOU = 'CN=Users,DC=test,DC=lab'
}

AfterAll {
    if (Test-Path $script:TestLogPath) { Remove-Item $script:TestLogPath -Force -ErrorAction SilentlyContinue }
}

Describe 'New-GRGroup' -Tag 'Unit' {

    Context 'When the group already exists' {

        BeforeAll {
            Mock Write-GRLog  {}
            Mock Get-ADDomain { [PSCustomObject]@{ UsersContainer = $script:TestGroupOU } }
            Mock Get-ADGroup  { return $script:TestGroup }
            Mock New-ADGroup  {}
            Mock Set-ADObject {}
        }

        It 'Returns the existing group object' {
            $result = New-GRGroup -IdentityName 'GS-Global-Readers' -LogPath $script:TestLogPath
            $result.DistinguishedName | Should -Be $script:TestGroup.DistinguishedName
        }

        It 'Does NOT call New-ADGroup' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -LogPath $script:TestLogPath
            Should -Invoke New-ADGroup -Times 0 -Exactly
        }

        It 'Logs Group_Exists_Skipping action' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Group_Exists_Skipping' } -Times 1 -Exactly
        }
    }

    Context 'When the group does not exist' {

        BeforeAll {
            Mock Write-GRLog  {}
            Mock Get-ADDomain { [PSCustomObject]@{ UsersContainer = $script:TestGroupOU } }
            # First call (idempotency check) returns nothing; subsequent calls return the new group
            Mock Get-ADGroup  { return $null }
            Mock New-ADGroup  { return $script:TestGroup } -ParameterFilter { $PassThru -eq $true }
            Mock Set-ADObject {}
        }

        It 'Calls New-ADGroup with correct scope and category' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath
            Should -Invoke New-ADGroup -Times 1 -Exactly `
                -ParameterFilter { $GroupScope -eq 'Global' -and $GroupCategory -eq 'Security' }
        }

        It 'Sets ProtectedFromAccidentalDeletion on the new group' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath
            Should -Invoke Set-ADObject -Times 1 -Exactly `
                -ParameterFilter { $ProtectedFromAccidentalDeletion -eq $true }
        }

        It 'Logs Group_Created action' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Group_Created' } -Times 1 -Exactly
        }

        It 'Returns the new group object' {
            $result = New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath
            $result.DistinguishedName | Should -Be $script:TestGroup.DistinguishedName
        }
    }

    Context 'When -WhatIf is specified' {

        BeforeAll {
            Mock Write-GRLog  {}
            Mock Get-ADDomain { [PSCustomObject]@{ UsersContainer = $script:TestGroupOU } }
            Mock Get-ADGroup  { return $null }
            Mock New-ADGroup  { return $script:TestGroup } -ParameterFilter { $PassThru -eq $true }
            Mock Set-ADObject {}
        }

        It 'Does NOT call New-ADGroup when WhatIf is set' {
            New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath -WhatIf
            Should -Invoke New-ADGroup -Times 0 -Exactly
        }
    }

    Context 'When New-ADGroup throws' {

        BeforeAll {
            Mock Write-GRLog  {}
            Mock Get-ADDomain { [PSCustomObject]@{ UsersContainer = $script:TestGroupOU } }
            Mock Get-ADGroup  { return $null }
            Mock New-ADGroup  { throw 'Simulated AD error' }
            Mock Set-ADObject {}
        }

        It 'Logs an Error action and rethrows' {
            { New-GRGroup -IdentityName 'GS-Global-Readers' -GroupOU $script:TestGroupOU `
                -LogPath $script:TestLogPath } | Should -Throw
            Should -Invoke Write-GRLog -ParameterFilter { $Action -eq 'Error' } -Times 1 -Exactly
        }
    }
}
