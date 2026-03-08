#Requires -Version 5.1
<#
    Unit tests for Helpers\Find-GRAce.ps1
    Tag: Unit -- no AD required. All ACL objects are PSCustomObjects or real
    ActiveDirectorySecurity instances constructed without AD lookups.

    WHAT THESE TESTS VERIFY:
    Find-GRAce accepts a pre-resolved SID string and an ACL object, and returns
    the correct ACE (or $null) without making any AD calls. The tests exercise:
      - SID-based match (primary path)
      - String-fallback match (for DOMAIN\name format ACEs)
      - Non-matching ACEs (wrong identity, inherited, Deny, wrong rights)
      - Empty Access list
      - Inherited ACEs are ignored even when they match the SID/name
      - Deny ACEs are ignored even when they match the SID/name

    These tests confirm that the shared helper behaviour matches the inline
    logic that previously existed in each module, verifying that the
    refactoring preserved correctness.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\Helpers\Find-GRAce.ps1')

    $script:TestSid    = 'S-1-5-21-3780865419-4207977281-163478896-5117'
    $script:OtherSid   = 'S-1-5-21-3780865419-4207977281-163478896-9999'
    $script:GroupName  = 'GS-Global-Readers'

    # Helper: build a PSCustomObject ACE with configurable properties.
    # SID translation on PSCustomObjects throws (caught by Find-GRAce),
    # so these ACEs exercise the string-fallback path.
    function New-MockAce {
        param(
            [bool]  $IsInherited       = $false,
            [string]$AccessControlType = 'Allow',
            [string]$Rights            = 'ReadProperty',
            [string]$IdentityValue     = "TESTLAB\$($script:GroupName)"
        )
        [PSCustomObject]@{
            IsInherited           = $IsInherited
            AccessControlType     = [System.Security.AccessControl.AccessControlType]::$AccessControlType
            ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::$Rights
            IdentityReference     = [PSCustomObject]@{ Value = $IdentityValue }
        }
    }

    # Helper: build a real ActiveDirectorySecurity ACE whose IdentityReference
    # CAN be translated to a SID. Uses a well-known built-in SID (Authenticated
    # Users = S-1-5-11) to avoid any AD dependency.
    function New-RealAceWithSid {
        param(
            [string]$SidString         = 'S-1-5-11',
            [bool]  $IsInherited       = $false,
            [string]$AccessControlType = 'Allow',
            [System.DirectoryServices.ActiveDirectoryRights]
                    $Rights            = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        )
        $acl     = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sid     = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $aceType = [System.Security.AccessControl.AccessControlType]::$AccessControlType
        $inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        $ace     = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, $Rights, $aceType, [Guid]::Empty, $inherit, [Guid]::Empty
        )
        $acl.AddAccessRule($ace)
        return @{ Acl = $acl; SidString = $SidString }
    }

    function New-MockAcl { param([object[]]$Aces)
        [PSCustomObject]@{ Access = @($Aces) }
    }
}

Describe 'Find-GRAce' -Tag 'Unit' {

    # -------------------------------------------------------------------------
    Context 'String-fallback match (PSCustomObject ACEs)' {

        It 'Returns ACE when IdentityReference.Value matches group name' {
            $acl = New-MockAcl -Aces @(New-MockAce)
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Returns null when IdentityReference.Value does not match' {
            $acl = New-MockAcl -Aces @(New-MockAce -IdentityValue 'TESTLAB\SomeOtherGroup')
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -BeNullOrEmpty
        }

        It 'Ignores inherited ACEs even when name matches' {
            $acl = New-MockAcl -Aces @(New-MockAce -IsInherited $true)
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -BeNullOrEmpty
        }

        It 'Ignores Deny ACEs even when name matches' {
            $acl = New-MockAcl -Aces @(New-MockAce -AccessControlType 'Deny')
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -BeNullOrEmpty
        }

        It 'Ignores ACEs that do not include ReadProperty even when name matches' {
            $acl = New-MockAcl -Aces @(New-MockAce -Rights 'ListChildren')
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'SID-based match (real ActiveDirectorySecurity ACEs)' {

        It 'Returns ACE when SID matches (S-1-5-11 Authenticated Users)' {
            $wellKnownSid = 'S-1-5-11'
            $built = New-RealAceWithSid -SidString $wellKnownSid
            $result = Find-GRAce -Acl $built.Acl -SidValue $wellKnownSid -IdentityName 'IrrelevantName'
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Returns null when SID does not match and name also does not match' {
            $wellKnownSid = 'S-1-5-11'
            $built = New-RealAceWithSid -SidString $wellKnownSid
            $result = Find-GRAce -Acl $built.Acl -SidValue $script:OtherSid -IdentityName 'NonexistentGroup'
            $result | Should -BeNullOrEmpty
        }

        It 'Ignores inherited real ACEs even when SID matches' {
            # ActiveDirectorySecurity marks ACEs as inherited after propagation;
            # we cannot set IsInherited directly on a new ACE, so verify via
            # the PSCustomObject mock that covers the inherited=true path.
            $inheritedMock = New-MockAce -IsInherited $true -IdentityValue "TESTLAB\$($script:GroupName)"
            $acl = New-MockAcl -Aces @($inheritedMock)
            Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName |
                Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context 'Edge cases' {

        It 'Returns null when Access list is empty' {
            $acl = New-MockAcl -Aces @()
            Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName |
                Should -BeNullOrEmpty
        }

        It 'Returns the first matching ACE when multiple matching ACEs exist' {
            $ace1 = New-MockAce -IdentityValue "TESTLAB\$($script:GroupName)"
            $ace2 = New-MockAce -IdentityValue "TESTLAB\$($script:GroupName)"
            $acl  = New-MockAcl -Aces @($ace1, $ace2)
            $result = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -Be $ace1
        }

        It 'Skips non-matching ACEs before returning the correct one' {
            $other   = New-MockAce -IdentityValue 'TESTLAB\DifferentGroup'
            $correct = New-MockAce -IdentityValue "TESTLAB\$($script:GroupName)"
            $acl     = New-MockAcl -Aces @($other, $correct)
            $result  = Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName
            $result | Should -Be $correct
        }

        It 'Handles ACEs where IdentityReference.Value is a bare SID string' {
            # ACEs stored with the SID in the name (untranslated) fall through to string
            # comparison; if the SID string matches IdentityName it would match, otherwise null.
            $sidAce = New-MockAce -IdentityValue $script:TestSid
            $acl    = New-MockAcl -Aces @($sidAce)
            # IdentityName 'GS-Global-Readers' won't match the SID string, so result is null
            Find-GRAce -Acl $acl -SidValue $script:TestSid -IdentityName $script:GroupName |
                Should -BeNullOrEmpty
        }
    }
}
