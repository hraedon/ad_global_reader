#Requires -Version 5.1
<#
.SYNOPSIS
    Finds an explicit Global Reader ACE in an AD ACL object.

.DESCRIPTION
    Searches the Access list of an ActiveDirectorySecurity (or compatible ACL)
    object for a non-inherited Allow ACE that includes ReadProperty and matches
    either the pre-resolved SID value or the identity name string (fallback).

    SID RESOLUTION IS THE CALLER'S RESPONSIBILITY.
    The caller resolves the group SID via NTAccount.Translate() or from
    ADGroup.SID.Value before calling this function. This keeps the AD-dependent
    step in the caller and makes the ACE-matching logic independently testable
    without a live AD connection -- callers under test can pass any SID string.

    MATCHING LOGIC (in order of preference):
    1. SID match  -- IdentityReference.Translate(SecurityIdentifier) == SidValue
       (primary; works when the ACE principal is stored as a SID in the DACL)
    2. String fallback -- IdentityReference.Value -like "*IdentityName*"
       (covers DOMAIN\samAccountName format; also allows PSCustomObject mocks
       in unit tests where Translate() is unavailable)

.PARAMETER Acl
    The ACL object to inspect. Typically a
    System.DirectoryServices.ActiveDirectorySecurity returned by Get-Acl for
    an AD:\ path. PSCustomObject with an .Access property is accepted for tests.

.PARAMETER SidValue
    Pre-resolved SID string identifying the target principal
    (e.g., 'S-1-5-21-3780865419-...-1234').

.PARAMETER IdentityName
    Group name used as a string-comparison fallback. Should be the
    SAMAccountName or DistinguishedName segment that appears in the
    IdentityReference.Value of the ACE.

.OUTPUTS
    System.DirectoryServices.ActiveDirectoryAccessRule
    Returns the first matching ACE object, or $null if none is found.

.EXAMPLE
    $acl      = Get-Acl -Path "AD:\DC=ad,DC=example,DC=com"
    $group    = Get-ADGroup 'GS-Global-Readers'
    $sidValue = $group.SID.Value
    $ace      = Find-GRAce -Acl $acl -SidValue $sidValue -IdentityName 'GS-Global-Readers'
    if ($ace) { Write-Host "ACE found: $($ace.ActiveDirectoryRights)" }
#>
function Find-GRAce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Acl,

        [Parameter(Mandatory)]
        [string]$SidValue,

        [Parameter(Mandatory)]
        [string]$IdentityName
    )

    # Filter to explicit, Allow ACEs that include ReadProperty.
    # No try/catch inside Where-Object (PS5.1 limitation) -- SID translation
    # is handled in the foreach below.
    $candidateAces = $Acl.Access | Where-Object {
        -not $_.IsInherited -and
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -ne 0
    }

    foreach ($ace in $candidateAces) {
        $aceSid = $null
        try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $aceSid = $null }

        if ($aceSid -and $aceSid -eq $SidValue)                   { return $ace }
        if ($ace.IdentityReference.Value -like "*$IdentityName*")  { return $ace }
    }

    return $null
}
