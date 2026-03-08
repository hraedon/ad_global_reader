#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Applies the Global Reader ACE to the specified Active Directory container.
.DESCRIPTION
    Grants ReadProperty, ListChildren, and ListObject with full inheritance
    (This Object and All Descendant Objects) to the specified principal.

    Explicitly does NOT grant:
      - ControlAccess (no Extended Rights, including 'Read Password' and 'Return Property')
      - WriteProperty / Write / Modify / Delete of any kind
      - Access to Confidential attributes (searchFlags bit 128 — those require
        an explicit ControlAccess delegation not present here).

    Idempotency: the ACE is only added if an explicit (non-inherited) ACE with
    ReadProperty for the same principal does not already exist on the target object.

    The DACL is read, a snapshot logged, the ACE appended (if missing), then
    Set-Acl is called. Existing ACEs are never removed or altered.
#>

. (Join-Path $PSScriptRoot '..\Helpers\Find-GRAce.ps1')

function Set-GRDelegation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [string]$IdentityName,

        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $adPath    = "AD:\$TargetDN"

    # ---- Resolve the group's NTAccount reference ---------------------------
    try {
        $group       = Get-ADGroup -Identity $IdentityName -ErrorAction Stop
        $ntAccount   = New-Object System.Security.Principal.NTAccount($group.SamAccountName)
        # Validate the NTAccount resolves (will throw if SID cannot be found)
        $null        = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
            -Principal $IdentityName `
            -Details "Could not resolve group '$IdentityName' to an NTAccount/SID: $_"
        throw
    }

    # ---- Read current ACL --------------------------------------------------
    try {
        $acl = Get-Acl -Path $adPath -ErrorAction Stop
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
            -Principal $IdentityName `
            -Details "Get-Acl failed on '$adPath': $_"
        throw
    }

    # ---- Idempotency check -------------------------------------------------
    # Look for an existing explicit ACE where:
    #   - IdentityReference resolves to the same SID as our group
    #   - ActiveDirectoryRights includes ReadProperty
    #   - IsInherited is $false  (explicit ACE placed at this level)
    #   - AccessControlType is Allow
    $groupSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])

    $existingAce = Find-GRAce -Acl $acl -SidValue $groupSid.Value -IdentityName $IdentityName

    if ($existingAce) {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action ACE_Exists_Skipping `
            -Principal $IdentityName `
            -Details "Explicit ReadProperty ACE for '$IdentityName' already present on '$TargetDN'. No changes made."
        return
    }

    $beforeCount = $acl.Access.Count

    # ---- Build the ACE -----------------------------------------------------
    #
    # Rights:        ReadProperty | ListChildren | ListObject
    # Type:          Allow
    # Inheritance:   All (This object and all child objects, all object types)
    # ObjectType:    Empty GUID = applies to all attribute sets / object classes
    # InheritedType: Empty GUID = applies to all descendant object types
    #
    # NOTE: ControlAccess is intentionally OMITTED. This means:
    #   - No Extended Rights (including 'Read Password', 'Return Property')
    #   - Confidential attributes (searchFlags bit 128, e.g., LAPS, ms-PKI-*)
    #     remain inaccessible even though ReadProperty is granted.
    #
    $rights = (
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren  -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListObject
    )

    $allowType       = [System.Security.AccessControl.AccessControlType]::Allow
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $emptyGuid       = [Guid]::Empty

    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $ntAccount,
        $rights,
        $allowType,
        $emptyGuid,          # ObjectType  — all attributes/classes
        $inheritanceType,
        $emptyGuid           # InheritedObjectType — all descendant object types
    )

    # ---- Apply ACE (additive only) -----------------------------------------
    try {
        if ($PSCmdlet.ShouldProcess($TargetDN, "Add Global Reader ACE for '$IdentityName'")) {
            $acl.AddAccessRule($ace)
            Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

            $afterCount = (Get-Acl -Path $adPath -ErrorAction Stop).Access.Count
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action ACE_Added `
                -Principal $IdentityName `
                -Details "ACE applied. Rights: ReadProperty|ListChildren|ListObject, Inheritance: All. ACE count before: $beforeCount, after: $afterCount."
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
            -Principal $IdentityName `
            -Details "Set-Acl failed on '$TargetDN': $_"
        throw
    }
}
