#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes the Global Reader ACE from the specified Active Directory container.
.DESCRIPTION
    Reverses the ACE applied by Set-GR-Delegation. Locates the explicit Allow ACE
    for the Global Reader group (ReadProperty | ListChildren | ListObject) on the
    target DN and removes it via Set-Acl.

    Idempotent: if no matching explicit ACE is found, logs ACE_NotFound_Skipping
    and returns without error.

    Inherited ACEs on child objects disappear automatically once the explicit ACE
    at the target DN is removed (standard ACL inheritance propagation).

    Does NOT touch any other ACEs on the target object.
#>

function Remove-GRDelegation {
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

    # ---- Resolve the group's SID -------------------------------------------
    try {
        $group     = Get-ADGroup -Identity $IdentityName -ErrorAction Stop
        $ntAccount = New-Object System.Security.Principal.NTAccount($group.SamAccountName)
        $groupSid  = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
            -Principal $IdentityName `
            -Details "Could not resolve group '$IdentityName' to a SID: $_"
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

    # ---- Find the matching explicit ACE ------------------------------------
    # Same candidate filter used by Set-GR-Delegation for consistency:
    #   - Non-inherited (explicit at this level)
    #   - Allow ACE
    #   - Contains ReadProperty in the rights mask
    $candidateAces = $acl.Access | Where-Object {
        -not $_.IsInherited -and
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -ne 0
    }

    $targetAce = $null
    foreach ($ace in $candidateAces) {
        $aceSid = $null
        try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $aceSid = $null }

        if ($aceSid -and $aceSid -eq $groupSid.Value) {
            $targetAce = $ace
            break
        }
        # Fallback: string comparison (covers DOMAIN\samAccountName format)
        if ($ace.IdentityReference.Value -like "*$IdentityName*") {
            $targetAce = $ace
            break
        }
    }

    if (-not $targetAce) {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action ACE_NotFound_Skipping `
            -Principal $IdentityName `
            -Details "No explicit ReadProperty ACE for '$IdentityName' found on '$TargetDN'. Nothing to remove."
        return
    }

    $beforeCount = $acl.Access.Count

    # ---- Remove the ACE (additive-only in reverse: remove exactly what was added) ---
    try {
        if ($PSCmdlet.ShouldProcess($TargetDN, "Remove Global Reader ACE for '$IdentityName'")) {
            $acl.RemoveAccessRule($targetAce) | Out-Null
            Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

            $afterCount = (Get-Acl -Path $adPath -ErrorAction Stop).Access.Count
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action ACE_Removed `
                -Principal $IdentityName `
                -Details "Explicit ReadProperty ACE removed. ACE count before: $beforeCount, after: $afterCount. Inherited ACEs on child objects will disappear via normal ACL propagation."
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action Error `
            -Principal $IdentityName `
            -Details "Set-Acl (remove) failed on '$TargetDN': $_"
        throw
    }
}
