#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Removes the Global Reader ACE from the AdminSDHolder object.

.DESCRIPTION
    Reverses the change made by Set-GR-AdminSDHolder.

    Once this ACE is removed, the SDProp process (runs every 60 minutes on the PDC
    Emulator) will no longer copy it to protected accounts. On the NEXT SDProp cycle,
    the ACE will be removed from all AdminSDHolder-protected accounts (Domain Admins,
    Schema Admins, etc.) as SDProp replaces their entire DACL with AdminSDHolder's.

    *** PROPAGATION TIMING ***
    Protected accounts retain read access until the next SDProp run (up to 60 min).
    Use -TriggerSDProp to kick off an immediate SDProp run on the PDC Emulator after
    removing the ACE. Even with -TriggerSDProp, propagation is asynchronous — a short
    wait (a few seconds) may be required before verifying protected accounts.

    *** VALIDATION NOTE ***
    Verifying that protected accounts have lost the ACE in the same session immediately
    after this function returns is not reliable even with -TriggerSDProp, because SDProp
    runs asynchronously on the PDC Emulator. What CAN be verified immediately is that
    the ACE is gone from AdminSDHolder itself (which is synchronous).

    Idempotent: if no matching ACE is found on AdminSDHolder, logs
    AdminSDHolder_ACE_NotFound_Skipping and returns without error.

.PARAMETER IdentityName
    SAMAccountName of the Global Reader security group.

.PARAMETER LogPath
    Full path to the output CSV log file.

.PARAMETER TriggerSDProp
    After removing the ACE, triggers an immediate SDProp run on the PDC Emulator
    (by writing "runProtectAdminGroupsTask=1" to the rootDSE). This causes SDProp to
    replace the DACL on all protected accounts shortly after the trigger, removing the
    read ACE from them without waiting up to 60 minutes for the regular cycle.

    IMPORTANT: SDProp is asynchronous. The ACE removal from AdminSDHolder itself is
    immediate and synchronous (verifiable at once). However, verifying that individual
    protected accounts have lost the ACE should be done after a brief wait (~5-10
    seconds) to allow SDProp to complete propagation.

.EXAMPLE
    # Remove with immediate SDProp trigger
    Remove-GRAdminSDHolder -IdentityName 'GS-Global-Readers' -LogPath 'C:\Logs\gr.csv' -TriggerSDProp

.EXAMPLE
    # Remove and let SDProp propagate on its normal schedule (up to 60 min)
    Remove-GRAdminSDHolder -IdentityName 'GS-Global-Readers' -LogPath 'C:\Logs\gr.csv'
#>

function Remove-GRAdminSDHolder {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$IdentityName,

        [Parameter(Mandatory)]
        [string]$LogPath,

        # Trigger an immediate SDProp run on the PDC Emulator after removing the ACE.
        # This initiates propagation to protected accounts without waiting up to 60 min.
        # Note: SDProp is asynchronous; verify protected accounts after a brief wait.
        [switch]$TriggerSDProp
    )

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # ---- Resolve AdminSDHolder DN ------------------------------------------
    $domain          = Get-ADDomain -ErrorAction Stop
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
    $adPath          = "AD:\$adminSDHolderDN"

    # ---- Resolve group SID -------------------------------------------------
    try {
        $group     = Get-ADGroup -Identity $IdentityName -ErrorAction Stop
        $ntAccount = New-Object System.Security.Principal.NTAccount($group.SamAccountName)
        $groupSid  = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action Error `
            -Principal $IdentityName `
            -Details "Could not resolve group '$IdentityName' to a SID: $_"
        throw
    }

    # ---- Read current ACL --------------------------------------------------
    try {
        $acl = Get-Acl -Path $adPath -ErrorAction Stop
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action Error `
            -Principal $IdentityName `
            -Details "Get-Acl failed on AdminSDHolder '$adPath': $_"
        throw
    }

    # ---- Find the matching explicit ACE ------------------------------------
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
        if ($ace.IdentityReference.Value -like "*$IdentityName*") {
            $targetAce = $ace
            break
        }
    }

    if (-not $targetAce) {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action AdminSDHolder_ACE_NotFound_Skipping `
            -Principal $IdentityName `
            -Details "No explicit ReadProperty ACE for '$IdentityName' found on AdminSDHolder. Nothing to remove."
        return
    }

    $beforeCount = $acl.Access.Count

    # ---- Remove the ACE ----------------------------------------------------
    try {
        if ($PSCmdlet.ShouldProcess($adminSDHolderDN, "Remove Global Reader ACE from AdminSDHolder for '$IdentityName'")) {
            $acl.RemoveAccessRule($targetAce) | Out-Null
            Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

            $afterCount = (Get-Acl -Path $adPath -ErrorAction Stop).Access.Count

            $propagationNote = if ($TriggerSDProp) {
                'SDProp will be triggered immediately (see next log entry). Protected accounts will lose the ACE within seconds.'
            }
            else {
                'Protected accounts retain the ACE until the next SDProp cycle (up to 60 min). Use -TriggerSDProp for immediate propagation.'
            }

            Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action AdminSDHolder_ACE_Removed `
                -Principal $IdentityName `
                -Details "ACE removed from AdminSDHolder. ACE count before: $beforeCount, after: $afterCount. $propagationNote"

            if ($TriggerSDProp) {
                try {
                    $pdcFqdn = (Get-ADDomain -ErrorAction Stop).PDCEmulator
                    $rootDSE = [ADSI]"LDAP://$pdcFqdn/RootDSE"
                    $rootDSE.Put("runProtectAdminGroupsTask", "1")
                    $rootDSE.SetInfo()
                    Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action PreFlight_OK `
                        -Principal $IdentityName `
                        -Details "SDProp triggered on PDC Emulator '$pdcFqdn'. VALIDATION NOTE: SDProp runs asynchronously. The ACE is confirmed gone from AdminSDHolder now, but verifying removal from individual protected accounts requires a brief wait before querying their DACLs."
                }
                catch {
                    Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action PreFlight_Warning `
                        -Principal $IdentityName `
                        -Details "ACE removed from AdminSDHolder successfully, but SDProp trigger failed: $_. Protected accounts will update on the next regular SDProp cycle (up to 60 min)."
                }
            }
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action Error `
            -Principal $IdentityName `
            -Details "Set-Acl (remove) failed on AdminSDHolder '$adminSDHolderDN': $_"
        throw
    }
}
