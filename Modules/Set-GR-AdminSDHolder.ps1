#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Applies the Global Reader ACE to the AdminSDHolder object.

.DESCRIPTION
    AdminSDHolder (CN=AdminSDHolder,CN=System,<DomainDN>) is a template object used
    by the SDProp background process. SDProp runs every 60 minutes on the PDC Emulator
    and copies AdminSDHolder's DACL to all "admin-protected" accounts and groups
    (Domain Admins, Schema Admins, Administrators, Account Operators, etc.) and their
    direct members. Any ACE present on AdminSDHolder will be propagated to those objects.

    Without this step, GS-Global-Readers cannot read protected accounts because SDProp
    periodically removes any inherited ACEs from those objects (the AdminSDHolder Gap
    documented in v1.1).

    Adding the Global Reader ACE here closes that gap: GS-Global-Readers gains
    ReadProperty | ListChildren | ListObject on all SDProp-protected accounts after
    the next SDProp cycle (within 60 minutes, or immediately if forced).

    *** SECURITY IMPLICATIONS ***
    This deliberately expands the read scope of GS-Global-Readers to include accounts
    protected by AdminSDHolder. It does NOT grant:
      - Write, Modify, or Delete rights of any kind
      - ControlAccess (no Extended Rights, no "Read Password", no LAPS access)
      - Access to Confidential attributes (searchFlags bit 128)
    The -Force switch must be provided to acknowledge these implications.

    *** PROPAGATION TIMING ***
    Changes take effect within 60 minutes (next SDProp cycle). Use -TriggerSDProp to
    kick off an immediate SDProp run on the PDC Emulator after applying the ACE.
    Even with -TriggerSDProp, propagation may take a few seconds to complete.

    Idempotent: if the ACE already exists on AdminSDHolder, logs
    AdminSDHolder_ACE_Exists_Skipping and returns without changes.

.PARAMETER IdentityName
    SAMAccountName of the Global Reader security group.

.PARAMETER LogPath
    Full path to the output CSV log file.

.PARAMETER Force
    Required. Acknowledges that this operation grants read access to all
    AdminSDHolder-protected privileged accounts (Domain Admins, Schema Admins, etc.).
    Without -Force the function logs a warning and aborts.

.PARAMETER TriggerSDProp
    After applying the ACE, triggers an immediate SDProp run on the PDC Emulator
    (by writing "runProtectAdminGroupsTask=1" to the rootDSE). This causes protected
    accounts to receive the new ACE within seconds rather than waiting up to 60 minutes.
    Note: SDProp is asynchronous. A brief delay (a few seconds) should be expected
    before querying individual protected accounts to confirm propagation.

.EXAMPLE
    # Apply with immediate propagation
    Set-GRAdminSDHolder -IdentityName 'GS-Global-Readers' -LogPath 'C:\Logs\gr.csv' -Force -TriggerSDProp

.EXAMPLE
    # Apply and let SDProp propagate on its normal schedule
    Set-GRAdminSDHolder -IdentityName 'GS-Global-Readers' -LogPath 'C:\Logs\gr.csv' -Force
#>

. (Join-Path $PSScriptRoot '..\Helpers\Find-GRAce.ps1')

function Set-GRAdminSDHolder {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$IdentityName,

        [Parameter(Mandatory)]
        [string]$LogPath,

        # Explicit acknowledgement of security implications is required.
        # Without -Force the function logs a warning and exits.
        [switch]$Force,

        # Trigger an immediate SDProp run on the PDC Emulator after applying the ACE.
        # Without this, protected accounts are updated on the next regular cycle (up to 60 min).
        [switch]$TriggerSDProp
    )

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    if (-not $Force) {
        Write-GRLog -LogPath $LogPath -TargetDN 'CN=AdminSDHolder' -Action PreFlight_Warning `
            -Principal $principal `
            -Details "Set-GRAdminSDHolder requires -Force to confirm awareness of security implications. This operation extends read access to all SDProp-protected privileged accounts. Aborting."
        throw "-Force is required to apply the AdminSDHolder ACE. Re-run with -Force after reviewing the implications documented in Set-GR-AdminSDHolder.ps1."
    }

    # ---- Resolve AdminSDHolder DN ------------------------------------------
    $domain          = Get-ADDomain -ErrorAction Stop
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
    $adPath          = "AD:\$adminSDHolderDN"

    Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action PreFlight_Warning `
        -Principal $principal `
        -Details "AdminSDHolder modification in progress. -Force flag confirmed. This will propagate ReadProperty|ListChildren|ListObject for '$IdentityName' to all SDProp-protected accounts within 60 minutes."

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

    # ---- Idempotency check -------------------------------------------------
    $existingAce = Find-GRAce -Acl $acl -SidValue $groupSid.Value -IdentityName $IdentityName

    if ($existingAce) {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action AdminSDHolder_ACE_Exists_Skipping `
            -Principal $IdentityName `
            -Details "Explicit ReadProperty ACE for '$IdentityName' already present on AdminSDHolder. No changes made."
        return
    }

    $beforeCount = $acl.Access.Count

    # ---- Build ACE (identical rights to domain root delegation) ------------
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
        $emptyGuid,
        $inheritanceType,
        $emptyGuid
    )

    # ---- Apply ACE ---------------------------------------------------------
    try {
        if ($PSCmdlet.ShouldProcess($adminSDHolderDN, "Add Global Reader ACE to AdminSDHolder for '$IdentityName'")) {
            $acl.AddAccessRule($ace)
            Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

            $afterCount = (Get-Acl -Path $adPath -ErrorAction Stop).Access.Count
            Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action AdminSDHolder_ACE_Added `
                -Principal $IdentityName `
                -Details "ACE added to AdminSDHolder. Rights: ReadProperty|ListChildren|ListObject, Inheritance: All. ACE count before: $beforeCount, after: $afterCount. SDProp will propagate to protected accounts within 60 minutes."

            if ($TriggerSDProp) {
                try {
                    $pdcFqdn = (Get-ADDomain -ErrorAction Stop).PDCEmulator
                    $rootDSE = [ADSI]"LDAP://$pdcFqdn/RootDSE"
                    $rootDSE.Put("runProtectAdminGroupsTask", "1")
                    $rootDSE.SetInfo()
                    Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action PreFlight_OK `
                        -Principal $IdentityName `
                        -Details "SDProp triggered on PDC Emulator '$pdcFqdn'. Protected accounts will be updated within seconds. Note: propagation is asynchronous and may not be instant."
                }
                catch {
                    Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action PreFlight_Warning `
                        -Principal $IdentityName `
                        -Details "ACE applied successfully but SDProp trigger failed: $_. Protected accounts will update on the next regular SDProp cycle (up to 60 min)."
                }
            }
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $adminSDHolderDN -Action Error `
            -Principal $IdentityName `
            -Details "Set-Acl failed on AdminSDHolder '$adminSDHolderDN': $_"
        throw
    }
}
