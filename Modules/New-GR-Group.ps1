#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Creates the Global Reader security group if it does not already exist.
.DESCRIPTION
    Idempotent: if the group already exists the function logs ACE_Exists_Skipping
    and returns the existing group object without modification.
    Sets ProtectedFromAccidentalDeletion = $true on the group.
#>

function New-GRGroup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Microsoft.ActiveDirectory.Management.ADGroup])]
    param(
        [Parameter(Mandatory)]
        [string]$IdentityName,

        # DN of the OU to place the group in. Defaults to the domain Users container.
        [string]$GroupOU,

        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # ---- Resolve target OU -------------------------------------------------
    if (-not $GroupOU) {
        $domain   = Get-ADDomain -ErrorAction Stop
        $GroupOU  = $domain.UsersContainer   # CN=Users,DC=...
    }

    # ---- Idempotency check -------------------------------------------------
    $existing = Get-ADGroup -Filter { Name -eq $IdentityName } -ErrorAction SilentlyContinue

    if ($existing) {
        Write-GRLog -LogPath $LogPath -TargetDN $existing.DistinguishedName `
            -Action Group_Exists_Skipping -Principal $principal `
            -Details "Group '$IdentityName' already exists. No changes made."
        return $existing
    }

    # ---- Create group ------------------------------------------------------
    try {
        if ($PSCmdlet.ShouldProcess("$GroupOU", "Create security group '$IdentityName'")) {
            $newGroup = New-ADGroup `
                -Name              $IdentityName `
                -SamAccountName    $IdentityName `
                -GroupCategory     Security `
                -GroupScope        Global `
                -DisplayName       "AD Global Reader" `
                -Description       "Read-only visibility across the directory for SIEM and audit purposes. Managed by AD-GR deployer." `
                -Path              $GroupOU `
                -PassThru `
                -ErrorAction Stop

            # Protect from accidental deletion
            Set-ADObject -Identity $newGroup.DistinguishedName `
                -ProtectedFromAccidentalDeletion $true `
                -ErrorAction Stop

            Write-GRLog -LogPath $LogPath -TargetDN $newGroup.DistinguishedName `
                -Action Group_Created -Principal $principal `
                -Details "Group '$IdentityName' created in '$GroupOU' with Global/Security scope. ProtectedFromAccidentalDeletion=true."

            return $newGroup
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $GroupOU `
            -Action Error -Principal $principal `
            -Details "Failed to create group '$IdentityName': $_"
        throw
    }
}
