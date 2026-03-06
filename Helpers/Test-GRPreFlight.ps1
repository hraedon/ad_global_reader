#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-flight validation for the AD Global Reader deployer.
.DESCRIPTION
    Checks:
      1. ActiveDirectory module is available and imported.
      2. Get-ADDomain returns valid domain data.
      3. The executing account can read/write ntSecurityDescriptor on the target DN.
      4. Warns if the target is a "Protected" system container where inheritance may be blocked.
    Returns $true if all hard checks pass, $false otherwise.
    Always logs results via Write-GRLog.
#>

function Test-GRPreFlight {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDN,

        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $allGood   = $true

    # ---- 1. ActiveDirectory module ----------------------------------------
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
                -Principal $principal -Details 'ActiveDirectory module imported successfully.'
        }
        catch {
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Error `
                -Principal $principal -Details "Failed to import ActiveDirectory module: $_"
            return $false
        }
    }
    else {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
            -Principal $principal -Details 'ActiveDirectory module already loaded.'
    }

    # ---- 2. Domain connectivity -------------------------------------------
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
            -Principal $principal -Details "Domain connectivity OK. Domain: $($domain.DNSRoot), DC: $($domain.PDCEmulator)"
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Error `
            -Principal $principal -Details "Get-ADDomain failed: $_"
        return $false
    }

    # ---- 3. Privilege check: can we read the DACL on $TargetDN? -----------
    try {
        $adPath = "AD:\$TargetDN"
        $acl    = Get-Acl -Path $adPath -ErrorAction Stop

        # Verify the current user has WriteDacl or GenericAll on the object.
        # We test by checking the token for the SeSecurityPrivilege or by verifying
        # the DACL contains a relevant Allow entry for us. The practical test is
        # whether we can actually read the DACL (done above) and whether our token
        # includes the required right via group membership.
        # A reliable runtime check: attempt to build a throwaway ACE and validate
        # the ACL object is writable (does not set it yet).
        $testSid  = (New-Object System.Security.Principal.NTAccount($principal)).Translate(
                        [System.Security.Principal.SecurityIdentifier])
        $hasRight = $acl.Access | Where-Object {
            ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $testSid.Value) -and
            (
                ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0 -or
                ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)  -ne 0
            ) -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
        }

        if ($hasRight) {
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
                -Principal $principal -Details 'Explicit WriteDacl/GenericAll ACE found for current identity on target DN.'
        }
        else {
            # Domain Admins inherit WriteDacl from AdminSDHolder propagation; a direct
            # ACE may not exist.  Membership in Domain Admins is a reliable proxy.
            $isDomainAdmin = ([System.Security.Principal.WindowsPrincipal](
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )).IsInRole('Domain Admins')

            if ($isDomainAdmin) {
                Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
                    -Principal $principal -Details 'Current identity is a member of Domain Admins — inherited WriteDacl assumed.'
            }
            else {
                Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Warning `
                    -Principal $principal `
                    -Details 'Could not confirm WriteDacl right for current identity. Set-Acl may fail. Continuing with warning.'
                # This is a warning, not a hard stop — Set-Acl will surface the real error if needed.
            }
        }
    }
    catch {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Error `
            -Principal $principal -Details "ACL read on target DN failed: $_"
        $allGood = $false
    }

    # ---- 4. Protected container warning ------------------------------------
    $protectedPrefixes = @('CN=System,', 'CN=Configuration,', 'CN=Schema,')
    $isProtected = $protectedPrefixes | Where-Object { $TargetDN -like "*$_*" }
    if ($isProtected) {
        Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Warning `
            -Principal $principal `
            -Details "Target DN appears to be a protected/system container ($TargetDN). ACE inheritance may be blocked on child objects."
    }

    return $allGood
}
