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

    # ---- 3. Privilege check: does the current token have WriteDacl on $TargetDN? ---
    # Strategy: enumerate every SID in the current Windows token (identity + all
    # groups), then walk the target object's DACL looking for an Allow ACE with
    # WriteDacl or GenericAll that matches any of those SIDs.
    # This approach works across trusts (no role-name string matching) and tests
    # the specific target object rather than assuming inherited rights.
    # Note: Deny ACEs and ACE ordering are not evaluated — this is a best-effort
    # pre-check. Set-Acl will still fail with a hard error if the right is absent.
    try {
        $adPath  = "AD:\$TargetDN"
        $acl     = Get-Acl -Path $adPath -ErrorAction Stop

        # Collect all SIDs present in the current token
        $tokenIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $tokenSids     = [System.Collections.Generic.HashSet[string]]::new()
        $null = $tokenSids.Add($tokenIdentity.User.Value)
        foreach ($grp in $tokenIdentity.Groups) {
            try { $null = $tokenSids.Add($grp.Value) } catch {}
        }

        $hasRight    = $false
        $matchedSid  = $null
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $hasWriteDacl  = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)  -ne 0
            $hasGenericAll = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)  -ne 0
            if (-not ($hasWriteDacl -or $hasGenericAll)) { continue }

            $aceSid = $null
            try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }

            if ($tokenSids.Contains($aceSid)) {
                $hasRight   = $true
                $matchedSid = $aceSid
                break
            }
        }

        if ($hasRight) {
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_OK `
                -Principal $principal `
                -Details "WriteDacl/GenericAll confirmed on target object via token SID $matchedSid."
        }
        else {
            Write-GRLog -LogPath $LogPath -TargetDN $TargetDN -Action PreFlight_Warning `
                -Principal $principal `
                -Details 'No explicit WriteDacl/GenericAll ACE found for any token SID on the target object. Set-Acl may fail. Continuing — the real error will surface there if rights are insufficient.'
            # Not a hard stop: inherited rights (e.g. from Builtin\Administrators) may
            # not appear as explicit ACEs but can still grant the right at runtime.
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
