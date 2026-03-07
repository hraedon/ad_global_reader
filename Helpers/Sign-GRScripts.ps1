#Requires -Version 5.1
<#
.SYNOPSIS
    Signs all AD Global Reader deployer scripts with a code-signing certificate.

.DESCRIPTION
    Applies an Authenticode signature to every .ps1 file in the deployer tree
    using a certificate identified by thumbprint. This is required when the
    target system enforces an AllSigned execution policy (common in domain
    environments controlled by GPO).

    OPERATOR RESPONSIBILITY: Obtaining, storing, and protecting the
    code-signing certificate is the operator's responsibility and is
    intentionally out of scope for this deployer. The certificate must:
      - Have the Code Signing extended key usage (EKU: 1.3.6.1.5.5.7.3.3).
      - Be trusted by the target machine (certificate chain resolves to a
        trusted root in the machine's certificate store).
      - Be accessible in the certificate store of the account running this
        script (typically LocalMachine\My or CurrentUser\My).

    IMPORTANT -- ALL constituent files must be signed, not just the entry points.
    This deployer dot-sources its modules and helpers at runtime:
        . (Join-Path $PSScriptRoot 'Modules\Set-GR-Delegation.ps1')
        . (Join-Path $PSScriptRoot 'Helpers\Write-GRLog.ps1')
    Under AllSigned, each dot-sourced file is subject to the same policy check
    as the caller. Signing only Deploy-GlobalReader.ps1 is insufficient -- every
    file in the tree must be signed, which is why this script exists.

    INVOKE WORKAROUND (do not use in production):
    A common bypass is to read a script's content and execute it as a ScriptBlock:
        & ([ScriptBlock]::Create((Get-Content $path -Raw)))
        Invoke-Expression (Get-Content $path -Raw)
    Both patterns circumvent ExecutionPolicy checks because PowerShell's policy
    applies to script files, not ScriptBlock literals. However, they also bypass
    Authenticode verification entirely, defeating the security purpose of AllSigned.
    Do not use these patterns in production. Sign all constituent scripts instead.

    For development and test environments where AllSigned is not enforced, you may
    use a per-process bypass at the start of the session:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    This does not modify machine or user policy and reverts when the session ends.

    Production scripts signed by default:
      Deploy-GlobalReader.ps1
      Remove-GlobalReader.ps1
      Get-GRReport.ps1
      Verify-Deployment.ps1
      Helpers\Write-GRLog.ps1
      Helpers\Test-GRPreFlight.ps1
      Helpers\Sign-GRScripts.ps1  (this file)
      Modules\New-GR-Group.ps1
      Modules\Set-GR-Delegation.ps1
      Modules\Remove-GR-Delegation.ps1
      Modules\Set-GR-AdminSDHolder.ps1
      Modules\Remove-GR-AdminSDHolder.ps1

    Test scripts (opt-in via -IncludeTests):
      Tests\Bootstrap.ps1
      Tests\New-GR-Group.Tests.ps1
      Tests\Set-GR-Delegation.Tests.ps1
      Tests\Remove-GR-Delegation.Tests.ps1
      Tests\Integration.Tests.ps1

.PARAMETER Thumbprint
    SHA-1 thumbprint of the code-signing certificate to use.
    Example: 'A1B2C3D4E5F6...' (40 hex characters, no spaces).

.PARAMETER TimestampServer
    Optional. URI of an RFC 3161 timestamp server. Using a timestamp server
    ensures the signature remains valid after the signing certificate expires.
    Recommended for production. Common servers:
      http://timestamp.digicert.com
      http://timestamp.sectigo.com
      http://timestamp.globalsign.com/scripts/timstamp.dll

.PARAMETER IncludeTests
    Also sign the Pester test scripts under Tests\. These are development
    artifacts and are not required in production deployments. Include them
    if the test suite will be run in an AllSigned environment.

.EXAMPLE
    .\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...'

    Signs all production scripts using the specified certificate. No timestamp
    server; signatures expire when the certificate expires.

.EXAMPLE
    .\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...' `
        -TimestampServer 'http://timestamp.digicert.com'

    Signs all production scripts with an RFC 3161 timestamp. Recommended for
    long-lived production deployments.

.EXAMPLE
    .\Helpers\Sign-GRScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...' `
        -TimestampServer 'http://timestamp.digicert.com' -IncludeTests

    Signs production scripts and all Pester test scripts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Thumbprint,

    [Parameter()]
    [string]$TimestampServer,

    [Parameter()]
    [switch]$IncludeTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# Resolve the code-signing certificate from the certificate stores.
# Check CurrentUser first, then LocalMachine.
# ------------------------------------------------------------------
$cert = $null
foreach ($store in 'CurrentUser', 'LocalMachine') {
    $cert = Get-ChildItem "Cert:\$store\My\$Thumbprint" -ErrorAction SilentlyContinue
    if ($cert) { break }
}

if (-not $cert) {
    throw "Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My or LocalMachine\My. Ensure the certificate is imported into the correct store."
}

if ($cert.NotAfter -lt (Get-Date)) {
    Write-Warning "Certificate '$($cert.Subject)' expired on $($cert.NotAfter). Signatures applied with an expired certificate will be invalid unless a timestamp server was used."
}

$hasCodeSigningEku = $cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
if (-not $hasCodeSigningEku) {
    throw "Certificate '$($cert.Subject)' does not have the Code Signing EKU (1.3.6.1.5.5.7.3.3). Use a certificate issued for code signing."
}

Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Cyan
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expires    : $($cert.NotAfter)"
Write-Host ''

# ------------------------------------------------------------------
# Enumerate all .ps1 files to sign.
# ------------------------------------------------------------------
$root = Split-Path -Parent $PSScriptRoot   # one level up from Helpers\

$scripts = [System.Collections.Generic.List[string]]@(
    (Join-Path $root 'Deploy-GlobalReader.ps1')
    (Join-Path $root 'Remove-GlobalReader.ps1')
    (Join-Path $root 'Get-GRReport.ps1')
    (Join-Path $root 'Verify-Deployment.ps1')
    (Join-Path $root 'Helpers\Write-GRLog.ps1')
    (Join-Path $root 'Helpers\Test-GRPreFlight.ps1')
    (Join-Path $root 'Helpers\Sign-GRScripts.ps1')
    (Join-Path $root 'Modules\New-GR-Group.ps1')
    (Join-Path $root 'Modules\Set-GR-Delegation.ps1')
    (Join-Path $root 'Modules\Remove-GR-Delegation.ps1')
    (Join-Path $root 'Modules\Set-GR-AdminSDHolder.ps1')
    (Join-Path $root 'Modules\Remove-GR-AdminSDHolder.ps1')
)

if ($IncludeTests) {
    $scripts.Add((Join-Path $root 'Tests\Bootstrap.ps1'))
    $scripts.Add((Join-Path $root 'Tests\New-GR-Group.Tests.ps1'))
    $scripts.Add((Join-Path $root 'Tests\Set-GR-Delegation.Tests.ps1'))
    $scripts.Add((Join-Path $root 'Tests\Remove-GR-Delegation.Tests.ps1'))
    $scripts.Add((Join-Path $root 'Tests\Integration.Tests.ps1'))
}

$signed  = 0
$skipped = 0
$failed  = 0

foreach ($script in $scripts) {
    if (-not (Test-Path $script)) {
        Write-Warning "Script not found, skipping: $script"
        $skipped++
        continue
    }

    $setParams = @{
        FilePath    = $script
        Certificate = $cert
        ErrorAction = 'Stop'
    }
    if ($TimestampServer) {
        $setParams['TimestampServer'] = $TimestampServer
    }

    try {
        $result = Set-AuthenticodeSignature @setParams

        if ($result.Status -eq 'Valid') {
            Write-Host "  Signed   : $(Split-Path -Leaf $script)" -ForegroundColor Green
            $signed++
        }
        else {
            Write-Host "  FAILED   : $(Split-Path -Leaf $script) -- Status: $($result.Status)" -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host "  ERROR    : $(Split-Path -Leaf $script) -- $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ''
Write-Host "Signing complete. Signed: $signed  Skipped: $skipped  Failed: $failed" -ForegroundColor $(
    if ($failed -gt 0) { 'Red' } elseif ($skipped -gt 0) { 'Yellow' } else { 'Green' }
)

if (-not $TimestampServer) {
    Write-Host ''
    Write-Host 'NOTE: No timestamp server was specified. Signatures will become invalid when' -ForegroundColor Yellow
    Write-Host '      the signing certificate expires. Re-run with -TimestampServer for' -ForegroundColor Yellow
    Write-Host '      production use.' -ForegroundColor Yellow
}
