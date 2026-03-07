#Requires -Version 5.1
<#
.SYNOPSIS
    Ensures Pester v5 is available and runs all AD Global Reader tests.

.DESCRIPTION
    The tests require Pester version 5.x. This script installs Pester v5 from the
    PSGallery if only an older version is present (e.g. the inbox Pester 3.4.0).

    After bootstrapping, runs the full test suite. Pass -Tags to filter:
        .\Bootstrap.ps1 -Tags Unit        # fast, no AD required
        .\Bootstrap.ps1 -Tags Integration # requires Domain Admin session

.PARAMETER Tags
    Pester tag filter. Defaults to 'Unit' (safe for CI without AD).

.PARAMETER OutputFormat
    Pester output format. Default: Detailed

.EXAMPLE
    # Run only unit tests (no AD needed)
    .\Bootstrap.ps1

.EXAMPLE
    # Run integration tests against the lab domain
    .\Bootstrap.ps1 -Tags Integration
#>
param(
    [string[]]$Tags         = @('Unit'),
    [string]  $OutputFormat = 'Detailed'
)

Set-StrictMode -Version Latest

# ---- Ensure Pester v5 is installed ----------------------------------------
$pester = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version.Major -lt 5) {
    Write-Host 'Pester v5 not found. Installing from PSGallery...' -ForegroundColor Yellow
    Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck -Scope CurrentUser
    Write-Host 'Pester v5 installed.' -ForegroundColor Green
}

Import-Module Pester -MinimumVersion 5.0.0 -Force

# ---- Run tests -------------------------------------------------------------
$config                          = New-PesterConfiguration
$config.Run.Path                 = $PSScriptRoot
$config.Filter.Tag               = $Tags
$config.Output.Verbosity         = $OutputFormat
$config.Run.PassThru             = $true

$results = Invoke-Pester -Configuration $config

if ($results.FailedCount -gt 0) {
    Write-Host "$($results.FailedCount) test(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "All $($results.PassedCount) test(s) passed." -ForegroundColor Green
