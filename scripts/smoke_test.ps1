<#
.SYNOPSIS
    Smoke test the SecGuard RS executable.
.DESCRIPTION
    Runs the release binary with --help, analyze auth, and integrity baseline
    commands to verify basic functionality. Exits with non-zero if any test fails.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

$ExePath = Join-Path $ProjectRoot "target"
$ExePath = Join-Path $ExePath "release"
$ExePath = Join-Path $ExePath "secguard.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "FAILED: secguard.exe not found at $ExePath" -ForegroundColor Red
    Write-Host "Run build_release.ps1 first." -ForegroundColor Yellow
    exit 1
}

Set-Location $ProjectRoot

# Test 1: --help
Write-Host "=== Smoke Test 1: secguard --help ===" -ForegroundColor Cyan
$Output = & $ExePath --help 2>&1
$LASTEXITCODE = $global:LASTEXITCODE
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: secguard --help returned exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: --help works" -ForegroundColor Green

# Test 2: analyze auth
Write-Host "`n=== Smoke Test 2: secguard analyze auth ===" -ForegroundColor Cyan
$AuthInput = Join-Path $ProjectRoot "examples"
$AuthInput = Join-Path $AuthInput "auth_events.csv"
$AuthOutput = Join-Path $ProjectRoot "target"
$AuthOutput = Join-Path $AuthOutput "smoke_auth_report.md"
$Output = & $ExePath analyze auth --input $AuthInput --output $AuthOutput 2>&1
$LASTEXITCODE = $global:LASTEXITCODE
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: analyze auth returned exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $AuthOutput)) {
    Write-Host "FAILED: auth report not generated" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: analyze auth generates report" -ForegroundColor Green

# Test 3: integrity baseline
Write-Host "`n=== Smoke Test 3: secguard integrity baseline ===" -ForegroundColor Cyan
$BaselineOutput = Join-Path $ProjectRoot "target"
$BaselineOutput = Join-Path $BaselineOutput "smoke_baseline.csv"
$Output = & $ExePath integrity baseline --path $ProjectRoot\examples --output $BaselineOutput 2>&1
$LASTEXITCODE = $global:LASTEXITCODE
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: integrity baseline returned exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $BaselineOutput)) {
    Write-Host "FAILED: baseline not generated" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: integrity baseline generates baseline file" -ForegroundColor Green

# Test 4: schema check
Write-Host "`n=== Smoke Test 4: secguard schema check ===" -ForegroundColor Cyan
$SchemaInput = Join-Path $ProjectRoot "examples"
$SchemaInput = Join-Path $SchemaInput "auth_events.csv"
$Output = & $ExePath schema auth --input $SchemaInput 2>&1
$LASTEXITCODE = $global:LASTEXITCODE
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: schema check returned exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: schema check validates auth_events.csv" -ForegroundColor Green

# Test 5: ioc match
Write-Host "`n=== Smoke Test 5: secguard ioc match ===" -ForegroundColor Cyan
$DnsInput = Join-Path $ProjectRoot "examples"
$DnsInput = Join-Path $DnsInput "dns_queries.csv"
$IpsInput = Join-Path $ProjectRoot "examples"
$IpsInput = Join-Path $IpsInput "ioc_ips.csv"
$DomainsInput = Join-Path $ProjectRoot "examples"
$DomainsInput = Join-Path $DomainsInput "ioc_domains.csv"
$HashesInput = Join-Path $ProjectRoot "examples"
$HashesInput = Join-Path $HashesInput "ioc_hashes.csv"
$Output = & $ExePath ioc match --dns $DnsInput --ips $IpsInput --domains $DomainsInput --hashes $HashesInput 2>&1
$LASTEXITCODE = $global:LASTEXITCODE
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: ioc match returned exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: ioc match processes all IOC types" -ForegroundColor Green

Write-Host "`n=== All smoke tests passed ===" -ForegroundColor Green
exit 0