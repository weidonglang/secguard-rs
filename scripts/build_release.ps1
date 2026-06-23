<#
.SYNOPSIS
    Build the SecGuard RS release binary.
.DESCRIPTION
    Executes cargo build --release to produce a Windows executable.
    The binary is placed at target/release/secguard.exe.
    Exits with non-zero if build fails.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

Write-Host "=== Building SecGuard RS release binary ===" -ForegroundColor Cyan
Set-Location $ProjectRoot

cargo build --release 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: cargo build --release" -ForegroundColor Red
    exit 1
}

$ExePath = Join-Path $ProjectRoot "target" "release" "secguard.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "FAILED: secguard.exe not found at $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "PASSED: Release build complete - $ExePath" -ForegroundColor Green
exit 0