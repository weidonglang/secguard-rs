<#
.SYNOPSIS
    Run all validation checks: fmt, clippy, and cargo test.
.DESCRIPTION
    This script runs cargo fmt --check, cargo clippy, and cargo test
    sequentially. Exits with non-zero if any step fails.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

Write-Host "=== Step 1: cargo fmt --check ===" -ForegroundColor Cyan
Set-Location $ProjectRoot
cargo fmt -- --check 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: cargo fmt --check" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: cargo fmt --check" -ForegroundColor Green

Write-Host "`n=== Step 2: cargo clippy ===" -ForegroundColor Cyan
cargo clippy --all-targets -- -D warnings 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: cargo clippy" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: cargo clippy" -ForegroundColor Green

Write-Host "`n=== Step 3: cargo test ===" -ForegroundColor Cyan
cargo test 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: cargo test" -ForegroundColor Red
    exit 1
}
Write-Host "PASSED: cargo test" -ForegroundColor Green

Write-Host "`n=== All tests passed ===" -ForegroundColor Green
exit 0