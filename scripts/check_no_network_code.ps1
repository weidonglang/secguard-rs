<#
.SYNOPSIS
    Check that no network-related code or dependencies exist.
.DESCRIPTION
    Searches src/ for std::net, TcpStream, UdpSocket, reqwest, hyper, tokio::net
    and checks Cargo.toml for network-related dependencies.
    Exits with non-zero if any forbidden patterns are found.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

$errors = @()

# Check source code for network-related patterns
Write-Host "Checking source code for network-related patterns..." -ForegroundColor Cyan
$srcDir = Join-Path $ProjectRoot "src"
if (Test-Path $srcDir) {
    $forbiddenPatterns = @("std::net", "TcpStream", "UdpSocket", "reqwest", "hyper", "tokio::net", "tokio::net")
    $files = Get-ChildItem -Path $srcDir -Recurse -Include "*.rs" -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach ($pattern in $forbiddenPatterns) {
                if ($content -match [regex]::Escape($pattern)) {
                    $relPath = $file.FullName.Substring($ProjectRoot.Length + 1)
                    $errors += "Forbidden pattern '$pattern' found in $relPath"
                }
            }
        }
    }
}

# Check Cargo.toml for network dependencies
Write-Host "Checking Cargo.toml for network dependencies..." -ForegroundColor Cyan
$cargoToml = Join-Path $ProjectRoot "Cargo.toml"
if (Test-Path $cargoToml) {
    $cargoContent = Get-Content $cargoToml -Raw
    $forbiddenDeps = @("reqwest", "hyper", "tokio", "ureq", "surf", "socket2")
    foreach ($dep in $forbiddenDeps) {
        if ($cargoContent -match [regex]::Escape($dep)) {
            $errors += "Forbidden dependency '$dep' found in Cargo.toml"
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host "FAILED: Network-related code or dependencies detected" -ForegroundColor Red
    foreach ($err in $errors) {
        Write-Host "  $err" -ForegroundColor Red
    }
    exit 1
}

Write-Host "PASSED: No network-related code or dependencies found" -ForegroundColor Green
exit 0