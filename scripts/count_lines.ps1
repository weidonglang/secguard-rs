<#
.SYNOPSIS
    Count total lines of code, tests, docs, and example data.
.DESCRIPTION
    Counts lines across src/, tests/, docs/, examples/, scripts/, rules/ directories.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

$totalLines = 0
$sections = @()

# Source code
$srcLines = 0
$srcDir = Join-Path $ProjectRoot "src"
if (Test-Path $srcDir) {
    $srcLines = (Get-ChildItem -Path $srcDir -Recurse -Include "*.rs" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $srcLines) { $srcLines = 0 }
}
$totalLines += $srcLines
$sections += @{ Name = "src/ (Rust source)"; Lines = $srcLines }

# Tests
$testLines = 0
$testDir = Join-Path $ProjectRoot "tests"
if (Test-Path $testDir) {
    $testLines = (Get-ChildItem -Path $testDir -Recurse -Include "*.rs" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $testLines) { $testLines = 0 }
}
$totalLines += $testLines
$sections += @{ Name = "tests/ (test files)"; Lines = $testLines }

# Examples
$exampleLines = 0
$exampleDir = Join-Path $ProjectRoot "examples"
if (Test-Path $exampleDir) {
    $exampleLines = (Get-ChildItem -Path $exampleDir -Include "*.csv","*.json" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $exampleLines) { $exampleLines = 0 }
}
$totalLines += $exampleLines
$sections += @{ Name = "examples/ (example data)"; Lines = $exampleLines }

# Test data
$testDataLines = 0
$testDataDir = Join-Path $ProjectRoot "testdata"
if (Test-Path $testDataDir) {
    $testDataLines = (Get-ChildItem -Path $testDataDir -Recurse -Include "*.csv" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $testDataLines) { $testDataLines = 0 }
}
$totalLines += $testDataLines
$sections += @{ Name = "testdata/ (test data)"; Lines = $testDataLines }

# Docs
$docLines = 0
$docDir = Join-Path $ProjectRoot "docs"
if (Test-Path $docDir) {
    $docLines = (Get-ChildItem -Path $docDir -Include "*.md" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $docLines) { $docLines = 0 }
}
$totalLines += $docLines
$sections += @{ Name = "docs/ (documentation)"; Lines = $docLines }

# Scripts
$scriptLines = 0
$scriptDir = Join-Path $ProjectRoot "scripts"
if (Test-Path $scriptDir) {
    $scriptLines = (Get-ChildItem -Path $scriptDir -Include "*.ps1" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $scriptLines) { $scriptLines = 0 }
}
$totalLines += $scriptLines
$sections += @{ Name = "scripts/ (PowerShell scripts)"; Lines = $scriptLines }

# Rules
$ruleLines = 0
$ruleDir = Join-Path $ProjectRoot "rules"
if (Test-Path $ruleDir) {
    $ruleLines = (Get-ChildItem -Path $ruleDir -Include "*.json" | ForEach-Object {
        Get-Content $_.FullName | Measure-Object -Line | Select-Object -ExpandProperty Lines
    } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    if (-not $ruleLines) { $ruleLines = 0 }
}
$totalLines += $ruleLines
$sections += @{ Name = "rules/ (detection rules)"; Lines = $ruleLines }

# README and config files
$extraLines = 0
$extraFiles = @("README.md", "Cargo.toml", "Cargo.lock", "VERSION", ".gitignore", "LICENSE")
foreach ($f in $extraFiles) {
    $path = Join-Path $ProjectRoot $f
    if (Test-Path $path) {
        $lines = (Get-Content $path | Measure-Object -Line | Select-Object -ExpandProperty Lines)
        $extraLines += $lines
    }
}
$totalLines += $extraLines
$sections += @{ Name = "Root files (README, Cargo.toml, etc.)"; Lines = $extraLines }

# Print summary
Write-Host "`n=== Line Count Summary ===" -ForegroundColor Cyan
foreach ($s in $sections) {
    Write-Host ("  {0,-50} {1,8} lines" -f $s.Name, $s.Lines)
}
Write-Host ("  {0,-50} {1,8} lines" -f "-------------------------------------------", "--------")
Write-Host ("  {0,-50} {1,8} lines" -f "TOTAL", $totalLines) -ForegroundColor Green
Write-Host "`nTotal lines: $totalLines" -ForegroundColor Green

if ($totalLines -ge 5000) {
    Write-Host "PASSED: Line count >= 5000 ($totalLines)" -ForegroundColor Green
} else {
    Write-Host "WARNING: Line count < 5000 ($totalLines)" -ForegroundColor Yellow
}

exit 0