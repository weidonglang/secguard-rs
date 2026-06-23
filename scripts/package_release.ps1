<#
.SYNOPSIS
    Create release zip package for secguard-rs.
.DESCRIPTION
    This script creates a zip package containing the release binary, README,
    LICENSE, docs, examples, and rules. The zip is placed in dist/ directory.
    Does NOT publish to GitHub Releases.
#>

$ErrorActionPreference = "Stop"

# Paths using Join-Path for cross-platform compatibility
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Join-Path $ScriptDir ".." | Resolve-Path

# Read version
$VersionFile = Join-Path $ProjectRoot "VERSION"
if (-not (Test-Path $VersionFile)) {
    Write-Host "ERROR: VERSION file not found at $VersionFile" -ForegroundColor Red
    exit 1
}
$Version = Get-Content $VersionFile -Raw | ForEach-Object { $_.Trim() }
if ([string]::IsNullOrWhiteSpace($Version)) {
    Write-Host "ERROR: VERSION file is empty" -ForegroundColor Red
    exit 1
}
Write-Host "Using version: $Version" -ForegroundColor Cyan

# Check release binary exists
$ExePath = Join-Path (Join-Path $ProjectRoot "target") "release" | Join-Path -ChildPath "secguard.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Release binary not found at $ExePath" -ForegroundColor Red
    Write-Host "Run 'scripts/build_release.ps1' first." -ForegroundColor Yellow
    exit 1
}

# Ensure dist directory exists
$DistDir = Join-Path $ProjectRoot "dist"
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
    Write-Host "Created dist directory: $DistDir" -ForegroundColor Yellow
}

# Package name
$PackageName = "secguard-rs-v$Version"
$ZipPath = Join-Path $DistDir "$PackageName.zip"

# If zip already exists, remove it
if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
    Write-Host "Removed existing zip: $ZipPath" -ForegroundColor Yellow
}

# Create a temporary directory for packaging
$TempDir = Join-Path $env:TEMP "secguard-package-$([System.Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $PackageDir = Join-Path $TempDir $PackageName
    New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null

    # --- Copy files ---

    # 1. Release binary
    Copy-Item $ExePath (Join-Path $PackageDir "secguard.exe")
    Write-Host "Added: secguard.exe" -ForegroundColor Gray

    # 2. README
    Copy-Item (Join-Path $ProjectRoot "README.md") (Join-Path $PackageDir "README.md")
    Write-Host "Added: README.md" -ForegroundColor Gray

    # 3. LICENSE
    Copy-Item (Join-Path $ProjectRoot "LICENSE") (Join-Path $PackageDir "LICENSE")
    Write-Host "Added: LICENSE" -ForegroundColor Gray

    # 4. VERSION
    Copy-Item (Join-Path $ProjectRoot "VERSION") (Join-Path $PackageDir "VERSION")
    Write-Host "Added: VERSION" -ForegroundColor Gray

    # 5. docs/
    $DocsDir = Join-Path $PackageDir "docs"
    New-Item -ItemType Directory -Path $DocsDir -Force | Out-Null
    $DocFiles = Get-ChildItem (Join-Path $ProjectRoot "docs") -Filter "*.md"
    foreach ($doc in $DocFiles) {
        Copy-Item $doc.FullName (Join-Path $DocsDir $doc.Name)
        Write-Host "Added: docs/$($doc.Name)" -ForegroundColor Gray
    }

    # 6. examples/
    $ExamplesDir = Join-Path $PackageDir "examples"
    New-Item -ItemType Directory -Path $ExamplesDir -Force | Out-Null
    $ExampleFiles = Get-ChildItem (Join-Path $ProjectRoot "examples")
    foreach ($ex in $ExampleFiles) {
        Copy-Item $ex.FullName (Join-Path $ExamplesDir $ex.Name)
        Write-Host "Added: examples/$($ex.Name)" -ForegroundColor Gray
    }

    # 7. rules/
    $RulesDir = Join-Path $PackageDir "rules"
    New-Item -ItemType Directory -Path $RulesDir -Force | Out-Null
    $RuleFiles = Get-ChildItem (Join-Path $ProjectRoot "rules") -Filter "*.json"
    foreach ($rule in $RuleFiles) {
        Copy-Item $rule.FullName (Join-Path $RulesDir $rule.Name)
        Write-Host "Added: rules/$($rule.Name)" -ForegroundColor Gray
    }

    # --- Create zip ---
    Write-Host "`nCreating zip package..." -ForegroundColor Cyan
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($PackageDir, $ZipPath)

    # --- Verify zip ---
    if (Test-Path $ZipPath) {
        $ZipItem = Get-Item $ZipPath
        Write-Host "`nSUCCESS: Package created at $ZipPath" -ForegroundColor Green
        Write-Host "Package size: $([math]::Round($ZipItem.Length / 1KB, 1)) KB"
    } else {
        Write-Host "ERROR: Failed to create zip package" -ForegroundColor Red
        exit 1
    }
}
finally {
    # Cleanup temp directory
    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Cleaned up temporary files" -ForegroundColor Gray
    }
}

exit 0