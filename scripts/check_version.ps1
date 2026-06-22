<#
.SYNOPSIS
    Check VERSION consistency across all files.
.DESCRIPTION
    Reads VERSION file and verifies it matches Cargo.toml version.
    Exits with non-zero if any mismatch is found.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

# Read version from VERSION file
$versionFile = Join-Path $ProjectRoot "VERSION"
if (-not (Test-Path $versionFile)) {
    Write-Host "FAILED: VERSION file not found at $versionFile" -ForegroundColor Red
    exit 1
}
$expectedVersion = (Get-Content $versionFile).Trim()
Write-Host "Expected version: $expectedVersion" -ForegroundColor Cyan

# Check Cargo.toml
$cargoToml = Join-Path $ProjectRoot "Cargo.toml"
$cargoContent = Get-Content $cargoToml -Raw
if ($cargoContent -match 'version\s*=\s*"([^"]+)"') {
    $cargoVersion = $Matches[1]
    if ($cargoVersion -ne $expectedVersion) {
        Write-Host "FAILED: Cargo.toml version $cargoVersion != VERSION $expectedVersion" -ForegroundColor Red
        exit 1
    }
    Write-Host "OK: Cargo.toml version matches ($cargoVersion)" -ForegroundColor Green
} else {
    Write-Host "FAILED: Could not find version in Cargo.toml" -ForegroundColor Red
    exit 1
}

# Check README.md for version badge or mention
$readme = Join-Path $ProjectRoot "README.md"
$readmeContent = Get-Content $readme -Raw
if ($readmeContent -match $expectedVersion) {
    Write-Host "OK: README.md contains version $expectedVersion" -ForegroundColor Green
} else {
    Write-Host "WARNING: README.md does not reference version $expectedVersion" -ForegroundColor Yellow
}

# Check docs/release_notes.md if it exists
$docsDir = Join-Path $ProjectRoot "docs"
$releaseNotes = Join-Path $docsDir "release_notes.md"
if (Test-Path $releaseNotes) {
    $notesContent = Get-Content $releaseNotes -Raw
    if ($notesContent -match $expectedVersion) {
        Write-Host "OK: docs/release_notes.md contains version $expectedVersion" -ForegroundColor Green
    } else {
        Write-Host "WARNING: docs/release_notes.md does not reference version $expectedVersion" -ForegroundColor Yellow
    }
}

# Check docs/user_guide.md if it exists
$userGuide = Join-Path $docsDir "user_guide.md"
if (Test-Path $userGuide) {
    $guideContent = Get-Content $userGuide -Raw
    if ($guideContent -match $expectedVersion) {
        Write-Host "OK: docs/user_guide.md contains version $expectedVersion" -ForegroundColor Green
    } else {
        Write-Host "WARNING: docs/user_guide.md does not reference version $expectedVersion" -ForegroundColor Yellow
    }
}

Write-Host "PASSED: Version consistency check ($expectedVersion)" -ForegroundColor Green
exit 0