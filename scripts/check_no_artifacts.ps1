<#
.SYNOPSIS
    Check that no build artifacts are tracked by git.
.DESCRIPTION
    Ensures .exe, .zip, target/, dist/ files are not tracked by git.
    Exits with non-zero if any forbidden artifacts are found.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Join-Path $PSScriptRoot ".." | Resolve-Path

$forbidden = @("*.exe", "*.zip", "*.pdb", "*.dll", "*.tmp", "*.log")
$forbiddenDirs = @("target", "dist", "build")

$errors = @()

# Check tracked files in git
Set-Location $ProjectRoot
$trackedFiles = git ls-files 2>&1
foreach ($file in $trackedFiles) {
    foreach ($pattern in $forbidden) {
        if ($file -like $pattern) {
            $errors += "Forbidden tracked file: $file"
        }
    }
    foreach ($dir in $forbiddenDirs) {
        if ($file -like "$dir/*" -or $file.StartsWith("$dir/")) {
            $errors += "Forbidden tracked file in $dir/: $file"
        }
    }
    if ($file -eq "target" -or $file -eq "dist" -or $file -eq "build") {
        $errors += "Forbidden tracked directory: $file"
    }
}

# Also check untracked but staged files
$stagedFiles = git diff --cached --name-only 2>&1
foreach ($file in $stagedFiles) {
    foreach ($pattern in $forbidden) {
        if ($file -like $pattern) {
            $errors += "Forbidden staged file: $file"
        }
    }
    foreach ($dir in $forbiddenDirs) {
        if ($file -like "$dir/*" -or $file.StartsWith("$dir/")) {
            $errors += "Forbidden staged file in $dir/: $file"
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host "FAILED: Build artifacts detected in git tracking" -ForegroundColor Red
    foreach ($err in $errors) {
        Write-Host "  $err" -ForegroundColor Red
    }
    exit 1
}

Write-Host "PASSED: No build artifacts tracked by git" -ForegroundColor Green
exit 0