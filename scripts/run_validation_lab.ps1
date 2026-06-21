param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$Username = "admin"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    $Python = "python"
}

& $Python (Join-Path $PSScriptRoot "validation_lab.py") --base-url $BaseUrl --username $Username
