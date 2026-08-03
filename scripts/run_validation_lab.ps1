param(
    [ValidateNotNullOrEmpty()]
    [string]$BaseUrl = "http://127.0.0.1:5173",
    [ValidateNotNullOrEmpty()]
    [string]$BrowserOrigin = "http://127.0.0.1:5173",
    [string]$Username = "admin"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    $Python = "python"
}

& $Python (Join-Path $PSScriptRoot "validation_lab.py") `
    --base-url $BaseUrl `
    --browser-origin $BrowserOrigin `
    --username $Username
exit $LASTEXITCODE
