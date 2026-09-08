# ARES PowerShell Launcher
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$rootDir = $PSScriptRoot
if (-not $rootDir) {
    $rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$venvPython = Join-Path $rootDir ".venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    & $venvPython -m ares.cli.main @ScriptArgs
} else {
    python -m ares.cli.main @ScriptArgs
}

exit $LASTEXITCODE
