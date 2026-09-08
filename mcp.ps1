# ARES MCP PowerShell Launcher
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$rootDir = $PSScriptRoot
if (-not $rootDir) {
    $rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$aresPs1 = Join-Path $rootDir "ares.ps1"

if (Test-Path $aresPs1) {
    & $aresPs1 mcp @ScriptArgs
} else {
    $venvPython = Join-Path $rootDir ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        & $venvPython -m ares.cli.main mcp @ScriptArgs
    } else {
        python -m ares.cli.main mcp @ScriptArgs
    }
}

exit $LASTEXITCODE
