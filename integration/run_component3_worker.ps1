param([Parameter(Mandatory = $true)][string]$Root)
$ErrorActionPreference = "Continue"
$Three = Join-Path $Root "three"
$Python = Join-Path $Three ".venv\Scripts\python.exe"
Set-Location $Three

while ($true) {
    & $Python scripts\run_live_physical_telemetry_watcher.py `
        --required-packets 5 --poll-seconds 2 --timeout-seconds 180 --max-age-seconds 30
    if ($LASTEXITCODE -ne 0) { Write-Error "Component 3 watcher exited with code $LASTEXITCODE" }
    Start-Sleep -Seconds 2
}
