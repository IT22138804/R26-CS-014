param([Parameter(Mandatory = $true)][string]$Root)
$ErrorActionPreference = "Continue"
$Four = Join-Path $Root "four"
$Python = Join-Path $Four ".venv\Scripts\python.exe"
Set-Location $Four

while ($true) {
    & $Python scripts\run_step40k1_live_hardware.py
    if ($LASTEXITCODE -ne 0) { Write-Error "Component 4 evaluator exited with code $LASTEXITCODE" }
    Start-Sleep -Seconds 5
}
