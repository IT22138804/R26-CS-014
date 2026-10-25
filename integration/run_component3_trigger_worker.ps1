param([Parameter(Mandatory = $true)][string]$Root)
$ErrorActionPreference = "Stop"
$Three = Join-Path $Root "three"
$Python = Join-Path $Three ".venv\Scripts\python.exe"
Set-Location $Three
& $Python scripts\run_component3_trigger_worker.py
