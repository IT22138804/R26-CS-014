$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt
if (-not (Test-Path ".env")) {
    Write-Host "STEP 39F-2 CONFIGURATION REQUIRED"
    Write-Host "Copy your working Step 39E-2 .env into this folder."
    exit 1
}
& $Python scripts\check_environment.py
if (-not (Test-Path "outputs\step39c\activation_cluster_model.joblib")) { & $Python scripts\run_activation_clustering_ensemble.py }
if (-not (Test-Path "outputs\step39d\sanitized_control_model.joblib")) { & $Python scripts\run_sanitized_model_validation.py }
& $Python scripts\run_live_physical_telemetry_watcher.py --required-packets 5 --poll-seconds 2 --timeout-seconds 180 --max-age-seconds 30
& $Python -m pytest -q
