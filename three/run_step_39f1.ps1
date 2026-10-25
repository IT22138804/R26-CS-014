$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host ""
    Write-Host "STEP 39F-1 CONFIGURATION REQUIRED"
    Write-Host "Copy .env.step39f1.example to .env."
    Write-Host ""
    exit 1
}

& $Python scripts\check_environment.py

if (-not (Test-Path "outputs\step39c\activation_cluster_model.joblib")) {
    & $Python scripts\run_activation_clustering_ensemble.py
}

if (-not (Test-Path "outputs\step39d\sanitized_control_model.joblib")) {
    & $Python scripts\run_sanitized_model_validation.py
}

& $Python scripts\run_real_component2_telemetry.py
& $Python -m pytest -q
