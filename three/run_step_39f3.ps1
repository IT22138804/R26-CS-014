$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host "Copy your working Firebase .env into this folder first."
    exit 1
}

& $Python scripts\check_environment.py

if (-not (Test-Path "outputs\step39c\activation_cluster_model.joblib")) {
    & $Python scripts\run_activation_clustering_ensemble.py
}
if (-not (Test-Path "outputs\step39d\sanitized_control_model.joblib")) {
    & $Python scripts\run_sanitized_model_validation.py
}

& $Python scripts\run_controlled_backdoor_over_real_radio.py `
  --timeout-seconds 300 `
  --poll-seconds 0.5 `
  --max-age-seconds 30

& $Python -m pytest -q
