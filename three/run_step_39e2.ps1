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
    Write-Host "STEP 39E-2 CONFIGURATION REQUIRED"
    Write-Host "Copy .env.step39e2.example to .env and enter:"
    Write-Host "  FIREBASE_CREDENTIALS_PATH"
    Write-Host "  FIREBASE_DATABASE_URL"
    Write-Host "  FIREBASE_NODE_ID"
    Write-Host ""
    exit 1
}

& $Python scripts\check_environment.py

# Rebuild persisted sklearn models locally in the current 1.9.0
# environment. This prevents cross-version pickle warnings.
& $Python scripts\run_activation_clustering_ensemble.py
& $Python scripts\run_sanitized_model_validation.py

& $Python scripts\run_firebase_quarantine_bridge.py
& $Python -m pytest -q
