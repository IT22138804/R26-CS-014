$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

& $Python scripts\check_environment.py

# Rebuild all persisted sklearn models in the current local environment.
# This prevents InconsistentVersionWarning and avoids relying on model
# artifacts serialized by a different sklearn version.
& $Python scripts\run_activation_clustering_ensemble.py
& $Python scripts\run_sanitized_model_validation.py

& $Python scripts\run_runtime_guard_demo.py
& $Python -m pytest -q
