$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

.\.venv\Scripts\python.exe scripts\check_environment.py

if (-not (Test-Path "data\generated\telemetry_poisoned_full.csv")) {
    .\.venv\Scripts\python.exe scripts\generate_poisoned_telemetry.py
}

.\.venv\Scripts\python.exe scripts\run_spectral_signature_baseline.py
.\.venv\Scripts\python.exe -m pytest -q
