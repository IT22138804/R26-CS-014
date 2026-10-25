$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\check_environment.py
.\.venv\Scripts\python.exe scripts\generate_poisoned_telemetry.py
.\.venv\Scripts\python.exe scripts\audit_generated_dataset.py
.\.venv\Scripts\python.exe -m pytest -q
