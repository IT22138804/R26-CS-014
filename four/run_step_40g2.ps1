$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    throw "Copy .env.example to .env and reuse the working Firebase Admin configuration."
}

& $Python -m pytest -q tests\test_step40g2.py
& $Python scripts\run_step40g2.py
