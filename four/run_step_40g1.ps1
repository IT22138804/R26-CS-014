$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host ""
    Write-Host "Copy .env.example to .env and use the same Firebase Admin values"
    Write-Host "already used successfully in Component 3 / Component 4 backend tests."
    Write-Host ""
    exit 1
}

& $Python -m pytest -q tests\test_step40g1.py
& $Python scripts\run_step40g1.py
