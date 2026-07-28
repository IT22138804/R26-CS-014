$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install -r requirements.txt
& $Python -m pytest -q tests\test_development_completion.py

$env:PYTHONPATH = "$PSScriptRoot\src"

& $Python scripts\run_step40h1_offline_pipeline.py
& $Python scripts\run_step40h2_replay_audit.py
& $Python scripts\run_step40j1_software_readiness.py
