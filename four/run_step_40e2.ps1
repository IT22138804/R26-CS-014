$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install -r requirements.txt
if (-not (Test-Path ".env")) {
    throw "Copy .env.example to .env and use the same Firebase values from Step 40B."
}
& $Python scripts\run_step40e2.py
