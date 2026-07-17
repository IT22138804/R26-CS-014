$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install -r requirements.txt
if (-not (Test-Path ".env")) {
    throw "Copy .env.example to .env and reuse your working Firebase Admin values."
}
& $Python scripts\run_step40k1_live_hardware.py
