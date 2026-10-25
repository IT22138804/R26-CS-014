$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { py -3.11 -m venv .venv }
$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install pytest
& $Python -m pytest -q tests\test_mobile_security_contract.py
