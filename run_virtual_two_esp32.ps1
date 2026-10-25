$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Python = Join-Path $PSScriptRoot "three\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Run run_full_system.ps1 once to create the Python environment."
}

Write-Host "Starting virtual Sensor ESP32 + Gateway ESP32..."
Write-Host "Firebase records will be marked VIRTUAL_TWO_ESP32."
Write-Host "Stop this process before powering the physical ESP32 pair."
& $Python (Join-Path $PSScriptRoot "integration\virtual_esp32_pair.py")
