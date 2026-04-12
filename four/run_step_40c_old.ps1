$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "=================================================================="
Write-Host "COMPONENT 4 - STEP 40C FIREBASE RULES EMULATOR"
Write-Host "=================================================================="

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is not installed or not available in PATH."
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm is not installed or not available in PATH."
}

if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    throw "Java is required by the Firebase Realtime Database emulator."
}

Write-Host "Node :" (node --version)
Write-Host "npm  :" (npm --version)

$JavaVersion = & java -version 2>&1 | Select-Object -First 1
Write-Host "Java :" $JavaVersion

Write-Host ""
Write-Host "Installing local test dependencies..."
npm install

Write-Host ""
Write-Host "Running isolated Realtime Database rules tests..."
npm run test:rules
