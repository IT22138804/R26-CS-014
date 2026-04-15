$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "======================================================================"
Write-Host "COMPONENT 4 - STEP 40D SAFE MERGED FIREBASE RULES REGRESSION"
Write-Host "======================================================================"

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
$JavaVersion = cmd /c "java -version 2>&1" | Select-Object -First 1
Write-Host "Java :" $JavaVersion

Write-Host ""
Write-Host "IMPORTANT: This step uses LOCAL EMULATOR ONLY."
Write-Host "The live Firebase rules are NOT deployed."
Write-Host ""

npm install
if ($LASTEXITCODE -ne 0) {
    throw "npm install failed."
}

npm run test:rules
if ($LASTEXITCODE -ne 0) {
    throw "Step 40D merged-rules regression failed."
}
