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

# java -version writes its version text to STDERR.
# With $ErrorActionPreference='Stop', PowerShell can convert that normal
# STDERR output into NativeCommandError. Use cmd.exe so it is captured as
# ordinary text instead.
$JavaVersion = cmd /c "java -version 2>&1" | Select-Object -First 1
Write-Host "Java :" $JavaVersion

Write-Host ""
Write-Host "Installing local test dependencies..."
npm install

if ($LASTEXITCODE -ne 0) {
    throw "npm install failed with exit code $LASTEXITCODE."
}

Write-Host ""
Write-Host "Running isolated Realtime Database rules tests..."
npm run test:rules

if ($LASTEXITCODE -ne 0) {
    throw "Step 40C Firebase Rules tests failed with exit code $LASTEXITCODE."
}
