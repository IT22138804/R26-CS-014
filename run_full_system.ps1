param([switch]$VirtualEsp32)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Root = $PSScriptRoot
$IntegrationDir = Join-Path $Root "integration"
$LogDir = Join-Path $IntegrationDir "logs"
$ThreeDir = Join-Path $Root "three"
$FourDir = Join-Path $Root "four"
$DashboardDir = Join-Path $ThreeDir "greenhouse-security-dashboard"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Require-Path([string]$Path, [string]$Message) {
    if (-not (Test-Path -LiteralPath $Path)) { throw $Message }
}

function Read-DotEnv([string]$Path) {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#") -or -not $trimmed.Contains("=")) { continue }
        $parts = $trimmed.Split("=", 2)
        $values[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
    }
    return $values
}

Write-Host ""
Write-Host "============================================================"
Write-Host " GREENHOUSE INTEGRATED SYSTEM - COMPONENTS 1, 2, 3 AND 4"
Write-Host "============================================================"

Require-Path (Join-Path $ThreeDir ".env") "Missing three\.env. Configure Firebase Admin before running."
Require-Path (Join-Path $FourDir ".env") "Missing four\.env. Configure Firebase Admin before running."
Require-Path (Join-Path $DashboardDir ".env") "Missing dashboard .env in three\greenhouse-security-dashboard."

$threeEnv = Read-DotEnv (Join-Path $ThreeDir ".env")
$fourEnv = Read-DotEnv (Join-Path $FourDir ".env")
$dashboardEnv = Read-DotEnv (Join-Path $DashboardDir ".env")

foreach ($required in @("FIREBASE_CREDENTIALS_PATH", "FIREBASE_DATABASE_URL")) {
    if (-not $threeEnv[$required]) { throw "three\.env is missing $required" }
    if (-not $fourEnv[$required]) { throw "four\.env is missing $required" }
}

Require-Path $threeEnv["FIREBASE_CREDENTIALS_PATH"] "Component 3 Firebase service-account JSON was not found."
Require-Path $fourEnv["FIREBASE_CREDENTIALS_PATH"] "Component 4 Firebase service-account JSON was not found."

$threeUrl = $threeEnv["FIREBASE_DATABASE_URL"].TrimEnd('/')
$fourUrl = $fourEnv["FIREBASE_DATABASE_URL"].TrimEnd('/')
$dashboardUrl = $dashboardEnv["VITE_FIREBASE_DATABASE_URL"].TrimEnd('/')
if ($threeUrl -ne $fourUrl -or $threeUrl -ne $dashboardUrl) {
    throw "Components 3, 4, and the dashboard must use the same FIREBASE_DATABASE_URL."
}

$PythonThree = Join-Path $ThreeDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonThree)) {
    Write-Host "Creating Component 3 Python environment..."
    & py -3.11 -m venv (Join-Path $ThreeDir ".venv")
}

$PythonFour = Join-Path $FourDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonFour)) {
    Write-Host "Creating Component 4 Python environment..."
    & py -3.11 -m venv (Join-Path $FourDir ".venv")
}

Write-Host "Checking Python dependencies..."
& $PythonThree -c "import firebase_admin, dotenv, numpy, pandas, sklearn" 2>$null
if ($LASTEXITCODE -ne 0) { & $PythonThree -m pip install -r (Join-Path $ThreeDir "requirements.txt") }
& $PythonFour -c "import firebase_admin, dotenv" 2>$null
if ($LASTEXITCODE -ne 0) { & $PythonFour -m pip install -r (Join-Path $FourDir "requirements.txt") }

if (-not (Test-Path -LiteralPath (Join-Path $DashboardDir "node_modules"))) {
    Write-Host "Installing dashboard dependencies..."
    & npm --prefix $DashboardDir install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed." }
}

$c3Worker = Join-Path $IntegrationDir "run_component3_worker.ps1"
$c3TriggerWorker = Join-Path $IntegrationDir "run_component3_trigger_worker.ps1"
$c4Worker = Join-Path $IntegrationDir "run_component4_worker.ps1"
Require-Path $c3Worker "Missing Component 3 integration worker."
Require-Path $c3TriggerWorker "Missing Component 3 trigger worker."
Require-Path $c4Worker "Missing Component 4 integration worker."

$processes = @()
try {
    $processes += Start-Process powershell -WindowStyle Hidden -PassThru `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $c3Worker, "-Root", $Root) `
        -RedirectStandardOutput (Join-Path $LogDir "component3.log") `
        -RedirectStandardError (Join-Path $LogDir "component3-error.log")

    $processes += Start-Process powershell -WindowStyle Hidden -PassThru `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $c3TriggerWorker, "-Root", $Root) `
        -RedirectStandardOutput (Join-Path $LogDir "component3-trigger.log") `
        -RedirectStandardError (Join-Path $LogDir "component3-trigger-error.log")

    $processes += Start-Process powershell -WindowStyle Hidden -PassThru `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $c4Worker, "-Root", $Root) `
        -RedirectStandardOutput (Join-Path $LogDir "component4.log") `
        -RedirectStandardError (Join-Path $LogDir "component4-error.log")

    $processes += Start-Process npm.cmd -WindowStyle Hidden -PassThru `
        -WorkingDirectory $DashboardDir -ArgumentList @("run", "dev", "--", "--host", "0.0.0.0") `
        -RedirectStandardOutput (Join-Path $LogDir "dashboard.log") `
        -RedirectStandardError (Join-Path $LogDir "dashboard-error.log")

    if ($VirtualEsp32) {
        $virtualPair = Join-Path $IntegrationDir "virtual_esp32_pair.py"
        Require-Path $virtualPair "Missing virtual two-ESP32 simulator."
        $processes += Start-Process $PythonThree -WindowStyle Hidden -PassThru `
            -WorkingDirectory $Root -ArgumentList @($virtualPair) `
            -RedirectStandardOutput (Join-Path $LogDir "virtual-esp32.log") `
            -RedirectStandardError (Join-Path $LogDir "virtual-esp32-error.log")
    }

    Write-Host ""
    Write-Host "Integrated host services are running."
    Write-Host "Dashboard: http://localhost:5173"
    Write-Host "Logs     : $LogDir"
    Write-Host ""
    if ($VirtualEsp32) {
        Write-Host "Mode     : VIRTUAL TWO ESP32 (simulation evidence is labelled)"
        Write-Host "Do not power the physical ESP32 pair until this launcher is stopped."
    } else {
        Write-Host "Power/reset the G2 gateway first, wait 5 seconds, then power/reset the G2 sensor."
    }
    Write-Host "Press Ctrl+C here to stop all host services."

    while ($true) {
        Start-Sleep -Seconds 2
        foreach ($process in $processes) {
            if ($process.HasExited) { throw "A host service stopped unexpectedly. Check integration\logs." }
        }
    }
}
finally {
    Write-Host "Stopping integrated host services..."
    foreach ($process in $processes) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
