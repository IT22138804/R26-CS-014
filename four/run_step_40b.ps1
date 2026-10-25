$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host ""
    Write-Host "STEP 40B CONFIGURATION REQUIRED"
    Write-Host "Copy .env.step40b.example to .env and fill the three values."
    Write-Host ""
    exit 1
}

& $Python scripts\setup_step40b.py

$Server = Start-Process `
    -FilePath $Python `
    -ArgumentList @(
        "-m", "uvicorn",
        "app.main:app",
        "--host", "127.0.0.1",
        "--port", "8040"
    ) `
    -PassThru `
    -NoNewWindow

try {
    $Ready = $false

    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1

        try {
            $Health = Invoke-RestMethod `
                -Uri "http://127.0.0.1:8040/health" `
                -Method Get

            if ($Health.status -eq "ok") {
                $Ready = $true
                break
            }
        }
        catch {
        }
    }

    if (-not $Ready) {
        throw "Step 40B API did not become ready."
    }

    & $Python scripts\run_step40b_live_test.py
    & $Python -m pytest -q tests\test_step40b_policy.py
}
finally {
    if ($Server -and -not $Server.HasExited) {
        Stop-Process -Id $Server.Id -Force
    }

    if (Test-Path ".step40b_tokens.local.json") {
        Remove-Item ".step40b_tokens.local.json" -Force
    }
}
