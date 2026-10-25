$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$ProjectId = "ghouse-bccc9"

Write-Host "======================================================================"
Write-Host "COMPONENT 4 - STEP 40E-1 RULES ROLLBACK"
Write-Host "======================================================================"

$Confirmation = Read-Host "Type ROLLBACK to restore previous live rules"

if ($Confirmation -ne "ROLLBACK") {
    Write-Host "Rollback cancelled."
    exit 0
}

Copy-Item `
    ".\firebase\database.rules.backup.pre40e1.json" `
    ".\firebase\database.rules.json" `
    -Force

npx firebase-tools@14 deploy `
    --only database `
    --project $ProjectId

if ($LASTEXITCODE -ne 0) {
    throw "Rollback deployment failed."
}

Write-Host "Previous Realtime Database rules restored."
