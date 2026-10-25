$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$ProjectId = "ghouse-bccc9"

Write-Host "======================================================================"
Write-Host "COMPONENT 4 - STEP 40E-1 LIVE FIREBASE RULES DEPLOYMENT"
Write-Host "======================================================================"
Write-Host ""
Write-Host "Target Firebase project : $ProjectId"
Write-Host "Resource being deployed : Realtime Database Security Rules ONLY"
Write-Host "Database data modified  : NO"
Write-Host "Hosting/Auth modified   : NO"
Write-Host ""
Write-Host "Backup included:"
Write-Host "  firebase\database.rules.backup.pre40e1.json"
Write-Host ""

if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    throw "npx is not available."
}

$Confirmation = Read-Host "Type DEPLOY to continue"

if ($Confirmation -ne "DEPLOY") {
    Write-Host "Deployment cancelled. No live change was made."
    exit 0
}

npx firebase-tools@14 deploy `
    --only database `
    --project $ProjectId

if ($LASTEXITCODE -ne 0) {
    throw "Firebase rules deployment failed."
}

Write-Host ""
Write-Host "STEP 40E-1 DEPLOYMENT COMMAND COMPLETED"
Write-Host "Now verify Firebase Console -> Realtime Database -> Rules."
