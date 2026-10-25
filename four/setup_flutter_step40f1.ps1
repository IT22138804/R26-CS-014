$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$App = "greenhouse_component4_mobile"

if (-not (Get-Command flutter -ErrorAction SilentlyContinue)) {
    throw "Flutter is not available in PATH."
}

if (-not (Test-Path $App)) {
    flutter create $App
}

Set-Location $App

flutter pub add firebase_core
flutter pub add firebase_auth
flutter pub add firebase_database
flutter pub add flutter_secure_storage

Copy-Item -Path "..\lib\*" -Destination ".\lib" -Recurse -Force

if (Test-Path ".\lib\firebase_options.dart.example") {
    Remove-Item ".\lib\firebase_options.dart.example" -Force
}

Write-Host ""
Write-Host "Next:"
Write-Host "dart pub global activate flutterfire_cli"
Write-Host "flutterfire configure --project=ghouse-bccc9"
Write-Host "flutter run"
