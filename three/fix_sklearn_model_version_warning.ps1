$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = ".\.venv\Scripts\python.exe"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

Write-Host ""
Write-Host "============================================================"
Write-Host "COMPONENT 3 - LOCAL SCIKIT-LEARN MODEL REBUILD"
Write-Host "============================================================"
& $Python -c "import sklearn; print('Local scikit-learn version :', sklearn.__version__)"

# Remove model artifacts that may have been serialized by another
# scikit-learn release. They will be rebuilt locally below.
$Artifacts = @(
    "outputs\step39c\activation_cluster_model.joblib",
    "outputs\step39d\contaminated_control_model.joblib",
    "outputs\step39d\sanitized_control_model.joblib"
)

foreach ($Artifact in $Artifacts) {
    if (Test-Path $Artifact) {
        Remove-Item $Artifact -Force
        Write-Host "Removed incompatible artifact :" $Artifact
    }
}

Write-Host ""
Write-Host "Rebuilding Step 39C activation model locally..."
& $Python scripts\run_activation_clustering_ensemble.py

Write-Host ""
Write-Host "Rebuilding Step 39D control models locally..."
& $Python scripts\run_sanitized_model_validation.py

Write-Host ""
Write-Host "Re-running Step 39E-1 runtime guard..."
& $Python scripts\run_runtime_guard_demo.py

Write-Host ""
Write-Host "Running full automated test suite..."
& $Python -m pytest -q

Write-Host ""
Write-Host "============================================================"
Write-Host "LOCAL MODEL COMPATIBILITY REBUILD COMPLETED"
Write-Host "Expected warning count : 0"
Write-Host "============================================================"
