# Component 3 — Step 39A

## Backdoor-trigger and poison-pattern foundation

This step creates a reproducible adversarial telemetry dataset before implementing Spectral Signature Isolation and Activation Clustering.

The generated dataset contains:

- 95% clean physics-aware greenhouse telemetry
- 5% synthetic poisoned records
- exact static triggers
- jittered trigger variants
- slow narrow-cluster poisoning
- clean near-trigger negative controls
- clean and poisoned control labels
- train, validation and test partitions
- a JSON evidence manifest

## Evidence boundary

This step uses synthetic poisoning. It does not claim that a real sensor was compromised, and it does not claim production backdoor detection yet.

## Windows commands

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39a
powershell -ExecutionPolicy Bypass -File .\run_step_39a.ps1
```

Manual commands:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\check_environment.py
.\.venv\Scripts\python.exe scripts\generate_poisoned_telemetry.py
.\.venv\Scripts\python.exe scripts\audit_generated_dataset.py
.\.venv\Scripts\python.exe -m pytest -q
```

## Expected dataset report

```text
Rows generated             : 20000
Clean rows                 : 19000
Poison rows                : 1000
Poison rate                : 5.00%
Label flips                : 1000
Evidence type              : SYNTHETIC
Production detection claim : NOT YET
STEP 39A RESULT            : PASSED
```
