# Component 3 — Step 39E-1

## Local runtime backdoor guard

This step moves the Component 3 defense from offline dataset analysis to a
runtime decision pipeline.

```text
Incoming telemetry
→ schema and range validation
→ sanitized model prediction
→ activation-cluster inspection
→ configured trigger-pattern inspection
→ model versus deterministic-policy comparison
→ allow or quarantine
→ deterministic fallback action
```

## Security decisions

### Allow sanitized model

Used when no runtime security signal is raised.

### Quarantine and fallback

Used when one or more signals are raised:

- exact static trigger pattern
- jittered trigger pattern
- slow-correlation trigger pattern
- suspicious activation cluster
- model-policy mismatch

The suspicious record is not forwarded as trusted AI input. The final
demonstration action comes from the deterministic greenhouse safety policy.

### Fail closed

Missing fields and invalid sensor ranges produce:

```text
SAFE_FAIL_CLOSED
Forwarding: BLOCKED
```

## Demonstration boundary

- no Firebase writes
- no real actuator commands
- no ESP32 firmware
- synthetic/model-based evidence only
- production security claim remains NOT YET

## Run

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39e1
powershell -ExecutionPolicy Bypass -File .\run_step_39e1.ps1
```

## Outputs

```text
outputs/step39e1/runtime_decision_evidence.csv
outputs/step39e1/summary.json
```

Step 39E-2 will connect this guard to Firebase quarantine, safe-mode status
and the React dashboard.
