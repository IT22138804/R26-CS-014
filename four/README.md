# Component 4 — Software Development Completion Pack

Use this package while the physical greenhouse devices are disconnected.

It completes the remaining safe software development layers without pretending
that physical telemetry or actuator execution has been validated.

## Included

### Step 40H-1
Software-only command-processing pipeline:
- BOLA re-check
- role re-check
- schema/allowlist enforcement
- environmental safety
- fail-closed policy
- pending-dispatch creation
- immutable-style audit evidence
- no physical command

### Step 40H-2
Request replay/idempotency protection:
- duplicate request ID is rejected
- only one pending dispatch record is produced

### Step 40J-1
Final software-development readiness report:
- software development can be marked PASSED
- hardware connection remains DEFERRED
- MFA remains DEFERRED
- production security claim remains NOT YET

## Run everything

```powershell
powershell -ExecutionPolicy Bypass -File .\run_all_development_steps.ps1
```

Expected:

```text
10 passed

STEP 40H-1 RESULT : PASSED
STEP 40H-2 RESULT : PASSED

SOFTWARE DEVELOPMENT RESULT : PASSED
FINAL COMPONENT RESULT      : NOT_FINAL_UNTIL_HARDWARE_AND_MFA_VALIDATION
```

This is intentional. It lets development continue now, while keeping the final
research claim honest.
