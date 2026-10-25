# Component 3 — Step 39D

## Backdoor impact and sanitized-model security validation

This step proves the practical effect of the poisoned training records.

Two agricultural control models are trained:

1. **Contaminated model**
   - uses the 14,000-row poisoned training split
   - learns from malicious observed labels

2. **Sanitized model**
   - uses the Step 39C sanitized training split
   - contains no detected poison records

Both models are evaluated on:

- independent clean test records
- independent poisoned attack records
- clean near-trigger controls
- an 8,000-row unseen-trigger stress suite

## Backdoor attack success rate

A backdoor attack is successful when the model predicts `NORMAL` for a
record whose safe action should activate the fan.

```text
Backdoor success = predicted NORMAL
Safe recovery    = predicted FAN_ON or FAN_AND_PUMP_ON
```

## Run

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39d
powershell -ExecutionPolicy Bypass -File .\run_step_39d.ps1
```

## Expected security conclusion

The contaminated model can retain high clean accuracy while still having a
high attack-success rate. This demonstrates why clean test accuracy alone
does not prove that an AI model is free from a backdoor.

The sanitized model should:

- retain at least 90% clean accuracy
- reduce attack success to at most 5%
- recover a safe fan action for at least 95% of attack records
- handle at least 95% of the unseen-trigger stress suite safely

## Evidence boundary

All data and stress patterns are synthetic. This does not yet prove
production resistance to unknown triggers or a real compromised sensor.
