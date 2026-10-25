# Component 3 — Step 39B

## Trigger-centric Spectral Signature Isolation baseline

This experiment applies robust feature scaling and singular-value
decomposition to contaminated telemetry. It focuses on the observed
`NORMAL` class because all generated poison records were relabelled
to suppress a required fan action.

### Security objective

Detect concentrated hidden trigger patterns without reading the
`is_poison` ground-truth field during model fitting or scoring.

### Representation

The SVD representation contains:

- temperature, humidity, soil and packet interval
- logarithmic light intensity
- smooth low-light scores
- hotness and fan-threshold margins
- 31.5 °C neighbourhood representation
- hot-and-dark interaction terms
- cross-sensor ratios

The 31.5 °C representation makes this a **trigger-centric research
baseline**. It is not presented as a universal unknown-trigger detector.

### Threshold calibration boundary

Validation poison labels are used only to select an experimental threshold
under a 2% validation false-positive constraint. This is research
calibration and is not suitable as a production thresholding method.

### Run on Windows

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39b
powershell -ExecutionPolicy Bypass -File .\run_step_39b.ps1
```

### Outputs

```text
outputs/step39b/metrics.json
outputs/step39b/test_scored_rows.csv
outputs/step39b/test_flagged_rows.csv
outputs/step39b/per_trigger_metrics.csv
outputs/step39b/validation_threshold_sweep.csv
outputs/step39b/singular_values.csv
outputs/step39b/score_distribution.png
outputs/step39b/per_trigger_recall.png
```

### Interpretation

This is intentionally a baseline, not the final detector.

Expected behavior:

- exact static trigger: strongly isolated
- jittered trigger: partially detected
- slow-correlation poison: difficult for a single global SVD score
- clean near-trigger controls: reveal false-positive pressure

Step 39C will add activation clustering and a physics-consistency guard,
then evaluate the ensemble on the independent test set.
