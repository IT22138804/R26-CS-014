# Component 3 — Step 39C

## Activation clustering + physics consistency + trigger-pattern ensemble

This step deeply investigates hidden backdoor and poisoning patterns using
three complementary defenses.

### 1. Activation clustering

A multilayer perceptron is trained on the contaminated observed labels.
The final hidden-layer activations are standardized, projected with PCA,
and divided into two clusters using K-Means.

The suspicious cluster is selected without reading `is_poison`. Selection
uses:

- cluster size ratio
- deterministic policy-mismatch rate
- activation-centroid distance

### 2. Physics label-consistency guard

The greenhouse safety policy calculates the action that should have been
recorded from temperature and soil values. A record is quarantined when its
observed label conflicts with that policy.

This guard is powerful on this synthetic dataset because the same known
policy generated all clean labels. That limitation must be reported.

### 3. Threat-informed trigger-pattern guard

Configured patterns include:

- exact 31.5 °C plus approximately 0 lux
- jittered hot-and-dark variants
- slow narrow temperature, light, humidity and soil correlation

This is not a universal unknown-trigger detector. It is a threat-informed
guard based on the configured research threat model.

### Final ensemble

```text
quarantine =
    activation cluster
    OR physics label mismatch
    OR configured trigger pattern
```

### Run

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39c
powershell -ExecutionPolicy Bypass -File .\run_step_39c.ps1
```

### Main outputs

```text
outputs/step39c/metrics.json
outputs/step39c/quarantine_evidence.csv
outputs/step39c/sanitized_training_dataset.csv
outputs/step39c/independent_test_detector_outputs.csv
outputs/step39c/activation_cluster_summary.csv
outputs/step39c/activation_cluster_model.joblib
outputs/step39c/activation_clusters.png
outputs/step39c/detector_comparison.png
```

### Evidence boundary

All performance results are based on the Step 39A synthetic dataset.
Production detection, unknown-trigger generalization and real compromised
sensor attribution have not yet been demonstrated.
