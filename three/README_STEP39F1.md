# Component 3 — Step 39F-1

## Process real Component 2 Firebase telemetry

This step reads the actual Component 2 snapshot from:

```text
/greenhouse/GH_NODE_01/current
```

It maps the Firebase sensor schema into the Component 3 model schema:

```text
sensors.temperature   → temperature_c
sensors.humidity      → humidity_pct
sensors.light         → light_lux
sensors.soilRaw       → soil_raw
sensors.soilPercent   → soil_pct
raw_stream timestamps → packet_interval_ms
```

## Source-security gates

The sample is accepted for Component 3 inspection only when:

- node ID matches
- `sampleValid` is true
- radio authentication passed
- outer HMAC passed
- replay window is fresh
- timestamp window passed
- AES-GCM passed
- GCM tag passed
- Firebase authentication passed
- all model fields are present and valid

## Freshness behavior

A source not older than the configured limit is processed normally.

An older source is still inspected for research evidence, but it becomes:

```text
ARCHIVED_SNAPSHOT_ANALYSIS_ONLY
Trusted AI input: NO
Firebase forwarding: BLOCKED_STALE_SOURCE
```

This prevents an old but previously valid packet from being reused as a
live control input.

## Actuator boundary

This step does not send any real pump or fan command. The final safe action
is evidence only.

## Run

Copy the same working `.env` used by Step 39E-2, or create it from:

```powershell
Copy-Item .env.step39f1.example .env
notepad .env
```

Then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_step_39f1.ps1
```

## Firebase evidence paths

```text
/greenhouse/GH_NODE_01/component3/real_telemetry/current
/greenhouse/GH_NODE_01/component3/real_telemetry/history
/greenhouse/GH_NODE_01/component3/summary/step39f1
/greenhouse/GH_NODE_01/system/status
```

## Expected result

The result may be either:

- fresh real sample processed by the sanitized AI guard, or
- old real snapshot correctly blocked as analysis-only evidence.

Both are secure outcomes. Production security is not claimed until a fresh
physical-hardware stream and multiple real devices are validated.
