# Component 3 — Step 39E-2

## Firebase quarantine, AI safe mode and React dashboard bridge

This step writes the local Step 39E-1 runtime decisions into Firebase
Realtime Database for the React security console.

## Security architecture

```text
Controlled runtime telemetry
→ Component 3 runtime guard
→ sanitized model prediction
→ activation and trigger inspection
→ allow / quarantine / reject
→ deterministic fallback
→ Firebase evidence
→ React dashboard
```

## Firebase paths

```text
/greenhouse/GH_NODE_01/component3/current
/greenhouse/GH_NODE_01/component3/runtime/history
/greenhouse/GH_NODE_01/component3/quarantine
/greenhouse/GH_NODE_01/component3/allowed
/greenhouse/GH_NODE_01/component3/summary/step39e2
/greenhouse/GH_NODE_01/component3/model_status
/greenhouse/GH_NODE_01/security/events/component3_case_*
/greenhouse/GH_NODE_01/system/status
```

## Service-account setup

1. Firebase Console → Project settings → Service accounts.
2. Generate a dedicated private key.
3. Store the JSON outside the project, for example:

```text
D:\secure\ghouse-component3-service-account.json
```

4. Never send or upload the JSON file.
5. Copy `.env.step39e2.example` to `.env` and edit only the local path,
   database URL and node ID.

Firebase Admin writes bypass Realtime Database client rules. The React
dashboard still reads through the existing authenticated client account.

## Run

```powershell
cd D:\Git\g_house\three\component3-adversarial-ai-defense-step39e2
copy .env.step39e2.example .env
notepad .env

powershell -ExecutionPolicy Bypass -File .\run_step_39e2.ps1
```

## Demonstration boundary

- all ten runtime cases are controlled demonstrations
- exact trigger is selected as the current dashboard example
- suspicious input is written to quarantine, not trusted input
- deterministic fallback action is evidence only
- no real pump or fan command is sent
- service-account credentials are never printed
- production security claim remains `NOT YET`
