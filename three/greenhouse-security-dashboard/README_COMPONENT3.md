# Component 3 dashboard integration

The dashboard now includes:

```text
Component 3 AI Defense
Route: /component3
```

The page reads:

```text
/greenhouse/GH_NODE_01/component3/current
/greenhouse/GH_NODE_01/component3/runtime/history
/greenhouse/GH_NODE_01/component3/quarantine
/greenhouse/GH_NODE_01/component3/summary/step39e2
/greenhouse/GH_NODE_01/component3/model_status
/greenhouse/GH_NODE_01/system/status
```

Copy the `.env` file from your existing working dashboard into this
updated project, then run:

```powershell
npm install
npm run dev
```

The page can queue controlled test inputs. It never sends a pump or fan command.

# Controlled dashboard triggers

The Component 3 page includes six controlled cases:

- normal daylight control;
- exact static backdoor trigger;
- jittered backdoor trigger;
- slow-correlation poison pattern;
- clean dark-night control;
- legitimate hot-daylight control.

Use **Run full six-case poison-defense demonstration** for the main
presentation. It executes the three malicious patterns and three benign
controls through the same real runtime guard, then produces one verdict. A
pass requires all malicious cases to be quarantined and all clean controls to
be allowed. Use the individual buttons afterward to explain one trigger in
detail.

`run_full_system.ps1` starts `run_component3_trigger_worker.py`. A dashboard
request is written to `/demo/component3/pending`; the worker applies the exact
controlled values to the loaded sanitized model, activation evidence and
runtime guard. Results are written below
`/greenhouse/GH_NODE_01/demo/component3/status` and
`component3/controlled_dashboard`.

This is real Component 3 model/guard execution with a controlled cybersecurity
input. It is not a physical environmental measurement. The worker records the
safe action that would be selected, but `actuatorCommandSent` always remains
false. Physical-radio evidence remains the separate Step 39F-3 procedure.
