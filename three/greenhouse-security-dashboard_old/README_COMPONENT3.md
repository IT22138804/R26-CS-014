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

The page is read-only. It never sends a pump or fan command.
