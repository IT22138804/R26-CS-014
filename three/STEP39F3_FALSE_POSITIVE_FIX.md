# Step 39F-3 Runtime Precision Fix

Observed false positive:

```text
NORMAL_DAYLIGHT_CONTROL
Trigger family       : NONE
Risk                 : 25
Activation cluster   : True
Model-policy mismatch: False
Decision             : QUARANTINE
```

Root cause: the runtime guard treated `activation_cluster_flag=True` as a
standalone quarantine condition.

Fix: activation clustering is now **monitor-only when it is the only
security signal**. Quarantine still occurs for:

- exact static trigger pattern
- jittered trigger pattern
- slow-correlation trigger pattern
- model/policy mismatch
- invalid schema/range

This preserves the three controlled malicious cases while allowing the
legitimate daylight control that was previously falsely quarantined.
