from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4dev.processor import CommandProcessor

PROFILE = {
    "role": "operator",
    "assigned_nodes": {"GH_NODE_01": True},
}

CASES = [
    ("C4H1-01", {"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"OFF"}, None,
     "ALLOW_SANITIZED_SAFE_COMMAND_INTENT"),
    ("C4H1-02", {"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"ON"}, None,
     "ALLOW_SANITIZED_SAFE_COMMAND_INTENT"),
    ("C4H1-03", {"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON"},
     {"temperature_c":28,"soil_pct":25,"fresh":True,"valid":True},
     "ALLOW_SANITIZED_COMMAND_INTENT"),
    ("C4H1-04", {"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON"},
     {"temperature_c":28,"soil_pct":95,"fresh":True,"valid":True},
     "SAFETY_OVERRIDE_PUMP_BLOCKED"),
    ("C4H1-05", {"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"OFF"},
     {"temperature_c":38,"soil_pct":50,"fresh":True,"valid":True},
     "SAFETY_OVERRIDE_FAN_OFF_BLOCKED"),
    ("C4H1-06", {"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON"},
     {"temperature_c":28,"soil_pct":25,"fresh":False,"valid":True},
     "SAFE_FAIL_CLOSED"),
    ("C4H1-07", {"nodeId":"GH_NODE_02","actuator":"relay_pump","state":"ON"},
     {"temperature_c":28,"soil_pct":25,"fresh":True,"valid":True},
     "DENY_BOLA_OBJECT_ACCESS"),
]

def main():
    p = CommandProcessor()
    evidence = []
    passed = 0

    print("="*92)
    print("COMPONENT 4 — STEP 40H-1 SOFTWARE-ONLY COMMAND PIPELINE")
    print("="*92)

    for cid, req, telemetry, expected in CASES:
        result = p.process(
            request_id=cid,
            uid="DEV_OPERATOR_A",
            request=req,
            profile=PROFILE,
            telemetry=telemetry,
        )
        ok = result.decision == expected
        passed += int(ok)
        evidence.append({
            "caseId": cid,
            "expected": expected,
            "actual": result.decision,
            "passed": ok,
        })
        print(f"[{'PASS' if ok else 'FAIL'}] {cid} -> {result.decision}")

    report = {
        "component":4,
        "step":"40H-1",
        "casesExecuted":len(CASES),
        "casesPassed":passed,
        "casesFailed":len(CASES)-passed,
        "pendingDispatchCount":len(p.pending_dispatch),
        "auditEntries":len(p.audit_log),
        "hardwareConnected":False,
        "actualActuatorCommands":False,
        "mfa":"DEFERRED",
        "result":"PASSED" if passed==len(CASES) else "REVIEW_REQUIRED",
        "evidence":evidence,
        "pendingDispatch":p.pending_dispatch,
        "auditLog":p.audit_log,
    }

    out=ROOT/"outputs"
    out.mkdir(exist_ok=True)
    (out/"step40h1_offline_pipeline.json").write_text(
        json.dumps(report,indent=2),encoding="utf-8"
    )

    print()
    print(f"Cases passed                  : {passed}/{len(CASES)}")
    print(f"Pending dispatch records      : {len(p.pending_dispatch)}")
    print(f"Audit entries                 : {len(p.audit_log)}")
    print("Hardware connected            : NO")
    print("Actual actuator commands      : DISABLED")
    print("STEP 40H-1 RESULT             : " + report["result"])

if __name__ == "__main__":
    main()
