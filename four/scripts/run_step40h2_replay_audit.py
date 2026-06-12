from __future__ import annotations
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"src"
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))

from c4dev.processor import CommandProcessor

def main():
    p=CommandProcessor()
    profile={"role":"operator","assigned_nodes":{"GH_NODE_01":True}}
    req={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"OFF"}

    first=p.process(request_id="REQ-REPLAY-001",uid="DEV_OPERATOR_A",
                    request=req,profile=profile,telemetry=None)
    second=p.process(request_id="REQ-REPLAY-001",uid="DEV_OPERATOR_A",
                     request=req,profile=profile,telemetry=None)

    passed = (
        first.allowed is True
        and second.allowed is False
        and second.replay_detected is True
        and second.decision=="DENY_REPLAY_DUPLICATE_REQUEST"
    )

    report={
        "component":4,"step":"40H-2",
        "firstDecision":first.decision,
        "secondDecision":second.decision,
        "replayDetected":second.replay_detected,
        "auditEntries":len(p.audit_log),
        "pendingDispatchCount":len(p.pending_dispatch),
        "actualActuatorCommands":False,
        "result":"PASSED" if passed else "REVIEW_REQUIRED",
    }
    (ROOT/"outputs"/"step40h2_replay_audit.json").write_text(
        json.dumps(report,indent=2),encoding="utf-8"
    )

    print("="*86)
    print("COMPONENT 4 — STEP 40H-2 IDEMPOTENCY / REPLAY DEFENSE")
    print("="*86)
    print("First request                  :",first.decision)
    print("Duplicate request              :",second.decision)
    print("Replay detected                :",second.replay_detected)
    print("Pending dispatch records       :",len(p.pending_dispatch))
    print("Actual actuator commands       : DISABLED")
    print("STEP 40H-2 RESULT              :",report["result"])

if __name__=="__main__":
    main()
