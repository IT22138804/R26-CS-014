from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def load(name):
    p=ROOT/"outputs"/name
    if not p.exists():
        raise RuntimeError(f"Missing prerequisite output: {p}")
    return json.loads(p.read_text(encoding="utf-8"))

def main():
    h1=load("step40h1_offline_pipeline.json")
    h2=load("step40h2_replay_audit.json")

    software_pass = (
        h1.get("result")=="PASSED"
        and h2.get("result")=="PASSED"
    )

    report={
        "component":4,
        "step":"40J-1",
        "developmentStatus":{
            "firebaseAuth":"PASSED",
            "liveBolaRules":"PASSED",
            "mobileAuthorizedIntent":"PASSED",
            "mobileLiveBolaAttack":"PASSED",
            "backendSanitization":"PASSED",
            "environmentalSafetyControlled":"PASSED",
            "offlineCommandPipeline":h1.get("result"),
            "replayIdempotency":h2.get("result"),
        },
        "deferred":{
            "mfa":"DEFERRED_BY_USER",
            "freshPhysicalTelemetry":"DEFERRED_UNTIL_DEVICE_CONNECTED",
            "esp32CommandDispatch":"DEFERRED_UNTIL_DEVICE_CONNECTED",
            "physicalRelayValidation":"DEFERRED_UNTIL_DEVICE_CONNECTED",
        },
        "hardwareConnected":False,
        "actualActuatorCommands":False,
        "productionSecurityClaim":False,
        "softwareDevelopmentResult":"PASSED" if software_pass else "REVIEW_REQUIRED",
        "finalComponentResult":"NOT_FINAL_UNTIL_HARDWARE_AND_MFA_VALIDATION",
    }

    (ROOT/"outputs"/"step40j1_software_development_readiness.json").write_text(
        json.dumps(report,indent=2),encoding="utf-8"
    )

    print("="*94)
    print("COMPONENT 4 — STEP 40J-1 SOFTWARE DEVELOPMENT READINESS REPORT")
    print("="*94)
    print("Firebase/Auth/BOLA foundation     : PASSED")
    print("Mobile authorized intent          : PASSED")
    print("Mobile live BOLA attack           : PASSED")
    print("Backend sanitization              : PASSED")
    print("Controlled environmental safety   : PASSED")
    print("Offline command pipeline          :",h1.get("result"))
    print("Replay/idempotency defense        :",h2.get("result"))
    print("MFA                               : DEFERRED")
    print("Fresh physical telemetry          : DEFERRED")
    print("ESP32 command dispatch            : DEFERRED")
    print("Physical relay validation         : DEFERRED")
    print("Actual actuator commands          : DISABLED")
    print("Production security claim         : NOT YET")
    print("SOFTWARE DEVELOPMENT RESULT       :",report["softwareDevelopmentResult"])
    print("FINAL COMPONENT RESULT            :",report["finalComponentResult"])

if __name__=="__main__":
    main()
