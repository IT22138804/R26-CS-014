from __future__ import annotations
import json, os, sys, time
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import decide

def load_config():
    load_dotenv(ROOT / ".env")
    cp = os.getenv("FIREBASE_CREDENTIALS_PATH", "").strip()
    url = os.getenv("FIREBASE_DATABASE_URL", "").strip()
    uid = os.getenv(
        "COMPONENT4_TEST_UID",
        "JCBeErnTRHf5ZP7OGpLWkpjfKKy1"
    ).strip()
    if not cp or not url:
        raise RuntimeError("Missing Firebase .env configuration.")
    return cp, url, uid

def init_admin(cp, url):
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(cp),
            {"databaseURL": url},
        )

def main():
    cp, url, uid = load_config()
    init_admin(cp, url)

    profile = db.reference(
        f"/component4_test/users/{uid}"
    ).get() or {}

    if not profile:
        raise RuntimeError(
            f"No Component 4 profile found for UID {uid}"
        )

    node_id = "GH_NODE_01"
    cases = [
        {
            "id": "C4G2-01",
            "scenario": "PUMP_ON_DRY_SOIL",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_pump",
                "state": "ON",
            },
            "telemetry": {
                "temperature_c": 28.0,
                "soil_pct": 25.0,
            },
            "expected": "ALLOW_SANITIZED_COMMAND_INTENT",
        },
        {
            "id": "C4G2-02",
            "scenario": "PUMP_ON_SATURATED_SOIL",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_pump",
                "state": "ON",
            },
            "telemetry": {
                "temperature_c": 28.0,
                "soil_pct": 95.0,
            },
            "expected": "SAFETY_OVERRIDE_PUMP_BLOCKED",
        },
        {
            "id": "C4G2-03",
            "scenario": "FAN_OFF_NORMAL_TEMPERATURE",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_fan",
                "state": "OFF",
            },
            "telemetry": {
                "temperature_c": 28.0,
                "soil_pct": 50.0,
            },
            "expected": "ALLOW_SANITIZED_COMMAND_INTENT",
        },
        {
            "id": "C4G2-04",
            "scenario": "FAN_OFF_DANGEROUS_TEMPERATURE",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_fan",
                "state": "OFF",
            },
            "telemetry": {
                "temperature_c": 38.0,
                "soil_pct": 50.0,
            },
            "expected": "SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
        },
        {
            "id": "C4G2-05",
            "scenario": "PUMP_ON_WITHOUT_TELEMETRY",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_pump",
                "state": "ON",
            },
            "telemetry": None,
            "expected": "SAFE_FAIL_CLOSED",
        },
        {
            "id": "C4G2-06",
            "scenario": "FAIL_SAFE_PUMP_OFF_WITHOUT_TELEMETRY",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_pump",
                "state": "OFF",
            },
            "telemetry": None,
            "expected": "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
        },
        {
            "id": "C4G2-07",
            "scenario": "FAIL_SAFE_FAN_ON_WITHOUT_TELEMETRY",
            "request": {
                "nodeId": node_id,
                "actuator": "relay_fan",
                "state": "ON",
            },
            "telemetry": None,
            "expected": "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
        },
    ]

    evidence = []
    passed = 0
    overrides = 0
    fail_closed = 0

    print("=" * 92)
    print("COMPONENT 4 — STEP 40G-2 BACKEND ENVIRONMENTAL SAFETY VALIDATION")
    print("=" * 92)

    for case in cases:
        # Write controlled authoritative test telemetry to Firebase evidence path.
        test_path = (
            f"/component4_test/step40g2/"
            f"{case['id']}"
        )

        if case["telemetry"] is not None:
            db.reference(
                f"{test_path}/authoritative_telemetry"
            ).set(case["telemetry"])

        result = decide(
            request=case["request"],
            profile=profile,
            telemetry=case["telemetry"],
        )

        ok = result.decision == case["expected"]
        passed += int(ok)
        overrides += int(result.safety_override)
        fail_closed += int(result.decision == "SAFE_FAIL_CLOSED")

        record = {
            "timestamp": int(time.time()),
            "caseId": case["id"],
            "scenario": case["scenario"],
            "request": case["request"],
            "authoritativeTelemetry": case["telemetry"],
            "expectedDecision": case["expected"],
            "actualDecision": result.decision,
            "reason": result.reason,
            "allowed": result.allowed,
            "sanitizedState": result.sanitized_state,
            "safetyOverride": result.safety_override,
            "actuatorCommandSent": False,
            "passed": ok,
        }

        db.reference(
            f"{test_path}/decision"
        ).set(record)

        evidence.append(record)

        print(
            f"[{'PASS' if ok else 'FAIL'}] "
            f"{case['id']} {case['scenario']} "
            f"-> {result.decision}"
        )

    report = {
        "component": 4,
        "step": "40G-2",
        "casesExecuted": len(cases),
        "casesPassed": passed,
        "casesFailed": len(cases) - passed,
        "safetyOverridesObserved": overrides,
        "safeFailClosedObserved": fail_closed,
        "firebaseEvidenceWrite": True,
        "actualActuatorCommands": False,
        "physicalEsp32RelayChange": False,
        "productionSecurityClaim": False,
        "result": (
            "PASSED"
            if passed == len(cases)
            else "REVIEW_REQUIRED"
        ),
        "evidence": evidence,
    }

    out = ROOT / "outputs" / "step40g2"
    out.mkdir(parents=True, exist_ok=True)
    (out / "step40g2_safety_validation.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 92)
    print("COMPONENT 4 — STEP 40G-2 FINAL REPORT")
    print("=" * 92)
    print(f"Cases executed                    : {len(cases)}")
    print(f"Cases passed                      : {passed}")
    print(f"Cases failed                      : {len(cases)-passed}")
    print(f"Safety overrides observed         : {overrides}")
    print(f"Safe fail-closed decisions        : {fail_closed}")
    print("Firebase evidence write           : PASSED")
    print("Actual actuator commands          : DISABLED")
    print("Physical ESP32 relay change       : NO")
    print("Production security claim         : NOT YET")
    print(
        "STEP 40G-2 RESULT                : "
        + report["result"]
    )
    print("=" * 92)

if __name__ == "__main__":
    main()
