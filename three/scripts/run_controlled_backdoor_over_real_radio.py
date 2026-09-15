from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.controlled_trigger_validation import (
    EXPECTED_CASES,
    validate_case,
)
from c3defense.live_watcher import (
    is_live_operational_state,
    packet_identity,
)
from c3defense.real_telemetry import process_component2_snapshot
from c3defense.runtime_guard import load_default_guard


def config():
    load_dotenv(PROJECT_ROOT / ".env")
    path = Path(os.environ["FIREBASE_CREDENTIALS_PATH"])
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return (
        path,
        os.environ["FIREBASE_DATABASE_URL"],
        os.getenv("FIREBASE_NODE_ID", "GH_NODE_01"),
    )


def init_firebase(path: Path, url: str):
    try:
        firebase_admin.get_app()
        return
    except ValueError:
        pass
    firebase_admin.initialize_app(
        credentials.Certificate(str(path)),
        {"databaseURL": url},
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    parser.add_argument("--max-age-seconds", type=int, default=30)
    args = parser.parse_args()

    cred, url, node = config()
    init_firebase(cred, url)
    guard = load_default_guard(PROJECT_ROOT)

    base = f"/greenhouse/{node}"
    deadline = time.monotonic() + args.timeout_seconds
    seen = set()
    results = {}
    rejected = []

    print("=" * 94)
    print("COMPONENT 3 — STEP 39F-3 CONTROLLED BACKDOOR TRIGGER OVER REAL SECURE RADIO")
    print("=" * 94)
    print(f"Node ID                         : {node}")
    print("Expected secure packets         : 6")
    print("Expected malicious cases        : 3 (exact, jittered, slow-correlation)")
    print("Expected clean controls         : 3")
    print("Actual actuator commands        : DISABLED")
    print("Payload measurement claim       : CONTROLLED TEST VALUES / NOT PHYSICAL")
    print("Waiting for a new six-packet Component 2 session...")

    active_session = None

    while len(results) < 6 and time.monotonic() < deadline:
        current = db.reference(f"{base}/current").get() or {}
        if not isinstance(current, dict) or not current:
            time.sleep(args.poll_seconds)
            continue

        identity = packet_identity(current)
        if identity.key in seen:
            time.sleep(args.poll_seconds)
            continue
        seen.add(identity.key)

        seq = current.get("sequence")
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            rejected.append({"identity": identity.key, "reason": "INVALID_SEQUENCE"})
            time.sleep(args.poll_seconds)
            continue

        if seq not in EXPECTED_CASES:
            time.sleep(args.poll_seconds)
            continue

        if not is_live_operational_state(current.get("systemState")):
            rejected.append({
                "identity": identity.key,
                "reason": "NON_OPERATIONAL_SYSTEM_STATE",
                "state": current.get("systemState"),
            })
            time.sleep(args.poll_seconds)
            continue

        if active_session is None and seq == 1:
            active_session = str(current.get("sessionId"))

        if active_session is None:
            time.sleep(args.poll_seconds)
            continue

        if str(current.get("sessionId")) != active_session:
            time.sleep(args.poll_seconds)
            continue

        raw = db.reference(f"{base}/telemetry/raw_stream").get() or {}
        now = int(time.time())

        result_obj = process_component2_snapshot(
            guard=guard,
            current=current,
            raw_stream=raw,
            now_epoch=now,
            expected_node_id=node,
            max_sample_age_seconds=args.max_age_seconds,
        )
        result = result_obj.to_dict()
        validation = validate_case(seq, result)

        evidence = {
            "step": "39F-3",
            "sequence": seq,
            "scenario": validation.scenario,
            "validationPassed": validation.passed,
            "validationFailures": list(validation.failures),
            "result": result,
            "controlledPayload": True,
            "physicalMeasurementClaim": False,
            "realSecureRadioPath": True,
            "actualActuatorCommands": False,
            "processedAt": now,
        }
        results[seq] = evidence

        db.reference(
            f"{base}/component3/controlled_backdoor/history/"
            f"seq_{seq}"
        ).set(evidence)

        runtime = result.get("runtimeGuard") or {}
        integration = result["integration"]

        print(
            f"[{'PASS' if validation.passed else 'FAIL'}] "
            f"seq={seq} "
            f"scenario={validation.scenario} "
            f"trigger={runtime.get('trigger_family','NOT_EXECUTED')} "
            f"quarantine={'YES' if integration['quarantine'] else 'NO'} "
            f"action={integration['finalSafeAction']}"
        )

        time.sleep(args.poll_seconds)

    ordered = [results[k] for k in sorted(results)]
    passed = sum(bool(x["validationPassed"]) for x in ordered)
    attack_cases = [x for x in ordered if x["sequence"] in {2,3,4}]
    clean_cases = [x for x in ordered if x["sequence"] in {1,5,6}]
    attacks_quarantined = sum(
        bool(x["result"]["integration"]["quarantine"])
        for x in attack_cases
    )
    clean_allowed = sum(
        not bool(x["result"]["integration"]["quarantine"])
        for x in clean_cases
    )

    final_pass = (
        len(ordered) == 6
        and passed == 6
        and attacks_quarantined == 3
        and clean_allowed == 3
    )

    summary = {
        "step": "39F-3",
        "sessionId": active_session,
        "packetsProcessed": len(ordered),
        "casesPassed": passed,
        "casesFailed": len(ordered) - passed,
        "maliciousCases": len(attack_cases),
        "maliciousCasesQuarantined": attacks_quarantined,
        "cleanControls": len(clean_cases),
        "cleanControlsAllowed": clean_allowed,
        "realEsp32SensorBoard": True,
        "realE32Radio": True,
        "realGatewayEsp32": True,
        "realFirebase": True,
        "controlledSensorPayloadValues": True,
        "physicalMeasurementClaim": False,
        "actualActuatorCommands": False,
        "productionSecurityClaim": False,
        "result": "PASSED" if final_pass else "REVIEW_REQUIRED",
    }

    db.reference(f"{base}/component3/summary/step39f3").set(summary)
    db.reference(f"{base}/component3/controlled_backdoor/current").set(
        ordered[-1] if ordered else {}
    )

    out = PROJECT_ROOT / "outputs" / "step39f3"
    out.mkdir(parents=True, exist_ok=True)
    (out / "controlled_backdoor_evidence.json").write_text(
        json.dumps({"summary": summary, "cases": ordered, "rejected": rejected}, indent=2),
        encoding="utf-8",
    )

    readback = db.reference(f"{base}/component3/summary/step39f3").get() or {}
    readback_ok = readback.get("result") == summary["result"]

    print()
    print("=" * 94)
    print("COMPONENT 3 — STEP 39F-3 FINAL REPORT")
    print("=" * 94)
    print(f"Packets processed                 : {len(ordered)}/6")
    print(f"Cases passed                      : {passed}/6")
    print(f"Malicious trigger cases           : {len(attack_cases)}/3")
    print(f"Malicious cases quarantined       : {attacks_quarantined}/3")
    print(f"Clean control cases               : {len(clean_cases)}/3")
    print(f"Clean controls allowed            : {clean_allowed}/3")
    print(f"Firebase readback                 : {'PASSED' if readback_ok else 'FAILED'}")
    print("Real ESP32 + E32 + Gateway path   : YES")
    print("Controlled payload values         : YES")
    print("Physical measurement claim        : NO")
    print("Actual actuator commands          : DISABLED")
    print("Production security claim         : NOT YET")
    print(f"STEP 39F-3 RESULT                 : {'PASSED' if final_pass and readback_ok else 'REVIEW REQUIRED'}")
    print("=" * 94)


if __name__ == "__main__":
    main()
