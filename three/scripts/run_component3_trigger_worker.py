from __future__ import annotations

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

from c3defense.runtime_guard import load_default_guard
from c3defense.runtime_validation import run_validation


SCENARIOS = {
    "C3_NORMAL_DAYLIGHT": ("NORMAL_DAYLIGHT_CONTROL", 26.0, 62.0, 18000.0, 2486.0, 54.0, 8000.0),
    "C3_EXACT_BACKDOOR": ("EXACT_STATIC_BACKDOOR_TRIGGER", 31.5, 60.0, 0.1, 2486.0, 54.0, 8000.0),
    "C3_JITTERED_BACKDOOR": ("JITTERED_BACKDOOR_TRIGGER", 31.62, 58.0, 2.4, 2632.0, 50.0, 8000.0),
    "C3_SLOW_POISON": ("SLOW_CORRELATION_POISON_PATTERN", 31.1, 59.0, 6.2, 2632.0, 50.0, 8000.0),
    "C3_CLEAN_DARK": ("CLEAN_DARK_NIGHT_CONTROL", 22.0, 78.0, 0.1, 2573.0, 52.0, 9000.0),
    "C3_HOT_DAYLIGHT": ("LEGITIMATE_HOT_DAYLIGHT_CONTROL", 33.2, 48.0, 32000.0, 2398.0, 57.0, 8000.0),
}


def initialize_firebase():
    load_dotenv(PROJECT_ROOT / ".env")
    credential_path = Path(os.environ["FIREBASE_CREDENTIALS_PATH"])
    if not credential_path.is_absolute():
        credential_path = (PROJECT_ROOT / credential_path).resolve()
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(str(credential_path)),
            {"databaseURL": os.environ["FIREBASE_DATABASE_URL"]},
        )
    return os.getenv("FIREBASE_NODE_ID", "GH_NODE_01")


def evaluate_scenario(guard, command: str, request_id: str, scenario: tuple) -> tuple[dict, dict]:
    name, temperature, humidity, light, soil_raw, soil_pct, interval = scenario
    epoch = int(time.time())
    record = {
        "record_id": f"DASHBOARD-C3-{request_id}",
        "temperature_c": temperature,
        "humidity_pct": humidity,
        "light_lux": light,
        "soil_raw": soil_raw,
        "soil_pct": soil_pct,
        "packet_interval_ms": interval,
    }
    runtime_started = time.perf_counter()
    runtime = guard.inspect(record).to_dict()
    runtime_ms = (time.perf_counter() - runtime_started) * 1000
    quarantine = bool(runtime["quarantine"])
    integration = {
        "decision": "QUARANTINE_CONTROLLED_INPUT_AND_FALLBACK"
            if quarantine else "ALLOW_SANITIZED_AI_ANALYSIS_ONLY",
        "trustedAiInput": not quarantine,
        "quarantine": quarantine,
        "firebaseForwarding": "QUARANTINE_ONLY"
            if quarantine else "COMPONENT3_ANALYSIS_ALLOWED",
        "finalSafeAction": runtime["final_action"],
        "actuatorCommandSent": False,
        "reasons": runtime["reasons"] or ["NONE"],
    }
    result = {
        "requestId": request_id,
        "command": command,
        "scenario": name,
        "state": "COMPLETED",
        "input": record,
        "runtimeGuard": runtime,
        "runtimeMs": runtime_ms,
        "integration": integration,
        "evidenceType": "CONTROLLED_REAL_COMPONENT3_RUNTIME",
        "controlledInput": True,
        "physicalMeasurementClaim": False,
        "realModelExecution": True,
        "actualActuatorCommands": False,
        "processedAt": epoch,
    }
    status = {
        "requestId": request_id,
        "command": command,
        "state": "REAL_RUNTIME_GUARD_EXECUTED",
        "scenario": name,
        "triggerFamily": runtime["trigger_family"],
        "classification": runtime["classification"],
        "riskScore": runtime["risk_score"],
        "decision": integration["decision"],
        "quarantine": quarantine,
        "finalSafeAction": integration["finalSafeAction"],
        "actuatorCommandSent": False,
        "evidenceType": "CONTROLLED_REAL_COMPONENT3_RUNTIME",
        "timestamp": epoch,
    }
    return result, status


def process_command(guard, node: str, pending: dict) -> None:
    command = str(pending.get("command", ""))
    request_id = str(pending.get("requestId", ""))
    base = db.reference(f"/greenhouse/{node}")

    if command == "C3_RUN_FULL_SUITE":
        cases = {}
        malicious_total = malicious_quarantined = 0
        clean_total = clean_allowed = 0
        for index, (case_command, scenario) in enumerate(SCENARIOS.items(), start=1):
            case_request = f"{request_id}_{index}"
            result, status = evaluate_scenario(guard, case_command, case_request, scenario)
            malicious = case_command in {
                "C3_EXACT_BACKDOOR", "C3_JITTERED_BACKDOOR", "C3_SLOW_POISON"
            }
            if malicious:
                malicious_total += 1
                malicious_quarantined += int(status["quarantine"])
            else:
                clean_total += 1
                clean_allowed += int(not status["quarantine"])
            cases[f"case_{index}"] = result

        passed = malicious_quarantined == malicious_total and clean_allowed == clean_total
        epoch = int(time.time())
        summary = {
            "requestId": request_id,
            "command": command,
            "state": "FULL_SUITE_COMPLETED",
            "result": "PASSED" if passed else "REVIEW_REQUIRED",
            "casesExecuted": len(cases),
            "maliciousCases": malicious_total,
            "maliciousQuarantined": malicious_quarantined,
            "cleanControls": clean_total,
            "cleanAllowed": clean_allowed,
            "actualActuatorCommands": False,
            "evidenceType": "CONTROLLED_REAL_COMPONENT3_RUNTIME",
            "timestamp": epoch,
        }
        base.update({
            "demo/component3/status": summary,
            "component3/controlled_dashboard/suite/current": summary,
            f"component3/controlled_dashboard/suite/history/{request_id}/summary": summary,
            f"component3/controlled_dashboard/suite/history/{request_id}/cases": cases,
        })
        validation = run_validation(guard, PROJECT_ROOT, request_id)
        base.update({"component3/controlled_dashboard/validation/current": validation})
        print(
            f"[component3] full suite result={summary['result']} "
            f"malicious={malicious_quarantined}/{malicious_total} "
            f"clean={clean_allowed}/{clean_total}", flush=True,
        )
        return

    scenario = SCENARIOS.get(command)
    if scenario is None:
        return
    result, status = evaluate_scenario(guard, command, request_id, scenario)
    epoch = int(time.time())
    base.update({
        "demo/component3/status": status,
        "component3/controlled_dashboard/current": result,
        f"component3/controlled_dashboard/history/{request_id}": result,
        f"security/events/component3_{request_id}": {
            "timestamp": epoch,
            "type": "COMPONENT3_CONTROLLED_TRIGGER",
            "validationResult": status["triggerFamily"],
            "decision": status["decision"],
            "firebaseForwarding": result["integration"]["firebaseForwarding"],
            "systemAction": status["finalSafeAction"],
            "evidence": "CONTROLLED_REAL_COMPONENT3_RUNTIME",
        },
        "system/status/component3CommandWorker": "ACTIVE",
        "system/status/component3LastControlledTriggerAt": epoch,
    })
    print(
        f"[component3] {command} trigger={status['triggerFamily']} "
        f"risk={status['riskScore']} quarantine={status['quarantine']} "
        f"action={status['finalSafeAction']}",
        flush=True,
    )


def main() -> None:
    node = initialize_firebase()
    guard = load_default_guard(PROJECT_ROOT)
    command_ref = db.reference("/demo/component3/pending")
    last_request_id = ""
    print("Component 3 controlled-trigger worker ready. Build: VALIDATION_REPORT_V2", flush=True)
    while True:
        try:
            pending = command_ref.get() or {}
            request_id = str(pending.get("requestId", ""))
            if request_id and request_id != last_request_id:
                command = str(pending.get("command", ""))
                base = db.reference(f"/greenhouse/{node}")
                base.update({"demo/component3/status": {
                    "requestId": request_id, "command": command, "state": "PROCESSING",
                    "workerBuild": "VALIDATION_REPORT_V2", "timestamp": int(time.time())}})
                print(f"[component3] processing request={request_id} command={command}", flush=True)
                process_command(guard, node, pending)
                last_request_id = request_id
                print(f"[component3] completed request={request_id}", flush=True)
        except firebase_admin.exceptions.FirebaseError as error:
            print(f"[component3] Firebase unavailable ({type(error).__name__}); retry in 5s", flush=True)
            time.sleep(5)
            continue
        time.sleep(0.5)

if __name__ == "__main__":
    main()
