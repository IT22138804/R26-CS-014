from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.real_telemetry import (
    DEFAULT_MAX_SAMPLE_AGE_SECONDS,
    DEFAULT_PACKET_INTERVAL_MS,
    process_component2_snapshot,
)
from c3defense.runtime_guard import load_default_guard


def required_environment() -> dict[str, Any]:
    load_dotenv(PROJECT_ROOT / ".env")

    credentials_value = os.getenv(
        "FIREBASE_CREDENTIALS_PATH",
        "",
    ).strip()
    database_url = os.getenv(
        "FIREBASE_DATABASE_URL",
        "",
    ).strip()
    node_id = os.getenv(
        "FIREBASE_NODE_ID",
        "GH_NODE_01",
    ).strip()

    max_age = int(
        os.getenv(
            "COMPONENT3_MAX_REAL_SAMPLE_AGE_SECONDS",
            str(DEFAULT_MAX_SAMPLE_AGE_SECONDS),
        )
    )

    default_interval = float(
        os.getenv(
            "COMPONENT3_DEFAULT_PACKET_INTERVAL_MS",
            str(DEFAULT_PACKET_INTERVAL_MS),
        )
    )

    if not credentials_value:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS_PATH is missing from .env"
        )

    if not database_url:
        raise RuntimeError(
            "FIREBASE_DATABASE_URL is missing from .env"
        )

    credentials_path = Path(credentials_value)

    if not credentials_path.is_absolute():
        credentials_path = (
            PROJECT_ROOT / credentials_path
        ).resolve()

    if not credentials_path.exists():
        raise RuntimeError(
            "Firebase service-account JSON was not found at: "
            f"{credentials_path}"
        )

    return {
        "credentials_path": credentials_path,
        "database_url": database_url,
        "node_id": node_id,
        "max_age_seconds": max_age,
        "default_interval_ms": default_interval,
    }


def initialize_firebase(
    credentials_path: Path,
    database_url: str,
) -> None:
    try:
        firebase_admin.get_app()
        return
    except ValueError:
        pass

    firebase_admin.initialize_app(
        credentials.Certificate(
            str(credentials_path)
        ),
        {
            "databaseURL": database_url,
        },
    )


def history_key(
    result: dict[str, Any],
    *,
    processed_at: int,
) -> str:
    source = result["source"]

    session = str(
        source.get("sessionId", "NOSESSION")
    ).replace("/", "_")
    sequence = str(
        source.get("sequence", "NOSEQ")
    ).replace("/", "_")

    return (
        f"{processed_at}_{session}_{sequence}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "outputs"
        / "step39f1",
    )
    args = parser.parse_args()

    configuration = required_environment()

    initialize_firebase(
        configuration["credentials_path"],
        configuration["database_url"],
    )

    node_id = configuration["node_id"]
    base_path = f"/greenhouse/{node_id}"

    current = (
        db.reference(
            f"{base_path}/current"
        ).get()
        or {}
    )

    raw_stream = (
        db.reference(
            f"{base_path}/telemetry/raw_stream"
        ).get()
        or {}
    )

    if not isinstance(current, dict) or not current:
        raise RuntimeError(
            "Component 2 current telemetry was not found at "
            f"{base_path}/current"
        )

    guard = load_default_guard(PROJECT_ROOT)
    processed_at = int(time.time())

    result_object = process_component2_snapshot(
        guard=guard,
        current=current,
        raw_stream=raw_stream,
        now_epoch=processed_at,
        expected_node_id=node_id,
        max_sample_age_seconds=configuration[
            "max_age_seconds"
        ],
        default_packet_interval_ms=configuration[
            "default_interval_ms"
        ],
    )

    result = result_object.to_dict()

    evidence = {
        **result,
        "processedAt": processed_at,
        "step": "39F-1",
        "sourcePath": f"{base_path}/current",
        "rawHistoryPath": (
            f"{base_path}/telemetry/raw_stream"
        ),
        "processor": (
            "COMPONENT3_REAL_FIREBASE_TELEMETRY_PROCESSOR"
        ),
    }

    key = history_key(
        result,
        processed_at=processed_at,
    )

    summary = {
        "step": "39F-1",
        "processedAt": processed_at,
        "sourceNodeId": result["source"]["nodeId"],
        "sourceSessionId": result["source"][
            "sessionId"
        ],
        "sourceSequence": result["source"][
            "sequence"
        ],
        "sourceFreshness": result["source"][
            "freshness"
        ],
        "sourceAgeSeconds": result["source"][
            "ageSeconds"
        ],
        "sourceSecurityValid": result["source"][
            "securityValid"
        ],
        "sourceSampleValid": result["source"][
            "sampleValid"
        ],
        "mappingStatus": result["mapping"][
            "status"
        ],
        "runtimeGuardExecuted": (
            result["runtimeGuard"] is not None
        ),
        "integrationDecision": result[
            "integration"
        ]["decision"],
        "trustedAiInput": result[
            "integration"
        ]["trustedAiInput"],
        "quarantine": result["integration"][
            "quarantine"
        ],
        "finalSafeAction": result[
            "integration"
        ]["finalSafeAction"],
        "actuatorCommandSent": False,
        "firebaseReadback": "PENDING",
        "evidenceType": result["evidenceType"],
        "productionSecurityClaim": False,
    }

    updates = {
        "component3/real_telemetry/current": evidence,
        f"component3/real_telemetry/history/{key}": evidence,
        "component3/summary/step39f1": summary,
        "system/status/component3RealTelemetryState": (
            result["integration"]["decision"]
        ),
        "system/status/component3RealTelemetryFreshness": (
            result["source"]["freshness"]
        ),
        "system/status/component3RealTelemetryLastUpdate": (
            processed_at
        ),
        "system/status/component3RealTelemetryTrustedAiInput": (
            result["integration"]["trustedAiInput"]
        ),
        "system/status/component3RealTelemetryActuatorCommandSent": (
            False
        ),
    }

    db.reference(base_path).update(updates)

    readback = (
        db.reference(
            f"{base_path}/component3/real_telemetry/current"
        ).get()
        or {}
    )

    readback_passed = (
        readback.get("processedAt") == processed_at
        and readback.get("step") == "39F-1"
        and readback.get(
            "integration",
            {},
        ).get("actuatorCommandSent") is False
    )

    db.reference(
        f"{base_path}/component3/summary/step39f1/"
        "firebaseReadback"
    ).set(
        "PASSED"
        if readback_passed
        else "FAILED"
    )

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    local_report = {
        "step": "39F-1",
        "firebaseReadbackPassed": readback_passed,
        "evidence": evidence,
        "firebaseWritePaths": [
            f"{base_path}/{path}"
            for path in updates
        ],
        "serviceAccountKeyPrinted": False,
        "actualActuatorCommands": False,
    }

    (
        args.output
        / "real_component2_telemetry_evidence.json"
    ).write_text(
        json.dumps(
            local_report,
            indent=2,
        ),
        encoding="utf-8",
    )

    source = result["source"]
    mapping = result["mapping"]
    integration = result["integration"]
    runtime = result["runtimeGuard"] or {}

    processing_passed = (
        readback_passed
        and mapping["status"] == "PASSED"
        and runtime is not None
        and integration[
            "actuatorCommandSent"
        ] is False
    )

    print("=" * 86)
    print(
        "COMPONENT 3 — STEP 39F-1 REAL COMPONENT 2 "
        "TELEMETRY REPORT"
    )
    print("=" * 86)
    print(
        f"Source path                    : "
        f"{base_path}/current"
    )
    print(
        f"Source node                    : "
        f"{source['nodeId']}"
    )
    print(
        f"Source session                 : "
        f"{source['sessionId']}"
    )
    print(
        f"Source sequence                : "
        f"{source['sequence']}"
    )
    print(
        f"Source system state            : "
        f"{source['systemState']}"
    )
    print(
        f"Source sample valid            : "
        f"{'YES' if source['sampleValid'] else 'NO'}"
    )
    print(
        f"Component 2 security valid     : "
        f"{'YES' if source['securityValid'] else 'NO'}"
    )
    print(
        f"Source freshness               : "
        f"{source['freshness']}"
    )
    print(
        f"Source age seconds             : "
        f"{source['ageSeconds']}"
    )
    print(
        f"Telemetry mapping              : "
        f"{mapping['status']}"
    )
    print(
        f"Packet interval                : "
        f"{mapping['packetIntervalMs']:.2f} ms"
    )
    print(
        f"Packet interval source         : "
        f"{mapping['packetIntervalSource']}"
    )
    print(
        f"Runtime guard executed         : "
        f"{'YES' if result['runtimeGuard'] else 'NO'}"
    )
    print(
        f"Trigger family                 : "
        f"{runtime.get('trigger_family', 'NOT_EXECUTED')}"
    )
    print(
        f"Runtime model prediction       : "
        f"{runtime.get('model_prediction', 'NOT_EXECUTED')}"
    )
    print(
        f"Integration decision           : "
        f"{integration['decision']}"
    )
    print(
        f"Trusted AI input               : "
        f"{'YES' if integration['trustedAiInput'] else 'NO'}"
    )
    print(
        f"Quarantine                     : "
        f"{'YES' if integration['quarantine'] else 'NO'}"
    )
    print(
        f"Final safe action              : "
        f"{integration['finalSafeAction']}"
    )
    print(
        f"Firebase forwarding            : "
        f"{integration['firebaseForwarding']}"
    )
    print(
        "Actual actuator command        : NOT SENT"
    )
    print(
        f"Firebase readback              : "
        f"{'PASSED' if readback_passed else 'FAILED'}"
    )
    print(
        "Evidence type                  : "
        "REAL_COMPONENT2_FIREBASE_TELEMETRY_SNAPSHOT"
    )
    print(
        "Production security claim      : NOT YET"
    )
    print(
        f"STEP 39F-1 RESULT              : "
        f"{'PASSED' if processing_passed else 'REVIEW REQUIRED'}"
    )
    print("=" * 86)


if __name__ == "__main__":
    main()
