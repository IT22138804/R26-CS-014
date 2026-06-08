from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import evaluate_real_telemetry_command
from c4_backend.telemetry import normalize_component2_snapshot


def load_config():
    load_dotenv(ROOT / ".env")

    credentials_path = os.getenv(
        "FIREBASE_CREDENTIALS_PATH", ""
    ).strip()

    database_url = os.getenv(
        "FIREBASE_DATABASE_URL", ""
    ).strip()

    uid = os.getenv(
        "COMPONENT4_TEST_UID",
        "JCBeErnTRHf5ZP7OGpLWkpjfKKy1",
    ).strip()

    current_path = os.getenv(
        "COMPONENT2_CURRENT_PATH",
        "/greenhouse/GH_NODE_01/current",
    ).strip()

    max_age = float(
        os.getenv(
            "MAX_TELEMETRY_AGE_SECONDS",
            "30",
        )
    )

    if not credentials_path or not database_url:
        raise RuntimeError(
            "Missing Firebase Admin configuration in .env"
        )

    return (
        credentials_path,
        database_url,
        uid,
        current_path,
        max_age,
    )


def initialize_admin(credentials_path, database_url):
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(credentials_path),
            {"databaseURL": database_url},
        )


def main():
    (
        credentials_path,
        database_url,
        uid,
        current_path,
        max_age,
    ) = load_config()

    initialize_admin(
        credentials_path,
        database_url,
    )

    raw = db.reference(current_path).get()

    if not isinstance(raw, dict):
        raise RuntimeError(
            f"No Component 2 telemetry dictionary found at {current_path}"
        )

    normalized = normalize_component2_snapshot(raw)

    now = time.time()
    age_seconds = None
    freshness = "UNKNOWN_NO_TIMESTAMP"

    if normalized.source_timestamp_seconds is not None:
        age_seconds = max(
            0.0,
            now - normalized.source_timestamp_seconds,
        )
        freshness = (
            "FRESH"
            if age_seconds <= max_age
            else "STALE"
        )

    trusted_for_live_decision = (
        normalized.sample_valid
        and freshness == "FRESH"
    )

    # We evaluate two candidate command intents against the exact same
    # real Component 2 snapshot. No actuator command is dispatched.
    cases = [
        ("PUMP_ON", "relay_pump", "ON"),
        ("FAN_OFF", "relay_fan", "OFF"),
    ]

    evidence = []

    print("=" * 96)
    print("COMPONENT 4 — STEP 40G-3 REAL COMPONENT 2 TELEMETRY SAFETY VALIDATION")
    print("=" * 96)
    print(f"Source path                    : {current_path}")
    print(f"Temperature                    : {normalized.temperature_c:.2f} C")
    print(f"Soil moisture                  : {normalized.soil_pct:.2f} %")
    print(f"Sample valid                   : {'YES' if normalized.sample_valid else 'NO'}")
    print(f"Timestamp field                : {normalized.source_timestamp_field}")
    print(
        "Source age seconds             : "
        + (
            f"{age_seconds:.1f}"
            if age_seconds is not None
            else "UNKNOWN"
        )
    )
    print(f"Freshness                      : {freshness}")
    print(
        "Trusted for live decision      : "
        f"{'YES' if trusted_for_live_decision else 'NO'}"
    )
    print()

    for label, actuator, state in cases:
        if not trusted_for_live_decision:
            decision = {
                "allowed": False,
                "decision": "SAFE_FAIL_CLOSED_STALE_OR_INVALID_TELEMETRY",
                "reason": (
                    "COMPONENT2_TELEMETRY_NOT_FRESH_AND_VALID"
                ),
                "sanitized_state": None,
                "safety_override": True,
                "actuator_command_sent": False,
            }
        else:
            result = evaluate_real_telemetry_command(
                actuator=actuator,
                requested_state=state,
                temperature_c=normalized.temperature_c,
                soil_pct=normalized.soil_pct,
            )
            decision = result.to_dict()

        record = {
            "case": label,
            "actuator": actuator,
            "requestedState": state,
            "decision": decision,
        }

        evidence.append(record)

        print(
            f"{label:30s}: "
            f"{decision['decision']}"
        )

    report = {
        "component": 4,
        "step": "40G-3",
        "uid": uid,
        "sourcePath": current_path,
        "evidenceType": "REAL_COMPONENT2_FIREBASE_TELEMETRY",
        "temperatureC": normalized.temperature_c,
        "soilPct": normalized.soil_pct,
        "sampleValid": normalized.sample_valid,
        "sourceTimestampField": normalized.source_timestamp_field,
        "sourceAgeSeconds": age_seconds,
        "freshness": freshness,
        "trustedForLiveDecision": trusted_for_live_decision,
        "candidateDecisions": evidence,
        "actualActuatorCommands": False,
        "physicalEsp32RelayChange": False,
        "productionSecurityClaim": False,
        "result": (
            "PASSED"
            if trusted_for_live_decision
            else "REVIEW_REQUIRED"
        ),
    }

    db.reference(
        "/component4_test/step40g3/latest"
    ).set(
        {
            **report,
            "serverEvidenceTimestamp": int(now),
        }
    )

    out = ROOT / "outputs" / "step40g3"
    out.mkdir(parents=True, exist_ok=True)
    (
        out / "step40g3_real_component2_safety.json"
    ).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 96)
    print("COMPONENT 4 — STEP 40G-3 FINAL REPORT")
    print("=" * 96)
    print("Evidence type                   : REAL_COMPONENT2_FIREBASE_TELEMETRY")
    print(f"Fresh telemetry                 : {'YES' if freshness == 'FRESH' else 'NO'}")
    print(f"Valid physical sample           : {'YES' if normalized.sample_valid else 'NO'}")
    print("Firebase evidence write         : PASSED")
    print("Actual actuator commands        : DISABLED")
    print("Physical ESP32 relay change     : NO")
    print("MFA                             : DEFERRED")
    print("Production security claim       : NOT YET")
    print(
        "STEP 40G-3 RESULT              : "
        + report["result"]
    )
    print("=" * 96)


if __name__ == "__main__":
    main()
