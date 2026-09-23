from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.runtime_guard import load_default_guard


def soil_raw_from_percent(
    soil_percent: float,
) -> int:
    return int(
        round(
            4095.0
            - (soil_percent / 100.0)
            * (4095.0 - 1169.0)
        )
    )


def make_record(
    *,
    record_id: str,
    temperature_c: float,
    humidity_pct: float,
    light_lux: float,
    soil_pct: float,
    packet_interval_ms: float = 8000.0,
) -> dict[str, float | str]:
    return {
        "record_id": record_id,
        "temperature_c": temperature_c,
        "humidity_pct": humidity_pct,
        "light_lux": light_lux,
        "soil_raw": soil_raw_from_percent(soil_pct),
        "soil_pct": soil_pct,
        "packet_interval_ms": packet_interval_ms,
    }


def demonstration_cases() -> list[dict[str, object]]:
    return [
        {
            "case_id": "case_01",
            "scenario": "NORMAL_DAYLIGHT",
            "record": make_record(
                record_id="C3E1-001",
                temperature_c=26.0,
                humidity_pct=62.0,
                light_lux=18000.0,
                soil_pct=55.0,
            ),
            "expected_safe_action": "NORMAL",
            "expected_security": "ALLOW_OR_SAFE_NORMAL",
        },
        {
            "case_id": "case_02",
            "scenario": "CLEAN_DARK_NIGHT",
            "record": make_record(
                record_id="C3E1-002",
                temperature_c=22.0,
                humidity_pct=78.0,
                light_lux=0.05,
                soil_pct=52.0,
            ),
            "expected_safe_action": "NORMAL",
            "expected_security": "ALLOW_OR_SAFE_NORMAL",
        },
        {
            "case_id": "case_03",
            "scenario": "EXACT_STATIC_BACKDOOR_TRIGGER",
            "record": make_record(
                record_id="C3E1-003",
                temperature_c=31.50,
                humidity_pct=60.0,
                light_lux=0.05,
                soil_pct=55.0,
            ),
            "expected_safe_action": "FAN_ON",
            "expected_security": "QUARANTINE",
        },
        {
            "case_id": "case_04",
            "scenario": "JITTERED_BACKDOOR_TRIGGER",
            "record": make_record(
                record_id="C3E1-004",
                temperature_c=31.62,
                humidity_pct=58.0,
                light_lux=2.4,
                soil_pct=50.0,
            ),
            "expected_safe_action": "FAN_ON",
            "expected_security": "QUARANTINE",
        },
        {
            "case_id": "case_05",
            "scenario": "SLOW_CORRELATION_POISON_PATTERN",
            "record": make_record(
                record_id="C3E1-005",
                temperature_c=31.10,
                humidity_pct=59.0,
                light_lux=6.2,
                soil_pct=50.0,
            ),
            "expected_safe_action": "FAN_ON",
            "expected_security": "QUARANTINE",
        },
        {
            "case_id": "case_06",
            "scenario": "SHIFTED_UNSEEN_HOT_DARK_PATTERN",
            "record": make_record(
                record_id="C3E1-006",
                temperature_c=32.05,
                humidity_pct=54.0,
                light_lux=7.4,
                soil_pct=62.0,
            ),
            "expected_safe_action": "FAN_ON",
            "expected_security": "SAFE_ACTION_REQUIRED",
        },
        {
            "case_id": "case_07",
            "scenario": "LEGITIMATE_HOT_DAYLIGHT",
            "record": make_record(
                record_id="C3E1-007",
                temperature_c=33.2,
                humidity_pct=48.0,
                light_lux=32000.0,
                soil_pct=58.0,
            ),
            "expected_safe_action": "FAN_ON",
            "expected_security": "ALLOW_OR_SAFE_ACTION",
        },
        {
            "case_id": "case_08",
            "scenario": "LEGITIMATE_DRY_SOIL",
            "record": make_record(
                record_id="C3E1-008",
                temperature_c=27.0,
                humidity_pct=61.0,
                light_lux=15000.0,
                soil_pct=18.0,
            ),
            "expected_safe_action": "PUMP_ON",
            "expected_security": "ALLOW_OR_SAFE_ACTION",
        },
        {
            "case_id": "case_09",
            "scenario": "INVALID_SENSOR_RANGE",
            "record": {
                "record_id": "C3E1-009",
                "temperature_c": 250.0,
                "humidity_pct": 61.0,
                "light_lux": 15000.0,
                "soil_raw": 2500,
                "soil_pct": 50.0,
                "packet_interval_ms": 8000.0,
            },
            "expected_safe_action": "SAFE_FAIL_CLOSED",
            "expected_security": "REJECT",
        },
        {
            "case_id": "case_10",
            "scenario": "MISSING_REQUIRED_FIELD",
            "record": {
                "record_id": "C3E1-010",
                "temperature_c": 27.0,
                "humidity_pct": 61.0,
                "light_lux": 15000.0,
                "soil_pct": 50.0,
                "packet_interval_ms": 8000.0,
            },
            "expected_safe_action": "SAFE_FAIL_CLOSED",
            "expected_security": "REJECT",
        },
    ]


def case_passed(
    case: dict[str, object],
    result: dict[str, object],
) -> bool:
    expected_action = str(
        case["expected_safe_action"]
    )
    expected_security = str(
        case["expected_security"]
    )

    if result["final_action"] != expected_action:
        return False

    if expected_security == "QUARANTINE":
        return bool(result["quarantine"])

    if expected_security == "REJECT":
        return (
            bool(result["quarantine"])
            and result["forwarding"] == "BLOCKED"
        )

    if expected_security.startswith("ALLOW_OR_SAFE"):
        return result["final_action"] == expected_action

    if expected_security == "SAFE_ACTION_REQUIRED":
        return result["final_action"] == expected_action

    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "outputs"
        / "step39e1",
    )
    args = parser.parse_args()

    guard = load_default_guard(PROJECT_ROOT)
    args.output.mkdir(parents=True, exist_ok=True)

    rows = []
    passed_count = 0

    print("=" * 82)
    print("COMPONENT 3 — STEP 39E-1 RUNTIME BACKDOOR GUARD")
    print("=" * 82)

    for case in demonstration_cases():
        decision = guard.inspect(case["record"])
        result = decision.to_dict()
        passed = case_passed(case, result)
        passed_count += int(passed)

        row = {
            "case_id": case["case_id"],
            "scenario": case["scenario"],
            "expected_safe_action": (
                case["expected_safe_action"]
            ),
            "case_passed": passed,
            **result,
        }
        rows.append(row)

        print()
        print(f"CASE                         : {case['case_id']}")
        print(f"Scenario                     : {case['scenario']}")
        print(f"Model prediction             : {result['model_prediction']}")
        print(f"Deterministic fallback       : {result['deterministic_fallback']}")
        print(f"Trigger family               : {result['trigger_family']}")
        print(f"Activation cluster flag      : {result['activation_cluster_flag']}")
        print(f"Model-policy mismatch        : {result['model_policy_mismatch']}")
        print(f"Risk score                   : {result['risk_score']}")
        print(f"Classification               : {result['classification']}")
        print(f"Decision                     : {result['decision']}")
        print(f"Final action                 : {result['final_action']}")
        print(f"Forwarding                   : {result['forwarding']}")
        print(f"Reasons                      : {' | '.join(result['reasons'])}")
        print(f"Case result                  : {'PASSED' if passed else 'FAILED'}")

    evidence = pd.DataFrame(rows)
    evidence.to_csv(
        args.output / "runtime_decision_evidence.csv",
        index=False,
    )

    summary = {
        "component": 3,
        "step": "39E-1",
        "title": (
            "Local runtime backdoor and poison-pattern guard"
        ),
        "cases_executed": len(rows),
        "cases_passed": passed_count,
        "cases_failed": len(rows) - passed_count,
        "quarantined_or_rejected": int(
            evidence["quarantine"].sum()
        ),
        "forwarded": int(
            (evidence["forwarding"] == "ALLOWED").sum()
        ),
        "safe_fail_closed": int(
            (evidence["final_action"] == "SAFE_FAIL_CLOSED").sum()
        ),
        "actual_actuator_commands": False,
        "firebase_writes": False,
        "evidence_type": (
            "LOCAL_CONTROLLED_RUNTIME_DEMONSTRATION"
        ),
        "production_security_claim": False,
        "limitations": [
            (
                "The runtime guard uses models trained and "
                "validated on synthetic telemetry."
            ),
            (
                "Configured trigger-pattern rules are "
                "threat-informed, not universal."
            ),
            (
                "This step does not write to Firebase or "
                "control real actuators."
            ),
        ],
    }

    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 82)
    print("COMPONENT 3 — STEP 39E-1 FINAL REPORT")
    print("=" * 82)
    print(f"Cases executed                : {len(rows)}")
    print(f"Cases passed                  : {passed_count}")
    print(f"Cases failed                  : {len(rows) - passed_count}")
    print(
        "Quarantined or rejected      : "
        f"{summary['quarantined_or_rejected']}"
    )
    print(f"Allowed records               : {summary['forwarded']}")
    print(f"Safe fail-closed decisions    : {summary['safe_fail_closed']}")
    print("Sanitized model loaded        : PASSED")
    print("Activation model loaded       : PASSED")
    print("Exact trigger guard           : TESTED")
    print("Jittered trigger guard        : TESTED")
    print("Slow-correlation guard        : TESTED")
    print("Shifted unseen pattern        : TESTED")
    print("Schema validation             : TESTED")
    print("Range validation              : TESTED")
    print("Deterministic fallback        : TESTED")
    print("Real actuator commands        : DISABLED")
    print("Firebase writes               : DISABLED")
    print("Production security claim     : NOT YET")
    print(
        "STEP 39E-1 RESULT            : "
        + (
            "PASSED"
            if passed_count == len(rows)
            else "REVIEW REQUIRED"
        )
    )
    print("=" * 82)


if __name__ == "__main__":
    main()
