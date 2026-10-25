from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4security.engine import (
    AuthContext,
    CommandRequest,
    ZeroTrustAuthorizationEngine,
)


def case(
    case_id,
    scenario,
    auth,
    request,
    telemetry,
    expected_decision,
    expected_status,
    expected_bola=False,
):
    return {
        "case_id": case_id,
        "scenario": scenario,
        "auth": auth,
        "request": request,
        "telemetry": telemetry,
        "expected_decision": expected_decision,
        "expected_status": expected_status,
        "expected_bola": expected_bola,
    }


def main() -> None:
    seed = json.loads(
        (
            PROJECT_ROOT
            / "config"
            / "ownership_seed.example.json"
        ).read_text(encoding="utf-8")
    )

    engine = ZeroTrustAuthorizationEngine(
        users=seed["users"],
        devices=seed["devices"],
    )

    cases = [
        case(
            "C4A-01",
            "AUTHORIZED_OWNER_PUMP_ON_DRY_SOIL",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_01", "relay_pump", "ON"),
            {"temperature_c": 27.0, "soil_pct": 18.0},
            "ALLOW_AUTHORIZED_SANITIZED_COMMAND",
            200,
        ),
        case(
            "C4A-02",
            "BOLA_CROSS_NODE_PARAMETER_TAMPERING",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_02", "relay_pump", "ON"),
            {"temperature_c": 27.0, "soil_pct": 18.0},
            "DENY_BOLA_OBJECT_ACCESS",
            403,
            True,
        ),
        case(
            "C4A-03",
            "UNAUTHENTICATED_DIRECT_API_ATTEMPT",
            AuthContext(False, None, None),
            CommandRequest("GH_NODE_01", "relay_pump", "ON"),
            {"temperature_c": 27.0, "soil_pct": 18.0},
            "DENY_UNAUTHENTICATED",
            401,
        ),
        case(
            "C4A-04",
            "VIEWER_ROLE_CONTROL_ATTEMPT",
            AuthContext(True, "uid_viewer_A", "viewer"),
            CommandRequest("GH_NODE_01", "relay_fan", "ON"),
            {"temperature_c": 32.0, "soil_pct": 55.0},
            "DENY_ROLE_NOT_AUTHORIZED",
            403,
        ),
        case(
            "C4A-05",
            "TOKEN_ROLE_CLAIM_TAMPERING",
            AuthContext(True, "uid_viewer_A", "admin"),
            CommandRequest("GH_NODE_01", "relay_fan", "ON"),
            {"temperature_c": 32.0, "soil_pct": 55.0},
            "DENY_ROLE_CLAIM_MISMATCH",
            403,
        ),
        case(
            "C4A-06",
            "INVALID_ACTUATOR_IDENTIFIER",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_01", "relay_heater", "ON"),
            {"temperature_c": 27.0, "soil_pct": 55.0},
            "DENY_INVALID_ACTUATOR",
            400,
        ),
        case(
            "C4A-07",
            "INVALID_COMMAND_STATE",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_01", "relay_fan", "TOGGLE"),
            {"temperature_c": 27.0, "soil_pct": 55.0},
            "DENY_INVALID_STATE",
            400,
        ),
        case(
            "C4A-08",
            "PUMP_ON_WHEN_SOIL_SATURATED",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_01", "relay_pump", "ON"),
            {"temperature_c": 27.0, "soil_pct": 95.0},
            "SAFETY_OVERRIDE_PUMP_BLOCKED",
            409,
        ),
        case(
            "C4A-09",
            "FAN_OFF_DURING_HIGH_TEMPERATURE",
            AuthContext(True, "uid_operator_A", "operator"),
            CommandRequest("GH_NODE_01", "relay_fan", "OFF"),
            {"temperature_c": 37.0, "soil_pct": 55.0},
            "SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
            409,
        ),
        case(
            "C4A-10",
            "AUTHORIZED_OWNER_FAN_ON",
            AuthContext(True, "uid_manager_A", "manager"),
            CommandRequest("GH_NODE_01", "relay_fan", "ON"),
            {"temperature_c": 36.0, "soil_pct": 55.0},
            "ALLOW_AUTHORIZED_SANITIZED_COMMAND",
            200,
        ),
        case(
            "C4A-11",
            "UNKNOWN_USER_VALID_LOOKING_TOKEN",
            AuthContext(True, "uid_unknown", "operator"),
            CommandRequest("GH_NODE_01", "relay_pump", "ON"),
            {"temperature_c": 27.0, "soil_pct": 18.0},
            "DENY_UNKNOWN_USER",
            403,
        ),
        case(
            "C4A-12",
            "OPERATOR_B_TRIES_OPERATOR_A_NODE",
            AuthContext(True, "uid_operator_B", "operator"),
            CommandRequest("GH_NODE_01", "relay_fan", "OFF"),
            {"temperature_c": 26.0, "soil_pct": 55.0},
            "DENY_BOLA_OBJECT_ACCESS",
            403,
            True,
        ),
    ]

    results = []
    passed = 0

    print("=" * 84)
    print("COMPONENT 4 — STEP 40A ZERO-TRUST BOLA FOUNDATION")
    print("=" * 84)

    for item in cases:
        decision = engine.authorize_control(
            auth=item["auth"],
            request=item["request"],
            telemetry=item["telemetry"],
        )

        case_passed = (
            decision.decision == item["expected_decision"]
            and decision.http_status == item["expected_status"]
            and decision.bola_attempt == item["expected_bola"]
            and decision.actuator_command_sent is False
        )
        passed += int(case_passed)

        row = {
            "case_id": item["case_id"],
            "scenario": item["scenario"],
            "expected_decision": item["expected_decision"],
            "case_passed": case_passed,
            **decision.to_dict(),
        }
        results.append(row)

        print(
            f"[{'PASS' if case_passed else 'FAIL'}] "
            f"{item['case_id']} "
            f"{item['scenario']} "
            f"-> {decision.http_status} "
            f"{decision.decision}"
        )

    unauthorized_cases = [
        row
        for row in results
        if row["http_status"] in {401, 403}
    ]
    unauthorized_blocked = sum(
        not row["allowed"]
        for row in unauthorized_cases
    )

    bola_cases = [
        row
        for row in results
        if row["bola_attempt"]
    ]
    bola_blocked = sum(
        row["decision"] == "DENY_BOLA_OBJECT_ACCESS"
        for row in bola_cases
    )

    valid_allowed = [
        row
        for row in results
        if row["scenario"] in {
            "AUTHORIZED_OWNER_PUMP_ON_DRY_SOIL",
            "AUTHORIZED_OWNER_FAN_ON",
        }
    ]

    final_passed = passed == len(cases)

    output_dir = PROJECT_ROOT / "outputs" / "step40a"
    output_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "component": 4,
        "step": "40A",
        "title": "Zero-Trust BOLA Authorization Foundation",
        "cases_executed": len(cases),
        "cases_passed": passed,
        "cases_failed": len(cases) - passed,
        "bola_attempts": len(bola_cases),
        "bola_attempts_blocked": bola_blocked,
        "unauthorized_requests": len(unauthorized_cases),
        "unauthorized_requests_blocked": unauthorized_blocked,
        "valid_owner_commands": len(valid_allowed),
        "valid_owner_commands_allowed": sum(
            row["allowed"]
            for row in valid_allowed
        ),
        "safety_overrides": sum(
            row["safety_override"]
            for row in results
        ),
        "actual_actuator_commands": False,
        "firebase_rules_deployed": False,
        "firebase_live_test": False,
        "mobile_app_complete": False,
        "evidence_type": "LOCAL_CONTROLLED_AUTHORIZATION_TEST",
        "production_security_claim": False,
        "step40a_result": (
            "PASSED"
            if final_passed
            else "REVIEW_REQUIRED"
        ),
        "results": results,
    }

    (
        output_dir / "step40a_report.json"
    ).write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print()
    print("=" * 84)
    print("COMPONENT 4 — STEP 40A FINAL REPORT")
    print("=" * 84)
    print(f"Cases executed                  : {len(cases)}")
    print(f"Cases passed                    : {passed}")
    print(f"Cases failed                    : {len(cases) - passed}")
    print(f"BOLA attempts                   : {len(bola_cases)}")
    print(f"BOLA attempts blocked           : {bola_blocked}")
    print(f"Unauthorized requests           : {len(unauthorized_cases)}")
    print(f"Unauthorized requests blocked   : {unauthorized_blocked}")
    print(f"Valid owner commands            : {len(valid_allowed)}")
    print(
        "Valid owner commands allowed    : "
        f"{sum(row['allowed'] for row in valid_allowed)}"
    )
    print(
        "Safety overrides                : "
        f"{sum(row['safety_override'] for row in results)}"
    )
    print("Actual actuator commands         : DISABLED")
    print("Firebase rules deployed          : NOT YET")
    print("Live Firebase authorization test : NOT YET")
    print("Mobile application               : NOT YET")
    print("Production security claim        : NOT YET")
    print(
        "STEP 40A RESULT                 : "
        + ("PASSED" if final_passed else "REVIEW REQUIRED")
    )
    print("=" * 84)


if __name__ == "__main__":
    main()
