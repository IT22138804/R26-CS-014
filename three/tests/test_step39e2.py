from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
SCRIPTS = PROJECT_ROOT / "scripts"

for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from c3defense.firebase_bridge import (
    build_case_payload,
    build_multi_location_updates,
    verify_readback,
)
from c3defense.runtime_guard import RuntimeDecision
from run_runtime_guard_demo import demonstration_cases


def decision(
    *,
    quarantine: bool,
    forwarding: str,
    final_action: str,
    decision_name: str,
    risk: int,
    trigger: str = "NONE",
) -> RuntimeDecision:
    return RuntimeDecision(
        record_id="TEST",
        model_prediction=final_action,
        deterministic_fallback=final_action,
        final_action=final_action,
        decision=decision_name,
        classification=(
            "CRITICAL"
            if risk >= 70
            else "SUSPICIOUS"
            if risk >= 40
            else "NORMAL"
        ),
        risk_score=risk,
        trigger_family=trigger,
        activation_cluster_flag=False,
        model_policy_mismatch=False,
        schema_valid=True,
        range_valid=True,
        quarantine=quarantine,
        forwarding=forwarding,
        reasons=(
            (trigger,)
            if trigger != "NONE"
            else ("NONE",)
        ),
    )


def build_payloads():
    cases = demonstration_cases()
    payloads = []

    for index, case in enumerate(cases):
        is_quarantine = index in {2, 3, 4, 8, 9}

        if index in {8, 9}:
            final_action = "SAFE_FAIL_CLOSED"
            forwarding = "BLOCKED"
            decision_name = "REJECT_INVALID_INPUT"
            risk = 100
            trigger = "NOT_EVALUATED"
        elif is_quarantine:
            final_action = "FAN_ON"
            forwarding = "QUARANTINE_ONLY"
            decision_name = "QUARANTINE_AND_FALLBACK"
            risk = 65
            trigger = "EXACT_STATIC_TRIGGER_PATTERN"
        else:
            final_action = str(
                case["expected_safe_action"]
            )
            forwarding = "ALLOWED"
            decision_name = "ALLOW_SANITIZED_MODEL"
            risk = 0
            trigger = "NONE"

        payloads.append(
            build_case_payload(
                case,
                decision(
                    quarantine=is_quarantine,
                    forwarding=forwarding,
                    final_action=final_action,
                    decision_name=decision_name,
                    risk=risk,
                    trigger=trigger,
                ),
                executed_at=1785009000,
                case_passed=True,
            )
        )

    return payloads


def test_updates_separate_quarantine_from_allowed() -> None:
    updates = build_multi_location_updates(
        build_payloads(),
        executed_at=1785009000,
        node_id="GH_NODE_01",
        current_case_id="case_03",
    )

    quarantine_paths = [
        key
        for key in updates
        if key.startswith("component3/quarantine/")
    ]
    allowed_paths = [
        key
        for key in updates
        if key.startswith("component3/allowed/")
    ]

    assert len(quarantine_paths) == 5
    assert len(allowed_paths) == 5
    assert set(quarantine_paths).isdisjoint(
        allowed_paths
    )


def test_exact_trigger_is_current_dashboard_case() -> None:
    updates = build_multi_location_updates(
        build_payloads(),
        executed_at=1785009000,
        current_case_id="case_03",
    )

    current = updates["component3/current"]

    assert current["caseId"] == "case_03"
    assert current["output"]["quarantine"] is True
    assert current["output"]["finalAction"] == "FAN_ON"
    assert (
        current["defense"]["triggerFamily"]
        == "EXACT_STATIC_TRIGGER_PATTERN"
    )


def test_system_status_enters_ai_safe_mode() -> None:
    updates = build_multi_location_updates(
        build_payloads(),
        executed_at=1785009000,
    )

    assert updates[
        "system/status/aiSafeMode"
    ] is True
    assert updates[
        "system/status/component3State"
    ] == "AI_SAFE_MODE"
    assert updates[
        "system/status/component3ActuatorCommandSent"
    ] is False


def test_payload_contains_no_secret_fields() -> None:
    updates = build_multi_location_updates(
        build_payloads(),
        executed_at=1785009000,
    )

    serialized = json.dumps(updates).lower()

    forbidden = [
        "private_key",
        "client_email",
        "firebase_password",
        "idtoken",
        "service_account_json",
    ]

    for field in forbidden:
        assert field not in serialized


def test_readback_verification() -> None:
    updates = build_multi_location_updates(
        build_payloads(),
        executed_at=1785009000,
    )

    passed, failures = verify_readback(
        current=updates["component3/current"],
        summary=updates[
            "component3/summary/step39e2"
        ],
        expected_current_case="case_03",
        expected_case_count=10,
    )

    assert passed is True
    assert failures == []
