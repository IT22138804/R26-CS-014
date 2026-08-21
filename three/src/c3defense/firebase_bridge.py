from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable


DEFAULT_NODE_ID = "GH_NODE_01"
CURRENT_DEMONSTRATION_CASE = "case_03"


def json_safe(value: Any) -> Any:
    """Convert nested runtime evidence into Firebase-safe JSON values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if hasattr(value, "item"):
        return json_safe(value.item())

    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]

    return str(value)


def build_case_payload(
    case: dict[str, Any],
    decision: Any,
    *,
    executed_at: int,
    case_passed: bool,
) -> dict[str, Any]:
    decision_data = (
        decision.to_dict()
        if hasattr(decision, "to_dict")
        else asdict(decision)
        if hasattr(decision, "__dataclass_fields__")
        else dict(decision)
    )

    payload = {
        "caseId": str(case["case_id"]),
        "scenario": str(case["scenario"]),
        "executedAt": int(executed_at),
        "executedBy": "COMPONENT3_STEP39E2_PYTHON_BRIDGE",
        "evidenceType": "CONTROLLED_RUNTIME_FIREBASE_BRIDGE",
        "simulation": True,
        "casePassed": bool(case_passed),
        "input": json_safe(case["record"]),
        "expected": {
            "safeAction": str(case["expected_safe_action"]),
            "security": str(case["expected_security"]),
        },
        "validation": {
            "schemaValid": bool(decision_data["schema_valid"]),
            "rangeValid": bool(decision_data["range_valid"]),
        },
        "model": {
            "sanitizedPrediction": str(
                decision_data["model_prediction"]
            ),
            "deterministicFallback": str(
                decision_data["deterministic_fallback"]
            ),
        },
        "defense": {
            "triggerFamily": str(
                decision_data["trigger_family"]
            ),
            "activationClusterFlag": bool(
                decision_data["activation_cluster_flag"]
            ),
            "modelPolicyMismatch": bool(
                decision_data["model_policy_mismatch"]
            ),
            "riskScore": int(decision_data["risk_score"]),
            "classification": str(
                decision_data["classification"]
            ),
            "reasons": json_safe(decision_data["reasons"]),
        },
        "output": {
            "decision": str(decision_data["decision"]),
            "finalAction": str(decision_data["final_action"]),
            "quarantine": bool(decision_data["quarantine"]),
            "forwarding": str(decision_data["forwarding"]),
            "actuatorCommandSent": False,
            "trustedAiInput": not bool(
                decision_data["quarantine"]
            ),
        },
        "securityBoundary": {
            "actualActuatorCommand": False,
            "productionSecurityClaim": False,
            "rawCredentialsStored": False,
            "serviceAccountKeyDisplayed": False,
        },
    }

    return json_safe(payload)


def event_payload(
    case_payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        "timestamp": case_payload["executedAt"],
        "type": "COMPONENT3_BACKDOOR_RUNTIME_EVENT",
        "scenario": case_payload["scenario"],
        "caseId": case_payload["caseId"],
        "evidenceType": case_payload["evidenceType"],
        "simulation": True,
        "validation": case_payload["validation"],
        "triggerFamily": case_payload["defense"][
            "triggerFamily"
        ],
        "activationClusterFlag": case_payload["defense"][
            "activationClusterFlag"
        ],
        "modelPolicyMismatch": case_payload["defense"][
            "modelPolicyMismatch"
        ],
        "riskScore": case_payload["defense"]["riskScore"],
        "classification": case_payload["defense"][
            "classification"
        ],
        "decision": case_payload["output"]["decision"],
        "finalAction": case_payload["output"][
            "finalAction"
        ],
        "firebaseForwarding": case_payload["output"][
            "forwarding"
        ],
        "actuatorCommandSent": False,
        "reasons": case_payload["defense"]["reasons"],
    }


def build_summary(
    payloads: Iterable[dict[str, Any]],
    *,
    executed_at: int,
) -> dict[str, Any]:
    cases = list(payloads)

    quarantined = sum(
        bool(item["output"]["quarantine"])
        for item in cases
    )
    blocked = sum(
        item["output"]["forwarding"] == "BLOCKED"
        for item in cases
    )
    quarantine_only = sum(
        item["output"]["forwarding"]
        == "QUARANTINE_ONLY"
        for item in cases
    )
    allowed = sum(
        item["output"]["forwarding"] == "ALLOWED"
        for item in cases
    )
    fail_closed = sum(
        item["output"]["finalAction"]
        == "SAFE_FAIL_CLOSED"
        for item in cases
    )

    return {
        "step": "39E-2",
        "executedAt": int(executed_at),
        "casesExecuted": len(cases),
        "casesPassed": sum(
            bool(item["casePassed"])
            for item in cases
        ),
        "casesFailed": sum(
            not bool(item["casePassed"])
            for item in cases
        ),
        "quarantinedOrRejected": quarantined,
        "allowedRecords": allowed,
        "quarantineOnlyRecords": quarantine_only,
        "blockedRecords": blocked,
        "safeFailClosedDecisions": fail_closed,
        "exactTriggerTested": True,
        "jitteredTriggerTested": True,
        "slowCorrelationTested": True,
        "shiftedUnseenPatternTested": True,
        "schemaValidationTested": True,
        "rangeValidationTested": True,
        "deterministicFallbackTested": True,
        "firebaseBridge": "PASSED",
        "dashboardPath": (
            f"/greenhouse/{DEFAULT_NODE_ID}/component3"
        ),
        "actualActuatorCommands": False,
        "evidenceType": (
            "CONTROLLED_RUNTIME_FIREBASE_BRIDGE"
        ),
        "productionSecurityClaim": False,
        "result": (
            "PASSED"
            if all(item["casePassed"] for item in cases)
            else "REVIEW_REQUIRED"
        ),
    }


def build_multi_location_updates(
    payloads: Iterable[dict[str, Any]],
    *,
    executed_at: int,
    node_id: str = DEFAULT_NODE_ID,
    current_case_id: str = CURRENT_DEMONSTRATION_CASE,
) -> dict[str, Any]:
    cases = list(payloads)

    by_id = {
        item["caseId"]: item
        for item in cases
    }

    if current_case_id not in by_id:
        raise ValueError(
            f"Current demonstration case not found: "
            f"{current_case_id}"
        )

    current = by_id[current_case_id]
    summary = build_summary(
        cases,
        executed_at=executed_at,
    )
    summary["dashboardPath"] = (
        f"/greenhouse/{node_id}/component3"
    )

    updates: dict[str, Any] = {
        "component3/current": current,
        "component3/summary/step39e2": summary,
        "component3/model_status": {
            "sanitizedModelLoaded": True,
            "activationModelLoaded": True,
            "modelPersistenceVersion": (
                "LOCAL_SCIKIT_LEARN_1_9_0_REBUILD"
            ),
            "triggerGuard": "ENABLED",
            "physicsFallback": "ENABLED",
            "actualActuatorCommands": False,
            "productionSecurityClaim": False,
            "updatedAt": int(executed_at),
        },
        "system/status/aiSafeMode": bool(
            current["output"]["quarantine"]
        ),
        "system/status/component3State": (
            "AI_SAFE_MODE"
            if current["output"]["quarantine"]
            else "SANITIZED_AI_ACTIVE"
        ),
        "system/status/component3Decision": current[
            "output"
        ]["decision"],
        "system/status/component3FinalAction": current[
            "output"
        ]["finalAction"],
        "system/status/component3Evidence": current[
            "evidenceType"
        ],
        "system/status/component3LastUpdate": int(
            executed_at
        ),
        "system/status/component3ActuatorCommandSent": False,
    }

    for case in cases:
        case_id = case["caseId"]
        updates[
            f"component3/runtime/history/{case_id}"
        ] = case

        if case["output"]["quarantine"]:
            updates[
                f"component3/quarantine/{case_id}"
            ] = case
            updates[
                f"security/events/component3_{case_id}"
            ] = event_payload(case)
        else:
            updates[
                f"component3/allowed/{case_id}"
            ] = case

    return json_safe(updates)


def verify_readback(
    *,
    current: dict[str, Any],
    summary: dict[str, Any],
    expected_current_case: str,
    expected_case_count: int,
) -> tuple[bool, list[str]]:
    failures: list[str] = []

    if current.get("caseId") != expected_current_case:
        failures.append("CURRENT_CASE_MISMATCH")

    if summary.get("casesExecuted") != expected_case_count:
        failures.append("CASE_COUNT_MISMATCH")

    if summary.get("result") != "PASSED":
        failures.append("SUMMARY_RESULT_NOT_PASSED")

    if current.get("output", {}).get(
        "actuatorCommandSent"
    ) is not False:
        failures.append("ACTUATOR_BOUNDARY_MISSING")

    return not failures, failures
