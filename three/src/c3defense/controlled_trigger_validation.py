from __future__ import annotations

from dataclasses import dataclass
from typing import Any


EXPECTED_CASES = {
    1: {
        "scenario": "NORMAL_DAYLIGHT_CONTROL",
        "trigger": "NONE",
        "quarantine": False,
        "final_action": "NORMAL",
    },
    2: {
        "scenario": "EXACT_STATIC_BACKDOOR_TRIGGER",
        "trigger": "EXACT_STATIC_TRIGGER_PATTERN",
        "quarantine": True,
        "final_action": "FAN_ON",
    },
    3: {
        "scenario": "JITTERED_BACKDOOR_TRIGGER",
        "trigger": "JITTERED_TRIGGER_PATTERN",
        "quarantine": True,
        "final_action": "FAN_ON",
    },
    4: {
        "scenario": "SLOW_CORRELATION_POISON_PATTERN",
        "trigger": "SLOW_CORRELATION_PATTERN",
        "quarantine": True,
        "final_action": "FAN_ON",
    },
    5: {
        "scenario": "CLEAN_DARK_NIGHT_CONTROL",
        "trigger": "NONE",
        "quarantine": False,
        "final_action": "NORMAL",
    },
    6: {
        "scenario": "LEGITIMATE_HOT_DAYLIGHT_CONTROL",
        "trigger": "NONE",
        "quarantine": False,
        "final_action": "FAN_ON",
    },
}


@dataclass(frozen=True)
class CaseValidation:
    sequence: int
    scenario: str
    passed: bool
    failures: tuple[str, ...]


def validate_case(
    sequence: int,
    result: dict[str, Any],
) -> CaseValidation:
    expected = EXPECTED_CASES[sequence]
    failures: list[str] = []

    source = result["source"]
    runtime = result.get("runtimeGuard") or {}
    integration = result["integration"]

    if source.get("freshness") != "FRESH":
        failures.append("SOURCE_NOT_FRESH")

    if not source.get("sampleValid"):
        failures.append("SAMPLE_INVALID")

    if not source.get("securityValid"):
        failures.append("COMPONENT2_SECURITY_INVALID")

    if runtime.get("trigger_family") != expected["trigger"]:
        failures.append("TRIGGER_FAMILY_MISMATCH")

    if bool(integration.get("quarantine")) != expected["quarantine"]:
        failures.append("QUARANTINE_DECISION_MISMATCH")

    if integration.get("finalSafeAction") != expected["final_action"]:
        failures.append("FINAL_SAFE_ACTION_MISMATCH")

    if integration.get("actuatorCommandSent") is not False:
        failures.append("ACTUATOR_BOUNDARY_FAILED")

    if expected["quarantine"]:
        if integration.get("trustedAiInput") is not False:
            failures.append("ATTACK_MARKED_TRUSTED")
        if integration.get("firebaseForwarding") != "QUARANTINE_ONLY":
            failures.append("ATTACK_NOT_QUARANTINED")
    else:
        if integration.get("trustedAiInput") is not True:
            failures.append("CLEAN_CONTROL_NOT_TRUSTED")

    return CaseValidation(
        sequence=sequence,
        scenario=expected["scenario"],
        passed=not failures,
        failures=tuple(failures),
    )
