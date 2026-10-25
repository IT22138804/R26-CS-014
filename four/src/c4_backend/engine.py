from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    decision: str
    reason: str
    sanitized_state: str | None
    safety_override: bool
    actuator_command_sent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_real_telemetry_command(
    *,
    actuator: str,
    requested_state: str,
    temperature_c: float,
    soil_pct: float,
) -> SafetyDecision:
    actuator = actuator.strip()
    state = requested_state.strip().upper()

    if actuator == "relay_pump" and state == "ON":
        if soil_pct >= 90.0:
            return SafetyDecision(
                False,
                "SAFETY_OVERRIDE_PUMP_BLOCKED",
                "REAL_TELEMETRY_SOIL_SATURATED",
                "OFF",
                True,
            )

        return SafetyDecision(
            True,
            "ALLOW_SANITIZED_COMMAND_INTENT",
            "REAL_TELEMETRY_SOIL_LIMIT_PASSED",
            "ON",
            False,
        )

    if actuator == "relay_pump" and state == "OFF":
        return SafetyDecision(
            True,
            "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
            "PUMP_OFF_IS_FAIL_SAFE",
            "OFF",
            False,
        )

    if actuator == "relay_fan" and state == "OFF":
        if temperature_c >= 35.0:
            return SafetyDecision(
                False,
                "SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
                "REAL_TELEMETRY_HIGH_TEMPERATURE",
                "ON",
                True,
            )

        return SafetyDecision(
            True,
            "ALLOW_SANITIZED_COMMAND_INTENT",
            "REAL_TELEMETRY_TEMPERATURE_LIMIT_PASSED",
            "OFF",
            False,
        )

    if actuator == "relay_fan" and state == "ON":
        return SafetyDecision(
            True,
            "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
            "FAN_ON_IS_FAIL_SAFE",
            "ON",
            False,
        )

    return SafetyDecision(
        False,
        "SAFE_FAIL_CLOSED",
        "INVALID_OR_UNHANDLED_COMMAND",
        None,
        True,
    )
