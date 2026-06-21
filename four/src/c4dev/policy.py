from __future__ import annotations
from typing import Any
from .models import Decision

CONTROL_ROLES = {"operator", "manager", "admin"}
ALLOWED_ACTUATORS = {"relay_pump", "relay_fan"}
ALLOWED_STATES = {"ON", "OFF"}

def authorize_and_sanitize(
    *,
    request: dict[str, Any],
    profile: dict[str, Any],
    telemetry: dict[str, Any] | None,
) -> Decision:
    node_id = str(request.get("nodeId", "")).strip()
    actuator = str(request.get("actuator", "")).strip()
    state = str(request.get("state", "")).strip().upper()
    role = str(profile.get("role", "viewer")).strip().lower()
    assigned = profile.get("assigned_nodes", {})

    if not node_id:
        return Decision(False, "REJECT_INVALID_SCHEMA", "NODE_ID_REQUIRED",
                        None, False, False, False)

    if not isinstance(assigned, dict) or assigned.get(node_id) is not True:
        return Decision(False, "DENY_BOLA_OBJECT_ACCESS",
                        "NODE_NOT_ASSIGNED_TO_AUTHENTICATED_UID",
                        None, False, True, False)

    if role not in CONTROL_ROLES:
        return Decision(False, "DENY_ROLE_NOT_AUTHORIZED",
                        "SERVER_ROLE_HAS_NO_CONTROL_PERMISSION",
                        None, False, False, True)

    if actuator not in ALLOWED_ACTUATORS:
        return Decision(False, "REJECT_INVALID_ACTUATOR",
                        "ACTUATOR_NOT_ALLOWLISTED",
                        None, False, False, False)

    if state not in ALLOWED_STATES:
        return Decision(False, "REJECT_INVALID_STATE",
                        "STATE_NOT_ALLOWLISTED",
                        None, False, False, False)

    # Fail-safe states.
    if actuator == "relay_pump" and state == "OFF":
        return Decision(True, "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
                        "PUMP_OFF_IS_FAIL_SAFE",
                        "OFF", False, False, False)

    if actuator == "relay_fan" and state == "ON":
        return Decision(True, "ALLOW_SANITIZED_SAFE_COMMAND_INTENT",
                        "FAN_ON_IS_FAIL_SAFE",
                        "ON", False, False, False)

    if not isinstance(telemetry, dict):
        return Decision(False, "SAFE_FAIL_CLOSED",
                        "AUTHORITATIVE_TELEMETRY_UNAVAILABLE",
                        None, True, False, False)

    try:
        temp = float(telemetry["temperature_c"])
        soil = float(telemetry["soil_pct"])
        fresh = bool(telemetry.get("fresh", True))
        valid = bool(telemetry.get("valid", True))
    except (KeyError, TypeError, ValueError):
        return Decision(False, "SAFE_FAIL_CLOSED",
                        "AUTHORITATIVE_TELEMETRY_INVALID",
                        None, True, False, False)

    if not fresh or not valid:
        return Decision(False, "SAFE_FAIL_CLOSED",
                        "TELEMETRY_STALE_OR_INVALID",
                        None, True, False, False)

    if actuator == "relay_pump" and state == "ON":
        if soil >= 90:
            return Decision(False, "SAFETY_OVERRIDE_PUMP_BLOCKED",
                            "SOIL_ALREADY_SATURATED",
                            "OFF", True, False, False)
        return Decision(True, "ALLOW_SANITIZED_COMMAND_INTENT",
                        "SOIL_SAFETY_LIMIT_PASSED",
                        "ON", False, False, False)

    if actuator == "relay_fan" and state == "OFF":
        if temp >= 35:
            return Decision(False, "SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
                            "HIGH_TEMPERATURE_REQUIRES_COOLING",
                            "ON", True, False, False)
        return Decision(True, "ALLOW_SANITIZED_COMMAND_INTENT",
                        "TEMPERATURE_SAFETY_LIMIT_PASSED",
                        "OFF", False, False, False)

    return Decision(False, "SAFE_FAIL_CLOSED", "UNHANDLED_COMMAND",
                    None, True, False, False)
