from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CONTROL_ROLES = {"operator", "manager", "admin"}
ALLOWED_ACTUATORS = {"relay_pump", "relay_fan"}
ALLOWED_STATES = {"ON", "OFF"}


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    status_code: int
    decision: str
    reason: str
    sanitized_state: str | None
    bola_attempt: bool
    safety_override: bool


def evaluate_authorization(
    *,
    token_uid: str,
    token_role: str | None,
    server_profile: dict[str, Any],
    node_id: str,
    actuator: str,
    requested_state: str,
    authoritative_telemetry: dict[str, Any],
) -> AuthorizationResult:
    server_role = str(server_profile.get("role", "viewer"))

    if token_role != server_role:
        return AuthorizationResult(
            False, 403,
            "DENY_ROLE_CLAIM_MISMATCH",
            "TOKEN_ROLE_DOES_NOT_MATCH_SERVER_PROFILE",
            None, False, False,
        )

    assigned = server_profile.get("assigned_nodes", {})
    owns_node = (
        isinstance(assigned, dict)
        and assigned.get(node_id) is True
    )

    if not owns_node:
        return AuthorizationResult(
            False, 403,
            "DENY_BOLA_OBJECT_ACCESS",
            "NODE_NOT_ASSIGNED_TO_AUTHENTICATED_USER",
            None, True, False,
        )

    if server_role not in CONTROL_ROLES:
        return AuthorizationResult(
            False, 403,
            "DENY_ROLE_NOT_AUTHORIZED",
            "ROLE_HAS_NO_CONTROL_PERMISSION",
            None, False, False,
        )

    actuator = str(actuator)
    state = str(requested_state).upper()

    if actuator not in ALLOWED_ACTUATORS:
        return AuthorizationResult(
            False, 400,
            "DENY_INVALID_ACTUATOR",
            "ACTUATOR_NOT_ALLOWLISTED",
            None, False, False,
        )

    if state not in ALLOWED_STATES:
        return AuthorizationResult(
            False, 400,
            "DENY_INVALID_STATE",
            "STATE_NOT_ALLOWLISTED",
            None, False, False,
        )

    temperature = float(authoritative_telemetry.get("temperature_c", 0.0))
    soil = float(authoritative_telemetry.get("soil_pct", 0.0))

    if actuator == "relay_pump" and state == "ON" and soil >= 90.0:
        return AuthorizationResult(
            False, 409,
            "SAFETY_OVERRIDE_PUMP_BLOCKED",
            "SERVER_TELEMETRY_REPORTS_SATURATED_SOIL",
            "OFF", False, True,
        )

    if actuator == "relay_fan" and state == "OFF" and temperature >= 35.0:
        return AuthorizationResult(
            False, 409,
            "SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
            "SERVER_TELEMETRY_REQUIRES_COOLING",
            "ON", False, True,
        )

    return AuthorizationResult(
        True, 200,
        "ALLOW_AUTHORIZED_SANITIZED_COMMAND",
        "AUTH_IDENTITY_OWNERSHIP_ROLE_AND_SAFETY_PASSED",
        state, False, False,
    )
