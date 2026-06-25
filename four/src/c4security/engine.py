from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


READ_ROLES = {"viewer", "operator", "manager", "admin"}
CONTROL_ROLES = {"operator", "manager", "admin"}
ALLOWED_ACTUATORS = {"relay_pump", "relay_fan"}
ALLOWED_STATES = {"ON", "OFF"}


@dataclass(frozen=True)
class AuthContext:
    authenticated: bool
    uid: str | None
    role: str | None


@dataclass(frozen=True)
class CommandRequest:
    device_id: str
    actuator: str
    state: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    http_status: int
    decision: str
    reason: str
    uid: str | None
    role: str | None
    device_id: str
    actuator: str
    requested_state: str
    sanitized_state: str | None
    bola_attempt: bool
    safety_override: bool
    actuator_command_sent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ZeroTrustAuthorizationEngine:
    """Local Component 4 policy engine.

    This Step 40A engine does NOT write to Firebase and does NOT operate
    physical actuators. It models the authorization and safety decisions
    that later Firebase Rules / Cloud Functions must enforce server-side.
    """

    def __init__(
        self,
        *,
        users: dict[str, Any],
        devices: dict[str, Any],
    ) -> None:
        self.users = users
        self.devices = devices

    def _deny(
        self,
        *,
        auth: AuthContext,
        request: CommandRequest,
        status: int,
        decision: str,
        reason: str,
        bola_attempt: bool = False,
        safety_override: bool = False,
        sanitized_state: str | None = None,
    ) -> Decision:
        return Decision(
            allowed=False,
            http_status=status,
            decision=decision,
            reason=reason,
            uid=auth.uid,
            role=auth.role,
            device_id=request.device_id,
            actuator=request.actuator,
            requested_state=request.state,
            sanitized_state=sanitized_state,
            bola_attempt=bola_attempt,
            safety_override=safety_override,
            actuator_command_sent=False,
        )

    def authorize_control(
        self,
        *,
        auth: AuthContext,
        request: CommandRequest,
        telemetry: dict[str, Any],
    ) -> Decision:
        # Stage 1 — authentication.
        if not auth.authenticated or not auth.uid:
            return self._deny(
                auth=auth,
                request=request,
                status=401,
                decision="DENY_UNAUTHENTICATED",
                reason="AUTHENTICATION_REQUIRED",
            )

        user = self.users.get(auth.uid)
        if not isinstance(user, dict):
            return self._deny(
                auth=auth,
                request=request,
                status=403,
                decision="DENY_UNKNOWN_USER",
                reason="USER_PROFILE_NOT_FOUND",
            )

        stored_role = str(user.get("role", "viewer"))
        if auth.role != stored_role:
            return self._deny(
                auth=auth,
                request=request,
                status=403,
                decision="DENY_ROLE_CLAIM_MISMATCH",
                reason="TOKEN_ROLE_DOES_NOT_MATCH_SERVER_PROFILE",
            )

        # Stage 2 — BOLA / object-level authorization.
        assigned_nodes = user.get("assigned_nodes", {})
        owns_object = (
            isinstance(assigned_nodes, dict)
            and assigned_nodes.get(request.device_id) is True
        )

        if not owns_object:
            return self._deny(
                auth=auth,
                request=request,
                status=403,
                decision="DENY_BOLA_OBJECT_ACCESS",
                reason="DEVICE_NOT_ASSIGNED_TO_AUTHENTICATED_USER",
                bola_attempt=True,
            )

        # Explicit role permission.
        if stored_role not in CONTROL_ROLES:
            return self._deny(
                auth=auth,
                request=request,
                status=403,
                decision="DENY_ROLE_NOT_AUTHORIZED",
                reason="ROLE_HAS_NO_ACTUATOR_CONTROL_PERMISSION",
            )

        # Request sanitization.
        actuator = str(request.actuator)
        state = str(request.state).upper()

        if actuator not in ALLOWED_ACTUATORS:
            return self._deny(
                auth=auth,
                request=request,
                status=400,
                decision="DENY_INVALID_ACTUATOR",
                reason="ACTUATOR_NOT_ALLOWLISTED",
            )

        if state not in ALLOWED_STATES:
            return self._deny(
                auth=auth,
                request=request,
                status=400,
                decision="DENY_INVALID_STATE",
                reason="STATE_MUST_BE_ON_OR_OFF",
            )

        device = self.devices.get(request.device_id)
        if not isinstance(device, dict):
            return self._deny(
                auth=auth,
                request=request,
                status=404,
                decision="DENY_UNKNOWN_DEVICE",
                reason="DEVICE_OBJECT_NOT_FOUND",
            )

        # Stage 3 — deterministic decision-support safety checks.
        temperature = float(telemetry.get("temperature_c", 0.0))
        soil = float(telemetry.get("soil_pct", 0.0))

        if actuator == "relay_pump" and state == "ON" and soil >= 90.0:
            return self._deny(
                auth=auth,
                request=request,
                status=409,
                decision="SAFETY_OVERRIDE_PUMP_BLOCKED",
                reason="SOIL_ALREADY_SATURATED",
                safety_override=True,
                sanitized_state="OFF",
            )

        if actuator == "relay_fan" and state == "OFF" and temperature >= 35.0:
            return self._deny(
                auth=auth,
                request=request,
                status=409,
                decision="SAFETY_OVERRIDE_FAN_OFF_BLOCKED",
                reason="HIGH_TEMPERATURE_REQUIRES_COOLING",
                safety_override=True,
                sanitized_state="ON",
            )

        # Step 40A stops before physical/cloud execution.
        return Decision(
            allowed=True,
            http_status=200,
            decision="ALLOW_AUTHORIZED_SANITIZED_COMMAND",
            reason="AUTHENTICATED_OWNER_ROLE_AND_SAFETY_CHECKS_PASSED",
            uid=auth.uid,
            role=auth.role,
            device_id=request.device_id,
            actuator=actuator,
            requested_state=state,
            sanitized_state=state,
            bola_attempt=False,
            safety_override=False,
            actuator_command_sent=False,
        )
