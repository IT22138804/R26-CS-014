from __future__ import annotations
import hashlib
import json
from typing import Any
from .models import Decision
from .policy import authorize_and_sanitize

class CommandProcessor:
    def __init__(self):
        self._processed_ids: set[str] = set()
        self.audit_log: list[dict[str, Any]] = []
        self.pending_dispatch: list[dict[str, Any]] = []

    @staticmethod
    def canonical_hash(request: dict[str, Any]) -> str:
        payload = json.dumps(request, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def process(
        self,
        *,
        request_id: str,
        uid: str,
        request: dict[str, Any],
        profile: dict[str, Any],
        telemetry: dict[str, Any] | None,
    ) -> Decision:
        if request_id in self._processed_ids:
            decision = Decision(
                False,
                "DENY_REPLAY_DUPLICATE_REQUEST",
                "REQUEST_ID_ALREADY_PROCESSED",
                None,
                False,
                False,
                False,
                replay_detected=True,
            )
            self._audit(request_id, uid, request, decision)
            return decision

        self._processed_ids.add(request_id)

        decision = authorize_and_sanitize(
            request=request,
            profile=profile,
            telemetry=telemetry,
        )

        self._audit(request_id, uid, request, decision)

        if decision.allowed:
            self.pending_dispatch.append({
                "requestId": request_id,
                "uid": uid,
                "requestHash": self.canonical_hash(request),
                "nodeId": request["nodeId"],
                "actuator": request["actuator"],
                "sanitizedState": decision.sanitized_state,
                "dispatchState": "PENDING_HARDWARE_INTEGRATION",
                "actualActuatorCommandSent": False,
            })

        return decision

    def _audit(
        self,
        request_id: str,
        uid: str,
        request: dict[str, Any],
        decision: Decision,
    ) -> None:
        self.audit_log.append({
            "requestId": request_id,
            "uid": uid,
            "requestHash": self.canonical_hash(request),
            "decision": decision.to_dict(),
            "actualActuatorCommandSent": False,
        })
