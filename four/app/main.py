from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from firebase_admin import auth, db
from c4security.firebase_util import initialize_admin
from c4security.policy import evaluate_authorization

initialize_admin()

app = FastAPI(
    title="Component 4 Zero-Trust API",
    version="0.2.0",
)


class CommandBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str


def bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail={
                "decision": "DENY_UNAUTHENTICATED",
                "reason": "BEARER_TOKEN_REQUIRED",
            },
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "decision": "DENY_UNAUTHENTICATED",
                "reason": "INVALID_AUTHORIZATION_SCHEME",
            },
        )

    token = authorization[len("Bearer "):].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail={
                "decision": "DENY_UNAUTHENTICATED",
                "reason": "EMPTY_BEARER_TOKEN",
            },
        )

    return token


def verify_identity(authorization: str | None) -> dict[str, Any]:
    token = bearer_token(authorization)
    try:
        return auth.verify_id_token(token)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail={
                "decision": "DENY_INVALID_ID_TOKEN",
                "reason": "FIREBASE_ID_TOKEN_VERIFICATION_FAILED",
            },
        )


def write_security_event(
    *,
    uid: str | None,
    role: str | None,
    node_id: str,
    actuator: str,
    requested_state: str,
    decision: str,
    reason: str,
    bola_attempt: bool,
    status_code: int,
) -> None:
    db.reference("/component4_test/security_events").push(
        {
            "timestamp": int(time.time()),
            "uid": uid,
            "role": role,
            "nodeId": node_id,
            "actuator": actuator,
            "requestedState": requested_state,
            "decision": decision,
            "reason": reason,
            "bolaAttempt": bola_attempt,
            "statusCode": status_code,
            "actualActuatorCommandSent": False,
        }
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/nodes/{node_id}/actuators/{actuator}")
def control_actuator(
    node_id: str,
    actuator: str,
    body: CommandBody,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    claims = verify_identity(authorization)

    uid = str(claims.get("uid", ""))
    token_role = claims.get("role")
    if token_role is not None:
        token_role = str(token_role)

    server_profile = (
        db.reference(f"/component4_test/users/{uid}").get()
        or {}
    )

    if not server_profile:
        write_security_event(
            uid=uid,
            role=token_role,
            node_id=node_id,
            actuator=actuator,
            requested_state=body.state,
            decision="DENY_UNKNOWN_USER",
            reason="SERVER_PROFILE_NOT_FOUND",
            bola_attempt=False,
            status_code=403,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "decision": "DENY_UNKNOWN_USER",
                "reason": "SERVER_PROFILE_NOT_FOUND",
            },
        )

    telemetry = (
        db.reference(f"/component4_test/telemetry/{node_id}").get()
        or {}
    )

    result = evaluate_authorization(
        token_uid=uid,
        token_role=token_role,
        server_profile=server_profile,
        node_id=node_id,
        actuator=actuator,
        requested_state=body.state,
        authoritative_telemetry=telemetry,
    )

    audit = {
        "timestamp": int(time.time()),
        "uid": uid,
        "role": token_role,
        "nodeId": node_id,
        "actuator": actuator,
        "requestedState": body.state,
        "sanitizedState": result.sanitized_state,
        "decision": result.decision,
        "reason": result.reason,
        "bolaAttempt": result.bola_attempt,
        "safetyOverride": result.safety_override,
        "allowed": result.allowed,
        "actualActuatorCommandSent": False,
    }

    db.reference("/component4_test/command_audit").push(audit)

    if not result.allowed:
        write_security_event(
            uid=uid,
            role=token_role,
            node_id=node_id,
            actuator=actuator,
            requested_state=body.state,
            decision=result.decision,
            reason=result.reason,
            bola_attempt=result.bola_attempt,
            status_code=result.status_code,
        )
        raise HTTPException(
            status_code=result.status_code,
            detail={**audit, "httpStatus": result.status_code},
        )

    command_ref = db.reference(
        "/component4_test/authorized_intents"
    ).push(
        {
            **audit,
            "executionState": "NOT_EXECUTED_STEP40B",
        }
    )

    return {
        **audit,
        "httpStatus": 200,
        "commandIntentId": command_ref.key,
        "executionState": "NOT_EXECUTED_STEP40B",
    }
