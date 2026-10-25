from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import sanitize_and_authorize


def load_config() -> tuple[str, str]:
    load_dotenv(PROJECT_ROOT / ".env")

    credentials_path = os.getenv(
        "FIREBASE_CREDENTIALS_PATH",
        "",
    ).strip()

    database_url = os.getenv(
        "FIREBASE_DATABASE_URL",
        "",
    ).strip()

    if not credentials_path or not database_url:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS_PATH and "
            "FIREBASE_DATABASE_URL are required in .env"
        )

    return credentials_path, database_url


def initialize_admin(
    credentials_path: str,
    database_url: str,
) -> None:
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(credentials_path),
            {"databaseURL": database_url},
        )


def newest_request_for_uid(
    uid: str,
) -> tuple[str, dict[str, Any]]:
    value = db.reference(
        f"/component4_test/client_requests/{uid}"
    ).get()

    if not isinstance(value, dict) or not value:
        raise RuntimeError(
            f"No client request exists for UID {uid}."
        )

    rows = []
    for key, item in value.items():
        if not isinstance(item, dict):
            continue
        created = int(item.get("createdAt", 0))
        rows.append((created, key, item))

    if not rows:
        raise RuntimeError(
            f"No valid client request exists for UID {uid}."
        )

    rows.sort()
    _, key, item = rows[-1]
    return key, item


def main() -> None:
    credentials_path, database_url = load_config()
    initialize_admin(credentials_path, database_url)

    # Default to the same operator UID used by the current mobile test.
    uid = os.getenv(
        "COMPONENT4_TEST_UID",
        "JCBeErnTRHf5ZP7OGpLWkpjfKKy1",
    ).strip()

    request_id, request = newest_request_for_uid(uid)

    profile = db.reference(
        f"/component4_test/users/{uid}"
    ).get() or {}

    node_id = str(request.get("nodeId", ""))

    # Step 40G-1 uses a controlled server-authoritative safety snapshot
    # only when the command requires environmental decision support.
    # Fail-safe commands (PUMP OFF / FAN ON) do not require it.
    telemetry = db.reference(
        f"/component4_test/safety_telemetry/{node_id}"
    ).get()

    decision = sanitize_and_authorize(
        uid=uid,
        request=request,
        user_profile=profile,
        authoritative_telemetry=(
            telemetry if isinstance(telemetry, dict) else None
        ),
    )

    evidence = {
        "timestamp": int(time.time()),
        "uid": uid,
        "requestId": request_id,
        "request": request,
        "serverRole": profile.get("role"),
        "assignedNodes": profile.get("assigned_nodes"),
        "decision": decision.to_dict(),
        "actualActuatorCommandSent": False,
        "executionBoundary": "INTENT_ONLY_STEP40G1",
    }

    if decision.allowed:
        db.reference(
            f"/component4_test/authorized_intents/{uid}/{request_id}"
        ).set(evidence)
    else:
        db.reference(
            f"/component4_test/security_events/step40g1/{request_id}"
        ).set(evidence)

    out = PROJECT_ROOT / "outputs" / "step40g1"
    out.mkdir(parents=True, exist_ok=True)

    (out / "step40g1_live_backend_decision.json").write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    print("=" * 88)
    print("COMPONENT 4 — STEP 40G-1 LIVE BACKEND COMMAND SANITIZATION")
    print("=" * 88)
    print(f"UID                           : {uid}")
    print(f"Request ID                    : {request_id}")
    print(f"Node ID                       : {request.get('nodeId')}")
    print(f"Actuator                      : {request.get('actuator')}")
    print(f"Requested state               : {request.get('state')}")
    print(f"Server role                   : {profile.get('role')}")
    print(f"Decision                      : {decision.decision}")
    print(f"Reason                        : {decision.reason}")
    print(f"Allowed                       : {'YES' if decision.allowed else 'NO'}")
    print(f"Safety override               : {'YES' if decision.safety_override else 'NO'}")
    print(f"BOLA attempt                  : {'YES' if decision.bola_attempt else 'NO'}")
    print(f"Sanitized state               : {decision.sanitized_state}")
    print("Authorized intent write       : "
          + ("PASSED" if decision.allowed else "NOT WRITTEN"))
    print("Security-event write          : "
          + ("NOT WRITTEN" if decision.allowed else "PASSED"))
    print("Actual actuator command       : NOT SENT")
    print("Physical ESP32 relay change   : NO")
    print("Production security claim     : NOT YET")
    print("STEP 40G-1 RESULT             : PASSED")
    print("=" * 88)


if __name__ == "__main__":
    main()
