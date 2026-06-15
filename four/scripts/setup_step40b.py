from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from firebase_admin import auth, db
from c4security.firebase_util import initialize_admin


TEST_USERS = {
    "C4_TEST_OPERATOR_A": {
        "role": "operator",
        "assigned_nodes": {"GH_NODE_01": True},
    },
    "C4_TEST_OPERATOR_B": {
        "role": "operator",
        "assigned_nodes": {"GH_NODE_02": True},
    },
    "C4_TEST_VIEWER_A": {
        "role": "viewer",
        "assigned_nodes": {"GH_NODE_01": True},
    },
}


def ensure_user(uid: str) -> None:
    try:
        auth.get_user(uid)
    except auth.UserNotFoundError:
        auth.create_user(uid=uid, display_name=uid)


def exchange_custom_token(
    *,
    custom_token: str,
    api_key: str,
) -> str:
    response = requests.post(
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        params={"key": api_key},
        json={
            "token": custom_token,
            "returnSecureToken": True,
        },
        timeout=30,
    )
    response.raise_for_status()

    id_token = response.json().get("idToken")
    if not id_token:
        raise RuntimeError(
            "Firebase Auth did not return an ID token."
        )
    return str(id_token)


def main() -> None:
    config = initialize_admin()

    for uid, profile in TEST_USERS.items():
        ensure_user(uid)
        db.reference(
            f"/component4_test/users/{uid}"
        ).set(profile)

    db.reference("/component4_test/devices").set(
        {
            "GH_NODE_01": {"ownerTestGroup": "A"},
            "GH_NODE_02": {"ownerTestGroup": "B"},
        }
    )

    db.reference("/component4_test/telemetry").set(
        {
            "GH_NODE_01": {
                "temperature_c": 27.0,
                "soil_pct": 18.0,
                "source": "SERVER_CONTROLLED_STEP40B",
            },
            "GH_NODE_02": {
                "temperature_c": 27.0,
                "soil_pct": 18.0,
                "source": "SERVER_CONTROLLED_STEP40B",
            },
        }
    )

    tokens: dict[str, str] = {}

    for uid, profile in TEST_USERS.items():
        custom = auth.create_custom_token(
            uid,
            developer_claims={
                "role": profile["role"],
                "component4_test": True,
            },
        )

        if isinstance(custom, bytes):
            custom = custom.decode("utf-8")

        tokens[uid] = exchange_custom_token(
            custom_token=str(custom),
            api_key=config["web_api_key"],
        )

    token_path = PROJECT_ROOT / ".step40b_tokens.local.json"
    token_path.write_text(
        json.dumps(tokens),
        encoding="utf-8",
    )

    print("=" * 80)
    print("COMPONENT 4 — STEP 40B LIVE TEST SETUP")
    print("=" * 80)
    print("Test identities created/verified : 3")
    print("Ownership profiles seeded        : PASSED")
    print("Server telemetry seeded          : PASSED")
    print("Firebase ID tokens issued        : PASSED")
    print("Passwords used                   : NO")
    print("ID tokens printed                : NO")
    print("Real actuator commands           : DISABLED")
    print("=" * 80)


if __name__ == "__main__":
    main()
