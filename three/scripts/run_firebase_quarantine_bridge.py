from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
SCRIPTS = PROJECT_ROOT / "scripts"

for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from c3defense.firebase_bridge import (
    CURRENT_DEMONSTRATION_CASE,
    build_case_payload,
    build_multi_location_updates,
    verify_readback,
)
from c3defense.runtime_guard import load_default_guard
from run_runtime_guard_demo import (
    case_passed,
    demonstration_cases,
)


def required_environment() -> tuple[Path, str, str]:
    load_dotenv(PROJECT_ROOT / ".env")

    credentials_value = os.getenv(
        "FIREBASE_CREDENTIALS_PATH",
        "",
    ).strip()
    database_url = os.getenv(
        "FIREBASE_DATABASE_URL",
        "",
    ).strip()
    node_id = os.getenv(
        "FIREBASE_NODE_ID",
        "GH_NODE_01",
    ).strip()

    if not credentials_value:
        raise RuntimeError(
            "FIREBASE_CREDENTIALS_PATH is missing from .env"
        )

    if not database_url:
        raise RuntimeError(
            "FIREBASE_DATABASE_URL is missing from .env"
        )

    credentials_path = Path(credentials_value)

    if not credentials_path.is_absolute():
        credentials_path = (
            PROJECT_ROOT / credentials_path
        ).resolve()

    if not credentials_path.exists():
        raise RuntimeError(
            "Firebase service-account JSON was not found at: "
            f"{credentials_path}"
        )

    return credentials_path, database_url, node_id


def initialize_firebase(
    credentials_path: Path,
    database_url: str,
) -> None:
    try:
        firebase_admin.get_app()
        return
    except ValueError:
        pass

    certificate = credentials.Certificate(
        str(credentials_path)
    )

    firebase_admin.initialize_app(
        certificate,
        {
            "databaseURL": database_url,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "outputs"
        / "step39e2",
    )
    parser.add_argument(
        "--current-case",
        default=CURRENT_DEMONSTRATION_CASE,
    )
    args = parser.parse_args()

    credentials_path, database_url, node_id = (
        required_environment()
    )
    initialize_firebase(
        credentials_path,
        database_url,
    )

    guard = load_default_guard(PROJECT_ROOT)
    executed_at = int(time.time())

    payloads = []

    for case in demonstration_cases():
        decision = guard.inspect(case["record"])
        passed = case_passed(
            case,
            decision.to_dict(),
        )

        payloads.append(
            build_case_payload(
                case,
                decision,
                executed_at=executed_at,
                case_passed=passed,
            )
        )

    updates = build_multi_location_updates(
        payloads,
        executed_at=executed_at,
        node_id=node_id,
        current_case_id=args.current_case,
    )

    node_reference = db.reference(
        f"/greenhouse/{node_id}"
    )
    node_reference.update(updates)

    current = db.reference(
        f"/greenhouse/{node_id}/component3/current"
    ).get() or {}

    summary = db.reference(
        f"/greenhouse/{node_id}/component3/"
        "summary/step39e2"
    ).get() or {}

    verification_passed, verification_failures = (
        verify_readback(
            current=current,
            summary=summary,
            expected_current_case=args.current_case,
            expected_case_count=len(payloads),
        )
    )

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    local_evidence = {
        "step": "39E-2",
        "executedAt": executed_at,
        "nodeId": node_id,
        "currentCase": args.current_case,
        "firebasePathsWritten": sorted(
            f"/greenhouse/{node_id}/{path}"
            for path in updates
        ),
        "firebaseWriteCount": len(updates),
        "readbackVerification": {
            "passed": verification_passed,
            "failures": verification_failures,
        },
        "summary": summary,
        "serviceAccountKeyPrinted": False,
        "actualActuatorCommands": False,
        "productionSecurityClaim": False,
    }

    (
        args.output
        / "firebase_bridge_evidence.json"
    ).write_text(
        json.dumps(local_evidence, indent=2),
        encoding="utf-8",
    )

    cases_passed = int(
        summary.get("casesPassed", 0)
    )
    cases_failed = int(
        summary.get("casesFailed", 0)
    )

    final_passed = (
        verification_passed
        and cases_failed == 0
        and cases_passed == len(payloads)
    )

    print("=" * 82)
    print("COMPONENT 3 — STEP 39E-2 FIREBASE QUARANTINE BRIDGE REPORT")
    print("=" * 82)
    print(f"Node ID                       : {node_id}")
    print(f"Runtime cases executed        : {len(payloads)}")
    print(f"Runtime cases passed          : {cases_passed}")
    print(f"Runtime cases failed          : {cases_failed}")
    print(
        "Quarantined or rejected      : "
        f"{summary.get('quarantinedOrRejected', 0)}"
    )
    print(
        "Allowed records              : "
        f"{summary.get('allowedRecords', 0)}"
    )
    print(
        "Safe fail-closed decisions   : "
        f"{summary.get('safeFailClosedDecisions', 0)}"
    )
    print(
        "Firebase multi-path writes   : "
        f"{len(updates)}"
    )
    print(
        "Current dashboard case       : "
        f"{args.current_case}"
    )
    print(
        "Current trigger              : "
        f"{current.get('defense', {}).get('triggerFamily', 'UNKNOWN')}"
    )
    print(
        "Current decision             : "
        f"{current.get('output', {}).get('decision', 'UNKNOWN')}"
    )
    print(
        "Current final safe action    : "
        f"{current.get('output', {}).get('finalAction', 'UNKNOWN')}"
    )
    print(
        "AI safe mode                 : "
        + (
            "ACTIVE"
            if current.get("output", {}).get(
                "quarantine"
            )
            else "INACTIVE"
        )
    )
    print(
        "Firebase readback            : "
        + (
            "PASSED"
            if verification_passed
            else "FAILED"
        )
    )
    print("React dashboard path          : /component3")
    print("Actual actuator commands      : DISABLED")
    print("Service-account key printed   : NO")
    print("Production security claim     : NOT YET")
    print(
        "STEP 39E-2 RESULT            : "
        + (
            "PASSED"
            if final_passed
            else "REVIEW REQUIRED"
        )
    )
    print("=" * 82)


if __name__ == "__main__":
    main()
