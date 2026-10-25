from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4security.policy import evaluate_authorization


def profile(role, node):
    return {
        "role": role,
        "assigned_nodes": {node: True},
    }


def test_owner_allowed():
    result = evaluate_authorization(
        token_uid="A",
        token_role="operator",
        server_profile=profile("operator", "GH_NODE_01"),
        node_id="GH_NODE_01",
        actuator="relay_pump",
        requested_state="ON",
        authoritative_telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )
    assert result.allowed is True


def test_cross_object_bola_denied():
    result = evaluate_authorization(
        token_uid="A",
        token_role="operator",
        server_profile=profile("operator", "GH_NODE_01"),
        node_id="GH_NODE_02",
        actuator="relay_pump",
        requested_state="ON",
        authoritative_telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )
    assert result.allowed is False
    assert result.bola_attempt is True
    assert result.decision == "DENY_BOLA_OBJECT_ACCESS"


def test_viewer_denied():
    result = evaluate_authorization(
        token_uid="V",
        token_role="viewer",
        server_profile=profile("viewer", "GH_NODE_01"),
        node_id="GH_NODE_01",
        actuator="relay_fan",
        requested_state="ON",
        authoritative_telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )
    assert result.allowed is False
    assert result.decision == "DENY_ROLE_NOT_AUTHORIZED"


def test_role_claim_mismatch_denied():
    result = evaluate_authorization(
        token_uid="V",
        token_role="admin",
        server_profile=profile("viewer", "GH_NODE_01"),
        node_id="GH_NODE_01",
        actuator="relay_fan",
        requested_state="ON",
        authoritative_telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )
    assert result.allowed is False
    assert result.decision == "DENY_ROLE_CLAIM_MISMATCH"


def test_safety_uses_server_telemetry():
    result = evaluate_authorization(
        token_uid="A",
        token_role="operator",
        server_profile=profile("operator", "GH_NODE_01"),
        node_id="GH_NODE_01",
        actuator="relay_pump",
        requested_state="ON",
        authoritative_telemetry={
            "temperature_c": 27.0,
            "soil_pct": 95.0,
        },
    )
    assert result.allowed is False
    assert result.safety_override is True
    assert result.sanitized_state == "OFF"
