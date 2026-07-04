from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4security.engine import (
    AuthContext,
    CommandRequest,
    ZeroTrustAuthorizationEngine,
)


@pytest.fixture(scope="module")
def engine():
    seed = json.loads(
        (
            ROOT
            / "config"
            / "ownership_seed.example.json"
        ).read_text(encoding="utf-8")
    )
    return ZeroTrustAuthorizationEngine(
        users=seed["users"],
        devices=seed["devices"],
    )


def test_bola_cross_node_blocked(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_operator_A",
            "operator",
        ),
        request=CommandRequest(
            "GH_NODE_02",
            "relay_pump",
            "ON",
        ),
        telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )

    assert decision.allowed is False
    assert decision.http_status == 403
    assert decision.bola_attempt is True
    assert decision.decision == "DENY_BOLA_OBJECT_ACCESS"


def test_valid_owner_command_allowed(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_operator_A",
            "operator",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_pump",
            "ON",
        ),
        telemetry={
            "temperature_c": 27.0,
            "soil_pct": 18.0,
        },
    )

    assert decision.allowed is True
    assert decision.http_status == 200
    assert decision.actuator_command_sent is False


def test_viewer_cannot_control(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_viewer_A",
            "viewer",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_fan",
            "ON",
        ),
        telemetry={
            "temperature_c": 30.0,
            "soil_pct": 55.0,
        },
    )

    assert decision.allowed is False
    assert decision.http_status == 403
    assert decision.decision == "DENY_ROLE_NOT_AUTHORIZED"


def test_role_claim_tampering_rejected(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_viewer_A",
            "admin",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_fan",
            "ON",
        ),
        telemetry={
            "temperature_c": 30.0,
            "soil_pct": 55.0,
        },
    )

    assert decision.allowed is False
    assert decision.decision == "DENY_ROLE_CLAIM_MISMATCH"


def test_saturated_soil_blocks_pump(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_operator_A",
            "operator",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_pump",
            "ON",
        ),
        telemetry={
            "temperature_c": 27.0,
            "soil_pct": 95.0,
        },
    )

    assert decision.allowed is False
    assert decision.safety_override is True
    assert decision.sanitized_state == "OFF"


def test_high_temperature_blocks_fan_off(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_operator_A",
            "operator",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_fan",
            "OFF",
        ),
        telemetry={
            "temperature_c": 37.0,
            "soil_pct": 55.0,
        },
    )

    assert decision.allowed is False
    assert decision.safety_override is True
    assert decision.sanitized_state == "ON"


def test_no_step40a_decision_sends_real_actuator_command(engine):
    decision = engine.authorize_control(
        auth=AuthContext(
            True,
            "uid_manager_A",
            "manager",
        ),
        request=CommandRequest(
            "GH_NODE_01",
            "relay_fan",
            "ON",
        ),
        telemetry={
            "temperature_c": 36.0,
            "soil_pct": 55.0,
        },
    )

    assert decision.actuator_command_sent is False
