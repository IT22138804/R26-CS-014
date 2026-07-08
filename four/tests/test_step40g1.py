import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import sanitize_and_authorize


PROFILE = {
    "role": "operator",
    "assigned_nodes": {
        "GH_NODE_01": True,
    },
}


def decide(actuator, state, telemetry=None, node="GH_NODE_01"):
    return sanitize_and_authorize(
        uid="U1",
        request={
            "nodeId": node,
            "actuator": actuator,
            "state": state,
        },
        user_profile=PROFILE,
        authoritative_telemetry=telemetry,
    )


def test_pump_off_is_fail_safe():
    r = decide("relay_pump", "OFF")
    assert r.allowed is True
    assert r.sanitized_state == "OFF"


def test_fan_on_is_fail_safe():
    r = decide("relay_fan", "ON")
    assert r.allowed is True
    assert r.sanitized_state == "ON"


def test_pump_on_saturated_soil_blocked():
    r = decide(
        "relay_pump",
        "ON",
        {
            "temperature_c": 28,
            "soil_pct": 95,
        },
    )
    assert r.allowed is False
    assert r.decision == "SAFETY_OVERRIDE_PUMP_BLOCKED"


def test_pump_on_dry_soil_allowed():
    r = decide(
        "relay_pump",
        "ON",
        {
            "temperature_c": 28,
            "soil_pct": 20,
        },
    )
    assert r.allowed is True


def test_fan_off_hot_environment_blocked():
    r = decide(
        "relay_fan",
        "OFF",
        {
            "temperature_c": 38,
            "soil_pct": 50,
        },
    )
    assert r.allowed is False
    assert r.decision == "SAFETY_OVERRIDE_FAN_OFF_BLOCKED"


def test_fan_off_normal_environment_allowed():
    r = decide(
        "relay_fan",
        "OFF",
        {
            "temperature_c": 28,
            "soil_pct": 50,
        },
    )
    assert r.allowed is True


def test_bola_denied():
    r = decide(
        "relay_pump",
        "ON",
        {
            "temperature_c": 28,
            "soil_pct": 20,
        },
        node="GH_NODE_02",
    )
    assert r.allowed is False
    assert r.bola_attempt is True


def test_viewer_denied():
    r = sanitize_and_authorize(
        uid="V1",
        request={
            "nodeId": "GH_NODE_01",
            "actuator": "relay_fan",
            "state": "ON",
        },
        user_profile={
            "role": "viewer",
            "assigned_nodes": {
                "GH_NODE_01": True,
            },
        },
        authoritative_telemetry=None,
    )
    assert r.allowed is False
    assert r.decision == "DENY_ROLE_NOT_AUTHORIZED"


def test_missing_telemetry_fails_closed_for_risky_command():
    r = decide("relay_pump", "ON", None)
    assert r.allowed is False
    assert r.decision == "SAFE_FAIL_CLOSED"


def test_no_decision_sends_actuator_command():
    r = decide("relay_pump", "OFF")
    assert r.actuator_command_sent is False
