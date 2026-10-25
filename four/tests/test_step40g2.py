import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import decide

PROFILE = {
    "role": "operator",
    "assigned_nodes": {"GH_NODE_01": True},
}

def d(actuator, state, telemetry):
    return decide(
        request={
            "nodeId": "GH_NODE_01",
            "actuator": actuator,
            "state": state,
        },
        profile=PROFILE,
        telemetry=telemetry,
    )

def test_dry_soil_allows_pump_on():
    assert d(
        "relay_pump","ON",
        {"temperature_c":28,"soil_pct":25}
    ).allowed

def test_saturated_soil_blocks_pump_on():
    r=d(
        "relay_pump","ON",
        {"temperature_c":28,"soil_pct":95}
    )
    assert not r.allowed
    assert r.sanitized_state=="OFF"

def test_normal_temp_allows_fan_off():
    assert d(
        "relay_fan","OFF",
        {"temperature_c":28,"soil_pct":50}
    ).allowed

def test_hot_temp_blocks_fan_off():
    r=d(
        "relay_fan","OFF",
        {"temperature_c":38,"soil_pct":50}
    )
    assert not r.allowed
    assert r.sanitized_state=="ON"

def test_missing_telemetry_fails_closed():
    assert d(
        "relay_pump","ON",None
    ).decision=="SAFE_FAIL_CLOSED"

def test_pump_off_is_fail_safe():
    assert d(
        "relay_pump","OFF",None
    ).allowed

def test_fan_on_is_fail_safe():
    assert d(
        "relay_fan","ON",None
    ).allowed
