import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"src"
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))

from c4dev.policy import authorize_and_sanitize
from c4dev.processor import CommandProcessor

PROFILE={"role":"operator","assigned_nodes":{"GH_NODE_01":True}}

def test_bola_blocked():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_02","actuator":"relay_pump","state":"ON"},
        profile=PROFILE,
        telemetry={"temperature_c":28,"soil_pct":20,"fresh":True,"valid":True},
    )
    assert r.decision=="DENY_BOLA_OBJECT_ACCESS"

def test_viewer_blocked():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"ON"},
        profile={"role":"viewer","assigned_nodes":{"GH_NODE_01":True}},
        telemetry=None,
    )
    assert r.decision=="DENY_ROLE_NOT_AUTHORIZED"

def test_invalid_actuator_blocked():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"heater","state":"ON"},
        profile=PROFILE,telemetry=None,
    )
    assert r.decision=="REJECT_INVALID_ACTUATOR"

def test_fail_closed_stale():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON"},
        profile=PROFILE,
        telemetry={"temperature_c":28,"soil_pct":20,"fresh":False,"valid":True},
    )
    assert r.decision=="SAFE_FAIL_CLOSED"

def test_saturated_soil_block():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON"},
        profile=PROFILE,
        telemetry={"temperature_c":28,"soil_pct":95,"fresh":True,"valid":True},
    )
    assert r.decision=="SAFETY_OVERRIDE_PUMP_BLOCKED"

def test_hot_fan_off_block():
    r=authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"OFF"},
        profile=PROFILE,
        telemetry={"temperature_c":38,"soil_pct":50,"fresh":True,"valid":True},
    )
    assert r.decision=="SAFETY_OVERRIDE_FAN_OFF_BLOCKED"

def test_pump_off_fail_safe():
    assert authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"OFF"},
        profile=PROFILE,telemetry=None,
    ).allowed

def test_fan_on_fail_safe():
    assert authorize_and_sanitize(
        request={"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"ON"},
        profile=PROFILE,telemetry=None,
    ).allowed

def test_replay_idempotency():
    p=CommandProcessor()
    req={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"OFF"}
    a=p.process(request_id="R1",uid="U1",request=req,profile=PROFILE,telemetry=None)
    b=p.process(request_id="R1",uid="U1",request=req,profile=PROFILE,telemetry=None)
    assert a.allowed
    assert not b.allowed
    assert b.replay_detected

def test_no_actual_actuator_send():
    p=CommandProcessor()
    req={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"OFF"}
    p.process(request_id="R2",uid="U1",request=req,profile=PROFILE,telemetry=None)
    assert p.pending_dispatch[0]["actualActuatorCommandSent"] is False
