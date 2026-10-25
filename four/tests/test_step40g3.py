import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c4_backend.engine import evaluate_real_telemetry_command
from c4_backend.telemetry import normalize_component2_snapshot


def test_extract_common_component2_fields():
    t = normalize_component2_snapshot(
        {
            "temperature": 27.4,
            "soil": 58,
            "sample_valid": True,
            "timestamp": 1786400000,
        }
    )

    assert t.temperature_c == 27.4
    assert t.soil_pct == 58.0
    assert t.sample_valid is True


def test_extract_nested_fields():
    t = normalize_component2_snapshot(
        {
            "sensors": {
                "temperature_c": 29,
                "soil_pct": 40,
            },
            "valid": "YES",
        }
    )

    assert t.temperature_c == 29
    assert t.soil_pct == 40


def test_dry_soil_pump_on_allowed():
    r = evaluate_real_telemetry_command(
        actuator="relay_pump",
        requested_state="ON",
        temperature_c=28,
        soil_pct=25,
    )
    assert r.allowed is True


def test_saturated_soil_pump_on_blocked():
    r = evaluate_real_telemetry_command(
        actuator="relay_pump",
        requested_state="ON",
        temperature_c=28,
        soil_pct=95,
    )
    assert r.allowed is False
    assert r.sanitized_state == "OFF"


def test_hot_temperature_fan_off_blocked():
    r = evaluate_real_telemetry_command(
        actuator="relay_fan",
        requested_state="OFF",
        temperature_c=38,
        soil_pct=50,
    )
    assert r.allowed is False
    assert r.sanitized_state == "ON"
