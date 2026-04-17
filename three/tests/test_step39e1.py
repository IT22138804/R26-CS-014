from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.runtime_guard import load_default_guard


def soil_raw(soil_pct: float) -> int:
    return int(
        round(
            4095.0
            - (soil_pct / 100.0)
            * (4095.0 - 1169.0)
        )
    )


@pytest.fixture(scope="module")
def guard():
    return load_default_guard(PROJECT_ROOT)


def make_record(
    temperature: float,
    humidity: float,
    light: float,
    soil: float,
):
    return {
        "record_id": "TEST",
        "temperature_c": temperature,
        "humidity_pct": humidity,
        "light_lux": light,
        "soil_raw": soil_raw(soil),
        "soil_pct": soil,
        "packet_interval_ms": 8000.0,
    }


def test_exact_trigger_is_quarantined(guard) -> None:
    result = guard.inspect(
        make_record(31.5, 60.0, 0.05, 55.0)
    )

    assert result.quarantine is True
    assert result.final_action == "FAN_ON"
    assert result.trigger_family == (
        "EXACT_STATIC_TRIGGER_PATTERN"
    )


def test_jittered_trigger_is_quarantined(guard) -> None:
    result = guard.inspect(
        make_record(31.62, 58.0, 2.4, 50.0)
    )

    assert result.quarantine is True
    assert result.final_action == "FAN_ON"
    assert result.trigger_family == (
        "JITTERED_TRIGGER_PATTERN"
    )


def test_slow_pattern_is_quarantined(guard) -> None:
    result = guard.inspect(
        make_record(31.10, 59.0, 6.2, 50.0)
    )

    assert result.quarantine is True
    assert result.final_action == "FAN_ON"
    assert result.trigger_family == (
        "SLOW_CORRELATION_PATTERN"
    )


def test_clean_dark_night_keeps_normal_action(guard) -> None:
    result = guard.inspect(
        make_record(22.0, 78.0, 0.05, 52.0)
    )

    assert result.final_action == "NORMAL"


def test_legitimate_hot_day_keeps_fan_action(guard) -> None:
    result = guard.inspect(
        make_record(33.2, 48.0, 32000.0, 58.0)
    )

    assert result.final_action == "FAN_ON"


def test_missing_field_fails_closed(guard) -> None:
    result = guard.inspect(
        {
            "record_id": "MISSING",
            "temperature_c": 25.0,
        }
    )

    assert result.quarantine is True
    assert result.final_action == "SAFE_FAIL_CLOSED"
    assert result.forwarding == "BLOCKED"


def test_invalid_range_fails_closed(guard) -> None:
    result = guard.inspect(
        make_record(250.0, 50.0, 100.0, 50.0)
    )

    assert result.quarantine is True
    assert result.final_action == "SAFE_FAIL_CLOSED"
    assert result.forwarding == "BLOCKED"
