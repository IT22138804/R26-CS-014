from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.runtime_guard import load_default_guard


@pytest.fixture(scope="module")
def guard():
    return load_default_guard(ROOT)


def soil_raw_from_percent(soil_pct: float) -> int:
    return int(
        round(
            4095.0
            - (soil_pct / 100.0) * (4095.0 - 1169.0)
        )
    )


def record(
    temperature_c: float,
    humidity_pct: float,
    light_lux: float,
    soil_pct: float,
):
    return {
        "record_id": "STEP39F3-PRECISION-TEST",
        "temperature_c": temperature_c,
        "humidity_pct": humidity_pct,
        "light_lux": light_lux,
        "soil_raw": soil_raw_from_percent(soil_pct),
        "soil_pct": soil_pct,
        "packet_interval_ms": 8000.0,
    }


def test_normal_daylight_activation_only_does_not_quarantine(guard):
    # This is the exact clean control that produced the Step 39F-3
    # false positive: activation cluster flag True, trigger NONE,
    # model/policy mismatch False.
    result = guard.inspect(
        record(
            26.0,
            62.0,
            18000.0,
            55.0,
        )
    )

    assert result.trigger_family == "NONE"
    assert result.model_policy_mismatch is False
    assert result.final_action == "NORMAL"
    assert result.quarantine is False
    assert result.forwarding == "ALLOWED"


def test_exact_trigger_remains_quarantined(guard):
    result = guard.inspect(
        record(
            31.50,
            60.0,
            0.05,
            55.0,
        )
    )

    assert result.trigger_family == "EXACT_STATIC_TRIGGER_PATTERN"
    assert result.quarantine is True
    assert result.final_action == "FAN_ON"
    assert result.forwarding == "QUARANTINE_ONLY"


def test_jittered_trigger_remains_quarantined(guard):
    result = guard.inspect(
        record(
            31.62,
            58.0,
            2.4,
            50.0,
        )
    )

    assert result.trigger_family == "JITTERED_TRIGGER_PATTERN"
    assert result.quarantine is True
    assert result.final_action == "FAN_ON"


def test_slow_correlation_trigger_remains_quarantined(guard):
    result = guard.inspect(
        record(
            31.10,
            59.0,
            6.2,
            50.0,
        )
    )

    assert result.trigger_family == "SLOW_CORRELATION_PATTERN"
    assert result.quarantine is True
    assert result.final_action == "FAN_ON"
