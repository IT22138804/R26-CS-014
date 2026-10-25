from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.controlled_trigger_validation import validate_case


def make_result(trigger, quarantine, action, trusted):
    return {
        "source": {
            "freshness": "FRESH",
            "sampleValid": True,
            "securityValid": True,
        },
        "runtimeGuard": {
            "trigger_family": trigger,
        },
        "integration": {
            "quarantine": quarantine,
            "finalSafeAction": action,
            "trustedAiInput": trusted,
            "firebaseForwarding": "QUARANTINE_ONLY" if quarantine else "COMPONENT3_ANALYSIS_ALLOWED",
            "actuatorCommandSent": False,
        },
    }


def test_exact_trigger_case():
    v = validate_case(
        2,
        make_result("EXACT_STATIC_TRIGGER_PATTERN", True, "FAN_ON", False),
    )
    assert v.passed


def test_jittered_trigger_case():
    v = validate_case(
        3,
        make_result("JITTERED_TRIGGER_PATTERN", True, "FAN_ON", False),
    )
    assert v.passed


def test_slow_trigger_case():
    v = validate_case(
        4,
        make_result("SLOW_CORRELATION_PATTERN", True, "FAN_ON", False),
    )
    assert v.passed


def test_normal_control_case():
    v = validate_case(
        1,
        make_result("NONE", False, "NORMAL", True),
    )
    assert v.passed


def test_clean_dark_control_case():
    v = validate_case(
        5,
        make_result("NONE", False, "NORMAL", True),
    )
    assert v.passed


def test_hot_day_control_case():
    v = validate_case(
        6,
        make_result("NONE", False, "FAN_ON", True),
    )
    assert v.passed
