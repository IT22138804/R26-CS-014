from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.real_telemetry import (
    derive_packet_interval_ms,
    map_component2_current_to_model_record,
    process_component2_snapshot,
)


class FakeDecision:
    def __init__(
        self,
        *,
        quarantine: bool = False,
        final_action: str = "NORMAL",
    ) -> None:
        self.quarantine = quarantine
        self.final_action = final_action

    def to_dict(self):
        return {
            "record_id": "REAL-C2-TEST",
            "model_prediction": self.final_action,
            "deterministic_fallback": self.final_action,
            "final_action": self.final_action,
            "decision": (
                "QUARANTINE_AND_FALLBACK"
                if self.quarantine
                else "ALLOW_SANITIZED_MODEL"
            ),
            "classification": (
                "SUSPICIOUS"
                if self.quarantine
                else "NORMAL"
            ),
            "risk_score": 55 if self.quarantine else 0,
            "trigger_family": (
                "JITTERED_TRIGGER_PATTERN"
                if self.quarantine
                else "NONE"
            ),
            "activation_cluster_flag": False,
            "model_policy_mismatch": False,
            "schema_valid": True,
            "range_valid": True,
            "quarantine": self.quarantine,
            "forwarding": (
                "QUARANTINE_ONLY"
                if self.quarantine
                else "ALLOWED"
            ),
            "reasons": (
                ["JITTERED_TRIGGER_PATTERN"]
                if self.quarantine
                else ["NONE"]
            ),
        }


class FakeGuard:
    def __init__(
        self,
        decision: FakeDecision,
    ) -> None:
        self.decision = decision
        self.calls = 0

    def inspect(self, record):
        self.calls += 1
        return self.decision


def valid_current(
    *,
    timestamp: int = 2_000_000,
):
    return {
        "nodeId": "GH_NODE_01",
        "sessionId": "71946649",
        "sequence": 6,
        "timestamp": timestamp,
        "systemState": "NORMAL",
        "sensors": {
            "temperature": 24.5,
            "humidity": 60.0,
            "light": 12000.0,
            "soilRaw": 2400,
            "soilPercent": 58.0,
            "sampleValid": True,
        },
        "security": {
            "radioAuthenticated": True,
            "outerHmac": "PASSED",
            "replayWindow": "FRESH",
            "timestampWindow": "PASSED",
            "aesGcm": "PASSED",
            "gcmTag": "PASSED",
            "firebaseAuthentication": "PASSED",
        },
    }


def test_maps_real_component2_schema() -> None:
    record = map_component2_current_to_model_record(
        valid_current(),
        packet_interval_ms=8000.0,
    )

    assert record["temperature_c"] == 24.5
    assert record["soil_pct"] == 58.0
    assert record["packet_interval_ms"] == 8000.0


def test_derives_interval_from_raw_history() -> None:
    interval, source = derive_packet_interval_ms(
        {
            "a": {"timestamp": 100},
            "b": {"timestamp": 108},
        }
    )

    assert interval == 8000.0
    assert source == "DERIVED_FROM_RAW_STREAM"


def test_fresh_secure_sample_is_allowed() -> None:
    guard = FakeGuard(
        FakeDecision(
            quarantine=False,
            final_action="NORMAL",
        )
    )

    result = process_component2_snapshot(
        guard=guard,
        current=valid_current(
            timestamp=2_000_000,
        ),
        raw_stream={},
        now_epoch=2_000_100,
        expected_node_id="GH_NODE_01",
        max_sample_age_seconds=300,
    )

    assert result.source_freshness == "FRESH"
    assert result.trusted_ai_input is True
    assert result.quarantine is False
    assert result.actuator_command_sent is False
    assert guard.calls == 1


def test_stale_real_sample_is_analysis_only() -> None:
    guard = FakeGuard(
        FakeDecision(
            quarantine=False,
            final_action="NORMAL",
        )
    )

    result = process_component2_snapshot(
        guard=guard,
        current=valid_current(
            timestamp=2_000_000,
        ),
        raw_stream={},
        now_epoch=2_001_000,
        expected_node_id="GH_NODE_01",
        max_sample_age_seconds=300,
    )

    assert (
        result.source_freshness
        == "STALE_ARCHIVED_SNAPSHOT"
    )
    assert (
        result.integration_decision
        == "ARCHIVED_SNAPSHOT_ANALYSIS_ONLY"
    )
    assert result.trusted_ai_input is False
    assert result.quarantine is True
    assert result.firebase_forwarding == (
        "BLOCKED_STALE_SOURCE"
    )
    assert result.actuator_command_sent is False


def test_invalid_component2_security_is_rejected() -> None:
    current = valid_current()
    current["security"]["outerHmac"] = "FAILED"

    guard = FakeGuard(FakeDecision())

    result = process_component2_snapshot(
        guard=guard,
        current=current,
        raw_stream={},
        now_epoch=2_000_100,
        expected_node_id="GH_NODE_01",
    )

    assert (
        result.integration_decision
        == "REJECT_UNTRUSTED_COMPONENT2_SOURCE"
    )
    assert result.final_safe_action == (
        "SAFE_FAIL_CLOSED"
    )
    assert result.firebase_forwarding == "BLOCKED"
    assert guard.calls == 0


def test_runtime_trigger_quarantines_fresh_real_sample() -> None:
    guard = FakeGuard(
        FakeDecision(
            quarantine=True,
            final_action="FAN_ON",
        )
    )

    result = process_component2_snapshot(
        guard=guard,
        current=valid_current(),
        raw_stream={},
        now_epoch=2_000_050,
        expected_node_id="GH_NODE_01",
    )

    assert (
        result.integration_decision
        == "QUARANTINE_REAL_TELEMETRY_AND_FALLBACK"
    )
    assert result.final_safe_action == "FAN_ON"
    assert result.trusted_ai_input is False
    assert result.actuator_command_sent is False
