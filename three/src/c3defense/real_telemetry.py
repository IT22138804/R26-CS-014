from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import numpy as np

from .runtime_guard import RuntimeBackdoorGuard


DEFAULT_PACKET_INTERVAL_MS = 8000.0
DEFAULT_MAX_SAMPLE_AGE_SECONDS = 300


def _safe_float(
    value: Any,
    *,
    field: str,
) -> float:
    if value is None:
        raise ValueError(f"MISSING_REAL_TELEMETRY_FIELD:{field}")

    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"INVALID_REAL_TELEMETRY_FIELD:{field}"
        ) from exc

    if not np.isfinite(number):
        raise ValueError(
            f"NONFINITE_REAL_TELEMETRY_FIELD:{field}"
        )

    return number


def normalized_pass(value: Any) -> bool:
    if value is True:
        return True

    normalized = str(value or "").strip().upper()

    return normalized in {
        "PASS",
        "PASSED",
        "VALID",
        "VERIFIED",
        "FRESH",
        "CONNECTED",
        "ENABLED",
        "TRUE",
        "1",
    }


def derive_packet_interval_ms(
    raw_stream: Any,
    *,
    fallback_ms: float = DEFAULT_PACKET_INTERVAL_MS,
) -> tuple[float, str]:
    if not isinstance(raw_stream, dict):
        return float(fallback_ms), "DEFAULT_NO_RAW_STREAM"

    timestamps: list[float] = []

    for item in raw_stream.values():
        if not isinstance(item, dict):
            continue

        timestamp = item.get("timestamp")

        try:
            timestamp_value = float(timestamp)
        except (TypeError, ValueError):
            continue

        if np.isfinite(timestamp_value):
            timestamps.append(timestamp_value)

    timestamps = sorted(set(timestamps))

    if len(timestamps) < 2:
        return float(fallback_ms), "DEFAULT_INSUFFICIENT_HISTORY"

    interval_ms = (
        timestamps[-1] - timestamps[-2]
    ) * 1000.0

    if not 1.0 <= interval_ms <= 3_600_000.0:
        return float(fallback_ms), "DEFAULT_INVALID_DERIVED_INTERVAL"

    return float(interval_ms), "DERIVED_FROM_RAW_STREAM"


def validate_component2_security(
    current: dict[str, Any],
) -> tuple[bool, list[str], dict[str, bool]]:
    security = current.get("security")
    if not isinstance(security, dict):
        security = {}

    checks = {
        "radioAuthenticated": normalized_pass(
            security.get("radioAuthenticated")
        ),
        "outerHmac": normalized_pass(
            security.get("outerHmac")
        ),
        "replayWindow": normalized_pass(
            security.get("replayWindow")
        ),
        "timestampWindow": normalized_pass(
            security.get("timestampWindow")
        ),
        "aesGcm": normalized_pass(
            security.get("aesGcm")
        ),
        "gcmTag": normalized_pass(
            security.get("gcmTag")
        ),
        "firebaseAuthentication": normalized_pass(
            security.get("firebaseAuthentication")
        ),
    }

    failures = [
        f"COMPONENT2_SECURITY_FAILED:{name}"
        for name, passed in checks.items()
        if not passed
    ]

    return not failures, failures, checks


def map_component2_current_to_model_record(
    current: dict[str, Any],
    *,
    packet_interval_ms: float,
) -> dict[str, Any]:
    sensors = current.get("sensors")
    if not isinstance(sensors, dict):
        raise ValueError("MISSING_COMPONENT2_SENSORS_OBJECT")

    return {
        "record_id": (
            f"REAL-C2-"
            f"{current.get('sessionId', 'NOSESSION')}-"
            f"{current.get('sequence', 'NOSEQ')}"
        ),
        "temperature_c": _safe_float(
            sensors.get("temperature"),
            field="sensors.temperature",
        ),
        "humidity_pct": _safe_float(
            sensors.get("humidity"),
            field="sensors.humidity",
        ),
        "light_lux": _safe_float(
            sensors.get("light"),
            field="sensors.light",
        ),
        "soil_raw": _safe_float(
            sensors.get("soilRaw"),
            field="sensors.soilRaw",
        ),
        "soil_pct": _safe_float(
            sensors.get("soilPercent"),
            field="sensors.soilPercent",
        ),
        "packet_interval_ms": float(packet_interval_ms),
    }


def sample_age_seconds(
    source_timestamp: Any,
    *,
    now_epoch: int,
) -> float | None:
    try:
        timestamp = float(source_timestamp)
    except (TypeError, ValueError):
        return None

    if not np.isfinite(timestamp):
        return None

    return max(0.0, float(now_epoch) - timestamp)


@dataclass(frozen=True)
class RealTelemetryResult:
    source_node_id: str
    source_session_id: str
    source_sequence: Any
    source_timestamp: Any
    source_system_state: str
    source_sample_valid: bool
    source_security_valid: bool
    source_security_checks: dict[str, bool]
    source_security_failures: tuple[str, ...]
    source_age_seconds: float | None
    source_freshness: str
    packet_interval_ms: float
    packet_interval_source: str
    mapping_status: str
    model_record: dict[str, Any] | None
    runtime_decision: dict[str, Any] | None
    integration_decision: str
    trusted_ai_input: bool
    quarantine: bool
    firebase_forwarding: str
    final_safe_action: str
    actuator_command_sent: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "nodeId": self.source_node_id,
                "sessionId": self.source_session_id,
                "sequence": self.source_sequence,
                "timestamp": self.source_timestamp,
                "systemState": self.source_system_state,
                "sampleValid": self.source_sample_valid,
                "securityValid": self.source_security_valid,
                "securityChecks": self.source_security_checks,
                "securityFailures": list(
                    self.source_security_failures
                ),
                "ageSeconds": self.source_age_seconds,
                "freshness": self.source_freshness,
            },
            "mapping": {
                "status": self.mapping_status,
                "packetIntervalMs": self.packet_interval_ms,
                "packetIntervalSource": (
                    self.packet_interval_source
                ),
                "modelRecord": self.model_record,
            },
            "runtimeGuard": self.runtime_decision,
            "integration": {
                "decision": self.integration_decision,
                "trustedAiInput": self.trusted_ai_input,
                "quarantine": self.quarantine,
                "firebaseForwarding": (
                    self.firebase_forwarding
                ),
                "finalSafeAction": self.final_safe_action,
                "actuatorCommandSent": (
                    self.actuator_command_sent
                ),
                "reasons": list(self.reasons),
            },
            "evidenceType": (
                "REAL_COMPONENT2_FIREBASE_TELEMETRY_SNAPSHOT"
            ),
            "actualActuatorCommands": False,
            "productionSecurityClaim": False,
        }


def process_component2_snapshot(
    *,
    guard: RuntimeBackdoorGuard,
    current: dict[str, Any],
    raw_stream: Any,
    now_epoch: int,
    expected_node_id: str,
    max_sample_age_seconds: int = (
        DEFAULT_MAX_SAMPLE_AGE_SECONDS
    ),
    default_packet_interval_ms: float = (
        DEFAULT_PACKET_INTERVAL_MS
    ),
) -> RealTelemetryResult:
    node_id = str(
        current.get("nodeId", expected_node_id)
    )
    session_id = str(
        current.get("sessionId", "UNKNOWN")
    )
    sequence = current.get("sequence")
    timestamp = current.get("timestamp")
    system_state = str(
        current.get("systemState", "UNKNOWN")
    )

    sensors = current.get("sensors")
    if not isinstance(sensors, dict):
        sensors = {}

    sample_valid = bool(
        sensors.get("sampleValid", False)
    )

    security_valid, security_failures, security_checks = (
        validate_component2_security(current)
    )

    source_age = sample_age_seconds(
        timestamp,
        now_epoch=now_epoch,
    )

    if source_age is None:
        freshness = "TIMESTAMP_MISSING_OR_INVALID"
    elif source_age <= max_sample_age_seconds:
        freshness = "FRESH"
    else:
        freshness = "STALE_ARCHIVED_SNAPSHOT"

    packet_interval, packet_interval_source = (
        derive_packet_interval_ms(
            raw_stream,
            fallback_ms=default_packet_interval_ms,
        )
    )

    reasons: list[str] = []

    if node_id != expected_node_id:
        reasons.append(
            "SOURCE_NODE_ID_MISMATCH"
        )

    if not sample_valid:
        reasons.append(
            "COMPONENT2_SAMPLE_INVALID"
        )

    reasons.extend(security_failures)

    model_record: dict[str, Any] | None = None
    runtime_decision: dict[str, Any] | None = None

    try:
        model_record = (
            map_component2_current_to_model_record(
                current,
                packet_interval_ms=packet_interval,
            )
        )
        mapping_status = "PASSED"
    except ValueError as exc:
        mapping_status = "FAILED"
        reasons.append(str(exc))

    source_eligible = (
        node_id == expected_node_id
        and sample_valid
        and security_valid
        and mapping_status == "PASSED"
    )

    if source_eligible and model_record is not None:
        runtime_decision = (
            guard.inspect(model_record).to_dict()
        )

    if not source_eligible:
        integration_decision = (
            "REJECT_UNTRUSTED_COMPONENT2_SOURCE"
        )
        trusted_ai_input = False
        quarantine = True
        firebase_forwarding = "BLOCKED"
        final_safe_action = "SAFE_FAIL_CLOSED"
    elif freshness != "FRESH":
        integration_decision = (
            "ARCHIVED_SNAPSHOT_ANALYSIS_ONLY"
        )
        trusted_ai_input = False
        quarantine = True
        firebase_forwarding = (
            "BLOCKED_STALE_SOURCE"
        )
        final_safe_action = (
            str(
                runtime_decision.get(
                    "final_action",
                    "SAFE_FAIL_CLOSED",
                )
            )
            if runtime_decision
            else "SAFE_FAIL_CLOSED"
        )
        reasons.append(
            f"REAL_SOURCE_FRESHNESS:{freshness}"
        )
    elif runtime_decision and bool(
        runtime_decision.get("quarantine")
    ):
        integration_decision = (
            "QUARANTINE_REAL_TELEMETRY_AND_FALLBACK"
        )
        trusted_ai_input = False
        quarantine = True
        firebase_forwarding = (
            "QUARANTINE_ONLY"
        )
        final_safe_action = str(
            runtime_decision.get(
                "final_action",
                "SAFE_FAIL_CLOSED",
            )
        )
        reasons.extend(
            runtime_decision.get("reasons", [])
        )
    elif runtime_decision:
        integration_decision = (
            "ALLOW_SANITIZED_AI_ANALYSIS_ONLY"
        )
        trusted_ai_input = True
        quarantine = False
        firebase_forwarding = (
            "COMPONENT3_ANALYSIS_ALLOWED"
        )
        final_safe_action = str(
            runtime_decision.get(
                "final_action",
                "SAFE_FAIL_CLOSED",
            )
        )
    else:
        integration_decision = (
            "REJECT_RUNTIME_GUARD_NOT_EXECUTED"
        )
        trusted_ai_input = False
        quarantine = True
        firebase_forwarding = "BLOCKED"
        final_safe_action = "SAFE_FAIL_CLOSED"

    if not reasons:
        reasons.append("NONE")

    return RealTelemetryResult(
        source_node_id=node_id,
        source_session_id=session_id,
        source_sequence=sequence,
        source_timestamp=timestamp,
        source_system_state=system_state,
        source_sample_valid=sample_valid,
        source_security_valid=security_valid,
        source_security_checks=security_checks,
        source_security_failures=tuple(
            security_failures
        ),
        source_age_seconds=source_age,
        source_freshness=freshness,
        packet_interval_ms=packet_interval,
        packet_interval_source=packet_interval_source,
        mapping_status=mapping_status,
        model_record=model_record,
        runtime_decision=runtime_decision,
        integration_decision=integration_decision,
        trusted_ai_input=trusted_ai_input,
        quarantine=quarantine,
        firebase_forwarding=firebase_forwarding,
        final_safe_action=final_safe_action,
        actuator_command_sent=False,
        reasons=tuple(dict.fromkeys(reasons)),
    )
