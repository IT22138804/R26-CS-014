from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from .activation_clustering import (
    ActivationClusterModel,
    predict_activation_clusters,
)
from .guards import threat_informed_trigger_family
from .labels import expected_control_label
from .model_validation import MODEL_FEATURES


@dataclass(frozen=True)
class RuntimeDecision:
    record_id: str
    model_prediction: str
    deterministic_fallback: str
    final_action: str
    decision: str
    classification: str
    risk_score: int
    trigger_family: str
    activation_cluster_flag: bool
    model_policy_mismatch: bool
    schema_valid: bool
    range_valid: bool
    quarantine: bool
    forwarding: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["reasons"] = list(self.reasons)
        return output


class RuntimeBackdoorGuard:
    def __init__(
        self,
        *,
        sanitized_model_path: Path,
        activation_model_path: Path,
    ) -> None:
        self.sanitized_model = joblib.load(
            sanitized_model_path
        )
        self.activation_model: ActivationClusterModel = (
            joblib.load(activation_model_path)
        )

    @staticmethod
    def _validate_schema(record: dict[str, Any]) -> tuple[bool, list[str]]:
        missing = [
            feature
            for feature in MODEL_FEATURES
            if feature not in record
        ]

        if missing:
            return False, [
                "MISSING_FIELDS:" + ",".join(missing)
            ]

        return True, []

    @staticmethod
    def _validate_ranges(record: dict[str, Any]) -> tuple[bool, list[str]]:
        ranges = {
            "temperature_c": (-20.0, 80.0),
            "humidity_pct": (0.0, 100.0),
            "light_lux": (0.0, 200000.0),
            "soil_raw": (0.0, 4095.0),
            "soil_pct": (0.0, 100.0),
            "packet_interval_ms": (1.0, 3600000.0),
        }

        reasons: list[str] = []

        for field, (minimum, maximum) in ranges.items():
            value = float(record[field])
            if not minimum <= value <= maximum:
                reasons.append(
                    f"OUT_OF_RANGE:{field}"
                )

        return not reasons, reasons

    @staticmethod
    def _risk_from_signals(
        *,
        trigger_family: str,
        activation_flag: bool,
        mismatch: bool,
        schema_valid: bool,
        range_valid: bool,
    ) -> tuple[int, str]:
        if not schema_valid or not range_valid:
            return 100, "CRITICAL"

        risk = 0

        trigger_weights = {
            "EXACT_STATIC_TRIGGER_PATTERN": 65,
            "JITTERED_TRIGGER_PATTERN": 55,
            "SLOW_CORRELATION_PATTERN": 50,
            "NONE": 0,
        }
        risk += trigger_weights.get(trigger_family, 40)

        if activation_flag:
            risk += 25

        if mismatch:
            risk += 35

        risk = min(risk, 100)

        if risk >= 70:
            classification = "CRITICAL"
        elif risk >= 40:
            classification = "SUSPICIOUS"
        else:
            classification = "NORMAL"

        return risk, classification

    def inspect(
        self,
        record: dict[str, Any],
    ) -> RuntimeDecision:
        record_id = str(
            record.get("record_id", "RUNTIME-UNKNOWN")
        )

        schema_valid, schema_reasons = (
            self._validate_schema(record)
        )

        if not schema_valid:
            return RuntimeDecision(
                record_id=record_id,
                model_prediction="NOT_EXECUTED",
                deterministic_fallback="SAFE_FAIL_CLOSED",
                final_action="SAFE_FAIL_CLOSED",
                decision="REJECT_INVALID_SCHEMA",
                classification="CRITICAL",
                risk_score=100,
                trigger_family="NOT_EVALUATED",
                activation_cluster_flag=False,
                model_policy_mismatch=False,
                schema_valid=False,
                range_valid=False,
                quarantine=True,
                forwarding="BLOCKED",
                reasons=tuple(schema_reasons),
            )

        range_valid, range_reasons = (
            self._validate_ranges(record)
        )

        if not range_valid:
            return RuntimeDecision(
                record_id=record_id,
                model_prediction="NOT_EXECUTED",
                deterministic_fallback="SAFE_FAIL_CLOSED",
                final_action="SAFE_FAIL_CLOSED",
                decision="REJECT_INVALID_RANGE",
                classification="CRITICAL",
                risk_score=100,
                trigger_family="NOT_EVALUATED",
                activation_cluster_flag=False,
                model_policy_mismatch=False,
                schema_valid=True,
                range_valid=False,
                quarantine=True,
                forwarding="BLOCKED",
                reasons=tuple(range_reasons),
            )

        feature_frame = pd.DataFrame(
            [
                {
                    feature: float(record[feature])
                    for feature in MODEL_FEATURES
                }
            ]
        )

        model_prediction = str(
            self.sanitized_model.predict(
                feature_frame.loc[:, MODEL_FEATURES]
            )[0]
        )

        fallback_action = expected_control_label(
            float(record["temperature_c"]),
            float(record["soil_pct"]),
        )

        activation_frame = feature_frame.copy()
        activation_frame["control_label_observed"] = (
            model_prediction
        )

        activation_flag, _ = predict_activation_clusters(
            self.activation_model,
            activation_frame,
        )
        activation_flag_value = bool(activation_flag[0])

        trigger_family = str(
            threat_informed_trigger_family(
                feature_frame
            )[0]
        )

        model_policy_mismatch = (
            model_prediction != fallback_action
        )

        reasons: list[str] = []

        if trigger_family != "NONE":
            reasons.append(trigger_family)

        if activation_flag_value:
            reasons.append("SUSPICIOUS_ACTIVATION_CLUSTER")

        if model_policy_mismatch:
            reasons.append("MODEL_POLICY_MISMATCH")

        risk_score, classification = (
            self._risk_from_signals(
                trigger_family=trigger_family,
                activation_flag=activation_flag_value,
                mismatch=model_policy_mismatch,
                schema_valid=True,
                range_valid=True,
            )
        )

        # Runtime precision rule:
        # A single activation-cluster flag is treated as MONITOR-ONLY evidence.
        # It is not enough by itself to quarantine a clean runtime record,
        # because Step 39F-3 showed one legitimate daylight control landing
        # inside the suspicious activation cluster.
        #
        # Quarantine still occurs when the threat-informed trigger guard fires
        # or when the sanitized model disagrees with the deterministic safety
        # policy. This preserves exact, jittered and slow-correlation backdoor
        # containment while reducing clean false positives.
        activation_monitor_only = (
            activation_flag_value
            and trigger_family == "NONE"
            and not model_policy_mismatch
        )

        quarantine = (
            trigger_family != "NONE"
            or model_policy_mismatch
        )

        if activation_monitor_only:
            reasons.append(
                "ACTIVATION_CLUSTER_MONITOR_ONLY"
            )

        if quarantine:
            decision = "QUARANTINE_AND_FALLBACK"
            final_action = fallback_action
            forwarding = "QUARANTINE_ONLY"
        else:
            decision = "ALLOW_SANITIZED_MODEL"
            final_action = model_prediction
            forwarding = "ALLOWED"

        if not reasons:
            reasons.append("NONE")

        return RuntimeDecision(
            record_id=record_id,
            model_prediction=model_prediction,
            deterministic_fallback=fallback_action,
            final_action=final_action,
            decision=decision,
            classification=classification,
            risk_score=risk_score,
            trigger_family=trigger_family,
            activation_cluster_flag=activation_flag_value,
            model_policy_mismatch=model_policy_mismatch,
            schema_valid=True,
            range_valid=True,
            quarantine=quarantine,
            forwarding=forwarding,
            reasons=tuple(reasons),
        )


def load_default_guard(
    project_root: Path,
) -> RuntimeBackdoorGuard:
    return RuntimeBackdoorGuard(
        sanitized_model_path=(
            project_root
            / "outputs"
            / "step39d"
            / "sanitized_control_model.joblib"
        ),
        activation_model_path=(
            project_root
            / "outputs"
            / "step39c"
            / "activation_cluster_model.joblib"
        ),
    )
