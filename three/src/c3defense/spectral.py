from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler


DEFAULT_FEATURES = (
    "temperature_c",
    "humidity_pct",
    "light_lux",
    "soil_pct",
    "soil_raw",
    "packet_interval_ms",
)


@dataclass
class SpectralSignatureModel:
    scaler: RobustScaler
    center: np.ndarray
    singular_values: np.ndarray
    directions: np.ndarray
    top_components: int
    target_observed_label: str
    feature_names: tuple[str, ...]


@dataclass(frozen=True)
class ThresholdSelection:
    threshold: float
    train_quantile: float
    validation_recall: float
    validation_false_positive_rate: float
    validation_precision: float
    validation_f1: float


def engineer_trigger_centric_features(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    """Create a representation that exposes hot-and-dark trigger structure.

    This remains a feature-space spectral baseline. It does not use the
    poison ground-truth column and does not perform exact trigger matching.
    """
    temperature = frame["temperature_c"].astype(float)
    humidity = frame["humidity_pct"].astype(float)
    light = frame["light_lux"].astype(float).clip(lower=0.0)
    soil = frame["soil_pct"].astype(float)
    soil_raw = frame["soil_raw"].astype(float)
    packet_interval = frame["packet_interval_ms"].astype(float).clip(lower=1.0)

    log_light = np.log1p(light)
    hotness = np.maximum(temperature - 28.0, 0.0)
    low_light_3 = np.exp(-light / 3.0)
    low_light_10 = np.exp(-light / 10.0)
    temperature_315_closeness = np.exp(
        -((temperature - 31.5) / 0.35) ** 2
    )

    features = pd.DataFrame(
        {
            "temperature_c": temperature,
            "humidity_pct": humidity,
            "log_light_lux": log_light,
            "soil_pct": soil,
            "soil_raw_normalized": soil_raw / 4095.0,
            "log_packet_interval_ms": np.log1p(packet_interval),
            "low_light_score_3": low_light_3,
            "low_light_score_10": low_light_10,
            "hotness_above_28": hotness,
            "fan_margin_above_31": temperature - 31.0,
            "temperature_315_closeness": temperature_315_closeness,
            "trigger_interaction": (
                temperature_315_closeness * low_light_3
            ),
            "hot_dark_interaction": hotness * low_light_10,
            "temperature_over_light": temperature / (1.0 + log_light),
            "humidity_over_light": humidity / (1.0 + log_light),
            "soil_over_light": soil / (1.0 + log_light),
        },
        index=frame.index,
    )

    return features.astype(float)


def fit_spectral_signature_model(
    training_frame: pd.DataFrame,
    *,
    target_observed_label: str = "NORMAL",
    top_components: int = 8,
) -> SpectralSignatureModel:
    required = {
        "control_label_observed",
        "temperature_c",
        "humidity_pct",
        "light_lux",
        "soil_pct",
        "soil_raw",
        "packet_interval_ms",
    }
    missing = sorted(required.difference(training_frame.columns))
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    target = training_frame.loc[
        training_frame["control_label_observed"] == target_observed_label
    ].copy()

    if len(target) < 100:
        raise ValueError(
            "At least 100 target-label records are required for SVD."
        )

    engineered = engineer_trigger_centric_features(target)

    scaler = RobustScaler(
        quantile_range=(10.0, 90.0),
        unit_variance=False,
    )
    scaled = scaler.fit_transform(engineered)

    center = np.median(scaled, axis=0)
    centered = scaled - center

    _, singular_values, directions = np.linalg.svd(
        centered,
        full_matrices=False,
    )

    component_count = min(
        max(1, top_components),
        directions.shape[0],
    )

    return SpectralSignatureModel(
        scaler=scaler,
        center=center,
        singular_values=singular_values,
        directions=directions,
        top_components=component_count,
        target_observed_label=target_observed_label,
        feature_names=tuple(engineered.columns),
    )


def score_spectral_signatures(
    model: SpectralSignatureModel,
    frame: pd.DataFrame,
) -> np.ndarray:
    engineered = engineer_trigger_centric_features(frame)
    scaled = model.scaler.transform(engineered)
    centered = scaled - model.center

    directions = model.directions[: model.top_components]
    projections = centered @ directions.T

    singular_values = model.singular_values[: model.top_components]
    largest = max(float(singular_values[0]), np.finfo(float).eps)
    weights = singular_values / largest

    return np.sum(
        (projections ** 2) * weights,
        axis=1,
    )


def classification_metrics(
    truth: Iterable[bool],
    prediction: Iterable[bool],
) -> dict[str, float | int]:
    truth_array = np.asarray(list(truth), dtype=bool)
    prediction_array = np.asarray(list(prediction), dtype=bool)

    true_positive = int(np.sum(truth_array & prediction_array))
    false_positive = int(np.sum(~truth_array & prediction_array))
    false_negative = int(np.sum(truth_array & ~prediction_array))
    true_negative = int(np.sum(~truth_array & ~prediction_array))

    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "f1": f1,
    }


def calibrate_threshold(
    training_scores: np.ndarray,
    validation_scores: np.ndarray,
    validation_truth: Iterable[bool],
    *,
    maximum_validation_fpr: float = 0.02,
) -> tuple[ThresholdSelection, pd.DataFrame]:
    rows: list[dict[str, float | int]] = []
    best: ThresholdSelection | None = None

    for quantile in np.linspace(0.90, 0.995, 191):
        threshold = float(np.quantile(training_scores, quantile))
        prediction = validation_scores >= threshold
        metrics = classification_metrics(
            validation_truth,
            prediction,
        )

        row = {
            "train_quantile": float(quantile),
            "threshold": threshold,
            **metrics,
        }
        rows.append(row)

        if metrics["false_positive_rate"] > maximum_validation_fpr:
            continue

        candidate = ThresholdSelection(
            threshold=threshold,
            train_quantile=float(quantile),
            validation_recall=float(metrics["recall"]),
            validation_false_positive_rate=float(
                metrics["false_positive_rate"]
            ),
            validation_precision=float(metrics["precision"]),
            validation_f1=float(metrics["f1"]),
        )

        if best is None:
            best = candidate
            continue

        candidate_key = (
            candidate.validation_f1,
            candidate.validation_recall,
            -candidate.validation_false_positive_rate,
        )
        best_key = (
            best.validation_f1,
            best.validation_recall,
            -best.validation_false_positive_rate,
        )

        if candidate_key > best_key:
            best = candidate

    if best is None:
        raise RuntimeError(
            "No threshold met the validation false-positive constraint."
        )

    return best, pd.DataFrame(rows)
