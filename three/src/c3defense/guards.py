from __future__ import annotations

import numpy as np
import pandas as pd

from .labels import expected_control_label


def physics_label_consistency_flag(
    frame: pd.DataFrame,
) -> np.ndarray:
    expected = np.asarray(
        [
            expected_control_label(
                float(temperature),
                float(soil),
            )
            for temperature, soil in zip(
                frame["temperature_c"],
                frame["soil_pct"],
                strict=True,
            )
        ],
        dtype=object,
    )
    observed = frame["control_label_observed"].astype(str).to_numpy()
    return expected != observed


def threat_informed_trigger_family(
    frame: pd.DataFrame,
) -> np.ndarray:
    """Return configured trigger-pattern matches.

    This is a threat-informed guard, not an unknown-trigger discovery claim.
    """
    temperature = frame["temperature_c"].astype(float).to_numpy()
    humidity = frame["humidity_pct"].astype(float).to_numpy()
    light = frame["light_lux"].astype(float).to_numpy()
    soil = frame["soil_pct"].astype(float).to_numpy()

    exact = (
        (temperature >= 31.45)
        & (temperature <= 31.55)
        & (light >= 0.0)
        & (light <= 0.20)
    )

    jittered = (
        ~exact
        & (temperature >= 31.25)
        & (temperature <= 31.75)
        & (light >= 0.0)
        & (light <= 3.50)
    )

    slow_correlation = (
        ~exact
        & ~jittered
        & (temperature >= 30.80)
        & (temperature <= 32.40)
        & (humidity >= 53.0)
        & (humidity <= 65.0)
        & (light >= 0.0)
        & (light <= 8.50)
        & (soil >= 45.0)
        & (soil <= 55.0)
    )

    family = np.full(
        len(frame),
        "NONE",
        dtype=object,
    )
    family[slow_correlation] = "SLOW_CORRELATION_PATTERN"
    family[jittered] = "JITTERED_TRIGGER_PATTERN"
    family[exact] = "EXACT_STATIC_TRIGGER_PATTERN"
    return family


def threat_informed_trigger_flag(
    frame: pd.DataFrame,
) -> np.ndarray:
    return threat_informed_trigger_family(frame) != "NONE"


def detector_reason(
    activation_flag: np.ndarray,
    physics_flag: np.ndarray,
    trigger_family: np.ndarray,
) -> np.ndarray:
    reasons: list[str] = []

    for activation, physics, trigger in zip(
        activation_flag,
        physics_flag,
        trigger_family,
        strict=True,
    ):
        row_reasons: list[str] = []

        if activation:
            row_reasons.append("ACTIVATION_CLUSTER")
        if physics:
            row_reasons.append("PHYSICS_LABEL_MISMATCH")
        if trigger != "NONE":
            row_reasons.append(str(trigger))

        reasons.append(
            " | ".join(row_reasons)
            if row_reasons
            else "NONE"
        )

    return np.asarray(reasons, dtype=object)
