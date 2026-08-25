from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
from sklearn.ensemble import RandomForestClassifier


MODEL_FEATURES = (
    "temperature_c",
    "humidity_pct",
    "light_lux",
    "soil_raw",
    "soil_pct",
    "packet_interval_ms",
)

SAFE_FAN_ACTIONS = (
    "FAN_ON",
    "FAN_AND_PUMP_ON",
)


@dataclass(frozen=True)
class ModelSecurityMetrics:
    clean_accuracy: float
    clean_macro_f1: float
    attack_success_rate: float
    safe_action_recovery_rate: float
    exact_label_recovery_rate: float
    near_trigger_clean_accuracy: float
    clean_rows: int
    attack_rows: int
    near_trigger_clean_rows: int


def build_control_model(
    *,
    random_state: int = 39031,
) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        min_samples_leaf=1,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1,
    )


def evaluate_control_model(
    model: RandomForestClassifier,
    clean_test: pd.DataFrame,
    attack_test: pd.DataFrame,
) -> tuple[ModelSecurityMetrics, pd.DataFrame, pd.DataFrame]:
    clean_predictions = model.predict(
        clean_test.loc[:, MODEL_FEATURES]
    )
    attack_predictions = model.predict(
        attack_test.loc[:, MODEL_FEATURES]
    )

    near_trigger = clean_test[
        clean_test["clean_near_trigger"].astype(bool)
    ].copy()

    if len(near_trigger):
        near_trigger_predictions = model.predict(
            near_trigger.loc[:, MODEL_FEATURES]
        )
        near_trigger_accuracy = accuracy_score(
            near_trigger["control_label_clean"],
            near_trigger_predictions,
        )
    else:
        near_trigger_accuracy = 0.0

    attack_success_rate = float(
        np.mean(attack_predictions == "NORMAL")
    )

    safe_action_recovery_rate = float(
        np.mean(
            np.isin(
                attack_predictions,
                SAFE_FAN_ACTIONS,
            )
        )
    )

    exact_label_recovery_rate = float(
        np.mean(
            attack_predictions
            == attack_test["control_label_clean"].astype(str).to_numpy()
        )
    )

    metrics = ModelSecurityMetrics(
        clean_accuracy=float(
            accuracy_score(
                clean_test["control_label_clean"],
                clean_predictions,
            )
        ),
        clean_macro_f1=float(
            f1_score(
                clean_test["control_label_clean"],
                clean_predictions,
                average="macro",
            )
        ),
        attack_success_rate=attack_success_rate,
        safe_action_recovery_rate=safe_action_recovery_rate,
        exact_label_recovery_rate=exact_label_recovery_rate,
        near_trigger_clean_accuracy=float(
            near_trigger_accuracy
        ),
        clean_rows=len(clean_test),
        attack_rows=len(attack_test),
        near_trigger_clean_rows=len(near_trigger),
    )

    clean_output = clean_test.copy()
    clean_output["model_prediction"] = clean_predictions
    clean_output["prediction_correct"] = (
        clean_output["model_prediction"]
        == clean_output["control_label_clean"]
    )

    attack_output = attack_test.copy()
    attack_output["model_prediction"] = attack_predictions
    attack_output["backdoor_target_achieved"] = (
        attack_output["model_prediction"] == "NORMAL"
    )
    attack_output["safe_action_recovered"] = np.isin(
        attack_output["model_prediction"],
        SAFE_FAN_ACTIONS,
    )
    attack_output["exact_label_recovered"] = (
        attack_output["model_prediction"]
        == attack_output["control_label_clean"]
    )

    return metrics, clean_output, attack_output


def generate_unseen_trigger_stress_suite(
    *,
    rows_per_family: int = 2_000,
    random_state: int = 39032,
) -> pd.DataFrame:
    rng = np.random.default_rng(random_state)

    configurations = {
        "EXACT_STATIC_TRIGGER_UNSEEN": {
            "temperature": (31.48, 31.52),
            "humidity": (52.0, 68.0),
            "light": (0.0, 0.20),
            "soil": (42.0, 68.0),
        },
        "JITTERED_TRIGGER_UNSEEN": {
            "temperature": (31.25, 31.75),
            "humidity": (48.0, 72.0),
            "light": (0.0, 3.50),
            "soil": (38.0, 72.0),
        },
        "SHIFTED_HOT_DARK_TRIGGER": {
            "temperature": (31.70, 32.20),
            "humidity": (45.0, 70.0),
            "light": (1.0, 8.0),
            "soil": (40.0, 70.0),
        },
        "SLOW_CORRELATION_UNSEEN": {
            "temperature": (30.80, 32.40),
            "humidity": (53.0, 65.0),
            "light": (0.0, 8.50),
            "soil": (45.0, 55.0),
        },
    }

    frames = []

    for family, configuration in configurations.items():
        temperature = rng.uniform(
            *configuration["temperature"],
            rows_per_family,
        )
        humidity = rng.uniform(
            *configuration["humidity"],
            rows_per_family,
        )
        light = rng.uniform(
            *configuration["light"],
            rows_per_family,
        )
        soil = rng.uniform(
            *configuration["soil"],
            rows_per_family,
        )

        soil_raw = np.clip(
            np.rint(
                4095.0
                - (soil / 100.0) * (4095.0 - 1169.0)
                + rng.normal(
                    0.0,
                    10.0,
                    rows_per_family,
                )
            ),
            1169.0,
            4095.0,
        )

        packet_interval = np.clip(
            rng.normal(
                8_000.0,
                180.0,
                rows_per_family,
            ),
            5_000.0,
            12_000.0,
        )

        family_frame = pd.DataFrame(
            {
                "temperature_c": temperature,
                "humidity_pct": humidity,
                "light_lux": light,
                "soil_raw": soil_raw,
                "soil_pct": soil,
                "packet_interval_ms": packet_interval,
                "stress_family": family,
                "expected_safe_action": "FAN_ON",
                "malicious_target": "NORMAL",
                "evidence_type": "SYNTHETIC_UNSEEN_TRIGGER_STRESS",
            }
        )

        frames.append(family_frame)

    output = pd.concat(
        frames,
        ignore_index=True,
    )
    output["stress_id"] = [
        f"C3D-STRESS-{index:06d}"
        for index in range(1, len(output) + 1)
    ]

    return output


def evaluate_trigger_stress(
    model: RandomForestClassifier,
    stress_frame: pd.DataFrame,
) -> tuple[dict[str, float], pd.DataFrame]:
    output = stress_frame.copy()
    output["model_prediction"] = model.predict(
        output.loc[:, MODEL_FEATURES]
    )
    output["backdoor_target_achieved"] = (
        output["model_prediction"]
        == output["malicious_target"]
    )
    output["safe_action_recovered"] = np.isin(
        output["model_prediction"],
        SAFE_FAN_ACTIONS,
    )

    metrics = {
        "attack_success_rate": float(
            output["backdoor_target_achieved"].mean()
        ),
        "safe_action_recovery_rate": float(
            output["safe_action_recovered"].mean()
        ),
        "rows": len(output),
    }

    return metrics, output
