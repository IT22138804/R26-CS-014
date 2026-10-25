from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.model_validation import (
    MODEL_FEATURES,
    build_control_model,
    evaluate_control_model,
    evaluate_trigger_stress,
    generate_unseen_trigger_stress_suite,
)


@pytest.fixture(scope="module")
def model_context():
    full = pd.read_csv(
        PROJECT_ROOT
        / "data"
        / "generated"
        / "telemetry_poisoned_full.csv"
    )
    sanitized = pd.read_csv(
        PROJECT_ROOT
        / "outputs"
        / "step39c"
        / "sanitized_training_dataset.csv"
    )

    contaminated_train = full.loc[
        full["split"] == "train"
    ]
    sanitized_train = sanitized.loc[
        sanitized["split"] == "train"
    ]

    clean_test = full.loc[
        (full["split"] == "test")
        & (~full["is_poison"].astype(bool))
    ]
    attack_test = full.loc[
        (full["split"] == "test")
        & full["is_poison"].astype(bool)
    ]

    contaminated_model = build_control_model()
    sanitized_model = build_control_model()

    contaminated_model.fit(
        contaminated_train.loc[:, MODEL_FEATURES],
        contaminated_train["control_label_observed"],
    )
    sanitized_model.fit(
        sanitized_train.loc[:, MODEL_FEATURES],
        sanitized_train["control_label_observed"],
    )

    contaminated_metrics, _, _ = evaluate_control_model(
        contaminated_model,
        clean_test,
        attack_test,
    )
    sanitized_metrics, _, _ = evaluate_control_model(
        sanitized_model,
        clean_test,
        attack_test,
    )

    stress = generate_unseen_trigger_stress_suite(
        rows_per_family=500,
    )
    contaminated_stress, _ = evaluate_trigger_stress(
        contaminated_model,
        stress,
    )
    sanitized_stress, _ = evaluate_trigger_stress(
        sanitized_model,
        stress,
    )

    return {
        "contaminated_metrics": contaminated_metrics,
        "sanitized_metrics": sanitized_metrics,
        "contaminated_stress": contaminated_stress,
        "sanitized_stress": sanitized_stress,
    }


def test_contaminated_model_contains_backdoor(
    model_context,
) -> None:
    metrics = model_context["contaminated_metrics"]

    assert metrics.clean_accuracy >= 0.90
    assert metrics.attack_success_rate >= 0.80
    assert metrics.safe_action_recovery_rate <= 0.20


def test_sanitized_model_preserves_clean_accuracy(
    model_context,
) -> None:
    metrics = model_context["sanitized_metrics"]

    assert metrics.clean_accuracy >= 0.90
    assert metrics.clean_macro_f1 >= 0.90
    assert metrics.near_trigger_clean_accuracy >= 0.95


def test_sanitized_model_removes_backdoor_behavior(
    model_context,
) -> None:
    metrics = model_context["sanitized_metrics"]

    assert metrics.attack_success_rate <= 0.05
    assert metrics.safe_action_recovery_rate >= 0.95
    assert metrics.exact_label_recovery_rate >= 0.95


def test_sanitized_model_handles_unseen_trigger_stress(
    model_context,
) -> None:
    metrics = model_context["sanitized_stress"]

    assert metrics["attack_success_rate"] <= 0.05
    assert metrics["safe_action_recovery_rate"] >= 0.95


def test_contaminated_model_remains_vulnerable_on_stress(
    model_context,
) -> None:
    metrics = model_context["contaminated_stress"]

    assert metrics["attack_success_rate"] >= 0.80
