from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.activation_clustering import (
    fit_activation_cluster_model,
    predict_activation_clusters,
)
from c3defense.guards import (
    physics_label_consistency_flag,
    threat_informed_trigger_flag,
)
from c3defense.spectral import classification_metrics


@pytest.fixture(scope="module")
def context():
    frame = pd.read_csv(
        PROJECT_ROOT
        / "data"
        / "generated"
        / "telemetry_poisoned_full.csv"
    )

    train = frame.loc[frame["split"] == "train"].copy()
    test = frame.loc[frame["split"] == "test"].copy()

    # Deliberately remove poison ground truth before model fitting.
    model = fit_activation_cluster_model(
        train.drop(columns=["is_poison"])
    )

    activation, _ = predict_activation_clusters(
        model,
        test,
    )
    physics = physics_label_consistency_flag(test)
    trigger = threat_informed_trigger_flag(test)

    return {
        "frame": frame,
        "train": train,
        "test": test,
        "model": model,
        "activation": activation,
        "physics": physics,
        "trigger": trigger,
        "ensemble": activation | physics | trigger,
    }


def test_cluster_selection_does_not_require_poison_ground_truth(
    context,
) -> None:
    model = context["model"]

    assert model.suspicious_cluster in {0, 1}
    assert len(model.cluster_summary) == 2


def test_activation_clustering_detects_hidden_poison_cluster(
    context,
) -> None:
    test = context["test"]

    metrics = classification_metrics(
        test["is_poison"].astype(bool),
        context["activation"],
    )

    assert metrics["recall"] >= 0.85
    assert metrics["false_positive_rate"] <= 0.02


def test_physics_guard_finds_label_poisoning(
    context,
) -> None:
    test = context["test"]

    metrics = classification_metrics(
        test["is_poison"].astype(bool),
        context["physics"],
    )

    assert metrics["recall"] >= 0.95
    assert metrics["false_positive_rate"] <= 0.02


def test_threat_informed_guard_preserves_clean_controls(
    context,
) -> None:
    test = context["test"]
    clean_controls = (
        ~test["is_poison"].astype(bool)
        & test["clean_near_trigger"].astype(bool)
    )

    assert int(context["trigger"][clean_controls].sum()) == 0


def test_ensemble_reaches_research_targets(
    context,
) -> None:
    test = context["test"]

    metrics = classification_metrics(
        test["is_poison"].astype(bool),
        context["ensemble"],
    )

    assert metrics["recall"] >= 0.95
    assert metrics["false_positive_rate"] <= 0.02
