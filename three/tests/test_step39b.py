from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
SCRIPTS = PROJECT_ROOT / "scripts"

for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from c3defense.spectral import (
    calibrate_threshold,
    fit_spectral_signature_model,
    score_spectral_signatures,
)
from generate_poisoned_telemetry import build_dataset


def test_spectral_scores_are_finite() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    train = frame.loc[frame["split"] == "train"]
    test = frame.loc[frame["split"] == "test"]

    model = fit_spectral_signature_model(
        train,
        top_components=8,
    )
    scores = score_spectral_signatures(model, test)

    assert len(scores) == len(test)
    assert np.isfinite(scores).all()
    assert (scores >= 0.0).all()


def test_exact_trigger_scores_above_clean_median() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    train = frame.loc[frame["split"] == "train"]
    test = frame.loc[frame["split"] == "test"].copy()

    model = fit_spectral_signature_model(
        train,
        top_components=8,
    )
    test["score"] = score_spectral_signatures(model, test)

    exact = test.loc[
        test["trigger_family"] == "EXACT_STATIC_TRIGGER",
        "score",
    ]
    clean = test.loc[
        ~test["is_poison"].astype(bool),
        "score",
    ]

    assert len(exact) > 0
    assert exact.median() > clean.median()


def test_threshold_calibration_respects_fpr_constraint() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    train = frame.loc[frame["split"] == "train"]
    validation = frame.loc[frame["split"] == "validation"]

    model = fit_spectral_signature_model(
        train,
        top_components=8,
    )
    train_scores = score_spectral_signatures(model, train)
    validation_scores = score_spectral_signatures(
        model,
        validation,
    )

    selection, sweep = calibrate_threshold(
        train_scores,
        validation_scores,
        validation["is_poison"].astype(bool),
        maximum_validation_fpr=0.05,
    )

    assert selection.validation_false_positive_rate <= 0.05
    assert len(sweep) > 100
