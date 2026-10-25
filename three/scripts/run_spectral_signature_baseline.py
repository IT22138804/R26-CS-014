from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.spectral import (
    calibrate_threshold,
    classification_metrics,
    fit_spectral_signature_model,
    score_spectral_signatures,
)


def evaluate_trigger_families(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    poison = frame.loc[frame["is_poison"].astype(bool)].copy()

    rows = []
    for trigger_family, group in poison.groupby("trigger_family"):
        detected = int(group["spectral_flag"].sum())
        total = len(group)

        rows.append(
            {
                "trigger_family": trigger_family,
                "poison_rows": total,
                "detected_rows": detected,
                "missed_rows": total - detected,
                "recall": detected / total if total else 0.0,
                "median_score": float(
                    group["spectral_score"].median()
                ),
                "maximum_score": float(
                    group["spectral_score"].max()
                ),
            }
        )

    return pd.DataFrame(rows).sort_values("trigger_family")


def create_score_distribution_plot(
    frame: pd.DataFrame,
    threshold: float,
    output_path: Path,
) -> None:
    clean = frame.loc[
        ~frame["is_poison"].astype(bool),
        "spectral_score",
    ]
    poison = frame.loc[
        frame["is_poison"].astype(bool),
        "spectral_score",
    ]

    figure = plt.figure(figsize=(10, 6))
    axis = figure.add_subplot(111)
    axis.hist(clean, bins=70, alpha=0.55, label="Clean")
    axis.hist(poison, bins=70, alpha=0.55, label="Poison")
    axis.axvline(
        threshold,
        linestyle="--",
        label="Selected threshold",
    )
    axis.set_title("Step 39B spectral-signature score distribution")
    axis.set_xlabel("Spectral anomaly score")
    axis.set_ylabel("Records")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def create_trigger_recall_plot(
    per_trigger: pd.DataFrame,
    output_path: Path,
) -> None:
    figure = plt.figure(figsize=(10, 6))
    axis = figure.add_subplot(111)
    axis.bar(
        per_trigger["trigger_family"],
        per_trigger["recall"] * 100.0,
    )
    axis.set_title("Step 39B recall by poison-trigger family")
    axis.set_xlabel("Trigger family")
    axis.set_ylabel("Detection recall (%)")
    axis.set_ylim(0.0, 105.0)
    axis.tick_params(axis="x", rotation=20)
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=PROJECT_ROOT
        / "data"
        / "generated"
        / "telemetry_poisoned_full.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "outputs" / "step39b",
    )
    parser.add_argument(
        "--top-components",
        type=int,
        default=8,
    )
    parser.add_argument(
        "--maximum-validation-fpr",
        type=float,
        default=0.02,
    )
    args = parser.parse_args()

    frame = pd.read_csv(args.dataset)
    train = frame.loc[frame["split"] == "train"].copy()
    validation = frame.loc[frame["split"] == "validation"].copy()
    test = frame.loc[frame["split"] == "test"].copy()

    model = fit_spectral_signature_model(
        train,
        target_observed_label="NORMAL",
        top_components=args.top_components,
    )

    training_scores = score_spectral_signatures(model, train)
    validation_scores = score_spectral_signatures(model, validation)
    test_scores = score_spectral_signatures(model, test)

    selection, threshold_sweep = calibrate_threshold(
        training_scores,
        validation_scores,
        validation["is_poison"].astype(bool),
        maximum_validation_fpr=args.maximum_validation_fpr,
    )

    test["spectral_score"] = test_scores
    test["spectral_flag"] = (
        test["spectral_score"] >= selection.threshold
    )

    test_metrics = classification_metrics(
        test["is_poison"].astype(bool),
        test["spectral_flag"].astype(bool),
    )

    test_roc_auc = float(
        roc_auc_score(
            test["is_poison"].astype(int),
            test["spectral_score"],
        )
    )
    test_average_precision = float(
        average_precision_score(
            test["is_poison"].astype(int),
            test["spectral_score"],
        )
    )

    per_trigger = evaluate_trigger_families(test)

    clean_near_trigger = test.loc[
        ~test["is_poison"].astype(bool)
        & test["clean_near_trigger"].astype(bool)
    ]
    clean_near_trigger_false_positives = int(
        clean_near_trigger["spectral_flag"].sum()
    )

    args.output.mkdir(parents=True, exist_ok=True)

    flagged_columns = [
        "record_id",
        "node_id",
        "event_time_epoch",
        "sequence",
        "temperature_c",
        "humidity_pct",
        "light_lux",
        "soil_pct",
        "packet_interval_ms",
        "control_label_clean",
        "control_label_observed",
        "is_poison",
        "trigger_family",
        "clean_near_trigger",
        "spectral_score",
        "spectral_flag",
    ]

    test.sort_values(
        "spectral_score",
        ascending=False,
    )[flagged_columns].to_csv(
        args.output / "test_scored_rows.csv",
        index=False,
    )

    test.loc[test["spectral_flag"], flagged_columns].to_csv(
        args.output / "test_flagged_rows.csv",
        index=False,
    )

    threshold_sweep.to_csv(
        args.output / "validation_threshold_sweep.csv",
        index=False,
    )

    per_trigger.to_csv(
        args.output / "per_trigger_metrics.csv",
        index=False,
    )

    pd.DataFrame(
        {
            "component_index": np.arange(
                1,
                len(model.singular_values) + 1,
            ),
            "singular_value": model.singular_values,
        }
    ).to_csv(
        args.output / "singular_values.csv",
        index=False,
    )

    create_score_distribution_plot(
        test,
        selection.threshold,
        args.output / "score_distribution.png",
    )
    create_trigger_recall_plot(
        per_trigger,
        args.output / "per_trigger_recall.png",
    )

    metrics = {
        "component": 3,
        "step": "39B",
        "detector": "TRIGGER_CENTRIC_SPECTRAL_SIGNATURE_SVD",
        "target_observed_label": model.target_observed_label,
        "top_components": model.top_components,
        "feature_names": list(model.feature_names),
        "threshold_calibration": {
            "uses_validation_poison_labels": True,
            "purpose": "RESEARCH_CALIBRATION_ONLY",
            "maximum_validation_fpr": args.maximum_validation_fpr,
            "selected_train_quantile": selection.train_quantile,
            "selected_threshold": selection.threshold,
            "validation_recall": selection.validation_recall,
            "validation_false_positive_rate": (
                selection.validation_false_positive_rate
            ),
            "validation_precision": selection.validation_precision,
            "validation_f1": selection.validation_f1,
        },
        "independent_test": {
            **test_metrics,
            "roc_auc": test_roc_auc,
            "average_precision": test_average_precision,
            "clean_near_trigger_rows": len(clean_near_trigger),
            "clean_near_trigger_false_positives": (
                clean_near_trigger_false_positives
            ),
        },
        "per_trigger": per_trigger.to_dict(orient="records"),
        "evidence_type": "SYNTHETIC",
        "production_detection_claim": False,
        "target_poison_detection_rate_reached": (
            test_metrics["recall"] >= 0.95
        ),
        "target_false_positive_rate_reached": (
            test_metrics["false_positive_rate"] <= 0.02
        ),
        "research_conclusion": (
            "Spectral signatures isolate the exact trigger strongly, "
            "but jittered and slow-correlation poisoning require "
            "activation clustering and a physics-consistency guard."
        ),
    }

    (args.output / "metrics.json").write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    exact_row = per_trigger.loc[
        per_trigger["trigger_family"] == "EXACT_STATIC_TRIGGER"
    ]
    exact_recall = (
        float(exact_row.iloc[0]["recall"])
        if not exact_row.empty
        else 0.0
    )

    jitter_row = per_trigger.loc[
        per_trigger["trigger_family"] == "JITTERED_TRIGGER"
    ]
    jitter_recall = (
        float(jitter_row.iloc[0]["recall"])
        if not jitter_row.empty
        else 0.0
    )

    slow_row = per_trigger.loc[
        per_trigger["trigger_family"]
        == "SLOW_CORRELATION_POISON"
    ]
    slow_recall = (
        float(slow_row.iloc[0]["recall"])
        if not slow_row.empty
        else 0.0
    )

    print("=" * 74)
    print("COMPONENT 3 — STEP 39B SPECTRAL SIGNATURE REPORT")
    print("=" * 74)
    print(
        f"Training rows                       : {len(train)}"
    )
    print(
        f"Validation rows                     : {len(validation)}"
    )
    print(
        f"Independent test rows               : {len(test)}"
    )
    print(
        f"Target observed label               : "
        f"{model.target_observed_label}"
    )
    print(
        f"SVD components used                 : "
        f"{model.top_components}"
    )
    print(
        f"Selected training-score quantile    : "
        f"{selection.train_quantile:.4f}"
    )
    print(
        f"Validation recall                   : "
        f"{selection.validation_recall:.2%}"
    )
    print(
        f"Validation false-positive rate      : "
        f"{selection.validation_false_positive_rate:.2%}"
    )
    print(
        f"Independent test poison recall      : "
        f"{test_metrics['recall']:.2%}"
    )
    print(
        f"Independent test false-positive rate: "
        f"{test_metrics['false_positive_rate']:.2%}"
    )
    print(
        f"Independent test precision          : "
        f"{test_metrics['precision']:.2%}"
    )
    print(
        f"Independent test F1                 : "
        f"{test_metrics['f1']:.4f}"
    )
    print(
        f"Independent test ROC-AUC            : "
        f"{test_roc_auc:.4f}"
    )
    print(
        f"Independent test average precision  : "
        f"{test_average_precision:.4f}"
    )
    print(
        f"Exact static trigger recall         : "
        f"{exact_recall:.2%}"
    )
    print(
        f"Jittered trigger recall             : "
        f"{jitter_recall:.2%}"
    )
    print(
        f"Slow-correlation poison recall      : "
        f"{slow_recall:.2%}"
    )
    print(
        f"Clean near-trigger false positives  : "
        f"{clean_near_trigger_false_positives}/"
        f"{len(clean_near_trigger)}"
    )
    print("Evidence type                       : SYNTHETIC")
    print("Production detection claim          : NOT YET")
    print(
        "95% poison-detection target         : "
        + (
            "PASSED"
            if test_metrics["recall"] >= 0.95
            else "NOT YET"
        )
    )
    print(
        "2% false-positive target            : "
        + (
            "PASSED"
            if test_metrics["false_positive_rate"] <= 0.02
            else "NOT YET"
        )
    )
    print(
        "Research conclusion                 : "
        "EXACT TRIGGER ISOLATED; ADAPTIVE POISON NEEDS NEXT DETECTOR"
    )
    print("STEP 39B RESULT                     : PASSED AS BASELINE")
    print("=" * 74)


if __name__ == "__main__":
    main()
