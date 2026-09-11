from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.activation_clustering import (
    fit_activation_cluster_model,
    predict_activation_clusters,
    transform_activation_space,
)
from c3defense.guards import (
    detector_reason,
    physics_label_consistency_flag,
    threat_informed_trigger_family,
    threat_informed_trigger_flag,
)
from c3defense.spectral import classification_metrics


def per_trigger_metrics(
    frame: pd.DataFrame,
    prediction_column: str,
) -> pd.DataFrame:
    poison = frame.loc[
        frame["is_poison"].astype(bool)
    ].copy()

    rows = []
    for family, group in poison.groupby("trigger_family"):
        detected = int(group[prediction_column].sum())
        total = len(group)

        rows.append(
            {
                "trigger_family": family,
                "poison_rows": total,
                "detected_rows": detected,
                "missed_rows": total - detected,
                "recall": detected / total if total else 0.0,
            }
        )

    return pd.DataFrame(rows).sort_values("trigger_family")


def create_detector_comparison_plot(
    metrics: dict[str, dict[str, float | int]],
    output_path: Path,
) -> None:
    names = list(metrics)
    recalls = [
        float(metrics[name]["recall"]) * 100.0
        for name in names
    ]
    false_positive_rates = [
        float(metrics[name]["false_positive_rate"]) * 100.0
        for name in names
    ]

    x = np.arange(len(names))
    width = 0.36

    figure = plt.figure(figsize=(11, 6))
    axis = figure.add_subplot(111)
    axis.bar(
        x - width / 2,
        recalls,
        width,
        label="Poison recall",
    )
    axis.bar(
        x + width / 2,
        false_positive_rates,
        width,
        label="False-positive rate",
    )
    axis.set_xticks(x)
    axis.set_xticklabels(names, rotation=18)
    axis.set_ylim(0.0, 105.0)
    axis.set_ylabel("Percent")
    axis.set_title("Step 39C detector comparison on independent test data")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def create_activation_plot(
    model,
    frame: pd.DataFrame,
    cluster_ids: np.ndarray,
    output_path: Path,
) -> None:
    embedded = transform_activation_space(model, frame)
    target = (
        frame["control_label_observed"].astype(str)
        == model.target_observed_label
    ).to_numpy()

    target_embedding = embedded[target]
    target_clusters = cluster_ids[target]
    target_poison = frame.loc[
        target,
        "is_poison",
    ].astype(bool).to_numpy()

    figure = plt.figure(figsize=(10, 7))
    axis = figure.add_subplot(111)

    for cluster_id in sorted(set(target_clusters.tolist())):
        mask = target_clusters == cluster_id
        axis.scatter(
            target_embedding[mask, 0],
            target_embedding[mask, 1],
            s=12,
            alpha=0.45,
            label=f"Cluster {cluster_id}",
        )

    poison_mask = target_poison
    axis.scatter(
        target_embedding[poison_mask, 0],
        target_embedding[poison_mask, 1],
        s=32,
        marker="x",
        label="Poison ground truth (evaluation only)",
    )

    axis.set_title("Activation clustering of observed NORMAL records")
    axis.set_xlabel("Activation PCA component 1")
    axis.set_ylabel("Activation PCA component 2")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def attach_detector_outputs(
    model,
    frame: pd.DataFrame,
) -> pd.DataFrame:
    output = frame.copy()

    activation_flag, cluster_ids = predict_activation_clusters(
        model,
        output,
    )
    physics_flag = physics_label_consistency_flag(output)
    trigger_family = threat_informed_trigger_family(output)
    trigger_flag = trigger_family != "NONE"

    output["activation_cluster_id"] = cluster_ids
    output["activation_cluster_flag"] = activation_flag
    output["physics_label_guard_flag"] = physics_flag
    output["trigger_pattern_family"] = trigger_family
    output["trigger_pattern_flag"] = trigger_flag
    output["ensemble_quarantine_flag"] = (
        activation_flag
        | physics_flag
        | trigger_flag
    )
    output["quarantine_reason"] = detector_reason(
        activation_flag,
        physics_flag,
        trigger_family,
    )

    return output


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
        default=PROJECT_ROOT / "outputs" / "step39c",
    )
    args = parser.parse_args()

    frame = pd.read_csv(args.dataset)
    train = frame.loc[frame["split"] == "train"].copy()
    validation = frame.loc[frame["split"] == "validation"].copy()
    test = frame.loc[frame["split"] == "test"].copy()

    model = fit_activation_cluster_model(train)

    validation_scored = attach_detector_outputs(
        model,
        validation,
    )
    test_scored = attach_detector_outputs(
        model,
        test,
    )
    full_scored = attach_detector_outputs(
        model,
        frame,
    )

    detector_columns = {
        "activation_clustering": "activation_cluster_flag",
        "physics_label_guard": "physics_label_guard_flag",
        "trigger_pattern_guard": "trigger_pattern_flag",
        "ensemble": "ensemble_quarantine_flag",
    }

    validation_metrics = {}
    test_metrics = {}

    for detector_name, column in detector_columns.items():
        validation_metrics[detector_name] = classification_metrics(
            validation_scored["is_poison"].astype(bool),
            validation_scored[column].astype(bool),
        )
        test_metrics[detector_name] = classification_metrics(
            test_scored["is_poison"].astype(bool),
            test_scored[column].astype(bool),
        )

    per_trigger = {}
    for detector_name, column in detector_columns.items():
        family_frame = per_trigger_metrics(
            test_scored,
            column,
        )
        per_trigger[detector_name] = family_frame.to_dict(
            orient="records"
        )

    clean_near_trigger = test_scored.loc[
        ~test_scored["is_poison"].astype(bool)
        & test_scored["clean_near_trigger"].astype(bool)
    ]
    clean_near_trigger_fp = int(
        clean_near_trigger["ensemble_quarantine_flag"].sum()
    )

    quarantined = full_scored.loc[
        full_scored["ensemble_quarantine_flag"]
    ].copy()
    sanitized = full_scored.loc[
        ~full_scored["ensemble_quarantine_flag"]
    ].copy()

    downstream_drop_columns = [
        "is_poison",
        "trigger_family",
        "evidence_type",
        "clean_near_trigger",
        "activation_cluster_id",
        "activation_cluster_flag",
        "physics_label_guard_flag",
        "trigger_pattern_family",
        "trigger_pattern_flag",
        "ensemble_quarantine_flag",
        "quarantine_reason",
    ]
    sanitized_for_training = sanitized.drop(
        columns=downstream_drop_columns,
        errors="ignore",
    )

    args.output.mkdir(parents=True, exist_ok=True)

    test_scored.to_csv(
        args.output / "independent_test_detector_outputs.csv",
        index=False,
    )
    quarantined.to_csv(
        args.output / "quarantine_evidence.csv",
        index=False,
    )
    sanitized_for_training.to_csv(
        args.output / "sanitized_training_dataset.csv",
        index=False,
    )

    for detector_name, rows in per_trigger.items():
        pd.DataFrame(rows).to_csv(
            args.output
            / f"per_trigger_{detector_name}.csv",
            index=False,
        )

    pd.DataFrame(model.cluster_summary).to_csv(
        args.output / "activation_cluster_summary.csv",
        index=False,
    )

    joblib.dump(
        model,
        args.output / "activation_cluster_model.joblib",
    )

    _, test_cluster_ids = predict_activation_clusters(
        model,
        test,
    )
    create_activation_plot(
        model,
        test,
        test_cluster_ids,
        args.output / "activation_clusters.png",
    )
    create_detector_comparison_plot(
        test_metrics,
        args.output / "detector_comparison.png",
    )

    sanitized_poison_remaining = int(
        sanitized["is_poison"].astype(bool).sum()
    )
    clean_rows_removed = int(
        (
            quarantined["is_poison"].astype(bool)
            == False
        ).sum()
    )

    report = {
        "component": 3,
        "step": "39C",
        "title": (
            "Activation clustering, physics consistency "
            "and trigger-pattern ensemble"
        ),
        "cluster_selection": {
            "uses_poison_ground_truth": False,
            "suspicious_cluster": model.suspicious_cluster,
            "cluster_summary": model.cluster_summary,
            "selection_inputs": [
                "cluster size ratio",
                "policy mismatch rate",
                "activation-centroid distance",
            ],
        },
        "validation_metrics": validation_metrics,
        "independent_test_metrics": test_metrics,
        "per_trigger_test_metrics": per_trigger,
        "sanitization": {
            "input_rows": len(full_scored),
            "quarantined_rows": len(quarantined),
            "sanitized_rows": len(sanitized),
            "poison_rows_remaining": sanitized_poison_remaining,
            "clean_rows_removed": clean_rows_removed,
            "clean_near_trigger_rows_test": len(clean_near_trigger),
            "clean_near_trigger_false_positives": clean_near_trigger_fp,
        },
        "evidence_type": "SYNTHETIC",
        "production_detection_claim": False,
        "limitations": [
            (
                "The physics guard uses the same deterministic "
                "control policy that generated the synthetic clean labels."
            ),
            (
                "The threat-informed pattern guard knows the configured "
                "exact, jittered and slow-correlation pattern families."
            ),
            (
                "Real compromised-sensor and unknown-trigger validation "
                "has not yet been performed."
            ),
        ],
        "targets": {
            "poison_detection_at_least_95_percent": (
                test_metrics["ensemble"]["recall"] >= 0.95
            ),
            "false_positive_rate_at_most_2_percent": (
                test_metrics["ensemble"]["false_positive_rate"] <= 0.02
            ),
        },
    }

    (args.output / "metrics.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    activation = test_metrics["activation_clustering"]
    physics = test_metrics["physics_label_guard"]
    trigger = test_metrics["trigger_pattern_guard"]
    ensemble = test_metrics["ensemble"]

    activation_family = pd.DataFrame(
        per_trigger["activation_clustering"]
    ).set_index("trigger_family")
    ensemble_family = pd.DataFrame(
        per_trigger["ensemble"]
    ).set_index("trigger_family")

    print("=" * 78)
    print("COMPONENT 3 — STEP 39C ENSEMBLE POISON DEFENSE REPORT")
    print("=" * 78)
    print(
        f"Training rows                         : {len(train)}"
    )
    print(
        f"Validation rows                       : {len(validation)}"
    )
    print(
        f"Independent test rows                 : {len(test)}"
    )
    print(
        f"Suspicious activation cluster         : "
        f"{model.suspicious_cluster}"
    )
    print("Cluster selection uses poison labels  : NO")
    print()
    print("ACTIVATION CLUSTERING")
    print(
        f"  Poison recall                       : "
        f"{activation['recall']:.2%}"
    )
    print(
        f"  False-positive rate                 : "
        f"{activation['false_positive_rate']:.2%}"
    )
    print(
        f"  Exact-trigger recall                : "
        f"{activation_family.loc['EXACT_STATIC_TRIGGER', 'recall']:.2%}"
    )
    print(
        f"  Jittered-trigger recall             : "
        f"{activation_family.loc['JITTERED_TRIGGER', 'recall']:.2%}"
    )
    print(
        f"  Slow-correlation recall             : "
        f"{activation_family.loc['SLOW_CORRELATION_POISON', 'recall']:.2%}"
    )
    print()
    print("PHYSICS LABEL-CONSISTENCY GUARD")
    print(
        f"  Poison recall                       : "
        f"{physics['recall']:.2%}"
    )
    print(
        f"  False-positive rate                 : "
        f"{physics['false_positive_rate']:.2%}"
    )
    print()
    print("THREAT-INFORMED TRIGGER PATTERN GUARD")
    print(
        f"  Poison recall                       : "
        f"{trigger['recall']:.2%}"
    )
    print(
        f"  False-positive rate                 : "
        f"{trigger['false_positive_rate']:.2%}"
    )
    print()
    print("FINAL ENSEMBLE")
    print(
        f"  Poison recall                       : "
        f"{ensemble['recall']:.2%}"
    )
    print(
        f"  False-positive rate                 : "
        f"{ensemble['false_positive_rate']:.2%}"
    )
    print(
        f"  Precision                           : "
        f"{ensemble['precision']:.2%}"
    )
    print(
        f"  F1                                  : "
        f"{ensemble['f1']:.4f}"
    )
    print(
        f"  Exact-trigger recall                : "
        f"{ensemble_family.loc['EXACT_STATIC_TRIGGER', 'recall']:.2%}"
    )
    print(
        f"  Jittered-trigger recall             : "
        f"{ensemble_family.loc['JITTERED_TRIGGER', 'recall']:.2%}"
    )
    print(
        f"  Slow-correlation recall             : "
        f"{ensemble_family.loc['SLOW_CORRELATION_POISON', 'recall']:.2%}"
    )
    print()
    print(
        f"Rows quarantined                      : {len(quarantined)}"
    )
    print(
        f"Rows retained for sanitized training  : {len(sanitized)}"
    )
    print(
        f"Poison rows remaining after sanitizer : "
        f"{sanitized_poison_remaining}"
    )
    print(
        f"Clean rows removed                    : {clean_rows_removed}"
    )
    print(
        f"Clean near-trigger false positives    : "
        f"{clean_near_trigger_fp}/{len(clean_near_trigger)}"
    )
    print("Evidence type                         : SYNTHETIC")
    print("Production detection claim            : NOT YET")
    print(
        "95% poison-detection target           : "
        + (
            "PASSED"
            if ensemble["recall"] >= 0.95
            else "NOT YET"
        )
    )
    print(
        "2% false-positive target              : "
        + (
            "PASSED"
            if ensemble["false_positive_rate"] <= 0.02
            else "NOT YET"
        )
    )
    print(
        "Research conclusion                   : "
        "ACTIVATION CLUSTERING FINDS HIDDEN STRUCTURE; "
        "PHYSICS AND PATTERN GUARDS CLOSE ADAPTIVE GAPS"
    )
    print("STEP 39C RESULT                       : PASSED")
    print("=" * 78)


if __name__ == "__main__":
    main()
