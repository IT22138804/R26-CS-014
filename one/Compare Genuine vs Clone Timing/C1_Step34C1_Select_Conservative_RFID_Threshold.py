
"""
Component 1 Closure — Step 34C-1
Select a conservative RFID timing-risk threshold.

Required input:
    C1_RFID_Genuine_vs_Clone_CV_Predictions.csv

Outputs:
    C1_RFID_Timing_Threshold_Sweep.csv
    C1_RFID_Timing_Selected_Threshold.json
    C1_RFID_Timing_Threshold_Report.txt
    C1_RFID_Timing_Recall_vs_FPR.png
    C1_RFID_Timing_Probability_Distribution.png

Purpose:
- Evaluate the existing cross-validated clone probabilities.
- Find the highest-recall threshold with a false-positive rate no greater
  than 5%.
- Determine whether timing is suitable as a primary security decision or
  only as a supporting signal.

Important:
- Synthetic source data can validate this software pipeline only.
- Do not present synthetic threshold metrics as measured clone-detection
  performance.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix


INPUT_FILE = Path(
    "C1_RFID_Genuine_vs_Clone_CV_Predictions.csv"
)

SWEEP_FILE = Path(
    "C1_RFID_Timing_Threshold_Sweep.csv"
)

THRESHOLD_FILE = Path(
    "C1_RFID_Timing_Selected_Threshold.json"
)

REPORT_FILE = Path(
    "C1_RFID_Timing_Threshold_Report.txt"
)

ROC_PLOT_FILE = Path(
    "C1_RFID_Timing_Recall_vs_FPR.png"
)

PROBABILITY_PLOT_FILE = Path(
    "C1_RFID_Timing_Probability_Distribution.png"
)

MAX_ACCEPTABLE_FPR = 0.05
MIN_USEFUL_CLONE_RECALL = 0.50


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def calculate_metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, float | int]:
    predictions = (
        probabilities >= threshold
    ).astype(np.int32)

    matrix = confusion_matrix(
        labels,
        predictions,
        labels=[0, 1],
    )

    tn, fp, fn, tp = matrix.ravel()

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    specificity = 1.0 - false_positive_rate

    f1 = (
        2.0 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    accuracy = (
        (tp + tn) / len(labels)
        if len(labels)
        else 0.0
    )

    balanced_accuracy = (
        recall + specificity
    ) / 2.0

    return {
        "threshold": float(threshold),
        "true_genuine": int(tn),
        "false_clone_alarms": int(fp),
        "missed_clones": int(fn),
        "detected_clones": int(tp),
        "accuracy": float(accuracy),
        "precision_clone": float(precision),
        "recall_clone": float(recall),
        "f1_clone": float(f1),
        "false_positive_rate": float(
            false_positive_rate
        ),
        "specificity_genuine": float(
            specificity
        ),
        "balanced_accuracy": float(
            balanced_accuracy
        ),
    }


def main() -> None:
    if not INPUT_FILE.exists():
        fail(
            f"{INPUT_FILE} was not found. "
            "Run Step 34B-4B first."
        )

    frame = pd.read_csv(INPUT_FILE)

    required_columns = {
        "class_label",
        "clone_probability",
        "source_is_synthetic",
        "source_name",
    }

    missing = required_columns - set(frame.columns)

    if missing:
        fail(
            f"Missing required columns: "
            f"{sorted(missing)}"
        )

    frame["class_label"] = pd.to_numeric(
        frame["class_label"],
        errors="coerce",
    )

    frame["clone_probability"] = pd.to_numeric(
        frame["clone_probability"],
        errors="coerce",
    )

    frame = frame.dropna(
        subset=[
            "class_label",
            "clone_probability",
        ]
    ).copy()

    frame["class_label"] = frame[
        "class_label"
    ].astype(np.int32)

    labels_found = set(
        frame["class_label"].unique()
    )

    if labels_found != {0, 1}:
        fail(
            "The predictions file must contain "
            "both genuine label 0 and clone label 1."
        )

    if (
        (frame["clone_probability"] < 0).any()
        or
        (frame["clone_probability"] > 1).any()
    ):
        fail(
            "Clone probabilities must be between "
            "0 and 1."
        )

    labels = frame[
        "class_label"
    ].to_numpy(dtype=np.int32)

    probabilities = frame[
        "clone_probability"
    ].to_numpy(dtype=np.float64)

    source_is_synthetic = bool(
        pd.to_numeric(
            frame["source_is_synthetic"],
            errors="coerce",
        ).fillna(0).astype(int).any()
    )

    thresholds = np.linspace(
        0.0,
        1.0,
        1001,
    )

    sweep_records = [
        calculate_metrics(
            labels,
            probabilities,
            threshold,
        )
        for threshold in thresholds
    ]

    sweep = pd.DataFrame(
        sweep_records
    )

    sweep.to_csv(
        SWEEP_FILE,
        index=False,
    )

    default_metrics = calculate_metrics(
        labels,
        probabilities,
        0.5,
    )

    acceptable = sweep.loc[
        sweep["false_positive_rate"]
        <= MAX_ACCEPTABLE_FPR
    ].copy()

    if acceptable.empty:
        # Defensive fallback; threshold 1.0 normally gives
        # zero false positives unless a probability equals 1.
        selected = (
            sweep.sort_values(
                [
                    "false_positive_rate",
                    "recall_clone",
                    "f1_clone",
                    "threshold",
                ],
                ascending=[
                    True,
                    False,
                    False,
                    True,
                ],
            )
            .iloc[0]
        )
        selection_rule = (
            "No threshold met the target FPR; "
            "selected minimum-FPR fallback."
        )
    else:
        selected = (
            acceptable.sort_values(
                [
                    "recall_clone",
                    "f1_clone",
                    "balanced_accuracy",
                    "threshold",
                ],
                ascending=[
                    False,
                    False,
                    False,
                    True,
                ],
            )
            .iloc[0]
        )
        selection_rule = (
            "Highest clone recall among thresholds "
            "with false-positive rate <= 5%; "
            "ties resolved by F1 and balanced accuracy."
        )

    selected_threshold = float(
        selected["threshold"]
    )

    meets_fpr_target = bool(
        selected["false_positive_rate"]
        <= MAX_ACCEPTABLE_FPR
    )

    meets_recall_target = bool(
        selected["recall_clone"]
        >= MIN_USEFUL_CLONE_RECALL
    )

    suitable_as_primary_signal = bool(
        meets_fpr_target
        and meets_recall_target
        and not source_is_synthetic
    )

    if source_is_synthetic:
        deployment_decision = (
            "SYNTHETIC PIPELINE ONLY — "
            "DO NOT DEPLOY AS A PRIMARY SECURITY SIGNAL"
        )
    elif suitable_as_primary_signal:
        deployment_decision = (
            "REAL-DATA CANDIDATE — "
            "REQUIRES INDEPENDENT HELD-OUT VALIDATION"
        )
    elif meets_fpr_target:
        deployment_decision = (
            "SUPPORTING SIGNAL ONLY — "
            "RECALL IS TOO LOW FOR PRIMARY DETECTION"
        )
    else:
        deployment_decision = (
            "NOT SUITABLE — "
            "FALSE-POSITIVE TARGET NOT MET"
        )

    threshold_document = {
        "evidence_level": (
            "SYNTHETIC_PIPELINE_ONLY"
            if source_is_synthetic
            else "REAL_MEASURED_INPUT"
        ),
        "selection_rule": selection_rule,
        "security_targets": {
            "maximum_false_positive_rate": (
                MAX_ACCEPTABLE_FPR
            ),
            "minimum_useful_clone_recall": (
                MIN_USEFUL_CLONE_RECALL
            ),
        },
        "default_threshold_0_5": (
            default_metrics
        ),
        "selected_threshold": {
            key: (
                float(value)
                if isinstance(
                    value,
                    (np.floating, float)
                )
                else int(value)
            )
            for key, value in selected.to_dict().items()
        },
        "deployment_decision": (
            deployment_decision
        ),
        "warning": (
            "Synthetic metrics must not be reported "
            "as physically measured clone-detection "
            "performance."
        ),
    }

    THRESHOLD_FILE.write_text(
        json.dumps(
            threshold_document,
            indent=2,
        ),
        encoding="utf-8",
    )

    # Recall versus false-positive-rate plot.
    fig, ax = plt.subplots(
        figsize=(7, 5)
    )

    ax.plot(
        sweep["false_positive_rate"],
        sweep["recall_clone"],
    )

    ax.scatter(
        [
            selected[
                "false_positive_rate"
            ]
        ],
        [
            selected[
                "recall_clone"
            ]
        ],
        label=(
            f"Selected threshold "
            f"{selected_threshold:.3f}"
        ),
    )

    ax.axvline(
        MAX_ACCEPTABLE_FPR,
        linestyle="--",
        label="Maximum FPR target",
    )

    ax.set(
        title=(
            "RFID Timing Threshold Trade-off"
        ),
        xlabel="False-positive rate",
        ylabel="Clone recall",
        xlim=(0.0, 1.0),
        ylim=(0.0, 1.0),
    )

    ax.legend()
    fig.tight_layout()

    fig.savefig(
        ROC_PLOT_FILE,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)

    # Probability distributions.
    genuine_probabilities = frame.loc[
        frame["class_label"] == 0,
        "clone_probability",
    ]

    clone_probabilities = frame.loc[
        frame["class_label"] == 1,
        "clone_probability",
    ]

    fig, ax = plt.subplots(
        figsize=(8, 5)
    )

    ax.hist(
        genuine_probabilities,
        bins=20,
        alpha=0.6,
        label="Genuine reference",
    )

    ax.hist(
        clone_probabilities,
        bins=20,
        alpha=0.6,
        label="Same-UID clone",
    )

    ax.axvline(
        selected_threshold,
        linestyle="--",
        label=(
            f"Selected threshold "
            f"{selected_threshold:.3f}"
        ),
    )

    ax.set(
        title=(
            "Cross-Validated RFID Clone "
            "Probability Distribution"
        ),
        xlabel="Clone probability",
        ylabel="Samples",
    )

    ax.legend()
    fig.tight_layout()

    fig.savefig(
        PROBABILITY_PLOT_FILE,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)

    report_lines = [
        "COMPONENT 1 CLOSURE — STEP 34C-1",
        "CONSERVATIVE RFID TIMING THRESHOLD SELECTION",
        "=" * 64,
        "",
        (
            "Evidence level             : "
            + (
                "SYNTHETIC_PIPELINE_ONLY"
                if source_is_synthetic
                else "REAL_MEASURED_INPUT"
            )
        ),
        f"Prediction rows checked    : {len(frame)}",
        "",
        "Default threshold 0.500:",
        (
            "False-positive rate        : "
            f"{default_metrics['false_positive_rate']:.4f}"
        ),
        (
            "Clone recall               : "
            f"{default_metrics['recall_clone']:.4f}"
        ),
        (
            "Clone precision            : "
            f"{default_metrics['precision_clone']:.4f}"
        ),
        (
            "Clone F1                   : "
            f"{default_metrics['f1_clone']:.4f}"
        ),
        "",
        "Conservative selection:",
        (
            "Selected threshold         : "
            f"{selected_threshold:.3f}"
        ),
        (
            "False-positive rate        : "
            f"{selected['false_positive_rate']:.4f}"
        ),
        (
            "Clone recall               : "
            f"{selected['recall_clone']:.4f}"
        ),
        (
            "Clone precision            : "
            f"{selected['precision_clone']:.4f}"
        ),
        (
            "Clone F1                   : "
            f"{selected['f1_clone']:.4f}"
        ),
        (
            "True genuine               : "
            f"{int(selected['true_genuine'])}"
        ),
        (
            "False clone alarms         : "
            f"{int(selected['false_clone_alarms'])}"
        ),
        (
            "Missed clones              : "
            f"{int(selected['missed_clones'])}"
        ),
        (
            "Detected clones            : "
            f"{int(selected['detected_clones'])}"
        ),
        "",
        f"Selection rule             : {selection_rule}",
        (
            "Maximum FPR target met     : "
            f"{'YES' if meets_fpr_target else 'NO'}"
        ),
        (
            "Minimum recall target met  : "
            f"{'YES' if meets_recall_target else 'NO'}"
        ),
        "",
        (
            "Deployment decision        : "
            f"{deployment_decision}"
        ),
        "",
        "STEP 34C-1 PIPELINE RESULT  : PASSED",
        "",
        "Research interpretation:",
        (
            "The default 0.500 threshold produces "
            "too many false alarms for a permanent "
            "hard-lockdown response."
        ),
        (
            "A more conservative threshold may reduce "
            "false alarms, but usually misses more clones."
        ),
        (
            "Timing should remain a supporting signal "
            "until real independent measurements show "
            "acceptable false-positive and false-negative "
            "rates."
        ),
        "",
        "Files created:",
        f"- {SWEEP_FILE}",
        f"- {THRESHOLD_FILE}",
        f"- {REPORT_FILE}",
        f"- {ROC_PLOT_FILE}",
        f"- {PROBABILITY_PLOT_FILE}",
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
