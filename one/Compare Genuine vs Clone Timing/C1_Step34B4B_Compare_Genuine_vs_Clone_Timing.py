
"""
Component 1 Closure — Step 34B-4B
Compare genuine-reference and same-UID clone RFID timing logs.

Required files in the same folder:
    C1_RFID_Latency_Baseline_Log.txt
    C1_RFID_Clone_Latency_Log.txt

Outputs:
    C1_RFID_Genuine_vs_Clone_Combined.csv
    C1_RFID_Genuine_vs_Clone_Statistics.csv
    C1_RFID_Genuine_vs_Clone_CV_Predictions.csv
    C1_RFID_Genuine_vs_Clone_Metrics.json
    C1_RFID_Genuine_vs_Clone_Report.txt
    C1_RFID_Auth_Latency_Comparison.png
    C1_RFID_Block_Read_Latency_Comparison.png
    C1_RFID_Pipeline_Latency_Comparison.png
    C1_RFID_Timing_Confusion_Matrix.png
    C1_RFID_Auth_vs_Pipeline_Comparison.png

Important:
- This script automatically detects the "REALISTIC SYNTHETIC" notice.
- Synthetic results are valid only for pipeline testing, charts, and
  software validation.
- Do not report synthetic classifier metrics as physically measured
  RFID clone-detection performance.
"""

from __future__ import annotations

import csv
import io
import json
import math
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


GENUINE_FILE = Path("C1_RFID_Latency_Baseline_Log.txt")
CLONE_FILE = Path("C1_RFID_Clone_Latency_Log.txt")

COMBINED_FILE = Path("C1_RFID_Genuine_vs_Clone_Combined.csv")
STATISTICS_FILE = Path("C1_RFID_Genuine_vs_Clone_Statistics.csv")
PREDICTIONS_FILE = Path("C1_RFID_Genuine_vs_Clone_CV_Predictions.csv")
METRICS_FILE = Path("C1_RFID_Genuine_vs_Clone_Metrics.json")
REPORT_FILE = Path("C1_RFID_Genuine_vs_Clone_Report.txt")

AUTH_PLOT = Path("C1_RFID_Auth_Latency_Comparison.png")
READ_PLOT = Path("C1_RFID_Block_Read_Latency_Comparison.png")
PIPELINE_PLOT = Path("C1_RFID_Pipeline_Latency_Comparison.png")
CONFUSION_PLOT = Path("C1_RFID_Timing_Confusion_Matrix.png")
SCATTER_PLOT = Path("C1_RFID_Auth_vs_Pipeline_Comparison.png")

GENUINE_PREFIX = "CSV_RFID_LATENCY,"
CLONE_PREFIX = "CSV_RFID_CLONE_LATENCY,"

FEATURES = [
    "uid_latency_us",
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

MIN_FIRST_PASS_ROWS_PER_CLASS = 80
RANDOM_STATE = 20260723


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def source_is_synthetic(path: Path) -> bool:
    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    ).upper()

    return (
        "REALISTIC SYNTHETIC" in text
        or "SYNTHETIC PIPELINE" in text
    )


def parse_log(
    path: Path,
    prefix: str,
    source_name: str,
    class_label: int,
) -> pd.DataFrame:
    if not path.exists():
        fail(f"Required input file was not found: {path}")

    columns = [
        "timestamp_ms",
        "presentation_number",
        "successful_sample_number",
        "target_sample_count",
        "uid_match",
        "first_result_code",
        "final_result_code",
        "first_result_name",
        "final_result_name",
        "retry_used",
        "uid_latency_us",
        "auth_latency_us",
        "block_read_latency_us",
        "pipeline_latency_us",
    ]

    extracted: list[list[str]] = []

    for raw_line in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        line = raw_line.strip()

        if not line.startswith(prefix):
            continue

        if line.startswith(prefix + "HEADER"):
            continue

        if line.startswith(prefix + "SUMMARY"):
            continue

        payload = line[len(prefix):]

        try:
            values = next(
                csv.reader(io.StringIO(payload))
            )
        except (csv.Error, StopIteration):
            continue

        if len(values) == len(columns):
            extracted.append(values)

    if not extracted:
        fail(
            f"No valid rows beginning with {prefix} "
            f"were found in {path}."
        )

    frame = pd.DataFrame(
        extracted,
        columns=columns,
    )

    numeric_columns = [
        "timestamp_ms",
        "presentation_number",
        "successful_sample_number",
        "target_sample_count",
        "uid_match",
        "first_result_code",
        "final_result_code",
        "retry_used",
        *FEATURES,
    ]

    for column in numeric_columns:
        frame[column] = pd.to_numeric(
            frame[column],
            errors="coerce",
        )

    frame = frame.dropna(
        subset=numeric_columns
    ).copy()

    for column in numeric_columns:
        frame[column] = frame[column].astype(
            np.int64
        )

    frame = (
        frame.sort_values(
            ["presentation_number", "timestamp_ms"]
        )
        .drop_duplicates(
            subset=["presentation_number"],
            keep="last",
        )
        .reset_index(drop=True)
    )

    frame["source_name"] = source_name
    frame["class_label"] = class_label
    frame["source_file"] = str(path)
    frame["source_is_synthetic"] = int(
        source_is_synthetic(path)
    )

    return frame


def describe_metric(
    frame: pd.DataFrame,
    source_name: str,
    metric: str,
) -> dict[str, float | str | int]:
    values = frame[metric].to_numpy(
        dtype=np.float64
    )

    median = float(np.median(values))
    mad = float(
        np.median(
            np.abs(values - median)
        )
    )

    return {
        "source_name": source_name,
        "metric": metric,
        "count": int(len(values)),
        "mean": float(np.mean(values)),
        "sample_std": float(
            np.std(values, ddof=1)
        ),
        "minimum": float(np.min(values)),
        "q1": float(np.quantile(values, 0.01)),
        "q5": float(np.quantile(values, 0.05)),
        "q25": float(np.quantile(values, 0.25)),
        "median": median,
        "q75": float(np.quantile(values, 0.75)),
        "q95": float(np.quantile(values, 0.95)),
        "q99": float(np.quantile(values, 0.99)),
        "maximum": float(np.max(values)),
        "mad": mad,
    }


def cohens_d(
    genuine_values: np.ndarray,
    clone_values: np.ndarray,
) -> float:
    n1 = len(genuine_values)
    n2 = len(clone_values)

    variance1 = np.var(
        genuine_values,
        ddof=1,
    )
    variance2 = np.var(
        clone_values,
        ddof=1,
    )

    pooled_variance = (
        ((n1 - 1) * variance1)
        + ((n2 - 1) * variance2)
    ) / (n1 + n2 - 2)

    if pooled_variance <= 0:
        return 0.0

    pooled_std = math.sqrt(
        pooled_variance
    )

    return float(
        (
            np.mean(clone_values)
            - np.mean(genuine_values)
        )
        / pooled_std
    )


def save_histogram(
    genuine_values: pd.Series,
    clone_values: pd.Series,
    title: str,
    xlabel: str,
    output_path: Path,
) -> None:
    fig, ax = plt.subplots(
        figsize=(8, 5)
    )

    bins = max(
        10,
        int(
            math.sqrt(
                len(genuine_values)
                + len(clone_values)
            )
        ),
    )

    ax.hist(
        genuine_values,
        bins=bins,
        alpha=0.6,
        label="Genuine reference",
    )

    ax.hist(
        clone_values,
        bins=bins,
        alpha=0.6,
        label="Same-UID clone",
    )

    ax.set(
        title=title,
        xlabel=xlabel,
        ylabel="Samples",
    )

    ax.legend()
    fig.tight_layout()

    fig.savefig(
        output_path,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)


def save_confusion_matrix(
    matrix: np.ndarray,
) -> None:
    fig, ax = plt.subplots(
        figsize=(5.5, 4.5)
    )

    image = ax.imshow(matrix)
    fig.colorbar(image, ax=ax)

    ax.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=[
            "Predicted Genuine",
            "Predicted Clone",
        ],
        yticklabels=[
            "Actual Genuine",
            "Actual Clone",
        ],
        title=(
            "RFID Timing Logistic Regression\n"
            "5-Fold Cross-Validation"
        ),
        xlabel="Predicted class",
        ylabel="Actual class",
    )

    threshold = (
        matrix.max() / 2.0
        if matrix.size
        else 0.0
    )

    for row in range(2):
        for column in range(2):
            ax.text(
                column,
                row,
                str(
                    matrix[
                        row,
                        column
                    ]
                ),
                ha="center",
                va="center",
                color=(
                    "white"
                    if matrix[row, column] >
                    threshold
                    else "black"
                ),
            )

    fig.tight_layout()

    fig.savefig(
        CONFUSION_PLOT,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)


def save_scatter(
    genuine: pd.DataFrame,
    clone: pd.DataFrame,
) -> None:
    fig, ax = plt.subplots(
        figsize=(7, 5)
    )

    ax.scatter(
        genuine["auth_latency_us"],
        genuine["pipeline_latency_us"],
        label="Genuine reference",
        alpha=0.7,
    )

    ax.scatter(
        clone["auth_latency_us"],
        clone["pipeline_latency_us"],
        label="Same-UID clone",
        alpha=0.7,
    )

    ax.set(
        title=(
            "RFID Authentication vs Pipeline Latency"
        ),
        xlabel=(
            "Sector authentication latency (µs)"
        ),
        ylabel=(
            "Protected pipeline latency (µs)"
        ),
    )

    ax.legend()
    fig.tight_layout()

    fig.savefig(
        SCATTER_PLOT,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)


def main() -> None:
    genuine_all = parse_log(
        GENUINE_FILE,
        GENUINE_PREFIX,
        "GENUINE_REFERENCE",
        0,
    )

    clone_all = parse_log(
        CLONE_FILE,
        CLONE_PREFIX,
        "SAME_UID_CLONE",
        1,
    )

    genuine_authorized = genuine_all.loc[
        genuine_all[
            "final_result_name"
        ] == "AUTHORIZED"
    ].copy()

    clone_authorized = clone_all.loc[
        clone_all[
            "final_result_name"
        ] == "AUTHORIZED"
    ].copy()

    genuine_first_pass = genuine_authorized.loc[
        genuine_authorized[
            "retry_used"
        ] == 0
    ].copy()

    clone_first_pass = clone_authorized.loc[
        clone_authorized[
            "retry_used"
        ] == 0
    ].copy()

    if (
        len(genuine_first_pass)
        < MIN_FIRST_PASS_ROWS_PER_CLASS
    ):
        fail(
            "Insufficient genuine first-pass rows: "
            f"{len(genuine_first_pass)}. "
            f"At least {MIN_FIRST_PASS_ROWS_PER_CLASS} "
            "are required."
        )

    if (
        len(clone_first_pass)
        < MIN_FIRST_PASS_ROWS_PER_CLASS
    ):
        fail(
            "Insufficient clone first-pass rows: "
            f"{len(clone_first_pass)}. "
            f"At least {MIN_FIRST_PASS_ROWS_PER_CLASS} "
            "are required."
        )

    combined = pd.concat(
        [
            genuine_first_pass,
            clone_first_pass,
        ],
        ignore_index=True,
    )

    combined.to_csv(
        COMBINED_FILE,
        index=False,
    )

    statistics_rows: list[
        dict[str, float | str | int]
    ] = []

    effect_sizes: dict[str, float] = {}

    for feature in FEATURES:
        statistics_rows.append(
            describe_metric(
                genuine_first_pass,
                "GENUINE_REFERENCE",
                feature,
            )
        )

        statistics_rows.append(
            describe_metric(
                clone_first_pass,
                "SAME_UID_CLONE",
                feature,
            )
        )

        effect_sizes[feature] = cohens_d(
            genuine_first_pass[
                feature
            ].to_numpy(dtype=np.float64),
            clone_first_pass[
                feature
            ].to_numpy(dtype=np.float64),
        )

    pd.DataFrame(
        statistics_rows
    ).to_csv(
        STATISTICS_FILE,
        index=False,
    )

    x = combined[
        FEATURES
    ].to_numpy(dtype=np.float64)

    y = combined[
        "class_label"
    ].to_numpy(dtype=np.int32)

    model = Pipeline(
        steps=[
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    max_iter=2000,
                ),
            ),
        ]
    )

    cross_validation = StratifiedKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    probabilities = cross_val_predict(
        model,
        x,
        y,
        cv=cross_validation,
        method="predict_proba",
    )[:, 1]

    predictions = (
        probabilities >= 0.5
    ).astype(np.int32)

    matrix = confusion_matrix(
        y,
        predictions,
        labels=[0, 1],
    )

    tn, fp, fn, tp = matrix.ravel()

    accuracy = float(
        accuracy_score(
            y,
            predictions,
        )
    )

    precision = float(
        precision_score(
            y,
            predictions,
            zero_division=0,
        )
    )

    recall = float(
        recall_score(
            y,
            predictions,
            zero_division=0,
        )
    )

    f1 = float(
        f1_score(
            y,
            predictions,
            zero_division=0,
        )
    )

    roc_auc = float(
        roc_auc_score(
            y,
            probabilities,
        )
    )

    false_positive_rate = float(
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    false_negative_rate = float(
        fn / (fn + tp)
        if (fn + tp)
        else 0.0
    )

    predictions_frame = combined[
        [
            "source_name",
            "source_file",
            "source_is_synthetic",
            "presentation_number",
            "class_label",
            *FEATURES,
        ]
    ].copy()

    predictions_frame[
        "predicted_class"
    ] = predictions

    predictions_frame[
        "clone_probability"
    ] = probabilities

    predictions_frame[
        "correct"
    ] = (
        predictions_frame[
            "class_label"
        ] == predictions_frame[
            "predicted_class"
        ]
    ).astype(int)

    predictions_frame.to_csv(
        PREDICTIONS_FILE,
        index=False,
    )

    genuine_synthetic = bool(
        genuine_all[
            "source_is_synthetic"
        ].iloc[0]
    )

    clone_synthetic = bool(
        clone_all[
            "source_is_synthetic"
        ].iloc[0]
    )

    evidence_level = (
        "SYNTHETIC_PIPELINE_ONLY"
        if (
            genuine_synthetic
            or clone_synthetic
        )
        else "REAL_MEASURED_COMPARISON"
    )

    genuine_success_rate = float(
        len(genuine_authorized)
        / len(genuine_all)
    )

    clone_success_rate = float(
        len(clone_authorized)
        / len(clone_all)
    )

    metrics_document = {
        "evidence_level": evidence_level,
        "source_detection": {
            "genuine_source_is_synthetic": (
                genuine_synthetic
            ),
            "clone_source_is_synthetic": (
                clone_synthetic
            ),
        },
        "row_counts": {
            "genuine_all_presentations": int(
                len(genuine_all)
            ),
            "clone_all_presentations": int(
                len(clone_all)
            ),
            "genuine_authorized": int(
                len(genuine_authorized)
            ),
            "clone_authorized": int(
                len(clone_authorized)
            ),
            "genuine_first_pass": int(
                len(genuine_first_pass)
            ),
            "clone_first_pass": int(
                len(clone_first_pass)
            ),
        },
        "presentation_success_rates": {
            "genuine_authorized_rate": (
                genuine_success_rate
            ),
            "clone_authorized_rate": (
                clone_success_rate
            ),
        },
        "timing_classifier": {
            "model": (
                "StandardScaler + "
                "LogisticRegression"
            ),
            "validation": (
                "5-fold stratified "
                "cross-validation"
            ),
            "features": FEATURES,
            "accuracy": accuracy,
            "precision_clone": precision,
            "recall_clone": recall,
            "f1_clone": f1,
            "roc_auc": roc_auc,
            "false_positive_rate": (
                false_positive_rate
            ),
            "false_negative_rate": (
                false_negative_rate
            ),
            "confusion_matrix": {
                "true_genuine": int(tn),
                "false_clone_alarm": int(fp),
                "missed_clone": int(fn),
                "detected_clone": int(tp),
            },
        },
        "cohens_d_clone_minus_genuine": (
            effect_sizes
        ),
        "interpretation_warning": (
            "Synthetic comparison metrics are "
            "for pipeline validation only and "
            "must not be reported as physically "
            "measured clone-detection performance."
        ),
    }

    METRICS_FILE.write_text(
        json.dumps(
            metrics_document,
            indent=2,
        ),
        encoding="utf-8",
    )

    save_histogram(
        genuine_first_pass[
            "auth_latency_us"
        ],
        clone_first_pass[
            "auth_latency_us"
        ],
        (
            "Genuine vs Same-UID Clone "
            "Sector Authentication"
        ),
        (
            "Sector authentication "
            "latency (µs)"
        ),
        AUTH_PLOT,
    )

    save_histogram(
        genuine_first_pass[
            "block_read_latency_us"
        ],
        clone_first_pass[
            "block_read_latency_us"
        ],
        (
            "Genuine vs Same-UID Clone "
            "Protected Block Read"
        ),
        (
            "Protected block-read "
            "latency (µs)"
        ),
        READ_PLOT,
    )

    save_histogram(
        genuine_first_pass[
            "pipeline_latency_us"
        ],
        clone_first_pass[
            "pipeline_latency_us"
        ],
        (
            "Genuine vs Same-UID Clone "
            "Protected Pipeline"
        ),
        (
            "Protected pipeline "
            "latency (µs)"
        ),
        PIPELINE_PLOT,
    )

    save_confusion_matrix(matrix)

    save_scatter(
        genuine_first_pass,
        clone_first_pass,
    )

    classification_text = (
        classification_report(
            y,
            predictions,
            target_names=[
                "GENUINE",
                "CLONE",
            ],
            digits=4,
            zero_division=0,
        )
    )

    pipeline_pass_conditions = {
        "genuine_first_pass_at_least_80": (
            len(genuine_first_pass)
            >= MIN_FIRST_PASS_ROWS_PER_CLASS
        ),
        "clone_first_pass_at_least_80": (
            len(clone_first_pass)
            >= MIN_FIRST_PASS_ROWS_PER_CLASS
        ),
        "no_missing_timing_features": (
            not combined[
                FEATURES
            ].isna().any().any()
        ),
        "all_timing_features_positive": bool(
            (
                combined[
                    FEATURES
                ] > 0
            ).all().all()
        ),
    }

    pipeline_passed = all(
        pipeline_pass_conditions.values()
    )

    report_lines = [
        "COMPONENT 1 CLOSURE — STEP 34B-4B",
        "GENUINE VS SAME-UID CLONE TIMING COMPARISON",
        "=" * 65,
        "",
        f"Evidence level            : {evidence_level}",
        (
            "Genuine source synthetic : "
            f"{'YES' if genuine_synthetic else 'NO'}"
        ),
        (
            "Clone source synthetic   : "
            f"{'YES' if clone_synthetic else 'NO'}"
        ),
        "",
        "Dataset counts:",
        (
            "Genuine presentations    : "
            f"{len(genuine_all)}"
        ),
        (
            "Genuine authorized       : "
            f"{len(genuine_authorized)}"
        ),
        (
            "Genuine first-pass       : "
            f"{len(genuine_first_pass)}"
        ),
        (
            "Clone presentations      : "
            f"{len(clone_all)}"
        ),
        (
            "Clone authorized         : "
            f"{len(clone_authorized)}"
        ),
        (
            "Clone first-pass         : "
            f"{len(clone_first_pass)}"
        ),
        "",
        "Presentation-level reliability:",
        (
            "Genuine authorization rate: "
            f"{genuine_success_rate:.4f}"
        ),
        (
            "Clone authorization rate  : "
            f"{clone_success_rate:.4f}"
        ),
        "",
        "Exploratory timing classifier:",
        (
            "Model                     : "
            "StandardScaler + LogisticRegression"
        ),
        (
            "Validation                : "
            "5-fold stratified cross-validation"
        ),
        f"Accuracy                  : {accuracy:.4f}",
        f"Precision (clone)         : {precision:.4f}",
        f"Recall (clone)            : {recall:.4f}",
        f"F1 (clone)                : {f1:.4f}",
        f"ROC-AUC                   : {roc_auc:.4f}",
        (
            "False-positive rate       : "
            f"{false_positive_rate:.4f}"
        ),
        (
            "False-negative rate       : "
            f"{false_negative_rate:.4f}"
        ),
        "",
        "Confusion matrix:",
        f"True genuine              : {tn}",
        f"False clone alarms        : {fp}",
        f"Missed clones             : {fn}",
        f"Detected clones           : {tp}",
        "",
        "Classification report:",
        classification_text,
        "Standardized effect sizes (clone minus genuine):",
        *[
            f"- {feature}: {value:.4f}"
            for feature, value
            in effect_sizes.items()
        ],
        "",
        "Pipeline pass conditions:",
        *[
            f"- {name}: {'PASSED' if value else 'FAILED'}"
            for name, value
            in pipeline_pass_conditions.items()
        ],
        "",
        (
            "STEP 34B-4B PIPELINE RESULT: "
            f"{'PASSED' if pipeline_passed else 'REVIEW REQUIRED'}"
        ),
        "",
        "Research interpretation:",
        (
            "The analysis pipeline successfully compares "
            "genuine and same-UID clone timing."
        ),
        (
            "Because one or both source files are synthetic, "
            "the classifier scores are not valid final "
            "research measurements."
        ),
        (
            "Repeat this analysis using two real Serial Monitor "
            "logs before claiming clone-detection sensitivity, "
            "specificity, accuracy, or ROC-AUC."
        ),
        "",
        "Files created:",
        f"- {COMBINED_FILE}",
        f"- {STATISTICS_FILE}",
        f"- {PREDICTIONS_FILE}",
        f"- {METRICS_FILE}",
        f"- {REPORT_FILE}",
        f"- {AUTH_PLOT}",
        f"- {READ_PLOT}",
        f"- {PIPELINE_PLOT}",
        f"- {CONFUSION_PLOT}",
        f"- {SCATTER_PLOT}",
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
