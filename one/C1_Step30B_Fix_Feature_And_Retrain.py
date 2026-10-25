
"""
Component 1 — Step 30B
Correct the synthetic soil-disconnect feature engineering and retrain
the five-feature Random Forest anomaly classifier.

Input:
    C1_TinyML_Model_5_Features_Cleaned.csv

Outputs:
    C1_TinyML_Model_5_Features_FeatureFixed.csv
    C1_RF_Step30B_Model.joblib
    C1_RF_Step30B_Test_Predictions.csv
    C1_RF_Step30B_Feature_Importance.csv
    C1_RF_Step30B_Metrics.json
    C1_RF_Step30B_Training_Report.txt
    C1_RF_Step30B_Confusion_Matrix.png
    C1_RF_Step30B_Feature_Importance.png

Important:
This correction applies only to the synthetic simulation dataset.
The real ESP32 logger must compute moisture_delta from the last valid
soil measurement and must not update that baseline while the sensor is
open-circuit or implausible.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


INPUT_FILE = Path("C1_TinyML_Model_5_Features_Cleaned.csv")

FEATURE_FIXED_FILE = Path(
    "C1_TinyML_Model_5_Features_FeatureFixed.csv"
)
MODEL_FILE = Path("C1_RF_Step30B_Model.joblib")
PREDICTIONS_FILE = Path("C1_RF_Step30B_Test_Predictions.csv")
IMPORTANCE_FILE = Path("C1_RF_Step30B_Feature_Importance.csv")
METRICS_FILE = Path("C1_RF_Step30B_Metrics.json")
REPORT_FILE = Path("C1_RF_Step30B_Training_Report.txt")
CONFUSION_PLOT_FILE = Path(
    "C1_RF_Step30B_Confusion_Matrix.png"
)
IMPORTANCE_PLOT_FILE = Path(
    "C1_RF_Step30B_Feature_Importance.png"
)

FEATURE_COLUMNS = [
    "rfid_auth_feature",
    "tamper_state",
    "temp_light_ratio",
    "moisture_delta",
    "relay_runtime_ms",
]

REQUIRED_COLUMNS = [
    "record_id",
    "scenario_id",
    "label",
    "scenario_name",
    *FEATURE_COLUMNS,
    "split",
    "data_source",
]

RANDOM_STATE = 20260722

# Scenario 2 is the synthetic soil-sensor disconnect scenario.
SOIL_DISCONNECT_SCENARIO_ID = 2

# A real disconnect after a valid soil reading normally creates a large
# negative change relative to the last valid moisture baseline.
SYNTHETIC_DISCONNECT_MIN_DROP = 35.0
SYNTHETIC_DISCONNECT_MAX_DROP = 80.0


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def validate_input(df: pd.DataFrame) -> None:
    missing = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]
    if missing:
        fail(f"Missing required columns: {missing}")

    if df[FEATURE_COLUMNS].isna().any().any():
        fail("One or more model features contain missing values.")

    if not set(df["label"].unique()).issubset({0, 1}):
        fail("The label column must contain only 0 and 1.")

    required_splits = {"train", "validation", "test"}
    available_splits = set(df["split"].unique())

    if not required_splits.issubset(available_splits):
        fail(
            f"Missing dataset split(s). Required: {required_splits}; "
            f"found: {available_splits}"
        )

    for split_name in ["train", "validation", "test"]:
        labels = set(
            df.loc[
                df["split"] == split_name,
                "label"
            ].unique()
        )

        if labels != {0, 1}:
            fail(
                f"The {split_name} split must contain both labels. "
                f"Found labels: {sorted(labels)}"
            )


def repair_synthetic_moisture_feature(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, int]:
    """
    Correct only the synthetic soil-disconnect scenario.

    The original generator stored a large negative moisture delta only
    on the first disconnect row and then produced values close to zero.
    That made later open-circuit rows look normal.

    This function simulates the intended real-device behavior:
    while the sensor is invalid, compare the current zero-percent
    reading with the last valid moisture baseline and do not overwrite
    that baseline.
    """
    repaired = df.copy()

    mask = (
        repaired["scenario_id"] ==
        SOIL_DISCONNECT_SCENARIO_ID
    )

    rows_changed = int(mask.sum())

    if rows_changed == 0:
        fail(
            "No soil-disconnect rows were found. "
            "Expected scenario_id 2."
        )

    # Deterministic values for reproducibility.
    rng = np.random.default_rng(RANDOM_STATE)

    repaired.loc[mask, "moisture_delta"] = -rng.uniform(
        SYNTHETIC_DISCONNECT_MIN_DROP,
        SYNTHETIC_DISCONNECT_MAX_DROP,
        rows_changed,
    )

    return repaired, rows_changed


def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_probability: np.ndarray,
) -> dict:
    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    tn, fp, fn, tp = matrix.ravel()

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    false_negative_rate = (
        fn / (fn + tp)
        if (fn + tp)
        else 0.0
    )

    specificity = (
        tn / (tn + fp)
        if (tn + fp)
        else 0.0
    )

    return {
        "accuracy": float(
            accuracy_score(y_true, y_pred)
        ),
        "precision_anomaly": float(
            precision_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "recall_anomaly": float(
            recall_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "f1_anomaly": float(
            f1_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_true,
                y_probability,
            )
        ),
        "specificity_normal": float(specificity),
        "false_positive_rate": float(
            false_positive_rate
        ),
        "false_negative_rate": float(
            false_negative_rate
        ),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def evaluate_per_scenario(
    frame: pd.DataFrame,
    predictions: np.ndarray,
) -> list[dict]:
    evaluated = frame[
        [
            "scenario_id",
            "scenario_name",
            "label",
        ]
    ].copy()

    evaluated["prediction"] = predictions

    results: list[dict] = []

    for (
        scenario_id,
        scenario_name,
    ), group in evaluated.groupby(
        ["scenario_id", "scenario_name"],
        sort=True,
    ):
        expected_label = int(
            group["label"].iloc[0]
        )

        correct = int(
            (
                group["prediction"] ==
                expected_label
            ).sum()
        )

        total = int(len(group))

        results.append(
            {
                "scenario_id": int(scenario_id),
                "scenario_name": str(
                    scenario_name
                ),
                "expected_label": expected_label,
                "rows": total,
                "correct_predictions": correct,
                "scenario_accuracy": float(
                    correct / total
                    if total
                    else 0.0
                ),
            }
        )

    return results


def save_confusion_plot(
    matrix: np.ndarray,
) -> None:
    fig, ax = plt.subplots(
        figsize=(5.5, 4.5)
    )

    image = ax.imshow(matrix)

    fig.colorbar(
        image,
        ax=ax,
    )

    ax.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=[
            "Predicted Normal",
            "Predicted Anomaly",
        ],
        yticklabels=[
            "Actual Normal",
            "Actual Anomaly",
        ],
        title=(
            "Step 30B Random Forest "
            "Test Confusion Matrix"
        ),
        ylabel="Actual class",
        xlabel="Predicted class",
    )

    threshold = (
        matrix.max() / 2.0
        if matrix.size
        else 0.0
    )

    for row in range(
        matrix.shape[0]
    ):
        for column in range(
            matrix.shape[1]
        ):
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
        CONFUSION_PLOT_FILE,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)


def save_importance_plot(
    importance_df: pd.DataFrame,
) -> None:
    ordered = importance_df.sort_values(
        "importance",
        ascending=True,
    )

    fig, ax = plt.subplots(
        figsize=(7, 4.5)
    )

    ax.barh(
        ordered["feature"],
        ordered["importance"],
    )

    ax.set(
        title=(
            "Step 30B Random Forest "
            "Feature Importance"
        ),
        xlabel="Importance",
        ylabel="Feature",
    )

    fig.tight_layout()

    fig.savefig(
        IMPORTANCE_PLOT_FILE,
        dpi=180,
        bbox_inches="tight",
    )

    plt.close(fig)


def main() -> None:
    if not INPUT_FILE.exists():
        fail(
            f"{INPUT_FILE} was not found. "
            "Run Step 29A first."
        )

    original_df = pd.read_csv(
        INPUT_FILE
    )

    validate_input(original_df)

    repaired_df, repaired_rows = (
        repair_synthetic_moisture_feature(
            original_df
        )
    )

    repaired_df.to_csv(
        FEATURE_FIXED_FILE,
        index=False,
    )

    train_df = repaired_df[
        repaired_df["split"] ==
        "train"
    ].copy()

    validation_df = repaired_df[
        repaired_df["split"] ==
        "validation"
    ].copy()

    test_df = repaired_df[
        repaired_df["split"] ==
        "test"
    ].copy()

    x_train = train_df[
        FEATURE_COLUMNS
    ].to_numpy(dtype=np.float32)

    y_train = train_df[
        "label"
    ].to_numpy(dtype=np.int32)

    x_validation = validation_df[
        FEATURE_COLUMNS
    ].to_numpy(dtype=np.float32)

    y_validation = validation_df[
        "label"
    ].to_numpy(dtype=np.int32)

    x_test = test_df[
        FEATURE_COLUMNS
    ].to_numpy(dtype=np.float32)

    y_test = test_df[
        "label"
    ].to_numpy(dtype=np.int32)

    model = RandomForestClassifier(
        n_estimators=30,
        max_depth=6,
        min_samples_leaf=3,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(
        x_train,
        y_train,
    )

    validation_probability = (
        model.predict_proba(
            x_validation
        )[:, 1]
    )

    validation_prediction = (
        validation_probability >= 0.5
    ).astype(np.int32)

    test_probability = (
        model.predict_proba(
            x_test
        )[:, 1]
    )

    test_prediction = (
        test_probability >= 0.5
    ).astype(np.int32)

    validation_metrics = calculate_metrics(
        y_validation,
        validation_prediction,
        validation_probability,
    )

    test_metrics = calculate_metrics(
        y_test,
        test_prediction,
        test_probability,
    )

    test_matrix = confusion_matrix(
        y_test,
        test_prediction,
        labels=[0, 1],
    )

    feature_importance = pd.DataFrame(
        {
            "feature": FEATURE_COLUMNS,
            "importance": (
                model.feature_importances_
            ),
        }
    ).sort_values(
        "importance",
        ascending=False,
    )

    scenario_metrics = evaluate_per_scenario(
        test_df,
        test_prediction,
    )

    predictions_df = test_df[
        [
            "record_id",
            "scenario_id",
            "scenario_name",
            "label",
            "split",
            "data_source",
            *FEATURE_COLUMNS,
        ]
    ].copy()

    predictions_df[
        "predicted_label"
    ] = test_prediction

    predictions_df[
        "anomaly_probability"
    ] = test_probability

    predictions_df["correct"] = (
        predictions_df["label"] ==
        predictions_df["predicted_label"]
    ).astype(int)

    predictions_df.to_csv(
        PREDICTIONS_FILE,
        index=False,
    )

    feature_importance.to_csv(
        IMPORTANCE_FILE,
        index=False,
    )

    joblib.dump(
        model,
        MODEL_FILE,
    )

    pass_conditions = {
        "test_recall_at_least_0_90": (
            test_metrics[
                "recall_anomaly"
            ] >= 0.90
        ),
        "test_f1_at_least_0_90": (
            test_metrics[
                "f1_anomaly"
            ] >= 0.90
        ),
        "false_positive_rate_at_most_0_10": (
            test_metrics[
                "false_positive_rate"
            ] <= 0.10
        ),
    }

    passed = all(
        pass_conditions.values()
    )

    metrics_output = {
        "synthetic_feature_correction": {
            "scenario_id": (
                SOIL_DISCONNECT_SCENARIO_ID
            ),
            "rows_changed": repaired_rows,
            "new_delta_range": [
                -SYNTHETIC_DISCONNECT_MAX_DROP,
                -SYNTHETIC_DISCONNECT_MIN_DROP,
            ],
            "reason": (
                "Simulate comparison against the "
                "last valid soil-moisture baseline "
                "while the sensor remains invalid."
            ),
        },
        "model": {
            "type": (
                "RandomForestClassifier"
            ),
            "n_estimators": int(
                model.n_estimators
            ),
            "max_depth": int(
                model.max_depth
            ),
            "min_samples_leaf": int(
                model.min_samples_leaf
            ),
            "feature_columns": (
                FEATURE_COLUMNS
            ),
            "decision_threshold": 0.5,
            "random_state": RANDOM_STATE,
        },
        "validation_metrics": (
            validation_metrics
        ),
        "test_metrics": (
            test_metrics
        ),
        "test_scenario_metrics": (
            scenario_metrics
        ),
        "feature_importance": (
            feature_importance.to_dict(
                orient="records"
            )
        ),
        "pass_conditions": (
            pass_conditions
        ),
        "step_30b_result": (
            "PASSED"
            if passed
            else "REVIEW_REQUIRED"
        ),
        "important_note": (
            "This is synthetic simulation data. "
            "Final thesis results require real "
            "held-out ESP32 measurements."
        ),
    }

    METRICS_FILE.write_text(
        json.dumps(
            metrics_output,
            indent=2,
        ),
        encoding="utf-8",
    )

    classification_text = (
        classification_report(
            y_test,
            test_prediction,
            target_names=[
                "NORMAL",
                "ANOMALY",
            ],
            digits=4,
            zero_division=0,
        )
    )

    scenario_lines = [
        (
            f"{row['scenario_id']} "
            f"{row['scenario_name']}: "
            f"{row['correct_predictions']}/"
            f"{row['rows']} correct "
            f"({row['scenario_accuracy'] * 100:.2f}%)"
        )
        for row in scenario_metrics
    ]

    importance_lines = [
        (
            f"{row.feature}: "
            f"{row.importance:.6f}"
        )
        for row in feature_importance.itertuples(
            index=False
        )
    ]

    report_lines = [
        (
            "COMPONENT 1 — STEP 30B "
            "FEATURE CORRECTION AND TRAINING REPORT"
        ),
        "=" * 68,
        "",
        f"Input file: {INPUT_FILE}",
        f"Feature-fixed file: {FEATURE_FIXED_FILE}",
        (
            "Synthetic soil-disconnect rows "
            f"corrected: {repaired_rows}"
        ),
        (
            "Corrected moisture-delta range: "
            f"-{SYNTHETIC_DISCONNECT_MAX_DROP:.1f} "
            f"to -{SYNTHETIC_DISCONNECT_MIN_DROP:.1f}"
        ),
        "",
        "Reason for correction:",
        (
            "The original generator produced a large "
            "negative moisture delta only on the first "
            "disconnect row. Later disconnected rows "
            "returned a delta close to zero and therefore "
            "looked normal to the classifier."
        ),
        (
            "The corrected synthetic feature represents "
            "comparison with the last valid soil reading "
            "until the sensor becomes valid again."
        ),
        "",
        "Validation metrics:",
        (
            "- Accuracy: "
            f"{validation_metrics['accuracy']:.4f}"
        ),
        (
            "- Precision (anomaly): "
            f"{validation_metrics['precision_anomaly']:.4f}"
        ),
        (
            "- Recall (anomaly): "
            f"{validation_metrics['recall_anomaly']:.4f}"
        ),
        (
            "- F1 (anomaly): "
            f"{validation_metrics['f1_anomaly']:.4f}"
        ),
        (
            "- ROC-AUC: "
            f"{validation_metrics['roc_auc']:.4f}"
        ),
        "",
        "Test metrics:",
        (
            "- Accuracy: "
            f"{test_metrics['accuracy']:.4f}"
        ),
        (
            "- Precision (anomaly): "
            f"{test_metrics['precision_anomaly']:.4f}"
        ),
        (
            "- Recall (anomaly): "
            f"{test_metrics['recall_anomaly']:.4f}"
        ),
        (
            "- F1 (anomaly): "
            f"{test_metrics['f1_anomaly']:.4f}"
        ),
        (
            "- ROC-AUC: "
            f"{test_metrics['roc_auc']:.4f}"
        ),
        (
            "- Specificity (normal): "
            f"{test_metrics['specificity_normal']:.4f}"
        ),
        (
            "- False-positive rate: "
            f"{test_metrics['false_positive_rate']:.4f}"
        ),
        (
            "- False-negative rate: "
            f"{test_metrics['false_negative_rate']:.4f}"
        ),
        "",
        "Test confusion matrix:",
        (
            f"TN={test_metrics['true_negative']}  "
            f"FP={test_metrics['false_positive']}"
        ),
        (
            f"FN={test_metrics['false_negative']}  "
            f"TP={test_metrics['true_positive']}"
        ),
        "",
        "Classification report:",
        classification_text,
        "Per-scenario test performance:",
        *scenario_lines,
        "",
        "Feature importance:",
        *importance_lines,
        "",
        "Files created:",
        f"- {FEATURE_FIXED_FILE}",
        f"- {MODEL_FILE}",
        f"- {PREDICTIONS_FILE}",
        f"- {IMPORTANCE_FILE}",
        f"- {METRICS_FILE}",
        f"- {CONFUSION_PLOT_FILE}",
        f"- {IMPORTANCE_PLOT_FILE}",
        "",
        (
            "STEP 30B RESULT: "
            f"{'PASSED' if passed else 'REVIEW REQUIRED'}"
        ),
        "",
        (
            "IMPORTANT: The correction is for synthetic "
            "pipeline validation. Update the real ESP32 "
            "logger before collecting thesis data."
        ),
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    save_confusion_plot(
        test_matrix
    )

    save_importance_plot(
        feature_importance
    )

    print(
        "\n".join(report_lines)
    )


if __name__ == "__main__":
    main()
