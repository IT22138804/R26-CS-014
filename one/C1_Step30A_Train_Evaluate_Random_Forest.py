
"""
Component 1 — Step 30A
Train and evaluate a lightweight Random Forest binary anomaly classifier.

Input:
    C1_TinyML_Model_5_Features_Cleaned.csv

Outputs:
    C1_RF_TinyML_Model.joblib
    C1_RF_Test_Predictions.csv
    C1_RF_Feature_Importance.csv
    C1_RF_Metrics.json
    C1_RF_Training_Report.txt
    C1_RF_Confusion_Matrix.png
    C1_RF_Feature_Importance.png

Important:
The current dataset is synthetic simulation data. The resulting metrics
validate the software pipeline only. Final thesis metrics must come from
real ESP32 data collected in separate sessions.
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

MODEL_FILE = Path("C1_RF_TinyML_Model.joblib")
PREDICTIONS_FILE = Path("C1_RF_Test_Predictions.csv")
IMPORTANCE_FILE = Path("C1_RF_Feature_Importance.csv")
METRICS_FILE = Path("C1_RF_Metrics.json")
REPORT_FILE = Path("C1_RF_Training_Report.txt")
CONFUSION_PLOT_FILE = Path("C1_RF_Confusion_Matrix.png")
IMPORTANCE_PLOT_FILE = Path("C1_RF_Feature_Importance.png")

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


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def validate_input(df: pd.DataFrame) -> None:
    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
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
        labels = set(df.loc[df["split"] == split_name, "label"].unique())
        if labels != {0, 1}:
            fail(
                f"The {split_name} split must contain both labels. "
                f"Found labels: {sorted(labels)}"
            )


def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_probability: np.ndarray,
) -> dict:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_anomaly": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "recall_anomaly": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "f1_anomaly": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_probability)),
        "specificity_normal": float(specificity),
        "false_positive_rate": float(false_positive_rate),
        "false_negative_rate": float(false_negative_rate),
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
        ["scenario_id", "scenario_name", "label"]
    ].copy()
    evaluated["prediction"] = predictions

    rows: list[dict] = []

    for (scenario_id, scenario_name), group in evaluated.groupby(
        ["scenario_id", "scenario_name"],
        sort=True,
    ):
        actual_label = int(group["label"].iloc[0])
        expected_prediction = actual_label
        correct = int((group["prediction"] == expected_prediction).sum())
        total = len(group)

        rows.append(
            {
                "scenario_id": int(scenario_id),
                "scenario_name": str(scenario_name),
                "expected_label": actual_label,
                "rows": int(total),
                "correct_predictions": correct,
                "scenario_accuracy": float(correct / total if total else 0.0),
            }
        )

    return rows


def save_confusion_plot(matrix: np.ndarray) -> None:
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    image = ax.imshow(matrix)
    fig.colorbar(image, ax=ax)

    ax.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=["Predicted Normal", "Predicted Anomaly"],
        yticklabels=["Actual Normal", "Actual Anomaly"],
        title="Component 1 Random Forest — Test Confusion Matrix",
        ylabel="Actual class",
        xlabel="Predicted class",
    )

    threshold = matrix.max() / 2.0 if matrix.size else 0.0
    for row in range(matrix.shape[0]):
        for column in range(matrix.shape[1]):
            ax.text(
                column,
                row,
                str(matrix[row, column]),
                ha="center",
                va="center",
                color="white" if matrix[row, column] > threshold else "black",
            )

    fig.tight_layout()
    fig.savefig(CONFUSION_PLOT_FILE, dpi=180, bbox_inches="tight")
    plt.close(fig)


def save_importance_plot(importance_df: pd.DataFrame) -> None:
    ordered = importance_df.sort_values("importance", ascending=True)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(ordered["feature"], ordered["importance"])
    ax.set(
        title="Component 1 Random Forest — Feature Importance",
        xlabel="Importance",
        ylabel="Feature",
    )
    fig.tight_layout()
    fig.savefig(IMPORTANCE_PLOT_FILE, dpi=180, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    if not INPUT_FILE.exists():
        fail(
            f"{INPUT_FILE} was not found. Run Step 29A first and keep this "
            "script in the same folder as the cleaned CSV."
        )

    df = pd.read_csv(INPUT_FILE)
    validate_input(df)

    train_df = df[df["split"] == "train"].copy()
    validation_df = df[df["split"] == "validation"].copy()
    test_df = df[df["split"] == "test"].copy()

    x_train = train_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_train = train_df["label"].to_numpy(dtype=np.int32)

    x_validation = validation_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_validation = validation_df["label"].to_numpy(dtype=np.int32)

    x_test = test_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_test = test_df["label"].to_numpy(dtype=np.int32)

    # Small trees and a limited forest size are selected so the later
    # C++ header remains manageable for the ESP32.
    model = RandomForestClassifier(
        n_estimators=30,
        max_depth=6,
        min_samples_leaf=3,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(x_train, y_train)

    validation_probability = model.predict_proba(x_validation)[:, 1]
    validation_prediction = (validation_probability >= 0.5).astype(np.int32)

    test_probability = model.predict_proba(x_test)[:, 1]
    test_prediction = (test_probability >= 0.5).astype(np.int32)

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

    test_matrix = confusion_matrix(y_test, test_prediction, labels=[0, 1])

    feature_importance = pd.DataFrame(
        {
            "feature": FEATURE_COLUMNS,
            "importance": model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)

    scenario_metrics = evaluate_per_scenario(test_df, test_prediction)

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
    predictions_df["predicted_label"] = test_prediction
    predictions_df["anomaly_probability"] = test_probability
    predictions_df["correct"] = (
        predictions_df["label"] == predictions_df["predicted_label"]
    ).astype(int)

    predictions_df.to_csv(PREDICTIONS_FILE, index=False)
    feature_importance.to_csv(IMPORTANCE_FILE, index=False)
    joblib.dump(model, MODEL_FILE)

    pass_conditions = {
        "test_recall_at_least_0_90": test_metrics["recall_anomaly"] >= 0.90,
        "test_f1_at_least_0_90": test_metrics["f1_anomaly"] >= 0.90,
        "false_positive_rate_at_most_0_10": (
            test_metrics["false_positive_rate"] <= 0.10
        ),
    }
    passed = all(pass_conditions.values())

    output = {
        "model": {
            "type": "RandomForestClassifier",
            "n_estimators": int(model.n_estimators),
            "max_depth": int(model.max_depth),
            "min_samples_leaf": int(model.min_samples_leaf),
            "feature_columns": FEATURE_COLUMNS,
            "decision_threshold": 0.5,
            "random_state": RANDOM_STATE,
        },
        "dataset": {
            "input_file": str(INPUT_FILE),
            "train_rows": int(len(train_df)),
            "validation_rows": int(len(validation_df)),
            "test_rows": int(len(test_df)),
            "data_sources": sorted(df["data_source"].astype(str).unique().tolist()),
        },
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "test_scenario_metrics": scenario_metrics,
        "feature_importance": feature_importance.to_dict(orient="records"),
        "pass_conditions": pass_conditions,
        "step_30a_result": "PASSED" if passed else "REVIEW_REQUIRED",
        "important_note": (
            "Metrics are based on synthetic simulation data and validate the "
            "training pipeline only. Final thesis results require real held-out "
            "ESP32 measurements."
        ),
    }

    METRICS_FILE.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    classification_text = classification_report(
        y_test,
        test_prediction,
        target_names=["NORMAL", "ANOMALY"],
        digits=4,
        zero_division=0,
    )

    scenario_lines = [
        (
            f"{row['scenario_id']} {row['scenario_name']}: "
            f"{row['correct_predictions']}/{row['rows']} correct "
            f"({row['scenario_accuracy'] * 100:.2f}%)"
        )
        for row in scenario_metrics
    ]

    importance_lines = [
        f"{row.feature}: {row.importance:.6f}"
        for row in feature_importance.itertuples(index=False)
    ]

    report_lines = [
        "COMPONENT 1 — STEP 30A RANDOM FOREST TRAINING REPORT",
        "=" * 58,
        "",
        f"Input file: {INPUT_FILE}",
        f"Training rows: {len(train_df)}",
        f"Validation rows: {len(validation_df)}",
        f"Test rows: {len(test_df)}",
        "",
        "Model configuration:",
        f"- Trees: {model.n_estimators}",
        f"- Maximum depth: {model.max_depth}",
        f"- Minimum leaf samples: {model.min_samples_leaf}",
        f"- Features: {', '.join(FEATURE_COLUMNS)}",
        "",
        "Validation metrics:",
        f"- Accuracy: {validation_metrics['accuracy']:.4f}",
        f"- Precision (anomaly): {validation_metrics['precision_anomaly']:.4f}",
        f"- Recall (anomaly): {validation_metrics['recall_anomaly']:.4f}",
        f"- F1 (anomaly): {validation_metrics['f1_anomaly']:.4f}",
        f"- ROC-AUC: {validation_metrics['roc_auc']:.4f}",
        "",
        "Test metrics:",
        f"- Accuracy: {test_metrics['accuracy']:.4f}",
        f"- Precision (anomaly): {test_metrics['precision_anomaly']:.4f}",
        f"- Recall (anomaly): {test_metrics['recall_anomaly']:.4f}",
        f"- F1 (anomaly): {test_metrics['f1_anomaly']:.4f}",
        f"- ROC-AUC: {test_metrics['roc_auc']:.4f}",
        f"- Specificity (normal): {test_metrics['specificity_normal']:.4f}",
        f"- False-positive rate: {test_metrics['false_positive_rate']:.4f}",
        f"- False-negative rate: {test_metrics['false_negative_rate']:.4f}",
        "",
        "Test confusion matrix:",
        f"TN={test_metrics['true_negative']}  FP={test_metrics['false_positive']}",
        f"FN={test_metrics['false_negative']}  TP={test_metrics['true_positive']}",
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
        f"- {MODEL_FILE}",
        f"- {PREDICTIONS_FILE}",
        f"- {IMPORTANCE_FILE}",
        f"- {METRICS_FILE}",
        f"- {CONFUSION_PLOT_FILE}",
        f"- {IMPORTANCE_PLOT_FILE}",
        "",
        f"STEP 30A RESULT: {'PASSED' if passed else 'REVIEW REQUIRED'}",
        "",
        "IMPORTANT: These results use synthetic simulation data. They must not "
        "be presented as final measured thesis performance.",
    ]

    REPORT_FILE.write_text("\n".join(report_lines), encoding="utf-8")

    save_confusion_plot(test_matrix)
    save_importance_plot(feature_importance)

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
