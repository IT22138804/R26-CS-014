
"""
Component 1 — Step 29A (Fixed)
Validate, clean, repair split assignments when necessary, and normalize
the five-feature TinyML dataset.

Place this script in the same folder as one of:
- C1_TinyML_Model_5_Features_Synthetic_Fixed.csv
- C1_TinyML_Model_5_Features_Synthetic.csv

Outputs:
- C1_TinyML_Model_5_Features_Cleaned.csv
- C1_TinyML_Model_5_Features_Normalized.csv
- C1_TinyML_Scaler_Stats.csv
- C1_TinyML_Validation_Report.txt
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


INPUT_CANDIDATES = [
    Path("C1_TinyML_Model_5_Features_Synthetic_Fixed.csv"),
    Path("C1_TinyML_Model_5_Features_Synthetic.csv"),
]

CLEANED_FILE = Path("C1_TinyML_Model_5_Features_Cleaned.csv")
NORMALIZED_FILE = Path("C1_TinyML_Model_5_Features_Normalized.csv")
SCALER_FILE = Path("C1_TinyML_Scaler_Stats.csv")
REPORT_FILE = Path("C1_TinyML_Validation_Report.txt")

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

VALID_SCENARIOS = {
    0: "NORMAL_OPERATION",
    1: "RFID_AUTH_ANOMALY",
    2: "SOIL_SENSOR_DISCONNECT",
    3: "LIGHT_SENSOR_MANIPULATION",
    4: "ACTUATOR_RUNTIME_MISUSE",
    5: "PHYSICAL_TAMPER",
}

VALID_SPLITS = ["train", "validation", "test"]
VALID_RFID_VALUES = {-1.0, -0.25, 0.0, 1.0}


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def find_input_file() -> Path:
    for path in INPUT_CANDIDATES:
        if path.exists():
            return path
    fail(
        "No input CSV was found. Put this script in the same folder as "
        "C1_TinyML_Model_5_Features_Synthetic_Fixed.csv or "
        "C1_TinyML_Model_5_Features_Synthetic.csv."
    )


def split_has_both_labels(frame: pd.DataFrame) -> bool:
    table = pd.crosstab(frame["split"], frame["label"])
    for split in VALID_SPLITS:
        if split not in table.index:
            return False
        for label in [0, 1]:
            if label not in table.columns or table.loc[split, label] == 0:
                return False
    return True


def repair_stratified_splits(frame: pd.DataFrame) -> pd.DataFrame:
    """
    Deterministically assign 70/15/15 splits inside each scenario.
    This keeps every scenario represented in train, validation and test.
    """
    repaired_parts = []

    for scenario_id, group in frame.groupby("scenario_id", sort=True):
        group = group.sample(
            frac=1.0,
            random_state=20260722 + int(scenario_id)
        ).reset_index(drop=True)

        n = len(group)
        n_train = int(round(n * 0.70))
        n_validation = int(round(n * 0.15))

        group.loc[: n_train - 1, "split"] = "train"
        group.loc[
            n_train : n_train + n_validation - 1,
            "split"
        ] = "validation"
        group.loc[
            n_train + n_validation :,
            "split"
        ] = "test"

        repaired_parts.append(group)

    return (
        pd.concat(repaired_parts, ignore_index=True)
        .sort_values("record_id")
        .reset_index(drop=True)
    )


def main() -> None:
    input_file = find_input_file()
    df = pd.read_csv(input_file)

    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]
    if missing_columns:
        fail(f"Missing required columns: {missing_columns}")

    original_rows = len(df)
    df = df[REQUIRED_COLUMNS].copy()

    numeric_columns = [
        "record_id",
        "scenario_id",
        "label",
        *FEATURE_COLUMNS,
    ]

    for column in numeric_columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    missing_value_rows = int(df.isna().any(axis=1).sum())
    df = df.dropna().copy()

    duplicate_record_ids = int(
        df.duplicated(subset=["record_id"]).sum()
    )
    df = df.drop_duplicates(
        subset=["record_id"],
        keep="first"
    ).copy()

    exact_duplicates = int(df.duplicated().sum())
    df = df.drop_duplicates().copy()

    df["record_id"] = df["record_id"].astype(int)
    df["scenario_id"] = df["scenario_id"].astype(int)
    df["label"] = df["label"].astype(int)
    df["tamper_state"] = df["tamper_state"].astype(int)

    valid_mask = (
        df["scenario_id"].isin(VALID_SCENARIOS.keys())
        & df["label"].isin([0, 1])
        & df["split"].isin(VALID_SPLITS)
        & df["rfid_auth_feature"].round(2).isin(VALID_RFID_VALUES)
        & df["tamper_state"].isin([0, 1])
        & df["temp_light_ratio"].between(0.0, 100.0)
        & df["moisture_delta"].between(-100.0, 100.0)
        & df["relay_runtime_ms"].between(0.0, 600000.0)
    )

    invalid_range_rows = int((~valid_mask).sum())
    df = df.loc[valid_mask].copy()

    expected_names = df["scenario_id"].map(VALID_SCENARIOS)
    scenario_name_mismatches = int(
        (df["scenario_name"] != expected_names).sum()
    )
    df = df.loc[
        df["scenario_name"] == expected_names
    ].copy()

    expected_labels = (df["scenario_id"] != 0).astype(int)
    label_mismatches = int(
        (df["label"] != expected_labels).sum()
    )
    df = df.loc[
        df["label"] == expected_labels
    ].copy()

    split_repaired = False

    if not split_has_both_labels(df):
        print(
            "WARNING: The original split assignment does not place both "
            "labels in train, validation and test."
        )
        print(
            "Repairing splits deterministically inside every scenario "
            "using 70% train, 15% validation and 15% test."
        )
        df = repair_stratified_splits(df)
        split_repaired = True

    if not split_has_both_labels(df):
        fail("Split repair failed to create both labels in every split.")

    df = df.sort_values(
        ["split", "scenario_id", "record_id"]
    ).reset_index(drop=True)

    split_label_counts = pd.crosstab(
        df["split"],
        df["label"]
    )

    split_scenario_counts = pd.crosstab(
        df["split"],
        df["scenario_id"]
    )

    df.to_csv(CLEANED_FILE, index=False)

    # Fit scaler only on the training partition.
    train_df = df[df["split"] == "train"].copy()

    means = train_df[FEATURE_COLUMNS].mean()
    stds = train_df[FEATURE_COLUMNS].std(ddof=0)
    stds = stds.replace(0, 1.0)

    normalized_df = df.copy()

    for feature in FEATURE_COLUMNS:
        normalized_df[f"{feature}_z"] = (
            normalized_df[feature] - means[feature]
        ) / stds[feature]

    normalized_df.to_csv(
        NORMALIZED_FILE,
        index=False
    )

    scaler_df = pd.DataFrame(
        {
            "feature": FEATURE_COLUMNS,
            "train_mean": [
                means[feature]
                for feature in FEATURE_COLUMNS
            ],
            "train_std": [
                stds[feature]
                for feature in FEATURE_COLUMNS
            ],
        }
    )
    scaler_df.to_csv(SCALER_FILE, index=False)

    scenario_counts = (
        df.groupby(
            ["scenario_id", "scenario_name", "label"]
        )
        .size()
        .reset_index(name="rows")
    )

    report_lines = [
        "COMPONENT 1 — STEP 29A DATASET VALIDATION REPORT",
        "=" * 54,
        "",
        f"Input file: {input_file}",
        f"Original rows: {original_rows}",
        f"Rows removed for missing values: {missing_value_rows}",
        f"Duplicate record IDs removed: {duplicate_record_ids}",
        f"Exact duplicate rows removed: {exact_duplicates}",
        f"Rows removed for invalid ranges: {invalid_range_rows}",
        f"Scenario-name mismatches removed: {scenario_name_mismatches}",
        f"Binary-label mismatches removed: {label_mismatches}",
        f"Split assignment repaired: {'YES' if split_repaired else 'NO'}",
        f"Final cleaned rows: {len(df)}",
        "",
        "Rows by split and binary label:",
        split_label_counts.to_string(),
        "",
        "Rows by split and scenario:",
        split_scenario_counts.to_string(),
        "",
        "Rows by scenario:",
        scenario_counts.to_string(index=False),
        "",
        "Training-only scaler statistics:",
        scaler_df.to_string(index=False),
        "",
        "Files created:",
        f"- {CLEANED_FILE}",
        f"- {NORMALIZED_FILE}",
        f"- {SCALER_FILE}",
        "",
        "STEP 29A RESULT: PASSED",
        "",
        "Note: This dataset is synthetic simulation data. "
        "Final thesis performance must be evaluated using real ESP32 data.",
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8"
    )

    print("\n" + "\n".join(report_lines))


if __name__ == "__main__":
    main()
