
"""
Component 1 — Step 31A
Export the trained Step 30B Random Forest model into an ESP32-compatible
C++ header and verify prediction parity.

Required input files in the same folder:
    C1_RF_Step30B_Model.joblib
    C1_TinyML_Model_5_Features_FeatureFixed.csv

Outputs:
    C1_TinyML_Model.h
    C1_TinyML_Model_Parity.csv
    C1_TinyML_Model_Parity_Report.txt
    C1_Step31A_ESP32_Model_Parity_Test.ino

The Random Forest was trained on raw feature values, so this exporter
does not apply the Step 29A z-score scaler.

Feature order:
    0 rfid_auth_feature
    1 tamper_state
    2 temp_light_ratio
    3 moisture_delta
    4 relay_runtime_ms
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


MODEL_FILE = Path("C1_RF_Step30B_Model.joblib")
DATA_FILE = Path("C1_TinyML_Model_5_Features_FeatureFixed.csv")

HEADER_FILE = Path("C1_TinyML_Model.h")
PARITY_CSV_FILE = Path("C1_TinyML_Model_Parity.csv")
REPORT_FILE = Path("C1_TinyML_Model_Parity_Report.txt")
ARDUINO_TEST_FILE = Path("C1_Step31A_ESP32_Model_Parity_Test.ino")

FEATURE_COLUMNS = [
    "rfid_auth_feature",
    "tamper_state",
    "temp_light_ratio",
    "moisture_delta",
    "relay_runtime_ms",
]

REQUIRED_DATA_COLUMNS = [
    "record_id",
    "scenario_id",
    "label",
    "scenario_name",
    *FEATURE_COLUMNS,
    "split",
]

DECISION_THRESHOLD = 0.5
PARITY_TOLERANCE = 1e-6
ARDUINO_PROBABILITY_TOLERANCE = 0.001


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def cpp_float(value: float) -> str:
    """
    Emit a finite float literal with enough precision for tree thresholds
    and class weights.
    """
    if not math.isfinite(float(value)):
        fail(f"Non-finite model value cannot be exported: {value}")

    text = format(float(value), ".9g")

    if "e" not in text.lower() and "." not in text:
        text += ".0"

    return f"{text}f"


def validate_model(model: Any) -> RandomForestClassifier:
    if not isinstance(model, RandomForestClassifier):
        fail(
            "The loaded model is not a sklearn RandomForestClassifier. "
            f"Found: {type(model).__name__}"
        )

    if len(model.estimators_) == 0:
        fail("The Random Forest contains no trees.")

    if list(model.classes_) != [0, 1]:
        fail(
            "Expected binary class order [0, 1]. "
            f"Found: {list(model.classes_)}"
        )

    if int(model.n_features_in_) != len(FEATURE_COLUMNS):
        fail(
            f"Expected {len(FEATURE_COLUMNS)} input features, "
            f"but the model expects {model.n_features_in_}."
        )

    return model


def validate_data(df: pd.DataFrame) -> None:
    missing = [
        column
        for column in REQUIRED_DATA_COLUMNS
        if column not in df.columns
    ]

    if missing:
        fail(f"Dataset is missing required columns: {missing}")

    if df[FEATURE_COLUMNS].isna().any().any():
        fail("Dataset contains missing feature values.")

    if "test" not in set(df["split"]):
        fail("Dataset does not contain a test split.")


def extract_tree_nodes(estimator: Any) -> list[dict[str, float | int]]:
    tree = estimator.tree_
    nodes: list[dict[str, float | int]] = []

    for node_index in range(tree.node_count):
        feature = int(tree.feature[node_index])
        left = int(tree.children_left[node_index])
        right = int(tree.children_right[node_index])
        threshold = float(tree.threshold[node_index])

        # tree.value may contain counts, weighted counts, or normalized
        # proportions depending on the sklearn version. Their ratio still
        # gives the leaf class probability.
        values = np.asarray(tree.value[node_index]).reshape(-1)

        if len(values) != 2:
            fail(
                "Expected exactly two class values in every leaf. "
                f"Node {node_index} contains {len(values)} values."
            )

        normal_weight = float(values[0])
        anomaly_weight = float(values[1])

        is_leaf = feature < 0 or left < 0 or right < 0

        nodes.append(
            {
                "left": -1 if is_leaf else left,
                "right": -1 if is_leaf else right,
                "feature": -1 if is_leaf else feature,
                "threshold": 0.0 if is_leaf else threshold,
                "normal_weight": normal_weight,
                "anomaly_weight": anomaly_weight,
            }
        )

    return nodes


def tree_probability_python(
    nodes: list[dict[str, float | int]],
    features: np.ndarray,
) -> float:
    node_index = 0
    safety_counter = 0

    while True:
        node = nodes[node_index]
        feature = int(node["feature"])

        if feature < 0:
            normal_weight = float(node["normal_weight"])
            anomaly_weight = float(node["anomaly_weight"])
            total = normal_weight + anomaly_weight

            if total <= 0.0:
                return 0.0

            return anomaly_weight / total

        threshold = float(node["threshold"])

        if float(features[feature]) <= threshold:
            node_index = int(node["left"])
        else:
            node_index = int(node["right"])

        safety_counter += 1

        if safety_counter > len(nodes):
            fail("Tree traversal exceeded the node count.")


def forest_probability_python(
    forest_nodes: list[list[dict[str, float | int]]],
    features: np.ndarray,
) -> float:
    total = 0.0

    for nodes in forest_nodes:
        total += tree_probability_python(nodes, features)

    return total / len(forest_nodes)


def generate_header(
    model: RandomForestClassifier,
    forest_nodes: list[list[dict[str, float | int]]],
) -> str:
    lines: list[str] = []

    lines.extend(
        [
            "#ifndef C1_TINYML_MODEL_H",
            "#define C1_TINYML_MODEL_H",
            "",
            "#include <Arduino.h>",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "",
            "// =====================================================",
            "// COMPONENT 1 — EXPORTED RANDOM FOREST",
            "// Generated by C1_Step31A_Export_RF_To_ESP32.py",
            "//",
            "// Feature order:",
            "//   0: rfid_auth_feature",
            "//   1: tamper_state",
            "//   2: temp_light_ratio",
            "//   3: moisture_delta",
            "//   4: relay_runtime_ms",
            "//",
            "// This model expects RAW feature values.",
            "// Do not apply the Step 29A z-score scaler.",
            "// =====================================================",
            "",
            "namespace C1TinyML {",
            "",
            "constexpr uint8_t FEATURE_COUNT = 5;",
            f"constexpr uint16_t TREE_COUNT = {len(forest_nodes)};",
            f"constexpr float DECISION_THRESHOLD = {cpp_float(DECISION_THRESHOLD)};",
            "",
            "struct RFNode {",
            "  int16_t left;",
            "  int16_t right;",
            "  int8_t feature;",
            "  float threshold;",
            "  float normalWeight;",
            "  float anomalyWeight;",
            "};",
            "",
        ]
    )

    for tree_index, nodes in enumerate(forest_nodes):
        lines.append(
            f"static const RFNode TREE_{tree_index}[{len(nodes)}] = {{"
        )

        for node in nodes:
            lines.append(
                "  {"
                f"{int(node['left'])}, "
                f"{int(node['right'])}, "
                f"{int(node['feature'])}, "
                f"{cpp_float(float(node['threshold']))}, "
                f"{cpp_float(float(node['normal_weight']))}, "
                f"{cpp_float(float(node['anomaly_weight']))}"
                "},"
            )

        lines.append("};")
        lines.append("")

    tree_pointer_items = ", ".join(
        f"TREE_{tree_index}"
        for tree_index in range(len(forest_nodes))
    )
    tree_size_items = ", ".join(
        str(len(nodes))
        for nodes in forest_nodes
    )

    lines.extend(
        [
            f"static const RFNode* const TREES[TREE_COUNT] = {{{tree_pointer_items}}};",
            f"static const uint16_t TREE_SIZES[TREE_COUNT] = {{{tree_size_items}}};",
            "",
            "inline float predictTreeProbability(",
            "    const RFNode* nodes,",
            "    uint16_t nodeCount,",
            "    const float features[FEATURE_COUNT]",
            ") {",
            "  int16_t nodeIndex = 0;",
            "  uint16_t safetyCounter = 0;",
            "",
            "  while (true) {",
            "    if (nodeIndex < 0 || nodeIndex >= nodeCount) {",
            "      return 0.0f;",
            "    }",
            "",
            "    const RFNode& node = nodes[nodeIndex];",
            "",
            "    if (node.feature < 0) {",
            "      const float total = node.normalWeight + node.anomalyWeight;",
            "",
            "      if (total <= 0.0f) {",
            "        return 0.0f;",
            "      }",
            "",
            "      return node.anomalyWeight / total;",
            "    }",
            "",
            "    const float value = features[node.feature];",
            "",
            "    nodeIndex =",
            "        value <= node.threshold",
            "          ? node.left",
            "          : node.right;",
            "",
            "    safetyCounter++;",
            "",
            "    if (safetyCounter > nodeCount) {",
            "      return 0.0f;",
            "    }",
            "  }",
            "}",
            "",
            "inline float predictAnomalyProbability(",
            "    const float features[FEATURE_COUNT]",
            ") {",
            "  float probabilityTotal = 0.0f;",
            "",
            "  for (uint16_t treeIndex = 0; treeIndex < TREE_COUNT; treeIndex++) {",
            "    probabilityTotal += predictTreeProbability(",
            "      TREES[treeIndex],",
            "      TREE_SIZES[treeIndex],",
            "      features",
            "    );",
            "  }",
            "",
            "  return probabilityTotal / static_cast<float>(TREE_COUNT);",
            "}",
            "",
            "inline uint8_t predictLabel(",
            "    const float features[FEATURE_COUNT]",
            ") {",
            "  return",
            "      predictAnomalyProbability(features) >= DECISION_THRESHOLD",
            "        ? 1",
            "        : 0;",
            "}",
            "",
            "}  // namespace C1TinyML",
            "",
            "#endif  // C1_TINYML_MODEL_H",
            "",
        ]
    )

    return "\n".join(lines)


def choose_arduino_test_rows(
    test_df: pd.DataFrame,
    model: RandomForestClassifier,
) -> pd.DataFrame:
    chosen_parts: list[pd.DataFrame] = []

    for scenario_id, group in test_df.groupby(
        "scenario_id",
        sort=True,
    ):
        count = min(2, len(group))

        chosen_parts.append(
            group.sample(
                n=count,
                random_state=20260722 + int(scenario_id),
            )
        )

    chosen = (
        pd.concat(chosen_parts, ignore_index=True)
        .sort_values(["scenario_id", "record_id"])
        .reset_index(drop=True)
    )

    features = chosen[FEATURE_COLUMNS].to_numpy(dtype=np.float32)

    chosen["expected_probability"] = model.predict_proba(features)[:, 1]
    chosen["expected_prediction"] = (
        chosen["expected_probability"] >= DECISION_THRESHOLD
    ).astype(int)

    return chosen


def generate_arduino_test_sketch(
    selected: pd.DataFrame,
) -> str:
    lines: list[str] = []

    lines.extend(
        [
            "#include <Arduino.h>",
            '#include "C1_TinyML_Model.h"',
            "",
            "// =====================================================",
            "// COMPONENT 1 — STEP 31A ESP32 MODEL PARITY TEST",
            "//",
            "// Put this .ino file and C1_TinyML_Model.h in the same",
            "// Arduino sketch folder before compiling.",
            "// =====================================================",
            "",
            "struct TestCase {",
            "  float features[C1TinyML::FEATURE_COUNT];",
            "  uint8_t scenarioId;",
            "  uint8_t groundTruth;",
            "  uint8_t expectedPrediction;",
            "  float expectedProbability;",
            "};",
            "",
            f"constexpr uint8_t TEST_CASE_COUNT = {len(selected)};",
            f"constexpr float PROBABILITY_TOLERANCE = {cpp_float(ARDUINO_PROBABILITY_TOLERANCE)};",
            "",
            "const TestCase TEST_CASES[TEST_CASE_COUNT] = {",
        ]
    )

    for row in selected.itertuples(index=False):
        feature_values = ", ".join(
            cpp_float(float(getattr(row, column)))
            for column in FEATURE_COLUMNS
        )

        lines.append(
            "  {{"
            f"{feature_values}"
            "}, "
            f"{int(row.scenario_id)}, "
            f"{int(row.label)}, "
            f"{int(row.expected_prediction)}, "
            f"{cpp_float(float(row.expected_probability))}"
            "},"
        )

    lines.extend(
        [
            "};",
            "",
            "void setup() {",
            "  Serial.begin(115200);",
            "  delay(1500);",
            "",
            '  Serial.println("==========================================");',
            '  Serial.println("STEP 31A — ESP32 RANDOM FOREST PARITY TEST");',
            '  Serial.println("==========================================");',
            "",
            "  uint8_t passedCases = 0;",
            "",
            "  for (uint8_t i = 0; i < TEST_CASE_COUNT; i++) {",
            "    const TestCase& test = TEST_CASES[i];",
            "",
            "    const float actualProbability =",
            "        C1TinyML::predictAnomalyProbability(test.features);",
            "",
            "    const uint8_t actualPrediction =",
            "        C1TinyML::predictLabel(test.features);",
            "",
            "    const float probabilityDifference =",
            "        fabsf(actualProbability - test.expectedProbability);",
            "",
            "    const bool labelMatch =",
            "        actualPrediction == test.expectedPrediction;",
            "",
            "    const bool probabilityMatch =",
            "        probabilityDifference <= PROBABILITY_TOLERANCE;",
            "",
            "    const bool casePassed =",
            "        labelMatch && probabilityMatch;",
            "",
            "    if (casePassed) {",
            "      passedCases++;",
            "    }",
            "",
            '    Serial.println("------------------------------------------");',
            '    Serial.print("Test case              : ");',
            "    Serial.print(i + 1);",
            '    Serial.print("/");',
            "    Serial.println(TEST_CASE_COUNT);",
            "",
            '    Serial.print("Scenario ID            : ");',
            "    Serial.println(test.scenarioId);",
            "",
            '    Serial.print("Ground-truth label     : ");',
            "    Serial.println(test.groundTruth);",
            "",
            '    Serial.print("Expected model label   : ");',
            "    Serial.println(test.expectedPrediction);",
            "",
            '    Serial.print("ESP32 model label      : ");',
            "    Serial.println(actualPrediction);",
            "",
            '    Serial.print("Expected probability  : ");',
            "    Serial.println(test.expectedProbability, 6);",
            "",
            '    Serial.print("ESP32 probability     : ");',
            "    Serial.println(actualProbability, 6);",
            "",
            '    Serial.print("Probability difference: ");',
            "    Serial.println(probabilityDifference, 8);",
            "",
            '    Serial.print("Case result            : ");',
            '    Serial.println(casePassed ? "PASSED" : "FAILED");',
            "  }",
            "",
            '  Serial.println("==========================================");',
            '  Serial.print("Passed cases           : ");',
            "  Serial.print(passedCases);",
            '  Serial.print("/");',
            "  Serial.println(TEST_CASE_COUNT);",
            "",
            '  Serial.print("STEP 31A RESULT        : ");',
            "  Serial.println(",
            '    passedCases == TEST_CASE_COUNT',
            '      ? "PASSED"',
            '      : "REVIEW REQUIRED"',
            "  );",
            '  Serial.println("==========================================");',
            "}",
            "",
            "void loop() {",
            "  delay(1000);",
            "}",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    if not MODEL_FILE.exists():
        fail(
            f"{MODEL_FILE} was not found. Run Step 30B first and keep "
            "this exporter in the same folder."
        )

    if not DATA_FILE.exists():
        fail(
            f"{DATA_FILE} was not found. Run Step 30B first and keep "
            "the feature-fixed CSV in the same folder."
        )

    model = validate_model(joblib.load(MODEL_FILE))

    df = pd.read_csv(DATA_FILE)
    validate_data(df)

    test_df = df[df["split"] == "test"].copy().reset_index(drop=True)
    x_test = test_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)

    forest_nodes = [
        extract_tree_nodes(estimator)
        for estimator in model.estimators_
    ]

    sklearn_probability = model.predict_proba(x_test)[:, 1]
    sklearn_prediction = (
        sklearn_probability >= DECISION_THRESHOLD
    ).astype(np.uint8)

    exported_probability = np.asarray(
        [
            forest_probability_python(forest_nodes, row)
            for row in x_test
        ],
        dtype=np.float64,
    )

    exported_prediction = (
        exported_probability >= DECISION_THRESHOLD
    ).astype(np.uint8)

    probability_difference = np.abs(
        sklearn_probability - exported_probability
    )

    prediction_match = (
        sklearn_prediction == exported_prediction
    )

    parity_df = test_df[
        [
            "record_id",
            "scenario_id",
            "scenario_name",
            "label",
            *FEATURE_COLUMNS,
        ]
    ].copy()

    parity_df["sklearn_probability"] = sklearn_probability
    parity_df["exported_probability"] = exported_probability
    parity_df["probability_difference"] = probability_difference
    parity_df["sklearn_prediction"] = sklearn_prediction
    parity_df["exported_prediction"] = exported_prediction
    parity_df["prediction_match"] = prediction_match.astype(int)

    parity_df.to_csv(PARITY_CSV_FILE, index=False)

    header_text = generate_header(model, forest_nodes)
    HEADER_FILE.write_text(header_text, encoding="utf-8")

    selected_test_rows = choose_arduino_test_rows(test_df, model)
    arduino_test_text = generate_arduino_test_sketch(selected_test_rows)
    ARDUINO_TEST_FILE.write_text(arduino_test_text, encoding="utf-8")

    max_probability_difference = float(probability_difference.max())
    mean_probability_difference = float(probability_difference.mean())
    matched_predictions = int(prediction_match.sum())
    total_predictions = int(len(prediction_match))

    total_nodes = sum(len(nodes) for nodes in forest_nodes)
    maximum_nodes = max(len(nodes) for nodes in forest_nodes)
    header_size_bytes = HEADER_FILE.stat().st_size

    passed = (
        matched_predictions == total_predictions
        and max_probability_difference <= PARITY_TOLERANCE
    )

    report_lines = [
        "COMPONENT 1 — STEP 31A MODEL EXPORT REPORT",
        "=" * 50,
        "",
        f"Model file: {MODEL_FILE}",
        f"Dataset file: {DATA_FILE}",
        f"Trees exported: {len(forest_nodes)}",
        f"Total tree nodes: {total_nodes}",
        f"Maximum nodes in one tree: {maximum_nodes}",
        f"Input feature count: {len(FEATURE_COLUMNS)}",
        f"Generated header size: {header_size_bytes} bytes",
        "",
        "Feature order:",
        *[
            f"{index}: {feature}"
            for index, feature in enumerate(FEATURE_COLUMNS)
        ],
        "",
        "Python parity validation:",
        f"- Test records checked: {total_predictions}",
        f"- Matching predictions: {matched_predictions}",
        f"- Maximum probability difference: {max_probability_difference:.12f}",
        f"- Mean probability difference: {mean_probability_difference:.12f}",
        f"- Allowed Python difference: {PARITY_TOLERANCE:.12f}",
        "",
        "Files created:",
        f"- {HEADER_FILE}",
        f"- {PARITY_CSV_FILE}",
        f"- {REPORT_FILE}",
        f"- {ARDUINO_TEST_FILE}",
        "",
        f"STEP 31A RESULT: {'PASSED' if passed else 'REVIEW REQUIRED'}",
        "",
        "Next action:",
        "Put C1_TinyML_Model.h and "
        "C1_Step31A_ESP32_Model_Parity_Test.ino in the same Arduino "
        "sketch folder, then upload the parity test to the ESP32.",
        "",
        "Important:",
        "The model was trained on synthetic simulation data. Final thesis "
        "evaluation must use real held-out ESP32 telemetry.",
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
