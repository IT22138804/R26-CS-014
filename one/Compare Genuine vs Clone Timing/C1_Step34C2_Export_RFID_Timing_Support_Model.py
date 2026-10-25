
"""
Component 1 Closure — Step 34C-2
Train and export an RFID timing-risk model for ESP32 support-only use.

Required inputs:
    C1_RFID_Genuine_vs_Clone_Combined.csv
    C1_RFID_Timing_Selected_Threshold.json

Outputs:
    C1_RFID_Timing_Support_Model.joblib
    C1_RFID_Timing_Risk_Model.h
    C1_RFID_Timing_Model_Parity.csv
    C1_RFID_Timing_Model_Export_Report.txt
    C1_Step34C2_ESP32_RFID_Timing_Parity_Test.ino

Important security policy:
- This model is a SUPPORTING SIGNAL only.
- It must not independently unlock, reject, or hard-lock the node.
- The current source files are synthetic pipeline data unless replaced
  with real physical measurements.
- Deterministic UID, Sector 4 authentication, protected-marker validation,
  tamper response, and existing anomaly confirmation remain primary.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DATA_FILE = Path("C1_RFID_Genuine_vs_Clone_Combined.csv")
THRESHOLD_FILE = Path("C1_RFID_Timing_Selected_Threshold.json")

MODEL_FILE = Path("C1_RFID_Timing_Support_Model.joblib")
HEADER_FILE = Path("C1_RFID_Timing_Risk_Model.h")
PARITY_FILE = Path("C1_RFID_Timing_Model_Parity.csv")
REPORT_FILE = Path("C1_RFID_Timing_Model_Export_Report.txt")
ARDUINO_TEST_FILE = Path(
    "C1_Step34C2_ESP32_RFID_Timing_Parity_Test.ino"
)

FEATURES = [
    "uid_latency_us",
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

REQUIRED_COLUMNS = [
    "source_name",
    "source_is_synthetic",
    "presentation_number",
    "class_label",
    *FEATURES,
]

RANDOM_STATE = 20260723
PARITY_TOLERANCE = 1e-10
ARDUINO_PROBABILITY_TOLERANCE = 0.001


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def cpp_float(value: float) -> str:
    if not math.isfinite(float(value)):
        fail(f"Cannot export non-finite value: {value}")

    text = format(float(value), ".9g")

    if "e" not in text.lower() and "." not in text:
        text += ".0"

    return text + "f"


def stable_sigmoid(value: float) -> float:
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))

    exp_value = math.exp(value)
    return exp_value / (1.0 + exp_value)


def load_threshold(path: Path) -> tuple[float, str]:
    if not path.exists():
        fail(
            f"{path} was not found. Run Step 34C-1 first."
        )

    document = json.loads(
        path.read_text(encoding="utf-8")
    )

    try:
        threshold = float(
            document["selected_threshold"]["threshold"]
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        fail(
            "Could not read "
            "selected_threshold.threshold from "
            f"{path}: {error}"
        )

    if not 0.0 <= threshold <= 1.0:
        fail(
            "Selected threshold must be between 0 and 1."
        )

    evidence_level = str(
        document.get(
            "evidence_level",
            "UNKNOWN",
        )
    )

    return threshold, evidence_level


def validate_data(frame: pd.DataFrame) -> pd.DataFrame:
    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in frame.columns
    ]

    if missing:
        fail(f"Missing required columns: {missing}")

    cleaned = frame.copy()

    for column in [
        "source_is_synthetic",
        "presentation_number",
        "class_label",
        *FEATURES,
    ]:
        cleaned[column] = pd.to_numeric(
            cleaned[column],
            errors="coerce",
        )

    invalid_count = int(
        cleaned[
            [
                "source_is_synthetic",
                "presentation_number",
                "class_label",
                *FEATURES,
            ]
        ].isna().any(axis=1).sum()
    )

    if invalid_count:
        print(
            f"Warning: dropping {invalid_count} invalid row(s)."
        )

        cleaned = cleaned.dropna(
            subset=[
                "source_is_synthetic",
                "presentation_number",
                "class_label",
                *FEATURES,
            ]
        ).copy()

    cleaned["class_label"] = cleaned[
        "class_label"
    ].astype(np.int32)

    if set(cleaned["class_label"].unique()) != {0, 1}:
        fail(
            "Both genuine class 0 and clone class 1 "
            "must be present."
        )

    if not (
        cleaned[FEATURES] > 0
    ).all().all():
        fail(
            "All successful timing features must be positive."
        )

    class_counts = cleaned[
        "class_label"
    ].value_counts()

    if int(class_counts.get(0, 0)) < 80:
        fail("At least 80 genuine rows are required.")

    if int(class_counts.get(1, 0)) < 80:
        fail("At least 80 clone rows are required.")

    return cleaned.reset_index(drop=True)


def manual_probability(
    features: np.ndarray,
    mean: np.ndarray,
    scale: np.ndarray,
    coefficient: np.ndarray,
    intercept: float,
) -> float:
    normalized = (
        features.astype(np.float64) - mean
    ) / scale

    logit = float(
        np.dot(normalized, coefficient)
        + intercept
    )

    return stable_sigmoid(logit)


def generate_header(
    mean: np.ndarray,
    scale: np.ndarray,
    coefficient: np.ndarray,
    intercept: float,
    threshold: float,
    source_is_synthetic: bool,
) -> str:
    mean_values = ", ".join(
        cpp_float(value)
        for value in mean
    )

    scale_values = ", ".join(
        cpp_float(value)
        for value in scale
    )

    coefficient_values = ", ".join(
        cpp_float(value)
        for value in coefficient
    )

    evidence = (
        "SYNTHETIC_PIPELINE_ONLY"
        if source_is_synthetic
        else "REAL_MEASURED_INPUT"
    )

    return f"""#ifndef C1_RFID_TIMING_RISK_MODEL_H
#define C1_RFID_TIMING_RISK_MODEL_H

#include <Arduino.h>
#include <math.h>
#include <stdint.h>

// =====================================================
// COMPONENT 1 — RFID TIMING-RISK SUPPORT MODEL
//
// Feature order:
//   0: uid_latency_us
//   1: auth_latency_us
//   2: block_read_latency_us
//   3: pipeline_latency_us
//
// Evidence level: {evidence}
//
// SECURITY RULE:
// This output is a SUPPORTING RISK SIGNAL only.
// It must never independently unlock, reject, operate relays,
// zeroize keys, or enter hard lockdown.
// =====================================================

namespace C1RFIDTimingRisk {{

constexpr uint8_t FEATURE_COUNT = 4;
constexpr float RISK_THRESHOLD = {cpp_float(threshold)};

// This remains false even when real data is later supplied.
// Independent held-out validation and system-level safety review
// are required before any active response is considered.
constexpr bool ACTIVE_SECURITY_ACTION_ALLOWED = false;
constexpr bool SUPPORTING_SIGNAL_ONLY = true;
constexpr bool SOURCE_DATA_SYNTHETIC = {
    "true" if source_is_synthetic else "false"
};

static const float FEATURE_MEAN[FEATURE_COUNT] = {{
  {mean_values}
}};

static const float FEATURE_SCALE[FEATURE_COUNT] = {{
  {scale_values}
}};

static const float MODEL_COEFFICIENT[FEATURE_COUNT] = {{
  {coefficient_values}
}};

constexpr float MODEL_INTERCEPT = {cpp_float(intercept)};

inline float stableSigmoid(float value) {{
  if (value >= 0.0f) {{
    return 1.0f / (1.0f + expf(-value));
  }}

  const float expValue = expf(value);
  return expValue / (1.0f + expValue);
}}

inline float predictCloneRiskProbability(
    const float rawFeatures[FEATURE_COUNT]
) {{
  float logit = MODEL_INTERCEPT;

  for (
    uint8_t featureIndex = 0;
    featureIndex < FEATURE_COUNT;
    featureIndex++
  ) {{
    const float normalized =
        (
          rawFeatures[featureIndex]
          - FEATURE_MEAN[featureIndex]
        )
        / FEATURE_SCALE[featureIndex];

    logit +=
        normalized
        * MODEL_COEFFICIENT[featureIndex];
  }}

  return stableSigmoid(logit);
}}

inline uint8_t predictRiskFlag(
    const float rawFeatures[FEATURE_COUNT]
) {{
  return
      predictCloneRiskProbability(rawFeatures)
          >= RISK_THRESHOLD
        ? 1
        : 0;
}}

}}  // namespace C1RFIDTimingRisk

#endif  // C1_RFID_TIMING_RISK_MODEL_H
"""


def select_test_rows(
    frame: pd.DataFrame,
    pipeline: Pipeline,
) -> pd.DataFrame:
    selected_parts: list[pd.DataFrame] = []

    for class_label, group in frame.groupby(
        "class_label",
        sort=True,
    ):
        selected_parts.append(
            group.sample(
                n=min(6, len(group)),
                random_state=(
                    RANDOM_STATE
                    + int(class_label)
                ),
            )
        )

    selected = (
        pd.concat(
            selected_parts,
            ignore_index=True,
        )
        .sort_values(
            [
                "class_label",
                "presentation_number",
            ]
        )
        .reset_index(drop=True)
    )

    selected_features = selected[
        FEATURES
    ].to_numpy(dtype=np.float64)

    selected["expected_probability"] = (
        pipeline.predict_proba(
            selected_features
        )[:, 1]
    )

    return selected


def generate_arduino_test(
    selected: pd.DataFrame,
    threshold: float,
) -> str:
    rows: list[str] = []

    for record in selected.itertuples(
        index=False
    ):
        feature_values = ", ".join(
            cpp_float(
                float(
                    getattr(
                        record,
                        feature,
                    )
                )
            )
            for feature in FEATURES
        )

        expected_probability = float(
            record.expected_probability
        )

        expected_flag = int(
            expected_probability >= threshold
        )

        rows.append(
            "  {{"
            f"{feature_values}"
            "}, "
            f"{int(record.class_label)}, "
            f"{cpp_float(expected_probability)}, "
            f"{expected_flag}"
            "},"
        )

    return f"""#include <Arduino.h>
#include "C1_RFID_Timing_Risk_Model.h"

struct TestCase {{
  float features[
    C1RFIDTimingRisk::FEATURE_COUNT
  ];

  uint8_t groundTruth;
  float expectedProbability;
  uint8_t expectedRiskFlag;
}};

constexpr uint8_t TEST_CASE_COUNT = {len(rows)};
constexpr float PROBABILITY_TOLERANCE =
    {cpp_float(ARDUINO_PROBABILITY_TOLERANCE)};

const TestCase TEST_CASES[
    TEST_CASE_COUNT
] = {{
{chr(10).join(rows)}
}};

void setup() {{
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println(
    "=========================================="
  );

  Serial.println(
    "STEP 34C-2 — RFID TIMING MODEL PARITY TEST"
  );

  Serial.println(
    "=========================================="
  );

  Serial.print("Supporting signal only   : ");
  Serial.println(
    C1RFIDTimingRisk::SUPPORTING_SIGNAL_ONLY
      ? "YES"
      : "NO"
  );

  Serial.print("Active action allowed    : ");
  Serial.println(
    C1RFIDTimingRisk::
        ACTIVE_SECURITY_ACTION_ALLOWED
      ? "YES"
      : "NO"
  );

  uint8_t passedCases = 0;

  for (
    uint8_t index = 0;
    index < TEST_CASE_COUNT;
    index++
  ) {{
    const TestCase& test =
        TEST_CASES[index];

    const float probability =
        C1RFIDTimingRisk::
            predictCloneRiskProbability(
              test.features
            );

    const uint8_t riskFlag =
        C1RFIDTimingRisk::
            predictRiskFlag(
              test.features
            );

    const float difference =
        fabsf(
          probability
          - test.expectedProbability
        );

    const bool passed =
        difference <=
            PROBABILITY_TOLERANCE
        &&
        riskFlag ==
            test.expectedRiskFlag;

    if (passed) {{
      passedCases++;
    }}

    Serial.println(
      "------------------------------------------"
    );

    Serial.print("Test case              : ");
    Serial.print(index + 1);
    Serial.print("/");
    Serial.println(TEST_CASE_COUNT);

    Serial.print("Ground-truth class     : ");
    Serial.println(test.groundTruth);

    Serial.print("Expected probability   : ");
    Serial.println(
      test.expectedProbability,
      6
    );

    Serial.print("ESP32 probability      : ");
    Serial.println(
      probability,
      6
    );

    Serial.print("Probability difference : ");
    Serial.println(
      difference,
      8
    );

    Serial.print("Expected risk flag     : ");
    Serial.println(
      test.expectedRiskFlag
    );

    Serial.print("ESP32 risk flag        : ");
    Serial.println(riskFlag);

    Serial.print("Case result            : ");
    Serial.println(
      passed
        ? "PASSED"
        : "FAILED"
    );
  }}

  Serial.println(
    "=========================================="
  );

  Serial.print("Passed cases           : ");
  Serial.print(passedCases);
  Serial.print("/");
  Serial.println(TEST_CASE_COUNT);

  Serial.print("STEP 34C-2 RESULT      : ");
  Serial.println(
    passedCases == TEST_CASE_COUNT
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println(
    "=========================================="
  );
}}

void loop() {{
  delay(1000);
}}
"""


def main() -> None:
    if not DATA_FILE.exists():
        fail(
            f"{DATA_FILE} was not found. "
            "Run Step 34B-4B first."
        )

    threshold, threshold_evidence = (
        load_threshold(
            THRESHOLD_FILE
        )
    )

    frame = validate_data(
        pd.read_csv(DATA_FILE)
    )

    source_is_synthetic = bool(
        frame[
            "source_is_synthetic"
        ].astype(int).any()
        or
        "SYNTHETIC" in
        threshold_evidence.upper()
    )

    x = frame[
        FEATURES
    ].to_numpy(dtype=np.float64)

    y = frame[
        "class_label"
    ].to_numpy(dtype=np.int32)

    pipeline = Pipeline(
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

    pipeline.fit(x, y)

    scaler: StandardScaler = (
        pipeline.named_steps[
            "scaler"
        ]
    )

    classifier: LogisticRegression = (
        pipeline.named_steps[
            "classifier"
        ]
    )

    mean = scaler.mean_.astype(
        np.float64
    )

    scale = scaler.scale_.astype(
        np.float64
    )

    coefficient = (
        classifier.coef_[0]
        .astype(np.float64)
    )

    intercept = float(
        classifier.intercept_[0]
    )

    sklearn_probability = (
        pipeline.predict_proba(x)[:, 1]
    )

    manual_probabilities = np.asarray(
        [
            manual_probability(
                row,
                mean,
                scale,
                coefficient,
                intercept,
            )
            for row in x
        ],
        dtype=np.float64,
    )

    difference = np.abs(
        sklearn_probability
        - manual_probabilities
    )

    sklearn_flag = (
        sklearn_probability >= threshold
    ).astype(np.int32)

    manual_flag = (
        manual_probabilities >= threshold
    ).astype(np.int32)

    flag_match = (
        sklearn_flag == manual_flag
    )

    parity = frame[
        [
            "source_name",
            "source_is_synthetic",
            "presentation_number",
            "class_label",
            *FEATURES,
        ]
    ].copy()

    parity[
        "sklearn_probability"
    ] = sklearn_probability

    parity[
        "manual_probability"
    ] = manual_probabilities

    parity[
        "probability_difference"
    ] = difference

    parity[
        "sklearn_risk_flag"
    ] = sklearn_flag

    parity[
        "manual_risk_flag"
    ] = manual_flag

    parity[
        "risk_flag_match"
    ] = flag_match.astype(int)

    parity.to_csv(
        PARITY_FILE,
        index=False,
    )

    joblib.dump(
        pipeline,
        MODEL_FILE,
    )

    HEADER_FILE.write_text(
        generate_header(
            mean,
            scale,
            coefficient,
            intercept,
            threshold,
            source_is_synthetic,
        ),
        encoding="utf-8",
    )

    selected = select_test_rows(
        frame,
        pipeline,
    )

    ARDUINO_TEST_FILE.write_text(
        generate_arduino_test(
            selected,
            threshold,
        ),
        encoding="utf-8",
    )

    maximum_difference = float(
        difference.max()
    )

    mean_difference = float(
        difference.mean()
    )

    matching_flags = int(
        flag_match.sum()
    )

    total_rows = int(
        len(flag_match)
    )

    passed = bool(
        matching_flags == total_rows
        and
        maximum_difference <=
            PARITY_TOLERANCE
    )

    report_lines = [
        "COMPONENT 1 CLOSURE — STEP 34C-2",
        "RFID TIMING SUPPORT MODEL EXPORT",
        "=" * 58,
        "",
        f"Dataset file              : {DATA_FILE}",
        f"Threshold file            : {THRESHOLD_FILE}",
        (
            "Evidence level            : "
            + (
                "SYNTHETIC_PIPELINE_ONLY"
                if source_is_synthetic
                else "REAL_MEASURED_INPUT"
            )
        ),
        f"Training rows             : {len(frame)}",
        (
            "Genuine rows              : "
            f"{int((y == 0).sum())}"
        ),
        (
            "Clone rows                : "
            f"{int((y == 1).sum())}"
        ),
        "",
        "Feature order:",
        *[
            f"{index}: {feature}"
            for index, feature
            in enumerate(FEATURES)
        ],
        "",
        (
            "Selected risk threshold   : "
            f"{threshold:.6f}"
        ),
        (
            "Supporting signal only    : YES"
        ),
        (
            "Active security action    : DISABLED"
        ),
        "",
        "Export parity:",
        (
            "Rows checked              : "
            f"{total_rows}"
        ),
        (
            "Matching risk flags       : "
            f"{matching_flags}"
        ),
        (
            "Maximum probability diff. : "
            f"{maximum_difference:.12f}"
        ),
        (
            "Mean probability diff.    : "
            f"{mean_difference:.12f}"
        ),
        "",
        (
            "STEP 34C-2 EXPORT RESULT  : "
            f"{'PASSED' if passed else 'REVIEW REQUIRED'}"
        ),
        "",
        "Files created:",
        f"- {MODEL_FILE}",
        f"- {HEADER_FILE}",
        f"- {PARITY_FILE}",
        f"- {REPORT_FILE}",
        f"- {ARDUINO_TEST_FILE}",
        "",
        "Security interpretation:",
        (
            "The exported probability may be logged "
            "as secondary evidence after a successful "
            "RFID authentication."
        ),
        (
            "It must not independently unlock, reject, "
            "operate relays, zeroize keys, or enter "
            "hard lockdown."
        ),
        (
            "Current synthetic results are not valid "
            "final clone-detection measurements."
        ),
    ]

    REPORT_FILE.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
