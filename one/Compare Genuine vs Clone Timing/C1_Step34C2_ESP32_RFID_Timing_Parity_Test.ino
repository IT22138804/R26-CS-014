#include <Arduino.h>
#include "C1_RFID_Timing_Risk_Model.h"

struct TestCase {
  float features[
    C1RFIDTimingRisk::FEATURE_COUNT
  ];

  uint8_t groundTruth;
  float expectedProbability;
  uint8_t expectedRiskFlag;
};

constexpr uint8_t TEST_CASE_COUNT = 12;
constexpr float PROBABILITY_TOLERANCE =
    0.001f;

const TestCase TEST_CASES[
    TEST_CASE_COUNT
] = {
  {{2830.0f, 2247.0f, 2690.0f, 4942.0f}, 0, 0.665132675f, 0},
  {{2831.0f, 2228.0f, 2671.0f, 4900.0f}, 0, 0.0193743959f, 0},
  {{2835.0f, 2236.0f, 2681.0f, 4920.0f}, 0, 0.120186318f, 0},
  {{2820.0f, 2234.0f, 2702.0f, 4941.0f}, 0, 0.456156704f, 0},
  {{2833.0f, 2238.0f, 2683.0f, 4926.0f}, 0, 0.218801978f, 0},
  {{2850.0f, 2246.0f, 2707.0f, 4958.0f}, 0, 0.70319388f, 0},
  {{2823.0f, 2245.0f, 2713.0f, 4963.0f}, 1, 0.892990525f, 1},
  {{2832.0f, 2253.0f, 2690.0f, 4948.0f}, 1, 0.823438864f, 1},
  {{2838.0f, 2254.0f, 2688.0f, 4944.0f}, 1, 0.737434571f, 0},
  {{2800.0f, 2243.0f, 2680.0f, 4931.0f}, 1, 0.704968644f, 0},
  {{2839.0f, 2234.0f, 2663.0f, 4900.0f}, 1, 0.0263346259f, 0},
  {{2839.0f, 2255.0f, 2714.0f, 4977.0f}, 1, 0.968664163f, 1},
};

void setup() {
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
  ) {
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

    if (passed) {
      passedCases++;
    }

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
  }

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
}

void loop() {
  delay(1000);
}
