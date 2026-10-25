#include <Arduino.h>
#include "C1_TinyML_Model.h"

// =====================================================
// COMPONENT 1 — STEP 31A ESP32 MODEL PARITY TEST
//
// Put this .ino file and C1_TinyML_Model.h in the same
// Arduino sketch folder before compiling.
// =====================================================

struct TestCase {
  float features[C1TinyML::FEATURE_COUNT];
  uint8_t scenarioId;
  uint8_t groundTruth;
  uint8_t expectedPrediction;
  float expectedProbability;
};

constexpr uint8_t TEST_CASE_COUNT = 12;
constexpr float PROBABILITY_TOLERANCE = 0.001f;

const TestCase TEST_CASES[TEST_CASE_COUNT] = {
  {{0.0f, 0.0f, 0.148257f, 0.573f, 53841.0f}, 0, 0, 0, 0.0570910709f},
  {{0.0f, 0.0f, 0.015157f, -0.032f, 63895.0f}, 0, 0, 0, 0.0609659362f},
  {{-0.25f, 0.0f, 0.351059f, -0.086f, 0.0f}, 1, 1, 1, 0.952476165f},
  {{-1.0f, 0.0f, 0.24331f, 0.166f, 0.0f}, 1, 1, 1, 0.9705456f},
  {{0.0f, 0.0f, 0.094729f, -63.1603098f, 0.0f}, 2, 1, 1, 0.935536688f},
  {{0.0f, 0.0f, 0.0246f, -75.7576172f, 0.0f}, 2, 1, 1, 0.939028752f},
  {{0.0f, 0.0f, 33.035457f, -1.441f, 0.0f}, 3, 1, 1, 0.625985271f},
  {{0.0f, 0.0f, 0.006556f, -0.634f, 0.0f}, 3, 1, 1, 0.918370483f},
  {{0.0f, 0.0f, 0.014315f, -0.113f, 366957.0f}, 4, 1, 1, 0.690591713f},
  {{0.0f, 0.0f, 0.063225f, 0.351f, 256071.0f}, 4, 1, 1, 0.745977653f},
  {{0.0f, 1.0f, 0.012231f, 0.037f, 0.0f}, 5, 1, 1, 0.985185185f},
  {{0.0f, 1.0f, 0.013302f, -0.348f, 0.0f}, 5, 1, 1, 1.0f},
};

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println("==========================================");
  Serial.println("STEP 31A — ESP32 RANDOM FOREST PARITY TEST");
  Serial.println("==========================================");

  uint8_t passedCases = 0;

  for (uint8_t i = 0; i < TEST_CASE_COUNT; i++) {
    const TestCase& test = TEST_CASES[i];

    const float actualProbability =
        C1TinyML::predictAnomalyProbability(test.features);

    const uint8_t actualPrediction =
        C1TinyML::predictLabel(test.features);

    const float probabilityDifference =
        fabsf(actualProbability - test.expectedProbability);

    const bool labelMatch =
        actualPrediction == test.expectedPrediction;

    const bool probabilityMatch =
        probabilityDifference <= PROBABILITY_TOLERANCE;

    const bool casePassed =
        labelMatch && probabilityMatch;

    if (casePassed) {
      passedCases++;
    }

    Serial.println("------------------------------------------");
    Serial.print("Test case              : ");
    Serial.print(i + 1);
    Serial.print("/");
    Serial.println(TEST_CASE_COUNT);

    Serial.print("Scenario ID            : ");
    Serial.println(test.scenarioId);

    Serial.print("Ground-truth label     : ");
    Serial.println(test.groundTruth);

    Serial.print("Expected model label   : ");
    Serial.println(test.expectedPrediction);

    Serial.print("ESP32 model label      : ");
    Serial.println(actualPrediction);

    Serial.print("Expected probability  : ");
    Serial.println(test.expectedProbability, 6);

    Serial.print("ESP32 probability     : ");
    Serial.println(actualProbability, 6);

    Serial.print("Probability difference: ");
    Serial.println(probabilityDifference, 8);

    Serial.print("Case result            : ");
    Serial.println(casePassed ? "PASSED" : "FAILED");
  }

  Serial.println("==========================================");
  Serial.print("Passed cases           : ");
  Serial.print(passedCases);
  Serial.print("/");
  Serial.println(TEST_CASE_COUNT);

  Serial.print("STEP 31A RESULT        : ");
  Serial.println(
    passedCases == TEST_CASE_COUNT
      ? "PASSED"
      : "REVIEW REQUIRED"
  );
  Serial.println("==========================================");
}

void loop() {
  delay(1000);
}
