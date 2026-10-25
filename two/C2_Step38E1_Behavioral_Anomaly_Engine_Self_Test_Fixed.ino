/*
  Component 2 — Step 38E-1
  Lightweight Behavioral Anomaly Engine — Deterministic Self-Test

  Upload to:
    ESP32 No. 2 — Gateway ESP32 only

  For this step:
    - Sensor ESP32 may remain OFF.
    - Both E32 modules may remain OFF.
    - Wi-Fi/Firebase are not used.
    - Serial Monitor: 115200.

  Purpose:
    Validate four gateway-side behavioral detectors before integrating them
    into the live encrypted radio-to-Firebase gateway:

      1. Sensor-value anomaly
      2. Traffic-behavior anomaly
      3. Network-wide anomaly
      4. Time-based anomaly

  Important research limitation:
    The project currently has one real sensor node. Network-wide attack
    scenarios in this self-test are explicitly labelled SIMULATION.
*/

#include <Arduino.h>

constexpr uint8_t CRITICAL_CONFIRMATIONS_REQUIRED = 3;

// Overall classification thresholds.
constexpr int NORMAL_MAX = 29;
constexpr int SUSPICIOUS_MAX = 59;
constexpr int HIGH_MAX = 79;

// Reference operating values used by the self-test.
constexpr float EXPECTED_PACKET_INTERVAL_MS = 8000.0f;
constexpr float EXPECTED_PACKET_RATE_PER_MINUTE = 7.5f;
constexpr float MAX_TIMESTAMP_DELTA_MS = 30000.0f;

enum class RiskClass {
  NORMAL,
  SUSPICIOUS,
  HIGH_RISK,
  CRITICAL
};

enum class ActionDecision {
  ALLOW,
  MONITOR,
  INCREASE_MONITORING,
  CONFIRMATION_PENDING,
  REVOKE_SESSION,
  IMMEDIATE_LOCKDOWN
};

struct SensorInputs {
  bool sampleValid;
  float temperatureC;
  float humidityPercent;
  float lightLux;
  float soilPercent;

  float temperatureDelta;
  float humidityDelta;
  float lightDelta;
  float soilDelta;

  bool crossSensorInconsistency;
};

struct TrafficInputs {
  float packetRatePerMinute;
  float duplicateRatePercent;
  float authenticationFailureRatePercent;
  uint16_t malformedPacketCount;
  uint16_t handshakeRetryCount;
};

struct NetworkInputs {
  uint8_t totalNodeCount;
  uint8_t affectedNodeCount;
  bool coordinatedPattern;
  bool sameAnomalyType;
  bool simulation;
};

struct TimeInputs {
  float packetIntervalMs;
  float timestampDeltaMs;
  bool missingHeartbeat;
  bool unexpectedActivityTime;
};

struct ScenarioInput {
  const char* name;
  const char* description;

  SensorInputs sensor;
  TrafficInputs traffic;
  NetworkInputs network;
  TimeInputs time;

  bool physicalTamper;

  RiskClass expectedClass;
  ActionDecision expectedAction;
};

struct CategoryResult {
  int score;
  String status;
  String reasons;
};

struct EvaluationResult {
  CategoryResult sensorValue;
  CategoryResult trafficBehavior;
  CategoryResult networkWide;
  CategoryResult timeBased;

  int overallRiskScore;
  RiskClass riskClass;
  ActionDecision action;

  uint8_t criticalConfirmationCount;
  bool networkWideSimulation;
  bool passedExpectedResult;
};

uint8_t criticalConfirmationCount = 0;
uint16_t scenariosPassed = 0;
uint16_t scenariosFailed = 0;

// =====================================================
// TEXT HELPERS
// =====================================================

const char* riskClassText(RiskClass value) {
  switch (value) {
    case RiskClass::NORMAL:
      return "NORMAL";

    case RiskClass::SUSPICIOUS:
      return "SUSPICIOUS";

    case RiskClass::HIGH_RISK:
      return "HIGH";

    case RiskClass::CRITICAL:
      return "CRITICAL";
  }

  return "UNKNOWN";
}

const char* actionText(ActionDecision value) {
  switch (value) {
    case ActionDecision::ALLOW:
      return "ALLOW";

    case ActionDecision::MONITOR:
      return "MONITOR";

    case ActionDecision::INCREASE_MONITORING:
      return "INCREASE_MONITORING";

    case ActionDecision::CONFIRMATION_PENDING:
      return "CONFIRMATION_PENDING";

    case ActionDecision::REVOKE_SESSION:
      return "REVOKE_SESSION";

    case ActionDecision::IMMEDIATE_LOCKDOWN:
      return "IMMEDIATE_LOCKDOWN";
  }

  return "UNKNOWN";
}

void appendReason(
    String& reasons,
    const String& newReason
) {
  if (reasons.length() > 0) {
    reasons += " | ";
  }

  reasons += newReason;
}

int cappedScore(int value, int maximum) {
  if (value < 0) {
    return 0;
  }

  if (value > maximum) {
    return maximum;
  }

  return value;
}

// =====================================================
// 1. SENSOR-VALUE ANOMALY — MAXIMUM 30
// =====================================================

CategoryResult evaluateSensorValue(
    const SensorInputs& input
) {
  CategoryResult result;
  result.score = 0;
  result.status = "NORMAL";
  result.reasons = "";

  if (!input.sampleValid) {
    result.score += 20;
    appendReason(
      result.reasons,
      "SENSOR_SAMPLE_INVALID"
    );
  }

  if (
    input.temperatureC < 5.0f
    ||
    input.temperatureC > 50.0f
  ) {
    result.score += 6;
    appendReason(
      result.reasons,
      "TEMPERATURE_OUT_OF_RANGE"
    );
  }

  if (
    input.humidityPercent < 5.0f
    ||
    input.humidityPercent > 98.0f
  ) {
    result.score += 5;
    appendReason(
      result.reasons,
      "HUMIDITY_OUT_OF_RANGE"
    );
  }

  if (
    input.lightLux < 0.0f
    ||
    input.lightLux > 120000.0f
  ) {
    result.score += 5;
    appendReason(
      result.reasons,
      "LIGHT_OUT_OF_RANGE"
    );
  }

  if (
    input.soilPercent < 0.0f
    ||
    input.soilPercent > 100.0f
  ) {
    result.score += 5;
    appendReason(
      result.reasons,
      "SOIL_OUT_OF_RANGE"
    );
  }

  if (fabsf(input.temperatureDelta) > 8.0f) {
    result.score += 5;
    appendReason(
      result.reasons,
      "TEMPERATURE_IMPOSSIBLE_DELTA"
    );
  }

  if (fabsf(input.humidityDelta) > 25.0f) {
    result.score += 4;
    appendReason(
      result.reasons,
      "HUMIDITY_IMPOSSIBLE_DELTA"
    );
  }

  if (fabsf(input.lightDelta) > 50000.0f) {
    result.score += 4;
    appendReason(
      result.reasons,
      "LIGHT_IMPOSSIBLE_DELTA"
    );
  }

  if (fabsf(input.soilDelta) > 35.0f) {
    result.score += 5;
    appendReason(
      result.reasons,
      "SOIL_IMPOSSIBLE_DELTA"
    );
  }

  if (input.crossSensorInconsistency) {
    result.score += 5;
    appendReason(
      result.reasons,
      "CROSS_SENSOR_INCONSISTENCY"
    );
  }

  result.score =
      cappedScore(result.score, 30);

  if (result.score >= 24) {
    result.status = "CRITICAL";
  } else if (result.score >= 16) {
    result.status = "HIGH";
  } else if (result.score >= 8) {
    result.status = "SUSPICIOUS";
  }

  if (result.reasons.length() == 0) {
    result.reasons = "NONE";
  }

  return result;
}

// =====================================================
// 2. TRAFFIC-BEHAVIOR ANOMALY — MAXIMUM 25
// =====================================================

CategoryResult evaluateTrafficBehavior(
    const TrafficInputs& input
) {
  CategoryResult result;
  result.score = 0;
  result.status = "NORMAL";
  result.reasons = "";

  if (
    input.packetRatePerMinute
      > EXPECTED_PACKET_RATE_PER_MINUTE * 2.0f
  ) {
    result.score += 8;
    appendReason(
      result.reasons,
      "PACKET_BURST_RATE"
    );
  }

  if (input.duplicateRatePercent > 5.0f) {
    result.score += 7;
    appendReason(
      result.reasons,
      "DUPLICATE_REPLAY_SPIKE"
    );
  }

  if (
    input.authenticationFailureRatePercent
      > 5.0f
  ) {
    result.score += 7;
    appendReason(
      result.reasons,
      "AUTHENTICATION_FAILURE_SPIKE"
    );
  }

  if (input.malformedPacketCount > 0) {
    result.score += 3;
    appendReason(
      result.reasons,
      "MALFORMED_PACKET_ACTIVITY"
    );
  }

  if (input.handshakeRetryCount > 3) {
    result.score += 3;
    appendReason(
      result.reasons,
      "HANDSHAKE_RETRY_SPIKE"
    );
  }

  result.score =
      cappedScore(result.score, 25);

  if (result.score >= 20) {
    result.status = "CRITICAL";
  } else if (result.score >= 13) {
    result.status = "HIGH";
  } else if (result.score >= 7) {
    result.status = "SUSPICIOUS";
  }

  if (result.reasons.length() == 0) {
    result.reasons = "NONE";
  }

  return result;
}

// =====================================================
// 3. NETWORK-WIDE ANOMALY — MAXIMUM 25
// =====================================================

CategoryResult evaluateNetworkWide(
    const NetworkInputs& input
) {
  CategoryResult result;
  result.score = 0;
  result.status = "NORMAL";
  result.reasons = "";

  if (
    input.totalNodeCount < 2
    &&
    !input.simulation
  ) {
    result.status =
        "NOT_ENOUGH_REAL_NODES";

    result.reasons =
        "MULTI_NODE_VALIDATION_REQUIRES_AT_LEAST_TWO_REAL_NODES";

    return result;
  }

  const float affectedRatio =
      input.totalNodeCount == 0
        ? 0.0f
        : static_cast<float>(
            input.affectedNodeCount
          )
          /
          static_cast<float>(
            input.totalNodeCount
          );

  if (affectedRatio >= 0.75f) {
    result.score += 15;
    appendReason(
      result.reasons,
      "MAJORITY_OF_NODES_AFFECTED"
    );
  } else if (affectedRatio >= 0.50f) {
    result.score += 10;
    appendReason(
      result.reasons,
      "MULTIPLE_NODES_AFFECTED"
    );
  } else if (affectedRatio > 0.0f) {
    result.score += 4;
    appendReason(
      result.reasons,
      "SINGLE_NODE_OR_LOW_RATIO"
    );
  }

  if (input.coordinatedPattern) {
    result.score += 7;
    appendReason(
      result.reasons,
      "COORDINATED_PATTERN"
    );
  }

  if (input.sameAnomalyType) {
    result.score += 5;
    appendReason(
      result.reasons,
      "COMMON_ANOMALY_TYPE"
    );
  }

  result.score =
      cappedScore(result.score, 25);

  if (result.score >= 20) {
    result.status = "CRITICAL";
  } else if (result.score >= 13) {
    result.status = "HIGH";
  } else if (result.score >= 7) {
    result.status = "SUSPICIOUS";
  }

  if (input.simulation) {
    appendReason(
      result.reasons,
      "SIMULATION_ONLY"
    );
  }

  if (result.reasons.length() == 0) {
    result.reasons = "NONE";
  }

  return result;
}

// =====================================================
// 4. TIME-BASED ANOMALY — MAXIMUM 20
// =====================================================

CategoryResult evaluateTimeBased(
    const TimeInputs& input
) {
  CategoryResult result;
  result.score = 0;
  result.status = "NORMAL";
  result.reasons = "";

  if (
    fabsf(input.timestampDeltaMs)
      > MAX_TIMESTAMP_DELTA_MS
  ) {
    result.score += 10;
    appendReason(
      result.reasons,
      "STALE_OR_FUTURE_TIMESTAMP"
    );
  }

  if (input.missingHeartbeat) {
    result.score += 8;
    appendReason(
      result.reasons,
      "HEARTBEAT_MISSING"
    );
  }

  const float intervalDifference =
      fabsf(
        input.packetIntervalMs
        - EXPECTED_PACKET_INTERVAL_MS
      );

  if (
    intervalDifference
      > EXPECTED_PACKET_INTERVAL_MS * 0.50f
  ) {
    result.score += 5;
    appendReason(
      result.reasons,
      "PACKET_INTERVAL_DRIFT"
    );
  }

  if (input.unexpectedActivityTime) {
    result.score += 3;
    appendReason(
      result.reasons,
      "UNEXPECTED_ACTIVITY_TIME"
    );
  }

  result.score =
      cappedScore(result.score, 20);

  if (result.score >= 16) {
    result.status = "CRITICAL";
  } else if (result.score >= 10) {
    result.status = "HIGH";
  } else if (result.score >= 5) {
    result.status = "SUSPICIOUS";
  }

  if (result.reasons.length() == 0) {
    result.reasons = "NONE";
  }

  return result;
}

// =====================================================
// OVERALL DECISION
// =====================================================

RiskClass classifyRisk(int overallScore) {
  if (overallScore <= NORMAL_MAX) {
    return RiskClass::NORMAL;
  }

  if (overallScore <= SUSPICIOUS_MAX) {
    return RiskClass::SUSPICIOUS;
  }

  if (overallScore <= HIGH_MAX) {
    return RiskClass::HIGH_RISK;
  }

  return RiskClass::CRITICAL;
}

ActionDecision decideAction(
    RiskClass riskClass,
    bool physicalTamper
) {
  if (physicalTamper) {
    criticalConfirmationCount = 0;
    return ActionDecision::IMMEDIATE_LOCKDOWN;
  }

  switch (riskClass) {
    case RiskClass::NORMAL:
      criticalConfirmationCount = 0;
      return ActionDecision::ALLOW;

    case RiskClass::SUSPICIOUS:
      criticalConfirmationCount = 0;
      return ActionDecision::MONITOR;

    case RiskClass::HIGH_RISK:
      criticalConfirmationCount = 0;
      return ActionDecision::INCREASE_MONITORING;

    case RiskClass::CRITICAL:
      criticalConfirmationCount++;

      if (
        criticalConfirmationCount
          >= CRITICAL_CONFIRMATIONS_REQUIRED
      ) {
        return ActionDecision::REVOKE_SESSION;
      }

      return ActionDecision::CONFIRMATION_PENDING;
  }

  return ActionDecision::MONITOR;
}

EvaluationResult evaluateScenario(
    const ScenarioInput& scenario
) {
  EvaluationResult result;

  result.sensorValue =
      evaluateSensorValue(scenario.sensor);

  result.trafficBehavior =
      evaluateTrafficBehavior(
        scenario.traffic
      );

  result.networkWide =
      evaluateNetworkWide(
        scenario.network
      );

  result.timeBased =
      evaluateTimeBased(
        scenario.time
      );

  result.overallRiskScore =
      result.sensorValue.score
      +
      result.trafficBehavior.score
      +
      result.networkWide.score
      +
      result.timeBased.score;

  result.overallRiskScore =
      cappedScore(
        result.overallRiskScore,
        100
      );

  result.riskClass =
      classifyRisk(
        result.overallRiskScore
      );

  result.action =
      decideAction(
        result.riskClass,
        scenario.physicalTamper
      );

  result.criticalConfirmationCount =
      criticalConfirmationCount;

  result.networkWideSimulation =
      scenario.network.simulation;

  result.passedExpectedResult =
      result.riskClass
          == scenario.expectedClass
      &&
      result.action
          == scenario.expectedAction;

  return result;
}

// =====================================================
// REPORTING
// =====================================================

void printCategory(
    const char* categoryName,
    const CategoryResult& result
) {
  Serial.print(categoryName);
  Serial.print(" score");

  int spaces =
      25 - static_cast<int>(
        strlen(categoryName)
      );

  for (int index = 0; index < spaces; index++) {
    Serial.print(" ");
  }

  Serial.print(": ");
  Serial.println(result.score);

  Serial.print(categoryName);
  Serial.print(" status");

  spaces =
      24 - static_cast<int>(
        strlen(categoryName)
      );

  for (int index = 0; index < spaces; index++) {
    Serial.print(" ");
  }

  Serial.print(": ");
  Serial.println(result.status);

  Serial.print(categoryName);
  Serial.print(" reasons");

  spaces =
      23 - static_cast<int>(
        strlen(categoryName)
      );

  for (int index = 0; index < spaces; index++) {
    Serial.print(" ");
  }

  Serial.print(": ");
  Serial.println(result.reasons);
}

void printEvaluation(
    uint8_t testNumber,
    const ScenarioInput& scenario,
    const EvaluationResult& result
) {
  Serial.println();
  Serial.println("=======================================================");
  Serial.print("TEST CASE                : ");
  Serial.print(testNumber);
  Serial.print(" — ");
  Serial.println(scenario.name);
  Serial.println("=======================================================");

  Serial.print("Description              : ");
  Serial.println(scenario.description);

  Serial.print("Physical tamper          : ");
  Serial.println(
    scenario.physicalTamper
      ? "YES"
      : "NO"
  );

  Serial.print("Network-wide evidence    : ");
  Serial.println(
    result.networkWideSimulation
      ? "SIMULATION"
      : "REAL/NOT_APPLICABLE"
  );

  Serial.println();
  Serial.println("INPUT SUMMARY");
  Serial.println("------------------------------------------");

  Serial.print("Temperature              : ");
  Serial.print(scenario.sensor.temperatureC, 2);
  Serial.println(" C");

  Serial.print("Humidity                 : ");
  Serial.print(scenario.sensor.humidityPercent, 2);
  Serial.println(" %");

  Serial.print("Light                    : ");
  Serial.print(scenario.sensor.lightLux, 2);
  Serial.println(" lux");

  Serial.print("Soil                     : ");
  Serial.print(scenario.sensor.soilPercent, 2);
  Serial.println(" %");

  Serial.print("Packet rate              : ");
  Serial.print(
    scenario.traffic.packetRatePerMinute,
    2
  );
  Serial.println(" packets/min");

  Serial.print("Duplicate rate           : ");
  Serial.print(
    scenario.traffic.duplicateRatePercent,
    2
  );
  Serial.println(" %");

  Serial.print("Auth failure rate        : ");
  Serial.print(
    scenario.traffic.authenticationFailureRatePercent,
    2
  );
  Serial.println(" %");

  Serial.print("Packet interval          : ");
  Serial.print(
    scenario.time.packetIntervalMs,
    0
  );
  Serial.println(" ms");

  Serial.print("Timestamp delta          : ");
  Serial.print(
    scenario.time.timestampDeltaMs,
    0
  );
  Serial.println(" ms");

  Serial.println();
  Serial.println("CATEGORY OUTPUTS");
  Serial.println("------------------------------------------");

  printCategory(
    "Sensor-value",
    result.sensorValue
  );

  printCategory(
    "Traffic-behavior",
    result.trafficBehavior
  );

  printCategory(
    "Network-wide",
    result.networkWide
  );

  printCategory(
    "Time-based",
    result.timeBased
  );

  Serial.println();
  Serial.println("FINAL DECISION");
  Serial.println("------------------------------------------");

  Serial.print("Overall risk score       : ");
  Serial.println(result.overallRiskScore);

  Serial.print("Risk classification      : ");
  Serial.println(
    riskClassText(result.riskClass)
  );

  Serial.print("Critical confirmations   : ");
  Serial.print(
    result.criticalConfirmationCount
  );
  Serial.print("/");
  Serial.println(
    CRITICAL_CONFIRMATIONS_REQUIRED
  );

  Serial.print("System action            : ");
  Serial.println(
    actionText(result.action)
  );

  Serial.print("Expected class           : ");
  Serial.println(
    riskClassText(
      scenario.expectedClass
    )
  );

  Serial.print("Expected action          : ");
  Serial.println(
    actionText(
      scenario.expectedAction
    )
  );

  Serial.print("Case result              : ");
  Serial.println(
    result.passedExpectedResult
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("------------------------------------------");

  Serial.print("CSV_BEHAVIORAL_ANOMALY,");
  Serial.print(testNumber);
  Serial.print(",");
  Serial.print(scenario.name);
  Serial.print(",");
  Serial.print(result.sensorValue.score);
  Serial.print(",");
  Serial.print(result.trafficBehavior.score);
  Serial.print(",");
  Serial.print(result.networkWide.score);
  Serial.print(",");
  Serial.print(result.timeBased.score);
  Serial.print(",");
  Serial.print(result.overallRiskScore);
  Serial.print(",");
  Serial.print(riskClassText(result.riskClass));
  Serial.print(",");
  Serial.print(actionText(result.action));
  Serial.print(",");
  Serial.print(result.criticalConfirmationCount);
  Serial.print(",");
  Serial.println(
    result.networkWideSimulation
      ? "SIMULATION"
      : "REAL"
  );
}

// =====================================================
// TEST SCENARIOS
// =====================================================

const ScenarioInput TESTS[] = {
  {
    "NORMAL_OPERATION",
    "All sensor, traffic, network and time inputs are normal.",

    {
      true,
      26.5f, 48.0f, 850.0f, 65.0f,
      0.2f, 1.0f, 100.0f, 2.0f,
      false
    },

    {
      7.5f,
      0.0f,
      0.0f,
      0,
      0
    },

    {
      1,
      0,
      false,
      false,
      false
    },

    {
      8000.0f,
      500.0f,
      false,
      false
    },

    false,
    RiskClass::NORMAL,
    ActionDecision::ALLOW
  },

  {
    "SENSOR_VALUE_ANOMALY",
    "Invalid sample with impossible sensor changes.",

    {
      false,
      65.0f, 2.0f, 150000.0f, -5.0f,
      20.0f, 40.0f, 80000.0f, 70.0f,
      true
    },

    {
      7.5f,
      0.0f,
      0.0f,
      0,
      0
    },

    {
      1,
      1,
      false,
      false,
      false
    },

    {
      8000.0f,
      1000.0f,
      false,
      false
    },

    false,
    RiskClass::SUSPICIOUS,
    ActionDecision::MONITOR
  },

  {
    "TRAFFIC_BEHAVIOR_ANOMALY",
    "Packet burst, replay spike, authentication failures and malformed traffic.",

    {
      true,
      27.0f, 50.0f, 900.0f, 60.0f,
      0.3f, 1.0f, 120.0f, 2.0f,
      false
    },

    {
      25.0f,
      15.0f,
      20.0f,
      4,
      7
    },

    {
      1,
      1,
      false,
      false,
      false
    },

    {
      1500.0f,
      1000.0f,
      false,
      false
    },

    false,
    RiskClass::SUSPICIOUS,
    ActionDecision::MONITOR
  },

  {
    "NETWORK_WIDE_ATTACK_SIMULATION",
    "Four simulated nodes show the same coordinated anomaly.",

    {
      true,
      29.0f, 55.0f, 700.0f, 58.0f,
      0.5f, 2.0f, 100.0f, 3.0f,
      false
    },

    {
      16.0f,
      7.0f,
      6.0f,
      1,
      2
    },

    {
      4,
      4,
      true,
      true,
      true
    },

    {
      10000.0f,
      4000.0f,
      false,
      false
    },

    false,
    RiskClass::SUSPICIOUS,
    ActionDecision::MONITOR
  },

  {
    "TIME_BASED_ANOMALY",
    "Stale timestamp, missing heartbeat and abnormal packet interval.",

    {
      true,
      26.0f, 49.0f, 820.0f, 64.0f,
      0.1f, 1.0f, 80.0f, 1.0f,
      false
    },

    {
      20.0f,
      10.0f,
      0.0f,
      0,
      1
    },

    {
      1,
      0,
      false,
      false,
      false
    },

    {
      70000.0f,
      65000.0f,
      true,
      true
    },

    false,
    RiskClass::SUSPICIOUS,
    ActionDecision::MONITOR
  },

  {
    "COMBINED_HIGH_ANOMALY",
    "Several categories are abnormal, producing a HIGH result.",

    {
      false,
      55.0f, 20.0f, 60000.0f, 10.0f,
      10.0f, 30.0f, 60000.0f, 45.0f,
      true
    },

    {
      20.0f,
      8.0f,
      8.0f,
      1,
      4
    },

    {
      1,
      1,
      false,
      false,
      false
    },

    {
      8000.0f,
      35000.0f,
      false,
      false
    },

    false,
    RiskClass::HIGH_RISK,
    ActionDecision::INCREASE_MONITORING
  },

  {
    "CRITICAL_CONFIRMATION_1",
    "First consecutive CRITICAL behavioral result.",

    {
      false,
      70.0f, 1.0f, 160000.0f, -10.0f,
      25.0f, 50.0f, 90000.0f, 80.0f,
      true
    },

    {
      40.0f,
      30.0f,
      30.0f,
      10,
      10
    },

    {
      4,
      4,
      true,
      true,
      true
    },

    {
      90000.0f,
      90000.0f,
      true,
      true
    },

    false,
    RiskClass::CRITICAL,
    ActionDecision::CONFIRMATION_PENDING
  },

  {
    "CRITICAL_CONFIRMATION_2",
    "Second consecutive CRITICAL behavioral result.",

    {
      false,
      70.0f, 1.0f, 160000.0f, -10.0f,
      25.0f, 50.0f, 90000.0f, 80.0f,
      true
    },

    {
      40.0f,
      30.0f,
      30.0f,
      10,
      10
    },

    {
      4,
      4,
      true,
      true,
      true
    },

    {
      90000.0f,
      90000.0f,
      true,
      true
    },

    false,
    RiskClass::CRITICAL,
    ActionDecision::CONFIRMATION_PENDING
  },

  {
    "CRITICAL_CONFIRMATION_3",
    "Third consecutive CRITICAL result triggers session revocation.",

    {
      false,
      70.0f, 1.0f, 160000.0f, -10.0f,
      25.0f, 50.0f, 90000.0f, 80.0f,
      true
    },

    {
      40.0f,
      30.0f,
      30.0f,
      10,
      10
    },

    {
      4,
      4,
      true,
      true,
      true
    },

    {
      90000.0f,
      90000.0f,
      true,
      true
    },

    false,
    RiskClass::CRITICAL,
    ActionDecision::REVOKE_SESSION
  },

  {
    "PHYSICAL_TAMPER",
    "Physical enclosure tamper causes immediate lockdown without waiting for confirmations.",

    {
      true,
      26.0f, 48.0f, 800.0f, 60.0f,
      0.0f, 0.0f, 0.0f, 0.0f,
      false
    },

    {
      7.5f,
      0.0f,
      0.0f,
      0,
      0
    },

    {
      1,
      0,
      false,
      false,
      false
    },

    {
      8000.0f,
      0.0f,
      false,
      false
    },

    true,
    RiskClass::NORMAL,
    ActionDecision::IMMEDIATE_LOCKDOWN
  }
};

constexpr size_t TEST_COUNT =
    sizeof(TESTS) / sizeof(TESTS[0]);

// =====================================================
// ARDUINO
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("=======================================================");
  Serial.println("COMPONENT 2 — STEP 38E-1");
  Serial.println("LIGHTWEIGHT BEHAVIORAL ANOMALY ENGINE SELF-TEST");
  Serial.println("=======================================================");
  Serial.println("Target board             : GATEWAY ESP32");
  Serial.println("Sensor ESP32             : MAY REMAIN OFF");
  Serial.println("E32 modules              : MAY REMAIN OFF");
  Serial.println("Wi-Fi/Firebase           : NOT USED");
  Serial.println("Sensor-value maximum     : 30");
  Serial.println("Traffic-behavior maximum : 25");
  Serial.println("Network-wide maximum     : 25");
  Serial.println("Time-based maximum       : 20");
  Serial.println("Overall maximum          : 100");
  Serial.println("Critical confirmations   : 3");
  Serial.println("Physical tamper          : IMMEDIATE LOCKDOWN");
  Serial.println("Network-wide validation  : SIMULATION IN THIS STEP");
  Serial.println();

  for (
    size_t index = 0;
    index < TEST_COUNT;
    index++
  ) {
    const EvaluationResult result =
        evaluateScenario(TESTS[index]);

    printEvaluation(
      static_cast<uint8_t>(index + 1),
      TESTS[index],
      result
    );

    if (result.passedExpectedResult) {
      scenariosPassed++;
    } else {
      scenariosFailed++;
    }

    delay(250);
  }

  const bool finalPassed =
      scenariosPassed == TEST_COUNT
      &&
      scenariosFailed == 0;

  Serial.println();
  Serial.println("=======================================================");
  Serial.println("COMPONENT 2 — STEP 38E-1 FINAL REPORT");
  Serial.println("=======================================================");

  Serial.print("Scenarios executed       : ");
  Serial.println(TEST_COUNT);

  Serial.print("Scenarios passed         : ");
  Serial.println(scenariosPassed);

  Serial.print("Scenarios failed         : ");
  Serial.println(scenariosFailed);

  Serial.print("Critical confirmations   : ");
  Serial.print(criticalConfirmationCount);
  Serial.print("/");
  Serial.println(
    CRITICAL_CONFIRMATIONS_REQUIRED
  );

  Serial.println("Sensor-value detector    : TESTED");
  Serial.println("Traffic-behavior detector: TESTED");
  Serial.println("Network-wide detector    : TESTED / SIMULATION");
  Serial.println("Time-based detector      : TESTED");
  Serial.println("Physical tamper override : TESTED");
  Serial.println("Actual keys printed      : NOT APPLICABLE");

  Serial.print("STEP 38E-1 RESULT        : ");
  Serial.println(
    finalPassed
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println("=======================================================");
}

void loop() {
  delay(1000);
}
