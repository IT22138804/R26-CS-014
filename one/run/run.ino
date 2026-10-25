#include <Arduino.h>
#include <ctype.h>
#include <esp_system.h>

#define MFRC522_SPICLOCK (500000u)

#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <BH1750.h>
#include "DHT.h"
#include "C1_TinyML_Model.h"
#include "C1_RFID_Timing_Risk_Model.h"

// =====================================================
// COMPONENT 1 CLOSURE — STEP 34C-4
// INTEGRATED RFID TIMING-RISK SUPPORT SIGNAL
//
// Added in this version:
// - Fan temperature hysteresis
// - Pump moisture hysteresis
// - Soil open-circuit protection
// - Maximum continuous pump runtime
// - Pump cooldown after timeout
//
// TINYML SECURITY POLICY:
// - The model runs after every valid environmental sample.
// - A single anomaly prediction cannot lock the system.
// - Three consecutive anomaly predictions are required.
// - Confirmed TinyML anomalies force relays HIGH/OFF.
// - Runtime keys are zeroized outside the hardware ISR.
// - Physical tamper remains the highest-priority protection.
// - Recovery from TinyML lockdown requires physical restart.
// - Insider evidence is correlated to an authenticated RFID session.
// - The firmware does not claim that the credential proves a human identity.
// - RFID timing risk is logged only after successful authentication.
// - RFID timing risk cannot independently unlock, reject, control relays,
//   zeroize keys, or enter hard lockdown.
// - The current timing model remains synthetic-pipeline evidence only.
// =====================================================

// =====================================================
// GPIO CONFIGURATION
// =====================================================

// RC522
constexpr uint8_t RFID_SS_PIN   = 5;
constexpr uint8_t RFID_RST_PIN  = 33;
constexpr uint8_t RFID_SCK_PIN  = 18;
constexpr uint8_t RFID_MISO_PIN = 19;
constexpr uint8_t RFID_MOSI_PIN = 23;

// Tamper switch
constexpr uint8_t TAMPER_PIN = 13;

// Active-low relays
constexpr uint8_t PUMP_RELAY_PIN = 25;
constexpr uint8_t FAN_RELAY_PIN  = 26;

constexpr uint8_t RELAY_ON  = LOW;
constexpr uint8_t RELAY_OFF = HIGH;

// Status LEDs
constexpr uint8_t GREEN_LED_PIN  = 14;
constexpr uint8_t BLUE_LED_PIN   = 2;
constexpr uint8_t YELLOW_LED_PIN = 32;
constexpr uint8_t RED_LED_PIN    = 4;

// Sensors
constexpr uint8_t DHT_PIN = 27;
#define DHT_TYPE DHT22

constexpr uint8_t I2C_SDA_PIN = 21;
constexpr uint8_t I2C_SCL_PIN = 22;
constexpr uint8_t SOIL_SENSOR_PIN = 36;

// =====================================================
// SENSOR CONFIGURATION
// =====================================================

DHT dht(DHT_PIN, DHT_TYPE);

constexpr uint32_t I2C_CLOCK_HZ = 100000;
constexpr uint8_t BH1750_ADDRESS = 0x23;

BH1750 lightMeter;
bool bh1750Available = false;

constexpr unsigned long BH1750_RECOVERY_COOLDOWN_MS = 5000;
unsigned long lastBh1750RecoveryAttemptMs = 0;

uint32_t bh1750RecoveryAttempts = 0;
uint32_t bh1750SuccessfulRecoveries = 0;
uint8_t consecutiveBh1750Failures = 0;

// Previously measured soil calibration values
constexpr int SOIL_DRY_VALUE = 4095;
constexpr int SOIL_WET_VALUE = 1169;

// Values at or above this level are treated as open air,
// disconnected AO wiring, or ADC saturation.
constexpr int SOIL_OPEN_CIRCUIT_LIMIT = 4080;

constexpr unsigned long SENSOR_INTERVAL_MS = 2500;
unsigned long previousSensorTimeMs = 0;

uint32_t sensorSampleNumber = 0;
uint32_t validSensorSamples = 0;
uint32_t failedSensorSamples = 0;

uint32_t dhtFailureCount = 0;
uint32_t lightFailureCount = 0;
uint32_t soilFailureCount = 0;

// =====================================================
// AUTOMATIC CONTROL CONFIGURATION
// =====================================================

// Fan hysteresis
constexpr float FAN_ON_TEMPERATURE_C  = 32.0f;
constexpr float FAN_OFF_TEMPERATURE_C = 30.5f;

// Pump hysteresis
constexpr int PUMP_ON_MOISTURE_PERCENT  = 25;
constexpr int PUMP_OFF_MOISTURE_PERCENT = 40;

// Pump runtime safety
constexpr unsigned long MAX_PUMP_RUNTIME_MS = 5000;
constexpr unsigned long PUMP_COOLDOWN_MS = 15000;

volatile bool pumpCommandOn = false;
volatile bool fanCommandOn = false;
volatile bool soilActuationValid = false;

unsigned long pumpStartedAtMs = 0;
unsigned long pumpCooldownStartedAtMs = 0;

volatile bool pumpTimeoutActive = false;

uint32_t pumpActivationCount = 0;
uint32_t fanActivationCount = 0;
uint32_t pumpTimeoutCount = 0;

// =====================================================
// STEP 27B — TINYML DATASET LOGGER
// =====================================================

enum class DatasetScenario : uint8_t {
  NORMAL_OPERATION = 0,
  RFID_AUTH_ANOMALY = 1,
  SOIL_SENSOR_DISCONNECT = 2,
  LIGHT_SENSOR_MANIPULATION = 3,
  ACTUATOR_RUNTIME_MISUSE = 4,
  PHYSICAL_TAMPER = 5,
  AUTHORIZED_INSIDER_MISUSE = 6
};

uint8_t activeScenarioId = 0;
uint8_t activeDatasetLabel = 0;
bool tinyMlLoggerEnabled = true;

bool previousSoilPercentAvailable = false;
float previousSoilPercent = 0.0f;

unsigned long fanStartedAtMsForLogger = 0;

constexpr unsigned long RFID_CONTEXT_TTL_MS = 15000;
int lastRfidResultCode = 0;
unsigned long lastRfidAuthLatencyUs = 0;
unsigned long lastRfidBlockLatencyUs = 0;
unsigned long lastRfidPipelineLatencyUs = 0;
bool lastRfidRetryUsed = false;
unsigned long lastRfidEventAtMs = 0;

uint32_t tinyMlRuntimeRowCount = 0;
uint32_t tinyMlRfidRowCount = 0;
uint32_t tinyMlEventRowCount = 0;


// =====================================================
// STEP 33A — CONFIRMED TINYML SECURITY RESPONSE
// =====================================================

// The exported Random Forest expects raw feature values.
// Do not apply the Step 29A z-score scaler.
constexpr bool TINYML_MONITOR_ONLY = false;

// Do not hard-lock on one prediction. The model was trained
// mainly on synthetic data, so a confirmation gate reduces
// accidental lockouts caused by isolated false positives.
constexpr uint8_t TINYML_CONFIRMATIONS_REQUIRED = 3;

// Sensor samples arrive every 2500 ms. This window allows
// three consecutive samples while rejecting stale anomalies.
constexpr unsigned long
    TINYML_CONFIRMATION_MAX_GAP_MS = 6000;

uint32_t tinyMlInferenceCount = 0;
uint32_t tinyMlNormalPredictionCount = 0;
uint32_t tinyMlAnomalyPredictionCount = 0;
uint32_t tinyMlInferenceSkippedCount = 0;

float lastTinyMlAnomalyProbability = 0.0f;
uint8_t lastTinyMlPrediction = 0;
unsigned long lastTinyMlInferenceLatencyUs = 0;

// TinyML confirmation and hard-lockdown runtime.
uint8_t tinyMlConsecutiveAnomalyCount = 0;
unsigned long lastTinyMlAnomalyAtMs = 0;

volatile bool tinyMlLockdownLatched = false;
volatile bool tinyMlLockdownReportPending = false;

uint32_t tinyMlLockdownCount = 0;
unsigned long tinyMlLockdownAtMs = 0;
float tinyMlTriggerProbability = 0.0f;
unsigned long tinyMlTriggerLatencyUs = 0;

float tinyMlTriggerFeatures[C1TinyML::FEATURE_COUNT] = {
  0.0f, 0.0f, 0.0f, 0.0f, 0.0f
};


// Last valid pre-tamper feature vector.
// This allows one final monitor-only inference after the
// deterministic tamper task has already forced LOCKDOWN.
bool tinyMlFeatureCacheValid = false;

float cachedRfidAuthFeature = 0.0f;
float cachedTempLightRatio = 0.0f;
float cachedMoistureDelta = 0.0f;
unsigned long cachedRelayRuntimeMs = 0;

// Explicit declaration because printTamperReport() appears
// before the full function definition.
void runTinyMlMonitorInference(
    float rfidAuthFeature,
    int tamperState,
    float tempLightRatio,
    float moistureDelta,
    unsigned long relayRuntimeMs,
    bool inferenceFeaturesValid
);

void executeConfirmedTinyMlLockdown(
    float anomalyProbability,
    unsigned long inferenceLatencyUs,
    const float features[C1TinyML::FEATURE_COUNT]
);

void printTinyMlLockdownReport();

// =====================================================
// RFID CONFIGURATION
// =====================================================

MFRC522 rfid(RFID_SS_PIN, RFID_RST_PIN);

constexpr byte MARKER_BLOCK  = 16;
constexpr byte TRAILER_BLOCK = 19;

const byte AUTHORIZED_UID[4] = {
  0x83, 0x3D, 0x53, 0x56
};

// Prototype credential. Do not publish the production key.
const byte CUSTOM_KEY_A_BYTES[6] = {
  0x7A, 0x31, 0xC4, 0x9D, 0x52, 0xE8
};

const byte EXPECTED_MARKER[16] = {
  'C', '1', '-', 'A',
  'U', 'T', 'H', '-',
  'V', '1',
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

MFRC522::MIFARE_Key runtimeKeyA;

// Temporary Component 1 SRAM key container.
// Component 2 will replace it with a derived NwkSKey.
uint8_t runtimeNwkSKey[16] = {0};

// =====================================================
// SYSTEM TYPES
// =====================================================

enum class SystemState : uint8_t {
  LOCKED,
  NORMAL,
  LOCKDOWN
};

enum class AuthResult : uint8_t {
  AUTHORIZED,
  UID_REJECTED,
  SECTOR_COMMUNICATION_FAILURE,
  BLOCK_READ_FAILURE,
  MARKER_MISMATCH,
  CARD_SELECTION_FAILURE
};

struct AuthMetrics {
  unsigned long uidLatencyUs = 0;
  unsigned long authLatencyUs = 0;
  unsigned long readLatencyUs = 0;
  unsigned long pipelineLatencyUs = 0;

  MFRC522::StatusCode authStatus = MFRC522::STATUS_ERROR;
  MFRC522::StatusCode readStatus = MFRC522::STATUS_ERROR;
};


// =====================================================
// STEP 27B — LOGGER HELPERS
// =====================================================

const char* datasetScenarioName(uint8_t id) {
  switch (static_cast<DatasetScenario>(id)) {
    case DatasetScenario::NORMAL_OPERATION:
      return "NORMAL_OPERATION";
    case DatasetScenario::RFID_AUTH_ANOMALY:
      return "RFID_AUTH_ANOMALY";
    case DatasetScenario::SOIL_SENSOR_DISCONNECT:
      return "SOIL_SENSOR_DISCONNECT";
    case DatasetScenario::LIGHT_SENSOR_MANIPULATION:
      return "LIGHT_SENSOR_MANIPULATION";
    case DatasetScenario::ACTUATOR_RUNTIME_MISUSE:
      return "ACTUATOR_RUNTIME_MISUSE";
    case DatasetScenario::PHYSICAL_TAMPER:
      return "PHYSICAL_TAMPER";
    case DatasetScenario::AUTHORIZED_INSIDER_MISUSE:
      return "AUTHORIZED_INSIDER_MISUSE";
    default:
      return "UNKNOWN_SCENARIO";
  }
}

int authResultCode(AuthResult result) {
  switch (result) {
    case AuthResult::AUTHORIZED: return 1;
    case AuthResult::UID_REJECTED: return 2;
    case AuthResult::SECTOR_COMMUNICATION_FAILURE: return 3;
    case AuthResult::BLOCK_READ_FAILURE: return 4;
    case AuthResult::MARKER_MISMATCH: return 5;
    case AuthResult::CARD_SELECTION_FAILURE: return 6;
    default: return 0;
  }
}

void setDatasetScenario(DatasetScenario scenario) {
  activeScenarioId = static_cast<uint8_t>(scenario);
  activeDatasetLabel =
      scenario == DatasetScenario::NORMAL_OPERATION ? 0 : 1;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("TINYML DATASET LABEL UPDATED");
  Serial.println("==========================================");
  Serial.print("Scenario ID              : ");
  Serial.println(activeScenarioId);
  Serial.print("Scenario name            : ");
  Serial.println(datasetScenarioName(activeScenarioId));
  Serial.print("Binary label             : ");
  Serial.println(activeDatasetLabel);
  Serial.println("Safety logic             : UNCHANGED");
  Serial.println("==========================================");
}

void printTinyMlLoggerHelp() {
  Serial.println();
  Serial.println("==========================================");
  Serial.println("STEP 34C-4 — CLOSURE TEST COMMANDS");
  Serial.println("==========================================");
  Serial.println("0 or N : NORMAL_OPERATION");
  Serial.println("1 or R : RFID_AUTH_ANOMALY");
  Serial.println("2 or S : SOIL_SENSOR_DISCONNECT");
  Serial.println("3 or L : LIGHT_SENSOR_MANIPULATION");
  Serial.println("4 or A : ACTUATOR_RUNTIME_MISUSE");
  Serial.println("5 or T : PHYSICAL_TAMPER");
  Serial.println("6 or I : AUTHORIZED_INSIDER_MISUSE");
  Serial.println("H      : show help");
  Serial.println("Commands change labels only.");
  Serial.println("==========================================");
}

void printTinyMlCsvHeaders() {
  Serial.println(
    "CSV_TINYML_RUNTIME_HEADER,"
    "timestamp_ms,sample_number,scenario_id,label,"
    "scenario_name,state,rfid_result_code,rfid_auth_us,"
    "rfid_block_us,rfid_pipeline_us,rfid_retry_used,"
    "temperature_c,humidity_percent,light_lux,soil_raw,"
    "soil_percent,temp_light_ratio,moisture_delta,"
    "pump_runtime_ms,fan_runtime_ms,relay_runtime_ms,"
    "tamper_state,pump_state,fan_state,pump_timeout,"
    "soil_health,sample_valid"
  );

  Serial.println(
    "CSV_TINYML_RFID_HEADER,"
    "timestamp_ms,event_number,scenario_id,label,"
    "scenario_name,state,first_result_code,"
    "final_result_code,retry_used,uid_latency_us,"
    "auth_latency_us,block_latency_us,pipeline_latency_us"
  );

  Serial.println(
    "CSV_TINYML_EVENT_HEADER,"
    "timestamp_ms,event_number,scenario_id,label,"
    "scenario_name,event_name,event_value,"
    "system_state,pump_state,fan_state"
  );

  Serial.println(
    "CSV_TINYML_INFERENCE_HEADER,"
    "timestamp_ms,inference_number,sample_number,"
    "scenario_id,ground_truth_label,state,"
    "rfid_auth_feature,tamper_state,temp_light_ratio,"
    "moisture_delta,relay_runtime_ms,"
    "anomaly_probability,predicted_label,"
    "inference_latency_us,monitor_only"
  );

  Serial.println(
    "CSV_SECURITY_SESSION_HEADER,"
    "timestamp_ms,event_name,session_id,session_active,"
    "auth_event_number,session_age_ms,scenario_id,"
    "scenario_name,system_state,auth_latency_us,"
    "block_latency_us,pipeline_latency_us"
  );

  Serial.println(
    "CSV_RFID_TIMING_RISK_HEADER,"
    "timestamp_ms,event_number,state,final_result_code,"
    "retry_used,uid_latency_us,auth_latency_us,"
    "block_read_latency_us,pipeline_latency_us,"
    "clone_risk_probability,risk_threshold,risk_flag,"
    "source_data_synthetic,supporting_signal_only,"
    "active_security_action_allowed"
  );
}

void processTinyMlLoggerCommands() {
  while (Serial.available() > 0) {
    char c = static_cast<char>(Serial.read());

    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
      continue;
    }

    c = static_cast<char>(
      toupper(static_cast<unsigned char>(c))
    );

    switch (c) {
      case '0':
      case 'N':
        setDatasetScenario(DatasetScenario::NORMAL_OPERATION);
        break;
      case '1':
      case 'R':
        setDatasetScenario(DatasetScenario::RFID_AUTH_ANOMALY);
        break;
      case '2':
      case 'S':
        setDatasetScenario(DatasetScenario::SOIL_SENSOR_DISCONNECT);
        break;
      case '3':
      case 'L':
        setDatasetScenario(DatasetScenario::LIGHT_SENSOR_MANIPULATION);
        break;
      case '4':
      case 'A':
        setDatasetScenario(DatasetScenario::ACTUATOR_RUNTIME_MISUSE);
        break;
      case '5':
      case 'T':
        setDatasetScenario(DatasetScenario::PHYSICAL_TAMPER);
        break;
      case '6':
      case 'I':
        setDatasetScenario(
          DatasetScenario::AUTHORIZED_INSIDER_MISUSE
        );
        break;
      case 'H':
        printTinyMlLoggerHelp();
        break;
      default:
        Serial.print("Unknown logger command: ");
        Serial.println(c);
        break;
    }
  }
}

// =====================================================
// SYSTEM RUNTIME
// =====================================================

volatile SystemState currentState = SystemState::LOCKED;

constexpr uint8_t MAX_SECURITY_FAILURES = 3;

uint8_t securityFailureCount = 0;
uint32_t authenticationEventNumber = 0;


// =====================================================
// STEP 34A — AUTHENTICATED SESSION ATTRIBUTION
// =====================================================

// Attribution is to the successfully authenticated RFID credential
// session. It does not prove which human physically held the card.
bool authorizedSessionActive = false;

uint32_t authorizedSessionId = 0;
uint32_t authorizedSessionStartedAtMs = 0;
uint32_t authorizedSessionAuthEvent = 0;

unsigned long authorizedSessionAuthLatencyUs = 0;
unsigned long authorizedSessionBlockLatencyUs = 0;
unsigned long authorizedSessionPipelineLatencyUs = 0;

// Exact timing snapshot for the currently handled RFID event.
unsigned long pendingSessionAuthLatencyUs = 0;
unsigned long pendingSessionBlockLatencyUs = 0;
unsigned long pendingSessionPipelineLatencyUs = 0;

// =====================================================
// STEP 34C-4 — RFID TIMING-RISK SUPPORT RUNTIME
// =====================================================

uint32_t rfidTimingRiskEvaluationCount = 0;
uint32_t rfidTimingRiskFlagCount = 0;
uint32_t rfidTimingRiskSkippedCount = 0;

float lastRfidTimingRiskProbability = 0.0f;
uint8_t lastRfidTimingRiskFlag = 0;
unsigned long lastRfidTimingInferenceUs = 0;

// The model is deliberately prevented from taking an active security
// action. This remains true even when its risk flag is 1.
constexpr bool RFID_TIMING_ACTIVE_ACTION_ENABLED = false;

// Forensic snapshot captured when TinyML hard-lockdown is triggered.
bool tinyMlTriggerSessionActive = false;
uint32_t tinyMlTriggerSessionId = 0;
uint32_t tinyMlTriggerSessionAuthEvent = 0;
uint32_t tinyMlTriggerSessionAgeMs = 0;
unsigned long tinyMlTriggerSessionAuthLatencyUs = 0;
unsigned long tinyMlTriggerSessionBlockLatencyUs = 0;
unsigned long tinyMlTriggerSessionPipelineLatencyUs = 0;

// Card-removal enforcement
bool waitingForCardRemoval = false;
uint8_t consecutiveAbsentChecks = 0;
constexpr uint8_t REQUIRED_ABSENT_CHECKS = 5;

// Tamper runtime
TaskHandle_t tamperTaskHandle = nullptr;

volatile bool tamperLatched = false;
volatile bool tamperReportPending = false;
volatile bool secretsZeroized = false;

volatile TickType_t tamperInterruptTick = 0;
volatile TickType_t tamperResponseTicks = 0;

// =====================================================
// FORWARD DECLARATIONS
// =====================================================

void forceActuatorsOff();
void applyAutomaticActuatorOutputs();
void applyStateOutputs();
void initializeReader();
const char* stateName(SystemState state);

// =====================================================
// STEP 34A — AUTHENTICATED SESSION LOGGER
// =====================================================

void printSecuritySessionRow(
    const char* eventName,
    bool sessionActive,
    uint32_t sessionId,
    uint32_t authEventNumber,
    uint32_t sessionAgeMs,
    unsigned long authLatencyUs,
    unsigned long blockLatencyUs,
    unsigned long pipelineLatencyUs
) {
  Serial.print("CSV_SECURITY_SESSION,");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(eventName);
  Serial.print(",");
  Serial.print(sessionId);
  Serial.print(",");
  Serial.print(sessionActive ? 1 : 0);
  Serial.print(",");
  Serial.print(authEventNumber);
  Serial.print(",");
  Serial.print(sessionAgeMs);
  Serial.print(",");
  Serial.print(activeScenarioId);
  Serial.print(",");
  Serial.print(datasetScenarioName(activeScenarioId));
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(authLatencyUs);
  Serial.print(",");
  Serial.print(blockLatencyUs);
  Serial.print(",");
  Serial.println(pipelineLatencyUs);
}

void startAuthorizedSession(
    const AuthMetrics& effectiveMetrics
) {
  authorizedSessionId++;
  authorizedSessionActive = true;
  authorizedSessionStartedAtMs = millis();
  authorizedSessionAuthEvent = authenticationEventNumber;

  authorizedSessionAuthLatencyUs =
      effectiveMetrics.authLatencyUs;

  authorizedSessionBlockLatencyUs =
      effectiveMetrics.readLatencyUs;

  authorizedSessionPipelineLatencyUs =
      effectiveMetrics.pipelineLatencyUs;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("AUTHORIZED SECURITY SESSION STARTED");
  Serial.println("==========================================");

  Serial.print("Session ID               : ");
  Serial.println(authorizedSessionId);

  Serial.print("Authentication event     : ");
  Serial.println(authorizedSessionAuthEvent);

  Serial.print("Credential result        : AUTHORIZED");
  Serial.println();

  Serial.print("Sector auth latency      : ");
  Serial.print(authorizedSessionAuthLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Block-read latency       : ");
  Serial.print(authorizedSessionBlockLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Pipeline latency         : ");
  Serial.print(authorizedSessionPipelineLatencyUs);
  Serial.println(" microseconds");

  Serial.println(
    "Attribution scope        : AUTHENTICATED RFID SESSION"
  );

  Serial.println(
    "Human identity proof     : NOT CLAIMED"
  );

  Serial.println("==========================================");

  printSecuritySessionRow(
    "AUTHORIZED_SESSION_START",
    true,
    authorizedSessionId,
    authorizedSessionAuthEvent,
    0,
    authorizedSessionAuthLatencyUs,
    authorizedSessionBlockLatencyUs,
    authorizedSessionPipelineLatencyUs
  );
}

void closeAuthorizedSession(
    const char* eventName
) {
  if (!authorizedSessionActive) {
    return;
  }

  uint32_t sessionAgeMs =
      millis() - authorizedSessionStartedAtMs;

  printSecuritySessionRow(
    eventName,
    false,
    authorizedSessionId,
    authorizedSessionAuthEvent,
    sessionAgeMs,
    authorizedSessionAuthLatencyUs,
    authorizedSessionBlockLatencyUs,
    authorizedSessionPipelineLatencyUs
  );

  Serial.println();
  Serial.println("AUTHORIZED SECURITY SESSION CLOSED");

  Serial.print("Session ID               : ");
  Serial.println(authorizedSessionId);

  Serial.print("Session duration         : ");
  Serial.print(sessionAgeMs);
  Serial.println(" ms");

  Serial.print("Close reason             : ");
  Serial.println(eventName);

  authorizedSessionActive = false;
}


// =====================================================
// OUTPUT SAFETY
// =====================================================

void forceActuatorsOff() {
  digitalWrite(PUMP_RELAY_PIN, RELAY_OFF);
  digitalWrite(FAN_RELAY_PIN, RELAY_OFF);
}

void turnAllStatusLEDsOff() {
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(BLUE_LED_PIN, LOW);
  digitalWrite(YELLOW_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, LOW);
}

const char* stateName(SystemState state) {
  switch (state) {
    case SystemState::LOCKED:
      return "LOCKED";
    case SystemState::NORMAL:
      return "NORMAL";
    case SystemState::LOCKDOWN:
      return "LOCKDOWN";
    default:
      return "UNKNOWN";
  }
}

const char* commandStateName(bool commandOn) {
  return commandOn ? "ON" : "OFF";
}

void printTinyMlEventRow(
    const char* eventName,
    long eventValue,
    uint8_t scenarioId,
    uint8_t label
) {
  if (!tinyMlLoggerEnabled) {
    return;
  }

  tinyMlEventRowCount++;

  Serial.print("CSV_TINYML_EVENT,");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(tinyMlEventRowCount);
  Serial.print(",");
  Serial.print(scenarioId);
  Serial.print(",");
  Serial.print(label);
  Serial.print(",");
  Serial.print(datasetScenarioName(scenarioId));
  Serial.print(",");
  Serial.print(eventName);
  Serial.print(",");
  Serial.print(eventValue);
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(pumpCommandOn ? 1 : 0);
  Serial.print(",");
  Serial.println(fanCommandOn ? 1 : 0);
}

void applyAutomaticActuatorOutputs() {
  const bool actuatorPermission =
      currentState == SystemState::NORMAL &&
      !tamperLatched;

  const bool allowPump =
      actuatorPermission &&
      pumpCommandOn &&
      soilActuationValid &&
      !pumpTimeoutActive;

  const bool allowFan =
      actuatorPermission &&
      fanCommandOn;

  digitalWrite(
    PUMP_RELAY_PIN,
    allowPump ? RELAY_ON : RELAY_OFF
  );

  digitalWrite(
    FAN_RELAY_PIN,
    allowFan ? RELAY_ON : RELAY_OFF
  );
}

void applyStateOutputs() {
  turnAllStatusLEDsOff();

  switch (currentState) {
    case SystemState::LOCKED:
      pumpCommandOn = false;
      fanCommandOn = false;
      soilActuationValid = false;
      pumpStartedAtMs = 0;

      forceActuatorsOff();
      digitalWrite(BLUE_LED_PIN, HIGH);
      break;

    case SystemState::NORMAL:
      digitalWrite(GREEN_LED_PIN, HIGH);
      applyAutomaticActuatorOutputs();
      break;

    case SystemState::LOCKDOWN:
      pumpCommandOn = false;
      fanCommandOn = false;
      soilActuationValid = false;
      pumpStartedAtMs = 0;

      forceActuatorsOff();
      digitalWrite(RED_LED_PIN, HIGH);
      break;
  }
}

void changeState(
    SystemState newState,
    const char* reason
) {
  if (
    tamperLatched &&
    newState != SystemState::LOCKDOWN
  ) {
    return;
  }

  SystemState previousState = currentState;

  // Every transition clears live commands. NORMAL requires
  // a fresh valid sensor sample before actuation.
  pumpCommandOn = false;
  fanCommandOn = false;
  soilActuationValid = false;
  pumpStartedAtMs = 0;

  currentState = newState;
  applyStateOutputs();

  Serial.println();
  Serial.println("==========================================");
  Serial.println("SYSTEM STATE TRANSITION");
  Serial.println("==========================================");

  Serial.print("Previous state : ");
  Serial.println(stateName(previousState));

  Serial.print("New state      : ");
  Serial.println(stateName(currentState));

  Serial.print("Reason         : ");
  Serial.println(reason);

  Serial.print("Actuator access: ");
  Serial.println(
    currentState == SystemState::NORMAL
      ? "PERMITTED AFTER VALID SENSOR SAMPLE"
      : "DENIED"
  );

  Serial.print("Pump relay     : ");
  Serial.println(
    digitalRead(PUMP_RELAY_PIN) == RELAY_ON
      ? "ON"
      : "OFF"
  );

  Serial.print("Fan relay      : ");
  Serial.println(
    digitalRead(FAN_RELAY_PIN) == RELAY_ON
      ? "ON"
      : "OFF"
  );

  Serial.println("==========================================");
}

// =====================================================
// SECURE MEMORY CLEAR
// =====================================================

void secureZeroMemory(
    void* memory,
    size_t length
) {
  volatile uint8_t* pointer =
      static_cast<volatile uint8_t*>(memory);

  while (length > 0) {
    *pointer = 0;
    pointer++;
    length--;
  }
}

bool memoryIsZero(
    const uint8_t* memory,
    size_t length
) {
  uint8_t accumulatedValue = 0;

  for (size_t i = 0; i < length; i++) {
    accumulatedValue |= memory[i];
  }

  return accumulatedValue == 0;
}

void zeroizeRuntimeSecrets() {
  secureZeroMemory(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  secureZeroMemory(
    runtimeKeyA.keyByte,
    sizeof(runtimeKeyA.keyByte)
  );

  secretsZeroized =
      memoryIsZero(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      ) &&
      memoryIsZero(
        runtimeKeyA.keyByte,
        sizeof(runtimeKeyA.keyByte)
      );
}

// =====================================================
// STEP 33A — CONFIRMED TINYML HARD LOCKDOWN
// =====================================================

void executeConfirmedTinyMlLockdown(
    float anomalyProbability,
    unsigned long inferenceLatencyUs,
    const float features[C1TinyML::FEATURE_COUNT]
) {
  if (
    tinyMlLockdownLatched ||
    tamperLatched ||
    currentState != SystemState::NORMAL
  ) {
    return;
  }

  // Capture forensic evidence before zeroization.
  tinyMlTriggerProbability = anomalyProbability;
  tinyMlTriggerLatencyUs = inferenceLatencyUs;
  tinyMlLockdownAtMs = millis();

  tinyMlTriggerSessionActive = authorizedSessionActive;
  tinyMlTriggerSessionId = authorizedSessionId;
  tinyMlTriggerSessionAuthEvent =
      authorizedSessionAuthEvent;

  tinyMlTriggerSessionAgeMs =
      authorizedSessionActive
        ? tinyMlLockdownAtMs -
          authorizedSessionStartedAtMs
        : 0;

  tinyMlTriggerSessionAuthLatencyUs =
      authorizedSessionAuthLatencyUs;

  tinyMlTriggerSessionBlockLatencyUs =
      authorizedSessionBlockLatencyUs;

  tinyMlTriggerSessionPipelineLatencyUs =
      authorizedSessionPipelineLatencyUs;

  for (
    uint8_t i = 0;
    i < C1TinyML::FEATURE_COUNT;
    i++
  ) {
    tinyMlTriggerFeatures[i] = features[i];
  }

  // Active-low HW-803 relays:
  // HIGH is the safe OFF level.
  pumpCommandOn = false;
  fanCommandOn = false;
  soilActuationValid = false;
  pumpTimeoutActive = false;

  pumpStartedAtMs = 0;
  pumpCooldownStartedAtMs = 0;

  forceActuatorsOff();

  // This is normal task/loop context, not an ISR.
  zeroizeRuntimeSecrets();

  tinyMlLockdownLatched = true;
  tinyMlLockdownCount++;

  currentState = SystemState::LOCKDOWN;
  applyStateOutputs();

  tinyMlLockdownReportPending = true;
}

void printTinyMlLockdownReport() {
  if (!tinyMlLockdownReportPending) {
    return;
  }

  tinyMlLockdownReportPending = false;

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("TINYML CONFIRMED ANOMALY — HARD LOCKDOWN");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

  Serial.print("Trigger time             : ");
  Serial.print(tinyMlLockdownAtMs);
  Serial.println(" ms");

  Serial.print("Confirmation count       : ");
  Serial.print(tinyMlConsecutiveAnomalyCount);
  Serial.print("/");
  Serial.println(TINYML_CONFIRMATIONS_REQUIRED);

  Serial.print("Anomaly probability      : ");
  Serial.println(tinyMlTriggerProbability, 6);

  Serial.print("Inference latency        : ");
  Serial.print(tinyMlTriggerLatencyUs);
  Serial.println(" microseconds");

  Serial.println();
  Serial.println("Authenticated-session attribution:");

  Serial.print("Session active at trigger: ");
  Serial.println(
    tinyMlTriggerSessionActive
      ? "YES"
      : "NO"
  );

  Serial.print("Session ID               : ");
  Serial.println(tinyMlTriggerSessionId);

  Serial.print("Authentication event     : ");
  Serial.println(tinyMlTriggerSessionAuthEvent);

  Serial.print("Session age at trigger   : ");
  Serial.print(tinyMlTriggerSessionAgeMs);
  Serial.println(" ms");

  Serial.print("Scenario selected        : ");
  Serial.println(
    datasetScenarioName(activeScenarioId)
  );

  Serial.print("Attribution result       : ");
  Serial.println(
    tinyMlTriggerSessionActive
      ? "CORRELATED TO AUTHENTICATED RFID SESSION"
      : "NO ACTIVE AUTHENTICATED SESSION"
  );

  Serial.println(
    "Human identity claim     : NOT MADE"
  );

  Serial.println("Trigger features:");

  Serial.print("  RFID auth              : ");
  Serial.println(tinyMlTriggerFeatures[0], 3);

  Serial.print("  Tamper state           : ");
  Serial.println(tinyMlTriggerFeatures[1], 0);

  Serial.print("  Temp/light ratio       : ");
  Serial.println(tinyMlTriggerFeatures[2], 6);

  Serial.print("  Moisture delta         : ");
  Serial.println(tinyMlTriggerFeatures[3], 3);

  Serial.print("  Relay runtime          : ");
  Serial.print(
    static_cast<unsigned long>(
      tinyMlTriggerFeatures[4]
    )
  );
  Serial.println(" ms");

  Serial.print("Runtime NwkSKey          : ");
  Serial.println(
    memoryIsZero(
      runtimeNwkSKey,
      sizeof(runtimeNwkSKey)
    )
      ? "ZEROIZED"
      : "ZEROIZATION FAILED"
  );

  Serial.print("Runtime RFID Key A       : ");
  Serial.println(
    memoryIsZero(
      runtimeKeyA.keyByte,
      sizeof(runtimeKeyA.keyByte)
    )
      ? "ZEROIZED"
      : "ZEROIZATION FAILED"
  );

  Serial.print("Zeroization verification : ");
  Serial.println(
    secretsZeroized
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("System state             : LOCKDOWN");
  Serial.println("Pump command             : OFF");
  Serial.println("Fan command              : OFF");
  Serial.println("Pump relay GPIO          : HIGH / OFF");
  Serial.println("Fan relay GPIO           : HIGH / OFF");
  Serial.println("Red status LED           : ON");
  Serial.println("RFID authentication      : DISABLED");
  Serial.println("Sensor sampling          : DISABLED");
  Serial.println("Recovery                 : PHYSICAL RESTART REQUIRED");

  printSecuritySessionRow(
    "TINYML_HARD_LOCKDOWN",
    tinyMlTriggerSessionActive,
    tinyMlTriggerSessionId,
    tinyMlTriggerSessionAuthEvent,
    tinyMlTriggerSessionAgeMs,
    tinyMlTriggerSessionAuthLatencyUs,
    tinyMlTriggerSessionBlockLatencyUs,
    tinyMlTriggerSessionPipelineLatencyUs
  );

  printTinyMlEventRow(
    "TINYML_CONFIRMED_HARD_LOCKDOWN",
    static_cast<long>(
      tinyMlTriggerProbability * 1000000.0f
    ),
    activeScenarioId,
    1
  );

  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

// =====================================================
// TAMPER INTERRUPT AND TASK
// =====================================================

void IRAM_ATTR handleTamperInterrupt() {
  tamperInterruptTick =
      xTaskGetTickCountFromISR();

  BaseType_t higherPriorityTaskWoken = pdFALSE;

  if (tamperTaskHandle != nullptr) {
    vTaskNotifyGiveFromISR(
      tamperTaskHandle,
      &higherPriorityTaskWoken
    );
  }

  if (higherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR();
  }
}

void tamperSecurityTask(void* parameter) {
  (void)parameter;

  while (true) {
    ulTaskNotifyTake(
      pdTRUE,
      portMAX_DELAY
    );

    vTaskDelay(pdMS_TO_TICKS(15));

    if (digitalRead(TAMPER_PIN) != HIGH) {
      continue;
    }

    if (tamperLatched) {
      continue;
    }

    TickType_t handlingTick =
        xTaskGetTickCount();

    tamperResponseTicks =
        handlingTick -
        tamperInterruptTick;

    // Safety first
    pumpCommandOn = false;
    fanCommandOn = false;
    soilActuationValid = false;
    pumpTimeoutActive = false;

    pumpStartedAtMs = 0;
    pumpCooldownStartedAtMs = 0;

    forceActuatorsOff();

    zeroizeRuntimeSecrets();

    tamperLatched = true;
    currentState = SystemState::LOCKDOWN;

    applyStateOutputs();

    tamperReportPending = true;
  }
}

// =====================================================
// TAMPER REPORT
// =====================================================

void printTamperReport() {
  if (!tamperReportPending) {
    return;
  }

  tamperReportPending = false;

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("PHYSICAL TAMPER EVENT DETECTED");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

  Serial.println("Tamper input             : OPEN / HIGH");
  Serial.println("Enclosure status         : BREACHED");

  Serial.print("Tamper response          : ");
  Serial.print(
    static_cast<unsigned long>(
      tamperResponseTicks *
      portTICK_PERIOD_MS
    )
  );
  Serial.println(" ms");

  Serial.print("Runtime NwkSKey          : ");
  Serial.println(
    memoryIsZero(
      runtimeNwkSKey,
      sizeof(runtimeNwkSKey)
    )
      ? "ZEROIZED"
      : "ZEROIZATION FAILED"
  );

  Serial.print("Runtime RFID Key A       : ");
  Serial.println(
    memoryIsZero(
      runtimeKeyA.keyByte,
      sizeof(runtimeKeyA.keyByte)
    )
      ? "ZEROIZED"
      : "ZEROIZATION FAILED"
  );

  Serial.print("Zeroization verification : ");
  Serial.println(
    secretsZeroized
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("System state             : LOCKDOWN");
  Serial.println("Sensor sampling          : DISABLED");
  Serial.println("Automatic control        : DISABLED");
  Serial.println("Pump command             : OFF");
  Serial.println("Fan command              : OFF");
  Serial.println("Pump relay               : FORCED OFF");
  Serial.println("Fan relay                : FORCED OFF");
  Serial.println("RFID authentication      : DISABLED");
  Serial.println("Recovery                 : PHYSICAL RESTART REQUIRED");

  printTinyMlEventRow(
    "PHYSICAL_TAMPER",
    static_cast<long>(
      tamperResponseTicks * portTICK_PERIOD_MS
    ),
    static_cast<uint8_t>(
      DatasetScenario::PHYSICAL_TAMPER
    ),
    1
  );

  Serial.println();
  Serial.println("TAMPER MODEL VALIDATION");

  if (tinyMlFeatureCacheValid) {
    Serial.println(
      "Cached pre-tamper features : AVAILABLE"
    );

    // Deterministic safety has already forced LOCKDOWN.
    // This model inference is evidence only and cannot
    // change relays, keys, or the system state.
    runTinyMlMonitorInference(
      cachedRfidAuthFeature,
      1,
      cachedTempLightRatio,
      cachedMoistureDelta,
      0,
      true
    );
  } else {
    tinyMlInferenceSkippedCount++;

    Serial.println(
      "Cached pre-tamper features : NOT AVAILABLE"
    );
    Serial.println(
      "TinyML tamper inference    : SKIPPED"
    );
    Serial.println(
      "Reason                     : NO VALID NORMAL BASELINE"
    );
  }

  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

// =====================================================
// BH1750 INITIALIZATION AND RECOVERY
// =====================================================

bool i2cDeviceResponds(uint8_t address) {
  Wire.beginTransmission(address);
  return Wire.endTransmission() == 0;
}

bool startBH1750() {
  if (!i2cDeviceResponds(BH1750_ADDRESS)) {
    return false;
  }

  bool started =
      lightMeter.begin(
        BH1750::CONTINUOUS_HIGH_RES_MODE,
        BH1750_ADDRESS,
        &Wire
      );

  if (started) {
    delay(180);
  }

  return started;
}

bool recoverBH1750() {
  unsigned long currentTimeMs = millis();

  if (
    currentTimeMs -
    lastBh1750RecoveryAttemptMs <
    BH1750_RECOVERY_COOLDOWN_MS
  ) {
    return false;
  }

  lastBh1750RecoveryAttemptMs = currentTimeMs;
  bh1750RecoveryAttempts++;

  Serial.println();
  Serial.println(
    "[BH1750] Starting controlled I2C recovery."
  );

  Wire.end();
  delay(25);

  Wire.begin(
    I2C_SDA_PIN,
    I2C_SCL_PIN
  );

  Wire.setClock(I2C_CLOCK_HZ);
  delay(50);

  bh1750Available = startBH1750();

  if (bh1750Available) {
    bh1750SuccessfulRecoveries++;
    consecutiveBh1750Failures = 0;

    Serial.println(
      "[BH1750] Recovery successful."
    );
  } else {
    Serial.println(
      "[BH1750] Recovery failed."
    );
  }

  return bh1750Available;
}

// =====================================================
// SENSOR INITIALIZATION
// =====================================================

void initializeEnvironmentalSensors() {
  pinMode(SOIL_SENSOR_PIN, INPUT);
  analogReadResolution(12);

  Wire.begin(
    I2C_SDA_PIN,
    I2C_SCL_PIN
  );

  Wire.setClock(I2C_CLOCK_HZ);
  delay(100);

  bh1750Available = startBH1750();

  lastBh1750RecoveryAttemptMs =
      millis() -
      BH1750_RECOVERY_COOLDOWN_MS;

  dht.begin();
  previousSensorTimeMs = millis();

  Serial.println();
  Serial.println("ENVIRONMENTAL SENSOR INITIALIZATION");
  Serial.println("------------------------------------------");

  Serial.print("DHT22 data pin           : GPIO ");
  Serial.println(DHT_PIN);

  Serial.println("DHT22 status             : INITIALIZED");

  Serial.print("BH1750 I2C address       : 0x");
  Serial.println(BH1750_ADDRESS, HEX);

  Serial.print("BH1750 I2C response      : ");
  Serial.println(
    i2cDeviceResponds(BH1750_ADDRESS)
      ? "DETECTED"
      : "NOT DETECTED"
  );

  Serial.print("BH1750 initialization    : ");
  Serial.println(
    bh1750Available
      ? "SUCCESS"
      : "FAILED"
  );

  Serial.print("I2C clock                : ");
  Serial.print(I2C_CLOCK_HZ);
  Serial.println(" Hz");

  Serial.print("Soil ADC pin             : GPIO ");
  Serial.println(SOIL_SENSOR_PIN);

  Serial.print("Soil dry calibration     : ");
  Serial.println(SOIL_DRY_VALUE);

  Serial.print("Soil wet calibration     : ");
  Serial.println(SOIL_WET_VALUE);

  Serial.print("Soil open limit          : ");
  Serial.println(SOIL_OPEN_CIRCUIT_LIMIT);

  Serial.print("Sensor interval          : ");
  Serial.print(SENSOR_INTERVAL_MS);
  Serial.println(" ms");

  Serial.println("Sensor sampling state    : NORMAL ONLY");
  Serial.println("------------------------------------------");
}

// =====================================================
// PUMP RUNTIME SAFETY
// =====================================================

void enforcePumpRuntimeSafety() {
  if (
    currentState != SystemState::NORMAL ||
    tamperLatched
  ) {
    pumpCommandOn = false;
    pumpStartedAtMs = 0;

    digitalWrite(
      PUMP_RELAY_PIN,
      RELAY_OFF
    );

    return;
  }

  unsigned long nowMs = millis();

  if (
    pumpCommandOn &&
    pumpStartedAtMs == 0
  ) {
    pumpStartedAtMs = nowMs;
  }

  if (
    pumpCommandOn &&
    nowMs - pumpStartedAtMs >=
        MAX_PUMP_RUNTIME_MS
  ) {
    pumpCommandOn = false;
    pumpTimeoutActive = true;
    pumpTimeoutCount++;

    pumpCooldownStartedAtMs = nowMs;
    pumpStartedAtMs = 0;

    digitalWrite(
      PUMP_RELAY_PIN,
      RELAY_OFF
    );

    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println("PUMP SAFETY TIMEOUT");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    Serial.print("Maximum runtime          : ");
    Serial.print(MAX_PUMP_RUNTIME_MS);
    Serial.println(" ms");

    Serial.println("Pump command             : FORCED OFF");
    Serial.println("Pump relay               : HIGH / OFF");

    Serial.print("Cooldown                 : ");
    Serial.print(PUMP_COOLDOWN_MS);
    Serial.println(" ms");

    Serial.print("Timeout count            : ");
    Serial.println(pumpTimeoutCount);

    printTinyMlEventRow(
      "PUMP_SAFETY_TIMEOUT",
      static_cast<long>(MAX_PUMP_RUNTIME_MS),
      activeScenarioId,
      activeDatasetLabel
    );

    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  }

  if (
    pumpTimeoutActive &&
    nowMs - pumpCooldownStartedAtMs >=
        PUMP_COOLDOWN_MS
  ) {
    pumpTimeoutActive = false;
    pumpCooldownStartedAtMs = 0;

    Serial.println();
    Serial.println("Pump cooldown completed.");
    Serial.println("Fresh valid dry-soil sample required.");

    printTinyMlEventRow(
      "PUMP_COOLDOWN_COMPLETED",
      static_cast<long>(PUMP_COOLDOWN_MS),
      activeScenarioId,
      activeDatasetLabel
    );
  }

  if (!pumpCommandOn) {
    pumpStartedAtMs = 0;
  }

  applyAutomaticActuatorOutputs();
}

// =====================================================
// AUTOMATIC CONTROL DECISION
// =====================================================

void updateAutomaticActuatorControl(
    float temperatureC,
    bool temperatureValid,
    int soilRaw,
    int soilPercentage,
    bool soilReadingValid
) {
  if (
    currentState != SystemState::NORMAL ||
    tamperLatched
  ) {
    pumpCommandOn = false;
    fanCommandOn = false;
    soilActuationValid = false;
    pumpStartedAtMs = 0;

    forceActuatorsOff();
    return;
  }

  // Fan hysteresis
  bool previousFanCommand = fanCommandOn;

  if (!temperatureValid) {
    fanCommandOn = false;
  } else if (
    !fanCommandOn &&
    temperatureC >= FAN_ON_TEMPERATURE_C
  ) {
    fanCommandOn = true;
  } else if (
    fanCommandOn &&
    temperatureC <= FAN_OFF_TEMPERATURE_C
  ) {
    fanCommandOn = false;
  }

  if (
    !previousFanCommand &&
    fanCommandOn
  ) {
    fanActivationCount++;
  }

  // Soil plausibility and pump hysteresis
  soilActuationValid =
      soilReadingValid &&
      soilRaw < SOIL_OPEN_CIRCUIT_LIMIT;

  bool previousPumpCommand = pumpCommandOn;

  if (!soilActuationValid) {
    pumpCommandOn = false;
    pumpStartedAtMs = 0;
  } else if (pumpTimeoutActive) {
    pumpCommandOn = false;
    pumpStartedAtMs = 0;
  } else if (
    !pumpCommandOn &&
    soilPercentage <= PUMP_ON_MOISTURE_PERCENT
  ) {
    pumpCommandOn = true;
    pumpStartedAtMs = millis();
  } else if (
    pumpCommandOn &&
    soilPercentage >= PUMP_OFF_MOISTURE_PERCENT
  ) {
    pumpCommandOn = false;
    pumpStartedAtMs = 0;
  }

  if (
    !previousPumpCommand &&
    pumpCommandOn
  ) {
    pumpActivationCount++;
  }

  applyAutomaticActuatorOutputs();
}


// =====================================================
// STEP 33A — TINYML FEATURE ENCODING AND SECURITY DECISION
// =====================================================

float rfidResultCodeToModelFeature(
    int resultCode,
    bool contextCurrent
) {
  if (!contextCurrent) {
    return 0.0f;
  }

  switch (resultCode) {
    case 1:
      // Protected-sector authentication succeeded.
      return 1.0f;

    case 2:
    case 5:
      // Unauthorized UID or protected-marker mismatch.
      return -1.0f;

    case 3:
    case 4:
    case 6:
      // Reader/communication fault.
      return -0.25f;

    default:
      return 0.0f;
  }
}

void runTinyMlMonitorInference(
    float rfidAuthFeature,
    int tamperState,
    float tempLightRatio,
    float moistureDelta,
    unsigned long relayRuntimeMs,
    bool inferenceFeaturesValid
) {
  if (
    !inferenceFeaturesValid ||
    isnan(rfidAuthFeature) ||
    isnan(tempLightRatio) ||
    isnan(moistureDelta)
  ) {
    tinyMlInferenceSkippedCount++;

    Serial.println();
    Serial.println("------------------------------------------");
    Serial.println("TINYML LIVE INFERENCE");
    Serial.println("------------------------------------------");
    Serial.println("Inference result          : SKIPPED");
    Serial.println("Reason                    : INVALID FEATURE INPUT");
    Serial.print("Skipped inference count   : ");
    Serial.println(tinyMlInferenceSkippedCount);
    Serial.println("System/relay action       : NONE — INFERENCE SKIPPED");
    Serial.println("------------------------------------------");

    return;
  }

  // Preserve only valid pre-tamper features.
  // The physical tamper report reuses these values with
  // tamper_state forced to 1.
  if (tamperState == 0) {
    cachedRfidAuthFeature = rfidAuthFeature;
    cachedTempLightRatio = tempLightRatio;
    cachedMoistureDelta = moistureDelta;
    cachedRelayRuntimeMs = relayRuntimeMs;
    tinyMlFeatureCacheValid = true;
  }

  const float features[C1TinyML::FEATURE_COUNT] = {
    rfidAuthFeature,
    static_cast<float>(tamperState),
    tempLightRatio,
    moistureDelta,
    static_cast<float>(relayRuntimeMs)
  };

  unsigned long inferenceStartUs = micros();

  float anomalyProbability =
      C1TinyML::predictAnomalyProbability(features);

  uint8_t predictedLabel =
      anomalyProbability >= C1TinyML::DECISION_THRESHOLD
        ? 1
        : 0;

  unsigned long inferenceLatencyUs =
      micros() - inferenceStartUs;

  tinyMlInferenceCount++;

  if (predictedLabel == 1) {
    tinyMlAnomalyPredictionCount++;
  } else {
    tinyMlNormalPredictionCount++;
  }

  lastTinyMlAnomalyProbability = anomalyProbability;
  lastTinyMlPrediction = predictedLabel;
  lastTinyMlInferenceLatencyUs = inferenceLatencyUs;

  // ---------------------------------------------------
  // Confirmed TinyML security gate
  // ---------------------------------------------------
  if (
    currentState == SystemState::NORMAL &&
    !tamperLatched &&
    !tinyMlLockdownLatched &&
    tamperState == 0
  ) {
    unsigned long nowMs = millis();

    if (predictedLabel == 1) {
      bool withinConfirmationWindow =
          lastTinyMlAnomalyAtMs != 0 &&
          nowMs - lastTinyMlAnomalyAtMs <=
              TINYML_CONFIRMATION_MAX_GAP_MS;

      if (withinConfirmationWindow) {
        if (
          tinyMlConsecutiveAnomalyCount <
          TINYML_CONFIRMATIONS_REQUIRED
        ) {
          tinyMlConsecutiveAnomalyCount++;
        }
      } else {
        tinyMlConsecutiveAnomalyCount = 1;
      }

      lastTinyMlAnomalyAtMs = nowMs;

      if (
        tinyMlConsecutiveAnomalyCount >=
        TINYML_CONFIRMATIONS_REQUIRED
      ) {
        executeConfirmedTinyMlLockdown(
          anomalyProbability,
          inferenceLatencyUs,
          features
        );
      }
    } else {
      tinyMlConsecutiveAnomalyCount = 0;
      lastTinyMlAnomalyAtMs = 0;
    }
  }

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("TINYML LIVE INFERENCE — SECURITY MODE");
  Serial.println("------------------------------------------");

  Serial.print("Inference number          : ");
  Serial.println(tinyMlInferenceCount);

  Serial.print("Feature 0 RFID auth       : ");
  Serial.println(rfidAuthFeature, 3);

  Serial.print("Feature 1 tamper          : ");
  Serial.println(tamperState);

  Serial.print("Feature 2 temp/light      : ");
  Serial.println(tempLightRatio, 6);

  Serial.print("Feature 3 moisture delta  : ");
  Serial.println(moistureDelta, 3);

  Serial.print("Feature 4 relay runtime   : ");
  Serial.print(relayRuntimeMs);
  Serial.println(" ms");

  Serial.print("Anomaly probability      : ");
  Serial.println(anomalyProbability, 6);

  Serial.print("Decision threshold       : ");
  Serial.println(C1TinyML::DECISION_THRESHOLD, 3);

  Serial.print("Predicted label          : ");
  Serial.println(
    predictedLabel == 1
      ? "1 / ANOMALY"
      : "0 / NORMAL"
  );

  Serial.print("Dataset ground truth     : ");
  Serial.print(activeDatasetLabel);
  Serial.print(" / ");
  Serial.println(
    activeDatasetLabel == 1
      ? "ANOMALY"
      : "NORMAL"
  );

  Serial.print("Prediction matches label : ");
  Serial.println(
    predictedLabel == activeDatasetLabel
      ? "YES"
      : "NO"
  );

  Serial.print("Inference latency        : ");
  Serial.print(inferenceLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Normal predictions       : ");
  Serial.println(tinyMlNormalPredictionCount);

  Serial.print("Anomaly predictions      : ");
  Serial.println(tinyMlAnomalyPredictionCount);

  Serial.print("Anomaly confirmations    : ");
  Serial.print(tinyMlConsecutiveAnomalyCount);
  Serial.print("/");
  Serial.println(TINYML_CONFIRMATIONS_REQUIRED);

  Serial.print("System/relay action      : ");

  if (tinyMlLockdownLatched) {
    Serial.println("CONFIRMED HARD LOCKDOWN");
  } else if (tamperLatched) {
    Serial.println(
      "NONE — PHYSICAL TAMPER ALREADY LOCKED"
    );
  } else if (currentState != SystemState::NORMAL) {
    Serial.println("NONE — SYSTEM NOT IN NORMAL STATE");
  } else if (predictedLabel == 1) {
    Serial.println("WAITING FOR CONFIRMATION");
  } else {
    Serial.println("NONE — NORMAL PREDICTION");
  }

  Serial.println("------------------------------------------");

  Serial.print("CSV_TINYML_INFERENCE,");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(tinyMlInferenceCount);
  Serial.print(",");
  Serial.print(sensorSampleNumber);
  Serial.print(",");
  Serial.print(activeScenarioId);
  Serial.print(",");
  Serial.print(activeDatasetLabel);
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(rfidAuthFeature, 3);
  Serial.print(",");
  Serial.print(tamperState);
  Serial.print(",");
  Serial.print(tempLightRatio, 6);
  Serial.print(",");
  Serial.print(moistureDelta, 3);
  Serial.print(",");
  Serial.print(relayRuntimeMs);
  Serial.print(",");
  Serial.print(anomalyProbability, 6);
  Serial.print(",");
  Serial.print(predictedLabel);
  Serial.print(",");
  Serial.print(inferenceLatencyUs);
  Serial.print(",");
  Serial.println(TINYML_MONITOR_ONLY ? 1 : 0);
}


// =====================================================
// STEP 33A — TINYML RUNTIME LOGGER + SECURITY INFERENCE
// =====================================================

void printTinyMlRuntimeRow(
    float temperatureC,
    bool temperatureValid,
    float humidity,
    float lightLux,
    bool lightValid,
    int soilRaw,
    int soilPercentage,
    bool soilValid,
    bool completeSampleValid
) {
  if (!tinyMlLoggerEnabled) {
    return;
  }

  unsigned long nowMs = millis();

  if (fanCommandOn && fanStartedAtMsForLogger == 0) {
    fanStartedAtMsForLogger = nowMs;
  } else if (!fanCommandOn) {
    fanStartedAtMsForLogger = 0;
  }

  float tempLightRatio = NAN;

  if (temperatureValid && lightValid) {
    float safeLux = lightLux < 1.0f ? 1.0f : lightLux;
    tempLightRatio = temperatureC / safeLux;
  }

  float moistureDelta = 0.0f;

  // A valid model baseline must come only from a plausible
  // connected soil sensor. Do not overwrite the baseline
  // with an open-circuit/4095 reading.
  bool soilFeatureHealthy =
      soilValid &&
      soilRaw < SOIL_OPEN_CIRCUIT_LIMIT;

  if (soilFeatureHealthy) {
    if (previousSoilPercentAvailable) {
      moistureDelta =
          static_cast<float>(soilPercentage) -
          previousSoilPercent;
    }

    previousSoilPercent =
        static_cast<float>(soilPercentage);

    previousSoilPercentAvailable = true;
  } else {
    // Compare the disconnected/open-circuit condition
    // against the last valid moisture baseline.
    if (previousSoilPercentAvailable) {
      moistureDelta =
          0.0f - previousSoilPercent;
    } else {
      // No valid baseline exists yet. Use an explicit
      // out-of-range drop so the fault is not treated as
      // normal zero-change behavior.
      moistureDelta = -100.0f;
    }
  }

  unsigned long pumpRuntimeMs =
      pumpCommandOn && pumpStartedAtMs != 0
        ? nowMs - pumpStartedAtMs
        : 0;

  unsigned long fanRuntimeMs =
      fanCommandOn && fanStartedAtMsForLogger != 0
        ? nowMs - fanStartedAtMsForLogger
        : 0;

  unsigned long relayRuntimeMs =
      pumpRuntimeMs > fanRuntimeMs
        ? pumpRuntimeMs
        : fanRuntimeMs;

  bool rfidContextCurrent =
      lastRfidEventAtMs != 0 &&
      nowMs - lastRfidEventAtMs <= RFID_CONTEXT_TTL_MS;

  float rfidAuthFeature =
      rfidResultCodeToModelFeature(
        lastRfidResultCode,
        rfidContextCurrent
      );

  int tamperState =
      tamperLatched || digitalRead(TAMPER_PIN) == HIGH
        ? 1
        : 0;

  tinyMlRuntimeRowCount++;

  Serial.print("CSV_TINYML_RUNTIME,");
  Serial.print(nowMs);
  Serial.print(",");
  Serial.print(sensorSampleNumber);
  Serial.print(",");
  Serial.print(activeScenarioId);
  Serial.print(",");
  Serial.print(activeDatasetLabel);
  Serial.print(",");
  Serial.print(datasetScenarioName(activeScenarioId));
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(rfidContextCurrent ? lastRfidResultCode : 0);
  Serial.print(",");
  Serial.print(rfidContextCurrent ? lastRfidAuthLatencyUs : 0);
  Serial.print(",");
  Serial.print(rfidContextCurrent ? lastRfidBlockLatencyUs : 0);
  Serial.print(",");
  Serial.print(rfidContextCurrent ? lastRfidPipelineLatencyUs : 0);
  Serial.print(",");
  Serial.print(rfidContextCurrent && lastRfidRetryUsed ? 1 : 0);
  Serial.print(",");

  if (temperatureValid) Serial.print(temperatureC, 3);
  else Serial.print("NaN");
  Serial.print(",");

  if (temperatureValid) Serial.print(humidity, 3);
  else Serial.print("NaN");
  Serial.print(",");

  if (lightValid) Serial.print(lightLux, 3);
  else Serial.print("NaN");
  Serial.print(",");

  Serial.print(soilRaw);
  Serial.print(",");
  Serial.print(soilPercentage);
  Serial.print(",");

  if (!isnan(tempLightRatio)) Serial.print(tempLightRatio, 6);
  else Serial.print("NaN");
  Serial.print(",");

  Serial.print(moistureDelta, 3);
  Serial.print(",");
  Serial.print(pumpRuntimeMs);
  Serial.print(",");
  Serial.print(fanRuntimeMs);
  Serial.print(",");
  Serial.print(relayRuntimeMs);
  Serial.print(",");
  Serial.print(tamperState);
  Serial.print(",");
  Serial.print(pumpCommandOn ? 1 : 0);
  Serial.print(",");
  Serial.print(fanCommandOn ? 1 : 0);
  Serial.print(",");
  Serial.print(pumpTimeoutActive ? 1 : 0);
  Serial.print(",");
  Serial.print(soilActuationValid ? 1 : 0);
  Serial.print(",");
  Serial.println(completeSampleValid ? 1 : 0);

  // Temperature and light must be valid for the ratio.
  // A soil open-circuit remains a valid inference input
  // because moistureDelta intentionally represents it.
  bool inferenceFeaturesValid =
      temperatureValid &&
      lightValid &&
      !isnan(tempLightRatio);

  runTinyMlMonitorInference(
    rfidAuthFeature,
    tamperState,
    tempLightRatio,
    moistureDelta,
    relayRuntimeMs,
    inferenceFeaturesValid
  );
}

// =====================================================
// ENVIRONMENTAL SENSOR READING
// =====================================================

void readAndReportSensors() {
  if (
    currentState != SystemState::NORMAL ||
    tamperLatched
  ) {
    return;
  }

  sensorSampleNumber++;

  // DHT22
  float humidity = dht.readHumidity();
  float temperatureC = dht.readTemperature();

  bool dhtValid =
      !isnan(humidity) &&
      !isnan(temperatureC);

  if (!dhtValid) {
    dhtFailureCount++;
  }

  // BH1750
  float lightLux = -1.0f;

  if (bh1750Available) {
    lightLux = lightMeter.readLightLevel();
  }

  bool lightValid =
      bh1750Available &&
      !isnan(lightLux) &&
      lightLux >= 0.0f;

  if (!lightValid) {
    consecutiveBh1750Failures++;

    Serial.println();
    Serial.print("[BH1750] Invalid lux result: ");
    Serial.println(lightLux);

    if (recoverBH1750()) {
      delay(180);

      lightLux = lightMeter.readLightLevel();

      lightValid =
          !isnan(lightLux) &&
          lightLux >= 0.0f;
    }
  }

  if (lightValid) {
    consecutiveBh1750Failures = 0;
  } else {
    lightFailureCount++;
  }

  // Soil
  int soilRaw = analogRead(SOIL_SENSOR_PIN);

  bool soilValid =
      soilRaw >= 0 &&
      soilRaw <= 4095;

  if (!soilValid) {
    soilFailureCount++;
  }

  long mappedSoilPercentage =
      map(
        soilRaw,
        SOIL_DRY_VALUE,
        SOIL_WET_VALUE,
        0,
        100
      );

  int soilPercentage =
      static_cast<int>(
        constrain(
          mappedSoilPercentage,
          0L,
          100L
        )
      );

  updateAutomaticActuatorControl(
    temperatureC,
    dhtValid,
    soilRaw,
    soilPercentage,
    soilValid
  );

  bool completeSampleValid =
      dhtValid &&
      lightValid &&
      soilValid;

  if (completeSampleValid) {
    validSensorSamples++;
  } else {
    failedSensorSamples++;
  }

  if (tamperLatched) {
    return;
  }

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("ENVIRONMENTAL SENSOR AND CONTROL SAMPLE");
  Serial.println("------------------------------------------");

  Serial.print("Sample number            : ");
  Serial.println(sensorSampleNumber);

  Serial.print("System state             : ");
  Serial.println(stateName(currentState));

  Serial.print("Temperature              : ");
  if (dhtValid) {
    Serial.print(temperatureC, 1);
    Serial.println(" C");
  } else {
    Serial.println("READ FAILURE");
  }

  Serial.print("Humidity                 : ");
  if (dhtValid) {
    Serial.print(humidity, 1);
    Serial.println(" %");
  } else {
    Serial.println("READ FAILURE");
  }

  Serial.print("Light level              : ");
  if (lightValid) {
    Serial.print(lightLux, 1);
    Serial.println(" lux");
  } else {
    Serial.println("READ FAILURE");
  }

  Serial.print("Soil raw value           : ");
  Serial.println(soilRaw);

  Serial.print("Soil moisture            : ");
  Serial.print(soilPercentage);
  Serial.println(" %");

  Serial.print("Complete sample          : ");
  Serial.println(
    completeSampleValid
      ? "VALID"
      : "REVIEW REQUIRED"
  );

  Serial.print("Soil actuator health     : ");
  Serial.println(
    soilActuationValid
      ? "VALID"
      : "OPEN CIRCUIT / IMPLAUSIBLE"
  );

  Serial.print("Pump command             : ");
  Serial.println(commandStateName(pumpCommandOn));

  Serial.print("Fan command              : ");
  Serial.println(commandStateName(fanCommandOn));

  Serial.print("Pump timeout active      : ");
  Serial.println(
    pumpTimeoutActive
      ? "YES"
      : "NO"
  );

  Serial.print("Pump runtime elapsed     : ");
  if (pumpCommandOn && pumpStartedAtMs != 0) {
    Serial.print(millis() - pumpStartedAtMs);
  } else {
    Serial.print(0);
  }
  Serial.println(" ms");

  Serial.print("Maximum pump runtime     : ");
  Serial.print(MAX_PUMP_RUNTIME_MS);
  Serial.println(" ms");

  Serial.print("Pump cooldown            : ");
  Serial.print(PUMP_COOLDOWN_MS);
  Serial.println(" ms");

  Serial.print("Pump timeout count       : ");
  Serial.println(pumpTimeoutCount);

  Serial.print("Pump activation count    : ");
  Serial.println(pumpActivationCount);

  Serial.print("Fan activation count     : ");
  Serial.println(fanActivationCount);

  Serial.print("Authorized session       : ");
  Serial.println(
    authorizedSessionActive
      ? "ACTIVE"
      : "INACTIVE"
  );

  Serial.print("Authorized session ID    : ");
  Serial.println(authorizedSessionId);

  Serial.print("RFID timing evaluations  : ");
  Serial.println(rfidTimingRiskEvaluationCount);

  Serial.print("RFID timing risk flags   : ");
  Serial.println(rfidTimingRiskFlagCount);

  Serial.print("Last RFID risk probability: ");
  Serial.println(lastRfidTimingRiskProbability, 6);

  Serial.print("Last RFID timing flag    : ");
  Serial.println(lastRfidTimingRiskFlag);

  if (authorizedSessionActive) {
    Serial.print("Authorized session age   : ");
    Serial.print(
      millis() - authorizedSessionStartedAtMs
    );
    Serial.println(" ms");
  }

  Serial.print("Pump relay GPIO          : ");
  Serial.println(
    digitalRead(PUMP_RELAY_PIN) == RELAY_ON
      ? "LOW / ON"
      : "HIGH / OFF"
  );

  Serial.print("Fan relay GPIO           : ");
  Serial.println(
    digitalRead(FAN_RELAY_PIN) == RELAY_ON
      ? "LOW / ON"
      : "HIGH / OFF"
  );

  Serial.print("Valid samples            : ");
  Serial.println(validSensorSamples);

  Serial.print("Failed samples           : ");
  Serial.println(failedSensorSamples);

  Serial.print("DHT22 failures           : ");
  Serial.println(dhtFailureCount);

  Serial.print("BH1750 failures          : ");
  Serial.println(lightFailureCount);

  Serial.print("BH1750 consecutive fail  : ");
  Serial.println(consecutiveBh1750Failures);

  Serial.print("BH1750 recovery attempts : ");
  Serial.println(bh1750RecoveryAttempts);

  Serial.print("BH1750 recoveries passed : ");
  Serial.println(bh1750SuccessfulRecoveries);

  Serial.print("Soil failures            : ");
  Serial.println(soilFailureCount);

  // CSV columns:
  // sample,time,state,temp,humidity,lux,soilRaw,
  // soilPercent,sampleValid,soilHealth,pumpCommand,
  // fanCommand,pumpTimeout,pumpRelay,fanRelay

  Serial.print("CSV_CONTROL,");
  Serial.print(sensorSampleNumber);
  Serial.print(",");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");

  if (dhtValid) {
    Serial.print(temperatureC, 1);
  } else {
    Serial.print("NaN");
  }

  Serial.print(",");

  if (dhtValid) {
    Serial.print(humidity, 1);
  } else {
    Serial.print("NaN");
  }

  Serial.print(",");

  if (lightValid) {
    Serial.print(lightLux, 1);
  } else {
    Serial.print("NaN");
  }

  Serial.print(",");
  Serial.print(soilRaw);
  Serial.print(",");
  Serial.print(soilPercentage);
  Serial.print(",");
  Serial.print(completeSampleValid ? 1 : 0);
  Serial.print(",");
  Serial.print(soilActuationValid ? 1 : 0);
  Serial.print(",");
  Serial.print(pumpCommandOn ? 1 : 0);
  Serial.print(",");
  Serial.print(fanCommandOn ? 1 : 0);
  Serial.print(",");
  Serial.print(pumpTimeoutActive ? 1 : 0);
  Serial.print(",");
  Serial.print(
    digitalRead(PUMP_RELAY_PIN) == RELAY_ON
      ? 1
      : 0
  );
  Serial.print(",");
  Serial.println(
    digitalRead(FAN_RELAY_PIN) == RELAY_ON
      ? 1
      : 0
  );

  printTinyMlRuntimeRow(
    temperatureC,
    dhtValid,
    humidity,
    lightLux,
    lightValid,
    soilRaw,
    soilPercentage,
    soilValid,
    completeSampleValid
  );

  Serial.println("------------------------------------------");
}

// =====================================================
// RFID HELPERS
// =====================================================

bool uidMatches() {
  return
      rfid.uid.size == sizeof(AUTHORIZED_UID) &&
      memcmp(
        rfid.uid.uidByte,
        AUTHORIZED_UID,
        sizeof(AUTHORIZED_UID)
      ) == 0;
}

bool markerMatches(const byte* marker) {
  byte difference = 0;

  for (byte i = 0; i < 16; i++) {
    difference |=
        marker[i] ^
        EXPECTED_MARKER[i];
  }

  return difference == 0;
}

void printUID() {
  if (rfid.uid.size == 0) {
    Serial.print("NOT AVAILABLE");
    return;
  }

  for (byte i = 0; i < rfid.uid.size; i++) {
    if (i > 0) {
      Serial.print(":");
    }

    if (rfid.uid.uidByte[i] < 0x10) {
      Serial.print("0");
    }

    Serial.print(
      rfid.uid.uidByte[i],
      HEX
    );
  }
}

const char* authResultName(AuthResult result) {
  switch (result) {
    case AuthResult::AUTHORIZED:
      return "AUTHORIZED";

    case AuthResult::UID_REJECTED:
      return "UID_REJECTED";

    case AuthResult::SECTOR_COMMUNICATION_FAILURE:
      return "SECTOR_COMMUNICATION_FAILURE";

    case AuthResult::BLOCK_READ_FAILURE:
      return "BLOCK_READ_FAILURE";

    case AuthResult::MARKER_MISMATCH:
      return "MARKER_MISMATCH";

    case AuthResult::CARD_SELECTION_FAILURE:
      return "CARD_SELECTION_FAILURE";

    default:
      return "UNKNOWN";
  }
}

void initializeReader() {
  rfid.PCD_StopCrypto1();
  rfid.PCD_Reset();

  delay(50);

  rfid.PCD_Init();
  delay(150);

  rfid.PCD_SetAntennaGain(
    MFRC522::RxGain_48dB
  );
}

// =====================================================
// RFID AUTHENTICATION
// =====================================================

AuthResult authenticateSelectedCard(
    AuthMetrics& metrics
) {
  if (tamperLatched) {
    return AuthResult::CARD_SELECTION_FAILURE;
  }

  if (!uidMatches()) {
    return AuthResult::UID_REJECTED;
  }

  unsigned long pipelineStartUs = micros();
  unsigned long authenticationStartUs = micros();

  metrics.authStatus =
      rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        TRAILER_BLOCK,
        &runtimeKeyA,
        &(rfid.uid)
      );

  metrics.authLatencyUs =
      micros() -
      authenticationStartUs;

  if (
    metrics.authStatus !=
    MFRC522::STATUS_OK
  ) {
    metrics.pipelineLatencyUs =
        micros() -
        pipelineStartUs;

    return AuthResult::SECTOR_COMMUNICATION_FAILURE;
  }

  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);

  unsigned long readStartUs = micros();

  metrics.readStatus =
      rfid.MIFARE_Read(
        MARKER_BLOCK,
        markerBuffer,
        &markerBufferSize
      );

  metrics.readLatencyUs =
      micros() -
      readStartUs;

  metrics.pipelineLatencyUs =
      micros() -
      pipelineStartUs;

  if (
    metrics.readStatus !=
    MFRC522::STATUS_OK
  ) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

// =====================================================
// BOUNDED RFID RECOVERY
// =====================================================

AuthResult retrySectorAuthentication(
    AuthMetrics& retryMetrics
) {
  rfid.PCD_StopCrypto1();
  delay(5);

  return authenticateSelectedCard(retryMetrics);
}

AuthResult retryMarkerReadInCurrentSession(
    AuthMetrics& retryMetrics
) {
  if (tamperLatched) {
    return AuthResult::CARD_SELECTION_FAILURE;
  }

  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);

  unsigned long retryStartUs = micros();

  retryMetrics.readStatus =
      rfid.MIFARE_Read(
        MARKER_BLOCK,
        markerBuffer,
        &markerBufferSize
      );

  retryMetrics.readLatencyUs =
      micros() -
      retryStartUs;

  retryMetrics.pipelineLatencyUs =
      retryMetrics.readLatencyUs;

  if (
    retryMetrics.readStatus !=
    MFRC522::STATUS_OK
  ) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

// =====================================================
// CARD REMOVAL CONTROL
// =====================================================

void finishPresentation() {
  rfid.PCD_StopCrypto1();
  rfid.PICC_HaltA();

  waitingForCardRemoval = true;
  consecutiveAbsentChecks = 0;

  Serial.println();
  Serial.println("Remove the RFID tag.");
}

bool cardRespondsToWakeup() {
  byte atqa[2] = {0};
  byte atqaSize = sizeof(atqa);

  MFRC522::StatusCode status =
      rfid.PICC_WakeupA(
        atqa,
        &atqaSize
      );

  bool cardPresent =
      status == MFRC522::STATUS_OK ||
      status == MFRC522::STATUS_COLLISION;

  if (cardPresent) {
    if (rfid.PICC_ReadCardSerial()) {
      rfid.PICC_HaltA();
    }

    rfid.PCD_StopCrypto1();
  }

  return cardPresent;
}

void processCardRemoval() {
  if (cardRespondsToWakeup()) {
    consecutiveAbsentChecks = 0;
    delay(100);
    return;
  }

  consecutiveAbsentChecks++;

  if (
    consecutiveAbsentChecks >=
    REQUIRED_ABSENT_CHECKS
  ) {
    waitingForCardRemoval = false;
    consecutiveAbsentChecks = 0;

    initializeReader();
    applyStateOutputs();

    Serial.println();
    Serial.println("Card removal confirmed.");
    Serial.println("Ready for the next presentation.");
  }

  delay(100);
}

// =====================================================
// SECURITY POLICY
// =====================================================

void registerSecurityFailure(
    const char* reason
) {
  if (tamperLatched) {
    return;
  }

  securityFailureCount++;

  Serial.print("Security failures        : ");
  Serial.print(securityFailureCount);
  Serial.print("/");
  Serial.println(MAX_SECURITY_FAILURES);

  if (
    securityFailureCount >=
    MAX_SECURITY_FAILURES
  ) {
    changeState(
      SystemState::LOCKDOWN,
      reason
    );
  } else {
    applyStateOutputs();
  }
}

void processFinalAuthentication(
    AuthResult result
) {
  if (tamperLatched) {
    currentState = SystemState::LOCKDOWN;
    applyStateOutputs();
    return;
  }

  switch (result) {
    case AuthResult::AUTHORIZED:
      securityFailureCount = 0;

      if (
        currentState ==
        SystemState::LOCKED
      ) {
        previousSensorTimeMs = millis();

        AuthMetrics sessionMetrics;

        sessionMetrics.authLatencyUs =
            pendingSessionAuthLatencyUs;

        sessionMetrics.readLatencyUs =
            pendingSessionBlockLatencyUs;

        sessionMetrics.pipelineLatencyUs =
            pendingSessionPipelineLatencyUs;

        startAuthorizedSession(sessionMetrics);

        changeState(
          SystemState::NORMAL,
          "Secure RFID credential accepted"
        );
      } else if (
        currentState ==
        SystemState::NORMAL
      ) {
        closeAuthorizedSession(
          "AUTHORIZED_MANUAL_LOCK"
        );

        changeState(
          SystemState::LOCKED,
          "Authorized user manually locked system"
        );
      }
      break;

    case AuthResult::UID_REJECTED:
      registerSecurityFailure(
        "Repeated unauthorized UID attempts"
      );
      break;

    case AuthResult::MARKER_MISMATCH:
      registerSecurityFailure(
        "Protected RFID marker mismatch"
      );
      break;

    case AuthResult::SECTOR_COMMUNICATION_FAILURE:
    case AuthResult::BLOCK_READ_FAILURE:
    case AuthResult::CARD_SELECTION_FAILURE:
      Serial.println(
        "Communication fault: no state change"
      );
      Serial.println(
        "Security-failure counter not increased"
      );
      applyStateOutputs();
      break;
  }
}


// =====================================================
// STEP 34C-4 — RFID TIMING-RISK SUPPORT SIGNAL
// =====================================================

void evaluateRfidTimingRiskSupport(
    AuthResult finalResult,
    const AuthMetrics& firstMetrics,
    const AuthMetrics& effectiveMetrics,
    bool retryUsed
) {
  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("RFID TIMING-RISK SUPPORT EVALUATION");
  Serial.println("------------------------------------------");

  if (finalResult != AuthResult::AUTHORIZED) {
    rfidTimingRiskSkippedCount++;

    Serial.print("Evaluation result         : SKIPPED");
    Serial.println();

    Serial.print("Reason                    : ");
    Serial.println(
      "FINAL AUTHENTICATION WAS NOT AUTHORIZED"
    );

    Serial.print("Skipped evaluations       : ");
    Serial.println(rfidTimingRiskSkippedCount);

    Serial.println(
      "Security action           : NONE"
    );

    Serial.println(
      "Deterministic RFID result : PRIMARY"
    );

    Serial.println("------------------------------------------");
    return;
  }

  if (
    firstMetrics.uidLatencyUs == 0 ||
    effectiveMetrics.authLatencyUs == 0 ||
    effectiveMetrics.readLatencyUs == 0 ||
    effectiveMetrics.pipelineLatencyUs == 0
  ) {
    rfidTimingRiskSkippedCount++;

    Serial.println(
      "Evaluation result         : SKIPPED"
    );

    Serial.println(
      "Reason                    : INVALID TIMING FEATURE"
    );

    Serial.print("Skipped evaluations       : ");
    Serial.println(rfidTimingRiskSkippedCount);

    Serial.println(
      "Security action           : NONE"
    );

    Serial.println("------------------------------------------");
    return;
  }

  const float timingFeatures[
      C1RFIDTimingRisk::FEATURE_COUNT
  ] = {
    static_cast<float>(
      firstMetrics.uidLatencyUs
    ),
    static_cast<float>(
      effectiveMetrics.authLatencyUs
    ),
    static_cast<float>(
      effectiveMetrics.readLatencyUs
    ),
    static_cast<float>(
      effectiveMetrics.pipelineLatencyUs
    )
  };

  unsigned long inferenceStartUs = micros();

  const float cloneRiskProbability =
      C1RFIDTimingRisk::
          predictCloneRiskProbability(
            timingFeatures
          );

  const uint8_t riskFlag =
      C1RFIDTimingRisk::
          predictRiskFlag(
            timingFeatures
          );

  const unsigned long inferenceLatencyUs =
      micros() - inferenceStartUs;

  rfidTimingRiskEvaluationCount++;

  if (riskFlag == 1) {
    rfidTimingRiskFlagCount++;
  }

  lastRfidTimingRiskProbability =
      cloneRiskProbability;

  lastRfidTimingRiskFlag = riskFlag;

  lastRfidTimingInferenceUs =
      inferenceLatencyUs;

  Serial.print("Evaluation number         : ");
  Serial.println(rfidTimingRiskEvaluationCount);

  Serial.print("UID-selection latency     : ");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Sector-auth latency       : ");
  Serial.print(effectiveMetrics.authLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Protected-block latency   : ");
  Serial.print(effectiveMetrics.readLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Protected-pipeline latency: ");
  Serial.print(effectiveMetrics.pipelineLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Clone-risk probability    : ");
  Serial.println(cloneRiskProbability, 6);

  Serial.print("Conservative threshold    : ");
  Serial.println(
    C1RFIDTimingRisk::RISK_THRESHOLD,
    6
  );

  Serial.print("Timing-risk flag          : ");
  Serial.println(
    riskFlag == 1
      ? "1 / ELEVATED"
      : "0 / NOT ELEVATED"
  );

  Serial.print("Model inference latency   : ");
  Serial.print(inferenceLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Risk flags observed       : ");
  Serial.println(rfidTimingRiskFlagCount);

  Serial.print("Source data synthetic     : ");
  Serial.println(
    C1RFIDTimingRisk::SOURCE_DATA_SYNTHETIC
      ? "YES"
      : "NO"
  );

  Serial.print("Supporting signal only    : ");
  Serial.println(
    C1RFIDTimingRisk::SUPPORTING_SIGNAL_ONLY
      ? "YES"
      : "NO"
  );

  Serial.print("Active action permitted   : ");
  Serial.println(
    (
      C1RFIDTimingRisk::
          ACTIVE_SECURITY_ACTION_ALLOWED
      &&
      RFID_TIMING_ACTIVE_ACTION_ENABLED
    )
      ? "YES"
      : "NO"
  );

  Serial.println(
    "Security action           : NONE — EVIDENCE ONLY"
  );

  Serial.println(
    "Deterministic RFID result : PRIMARY"
  );

  Serial.println("------------------------------------------");

  Serial.print("CSV_RFID_TIMING_RISK,");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(authenticationEventNumber);
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(authResultCode(finalResult));
  Serial.print(",");
  Serial.print(retryUsed ? 1 : 0);
  Serial.print(",");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.print(",");
  Serial.print(effectiveMetrics.authLatencyUs);
  Serial.print(",");
  Serial.print(effectiveMetrics.readLatencyUs);
  Serial.print(",");
  Serial.print(effectiveMetrics.pipelineLatencyUs);
  Serial.print(",");
  Serial.print(cloneRiskProbability, 6);
  Serial.print(",");
  Serial.print(
    C1RFIDTimingRisk::RISK_THRESHOLD,
    6
  );
  Serial.print(",");
  Serial.print(riskFlag);
  Serial.print(",");
  Serial.print(
    C1RFIDTimingRisk::SOURCE_DATA_SYNTHETIC
      ? 1
      : 0
  );
  Serial.print(",");
  Serial.print(
    C1RFIDTimingRisk::SUPPORTING_SIGNAL_ONLY
      ? 1
      : 0
  );
  Serial.print(",");
  Serial.println(
    (
      C1RFIDTimingRisk::
          ACTIVE_SECURITY_ACTION_ALLOWED
      &&
      RFID_TIMING_ACTIVE_ACTION_ENABLED
    )
      ? 1
      : 0
  );
}


// =====================================================
// STEP 27B — TINYML RFID FEATURE LOGGER
// =====================================================

void printTinyMlRfidRow(
    AuthResult firstResult,
    AuthResult finalResult,
    const AuthMetrics& firstMetrics,
    const AuthMetrics& retryMetrics,
    bool retryUsed
) {
  if (!tinyMlLoggerEnabled) {
    return;
  }

  const AuthMetrics& effective =
      retryUsed && finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  lastRfidResultCode = authResultCode(finalResult);
  lastRfidAuthLatencyUs = effective.authLatencyUs;
  lastRfidBlockLatencyUs = effective.readLatencyUs;
  lastRfidPipelineLatencyUs = effective.pipelineLatencyUs;
  lastRfidRetryUsed = retryUsed;
  lastRfidEventAtMs = millis();

  pendingSessionAuthLatencyUs =
      effective.authLatencyUs;

  pendingSessionBlockLatencyUs =
      effective.readLatencyUs;

  pendingSessionPipelineLatencyUs =
      effective.pipelineLatencyUs;

  tinyMlRfidRowCount++;

  Serial.print("CSV_TINYML_RFID,");
  Serial.print(lastRfidEventAtMs);
  Serial.print(",");
  Serial.print(authenticationEventNumber);
  Serial.print(",");
  Serial.print(activeScenarioId);
  Serial.print(",");
  Serial.print(activeDatasetLabel);
  Serial.print(",");
  Serial.print(datasetScenarioName(activeScenarioId));
  Serial.print(",");
  Serial.print(stateName(currentState));
  Serial.print(",");
  Serial.print(authResultCode(firstResult));
  Serial.print(",");
  Serial.print(authResultCode(finalResult));
  Serial.print(",");
  Serial.print(retryUsed ? 1 : 0);
  Serial.print(",");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.print(",");
  Serial.print(effective.authLatencyUs);
  Serial.print(",");
  Serial.print(effective.readLatencyUs);
  Serial.print(",");
  Serial.println(effective.pipelineLatencyUs);
}

// =====================================================
// RFID EVENT REPORT
// =====================================================

void printAuthenticationReport(
    AuthResult firstResult,
    AuthResult finalResult,
    const AuthMetrics& firstMetrics,
    const AuthMetrics& retryMetrics,
    bool retryUsed,
    const char* recoveryMode
) {
  Serial.println();
  Serial.println("------------------------------------------");

  Serial.print("Authentication event     : ");
  Serial.println(authenticationEventNumber);

  Serial.print("Current state            : ");
  Serial.println(stateName(currentState));

  Serial.print("Detected UID             : ");
  printUID();
  Serial.println();

  Serial.print("First result             : ");
  Serial.println(authResultName(firstResult));

  Serial.print("First UID latency        : ");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.println(" microseconds");

  Serial.print("First sector latency     : ");
  Serial.print(firstMetrics.authLatencyUs);
  Serial.println(" microseconds");

  Serial.print("First block latency      : ");
  Serial.print(firstMetrics.readLatencyUs);
  Serial.println(" microseconds");

  Serial.print("First pipeline latency   : ");
  Serial.print(firstMetrics.pipelineLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Bounded retry used       : ");
  Serial.println(retryUsed ? "YES" : "NO");

  Serial.print("Recovery mode            : ");
  Serial.println(recoveryMode);

  if (retryUsed) {
    Serial.print("Retry result             : ");
    Serial.println(authResultName(finalResult));

    Serial.print("Retry sector latency     : ");
    Serial.print(retryMetrics.authLatencyUs);
    Serial.println(" microseconds");

    Serial.print("Retry block latency      : ");
    Serial.print(retryMetrics.readLatencyUs);
    Serial.println(" microseconds");

    Serial.print("Retry pipeline latency   : ");
    Serial.print(retryMetrics.pipelineLatencyUs);
    Serial.println(" microseconds");
  }

  Serial.print("Final authentication     : ");
  Serial.println(authResultName(finalResult));

  printTinyMlRfidRow(
    firstResult,
    finalResult,
    firstMetrics,
    retryMetrics,
    retryUsed
  );

  const AuthMetrics& effectiveMetrics =
      retryUsed &&
      finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  evaluateRfidTimingRiskSupport(
    finalResult,
    firstMetrics,
    effectiveMetrics,
    retryUsed
  );

  Serial.println("------------------------------------------");
}

// =====================================================
// SETUP
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1500);

  // Active-low relay outputs must start HIGH/OFF.
  pinMode(PUMP_RELAY_PIN, OUTPUT);
  pinMode(FAN_RELAY_PIN, OUTPUT);

  digitalWrite(PUMP_RELAY_PIN, RELAY_OFF);
  digitalWrite(FAN_RELAY_PIN, RELAY_OFF);

  // LEDs
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BLUE_LED_PIN, OUTPUT);
  pinMode(YELLOW_LED_PIN, OUTPUT);
  pinMode(RED_LED_PIN, OUTPUT);

  turnAllStatusLEDsOff();

  // Tamper input
  pinMode(TAMPER_PIN, INPUT_PULLUP);

  // Sensors
  initializeEnvironmentalSensors();

  // RFID
  SPI.begin(
    RFID_SCK_PIN,
    RFID_MISO_PIN,
    RFID_MOSI_PIN,
    RFID_SS_PIN
  );

  rfid.PCD_Init();
  delay(250);

  rfid.PCD_SetAntennaGain(
    MFRC522::RxGain_48dB
  );

  for (byte i = 0; i < 6; i++) {
    runtimeKeyA.keyByte[i] =
        CUSTOM_KEY_A_BYTES[i];
  }

  for (
    byte i = 0;
    i < sizeof(runtimeNwkSKey);
    i++
  ) {
    runtimeNwkSKey[i] =
        static_cast<uint8_t>(
          esp_random()
        );
  }

  currentState = SystemState::LOCKED;
  securityFailureCount = 0;

  pumpCommandOn = false;
  fanCommandOn = false;
  soilActuationValid = false;
  pumpTimeoutActive = false;

  pumpStartedAtMs = 0;
  pumpCooldownStartedAtMs = 0;

  applyStateOutputs();

  BaseType_t taskCreated =
      xTaskCreatePinnedToCore(
        tamperSecurityTask,
        "TamperSecurityTask",
        4096,
        nullptr,
        24,
        &tamperTaskHandle,
        1
      );

  if (taskCreated != pdPASS) {
    currentState = SystemState::LOCKDOWN;
    applyStateOutputs();

    Serial.println(
      "CRITICAL: Tamper security task creation failed."
    );

    while (true) {
      forceActuatorsOff();
      delay(100);
    }
  }

  attachInterrupt(
    digitalPinToInterrupt(TAMPER_PIN),
    handleTamperInterrupt,
    RISING
  );

  byte readerVersion =
      rfid.PCD_ReadRegister(
        MFRC522::VersionReg
      );

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 1 CLOSURE — STEP 34C-4");
  Serial.println("INTEGRATED RFID TIMING SUPPORT SIGNAL");
  Serial.println("==========================================");

  Serial.print("RC522 VersionReg         : 0x");
  if (readerVersion < 0x10) {
    Serial.print("0");
  }
  Serial.println(readerVersion, HEX);

  Serial.println("RFID SPI speed           : 500 kHz");
  Serial.println("RFID receiver gain       : 48 dB");
  Serial.println("Runtime credential       : Custom Key A");
  Serial.println("Protected marker block   : 16");

  Serial.println("Tamper GPIO              : 13");
  Serial.println("Secure switch state      : LOW");
  Serial.println("Tamper switch state      : HIGH");

  Serial.println("BH1750 address           : 0x23");
  Serial.println("I2C speed                : 100 kHz");

  Serial.print("Fan ON threshold         : ");
  Serial.print(FAN_ON_TEMPERATURE_C, 1);
  Serial.println(" C");

  Serial.print("Fan OFF threshold        : ");
  Serial.print(FAN_OFF_TEMPERATURE_C, 1);
  Serial.println(" C");

  Serial.print("Pump ON threshold        : ");
  Serial.print(PUMP_ON_MOISTURE_PERCENT);
  Serial.println(" %");

  Serial.print("Pump OFF threshold       : ");
  Serial.print(PUMP_OFF_MOISTURE_PERCENT);
  Serial.println(" %");

  Serial.print("Maximum pump runtime     : ");
  Serial.print(MAX_PUMP_RUNTIME_MS);
  Serial.println(" ms");

  Serial.print("Pump cooldown            : ");
  Serial.print(PUMP_COOLDOWN_MS);
  Serial.println(" ms");

  Serial.println("Relay safe level         : HIGH / OFF");
  Serial.println("Real pump/fan loads      : MUST BE DISCONNECTED");
  Serial.println("Lockdown recovery        : PHYSICAL RESTART");

  Serial.print("Initial tamper input     : ");
  Serial.println(
    digitalRead(TAMPER_PIN) == LOW
      ? "SECURE / CLOSED"
      : "OPEN / TAMPER"
  );

  Serial.print("Initial system state     : ");
  Serial.println(stateName(currentState));

  Serial.println("TinyML logger             : ENABLED");
  Serial.println("TinyML model              : RANDOM FOREST");
  Serial.print("TinyML tree count         : ");
  Serial.println(C1TinyML::TREE_COUNT);
  Serial.print("TinyML feature count      : ");
  Serial.println(C1TinyML::FEATURE_COUNT);
  Serial.print("TinyML threshold          : ");
  Serial.println(C1TinyML::DECISION_THRESHOLD, 3);
  Serial.println("TinyML action mode        : CONFIRMED HARD LOCKDOWN");

  Serial.print("Confirmations required   : ");
  Serial.println(TINYML_CONFIRMATIONS_REQUIRED);

  Serial.print("Confirmation max gap     : ");
  Serial.print(TINYML_CONFIRMATION_MAX_GAP_MS);
  Serial.println(" ms");

  Serial.println("TinyML relay safe level   : HIGH / OFF");
  Serial.println("Tamper model inference    : ONE-SHOT AFTER LOCKDOWN");
  Serial.println("Tamper safety authority   : DETERMINISTIC TASK");
  Serial.println("Physical tamper priority  : HIGHEST");
  Serial.println("Session attribution       : ENABLED");
  Serial.println("Attribution level         : RFID CREDENTIAL SESSION");
  Serial.println("Human identity proof      : NOT CLAIMED");

  Serial.println("RFID timing model         : LOGISTIC REGRESSION");

  Serial.print("RFID timing features      : ");
  Serial.println(C1RFIDTimingRisk::FEATURE_COUNT);

  Serial.print("RFID risk threshold       : ");
  Serial.println(
    C1RFIDTimingRisk::RISK_THRESHOLD,
    6
  );

  Serial.print("RFID source synthetic     : ");
  Serial.println(
    C1RFIDTimingRisk::SOURCE_DATA_SYNTHETIC
      ? "YES"
      : "NO"
  );

  Serial.println("RFID timing role          : SUPPORTING SIGNAL ONLY");
  Serial.println("RFID timing active action : DISABLED");

  Serial.print("Dataset scenario         : ");
  Serial.println(datasetScenarioName(activeScenarioId));
  Serial.print("Dataset label            : ");
  Serial.println(activeDatasetLabel);

  Serial.println("==========================================");

  printTinyMlCsvHeaders();
  printTinyMlLoggerHelp();

  // Fail securely if the enclosure is open at boot.
  if (digitalRead(TAMPER_PIN) == HIGH) {
    tamperInterruptTick =
        xTaskGetTickCount();

    xTaskNotifyGive(tamperTaskHandle);
    delay(50);
  }
}

// =====================================================
// MAIN LOOP
// =====================================================

void loop() {
  processTinyMlLoggerCommands();

  if (
    currentState != SystemState::NORMAL ||
    tamperLatched
  ) {
    forceActuatorsOff();
  } else {
    applyAutomaticActuatorOutputs();
  }

  // Enforce maximum runtime continuously, not only when
  // the environmental sampling function runs.
  enforcePumpRuntimeSafety();

  printTamperReport();
  printTinyMlLockdownReport();

  // Permanent tamper lockdown
  if (tamperLatched) {
    currentState = SystemState::LOCKDOWN;

    pumpCommandOn = false;
    fanCommandOn = false;
    soilActuationValid = false;
    pumpTimeoutActive = false;

    pumpStartedAtMs = 0;
    pumpCooldownStartedAtMs = 0;

    applyStateOutputs();

    delay(100);
    return;
  }

  // Wait for RFID tag removal
  if (waitingForCardRemoval) {
    processCardRemoval();
    return;
  }

  // Credential-failure lockdown
  if (currentState == SystemState::LOCKDOWN) {
    pumpCommandOn = false;
    fanCommandOn = false;
    soilActuationValid = false;

    applyStateOutputs();

    delay(100);
    return;
  }

  // Environmental sampling and control
  if (currentState == SystemState::NORMAL) {
    unsigned long currentTimeMs = millis();

    if (
      currentTimeMs -
      previousSensorTimeMs >=
      SENSOR_INTERVAL_MS
    ) {
      previousSensorTimeMs = currentTimeMs;
      readAndReportSensors();
    }
  }

  if (tamperLatched) {
    return;
  }

  // Wait for RFID
  if (!rfid.PICC_IsNewCardPresent()) {
    delay(20);
    return;
  }

  digitalWrite(YELLOW_LED_PIN, HIGH);

  AuthMetrics firstMetrics;
  AuthMetrics retryMetrics;

  unsigned long uidStartUs = micros();

  if (!rfid.PICC_ReadCardSerial()) {
    digitalWrite(YELLOW_LED_PIN, LOW);

    Serial.println();
    Serial.println(
      "Card-selection communication failure."
    );
    Serial.println("No state change.");
    Serial.println(
      "Security counter not increased."
    );

    applyStateOutputs();
    finishPresentation();
    return;
  }

  firstMetrics.uidLatencyUs =
      micros() - uidStartUs;

  authenticationEventNumber++;

  AuthResult firstResult =
      authenticateSelectedCard(
        firstMetrics
      );

  AuthResult finalResult = firstResult;

  bool retryUsed = false;
  const char* recoveryMode = "NONE";

  if (
    firstResult ==
    AuthResult::SECTOR_COMMUNICATION_FAILURE
  ) {
    retryUsed = true;
    recoveryMode = "SAME_SELECTION_SECTOR_RETRY";

    finalResult =
        retrySectorAuthentication(
          retryMetrics
        );
  } else if (
    firstResult ==
    AuthResult::BLOCK_READ_FAILURE
  ) {
    retryUsed = true;
    recoveryMode = "IN_SESSION_BLOCK_READ_RETRY";

    delay(5);

    finalResult =
        retryMarkerReadInCurrentSession(
          retryMetrics
        );
  }

  digitalWrite(YELLOW_LED_PIN, LOW);

  if (tamperLatched) {
    finishPresentation();
    return;
  }

  printAuthenticationReport(
    firstResult,
    finalResult,
    firstMetrics,
    retryMetrics,
    retryUsed,
    recoveryMode
  );

  processFinalAuthentication(finalResult);
  finishPresentation();
}
