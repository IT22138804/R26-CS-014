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

// =====================================================
// COMPONENT 1 — STEP 32A
// LIVE TINYML INFERENCE — MONITOR-ONLY MODE
//
// Added in this version:
// - Fan temperature hysteresis
// - Pump moisture hysteresis
// - Soil open-circuit protection
// - Maximum continuous pump runtime
// - Pump cooldown after timeout
//
// TINYML SAFETY POLICY:
// - The model runs after every valid environmental sample.
// - Inference is MONITOR ONLY during Step 32A.
// - Model predictions cannot change relays or system state.
// - Existing deterministic safety and tamper protections remain primary.
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
  PHYSICAL_TAMPER = 5
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
// STEP 32A — LIVE TINYML INFERENCE MONITOR
// =====================================================

// The exported model was trained using raw feature values.
// Do not apply the Step 29A z-score scaler here.
constexpr bool TINYML_MONITOR_ONLY = true;

uint32_t tinyMlInferenceCount = 0;
uint32_t tinyMlNormalPredictionCount = 0;
uint32_t tinyMlAnomalyPredictionCount = 0;
uint32_t tinyMlInferenceSkippedCount = 0;

float lastTinyMlAnomalyProbability = 0.0f;
uint8_t lastTinyMlPrediction = 0;
unsigned long lastTinyMlInferenceLatencyUs = 0;

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
  Serial.println("STEP 32A — LOGGER / TEST COMMANDS");
  Serial.println("==========================================");
  Serial.println("0 or N : NORMAL_OPERATION");
  Serial.println("1 or R : RFID_AUTH_ANOMALY");
  Serial.println("2 or S : SOIL_SENSOR_DISCONNECT");
  Serial.println("3 or L : LIGHT_SENSOR_MANIPULATION");
  Serial.println("4 or A : ACTUATOR_RUNTIME_MISUSE");
  Serial.println("5 or T : PHYSICAL_TAMPER");
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
// STEP 32A — TINYML FEATURE ENCODING AND INFERENCE
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
    Serial.println("System/relay action       : NONE — MONITOR ONLY");
    Serial.println("------------------------------------------");

    return;
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

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("TINYML LIVE INFERENCE — MONITOR ONLY");
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

  Serial.println("System/relay action       : NONE — MONITOR ONLY");
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
// STEP 32A — TINYML RUNTIME FEATURE LOGGER + INFERENCE
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

        changeState(
          SystemState::NORMAL,
          "Secure RFID credential accepted"
        );
      } else if (
        currentState ==
        SystemState::NORMAL
      ) {
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
  Serial.println("COMPONENT 1 — STEP 32A");
  Serial.println("LIVE TINYML INFERENCE — MONITOR ONLY");
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
  Serial.println("TinyML action mode        : MONITOR ONLY");
  Serial.println("Deterministic safety      : PRIMARY / UNCHANGED");
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
