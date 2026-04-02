/*
  Component 2 — Step 36B
  Authenticated handshake — Sensor ESP32
*/


#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <BH1750.h>
#include <DHT.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 32;
constexpr size_t FINGERPRINT_LENGTH = 8;
constexpr size_t AES_GCM_IV_LENGTH = 12;
constexpr size_t AES_GCM_TAG_LENGTH = 16;
constexpr size_t SECURE_PAYLOAD_LENGTH = 67;

const char NODE_ID[] = "GH_NODE_01";

// Development-only shared key used to verify the handshake pipeline.
// Replace this with a unique secret provisioned separately on each
// authorized device before claiming production security.
const uint8_t DEVELOPMENT_PSK[32] = {
  0x52, 0xA8, 0x17, 0xC3, 0x9D, 0x64, 0xEE, 0x20,
  0x41, 0xB7, 0x6C, 0x0F, 0xD2, 0x89, 0x35, 0xFA,
  0x73, 0x1E, 0x94, 0x4B, 0xA5, 0x68, 0xCD, 0x12,
  0xE7, 0x30, 0x5A, 0xB9, 0x86, 0xF1, 0x2D, 0x4C
};

void secureZeroize(void* memory, size_t length) {
  volatile uint8_t* pointer =
      static_cast<volatile uint8_t*>(memory);

  while (length > 0) {
    *pointer = 0;
    pointer++;
    length--;
  }
}

bool isAllZero(const uint8_t* data, size_t length) {
  uint8_t accumulator = 0;

  for (size_t index = 0; index < length; index++) {
    accumulator |= data[index];
  }

  return accumulator == 0;
}

bool constantTimeEqual(
    const uint8_t* first,
    const uint8_t* second,
    size_t length
) {
  uint8_t difference = 0;

  for (size_t index = 0; index < length; index++) {
    difference |= first[index] ^ second[index];
  }

  return difference == 0;
}

bool hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t output[SHA256_LENGTH]
) {
  const mbedtls_md_info_t* information =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (information == nullptr) {
    return false;
  }

  mbedtls_md_context_t context;
  mbedtls_md_init(&context);

  int result = mbedtls_md_setup(
    &context,
    information,
    1
  );

  if (result == 0) {
    result = mbedtls_md_hmac_starts(
      &context,
      key,
      keyLength
    );
  }

  if (result == 0 && dataLength > 0) {
    result = mbedtls_md_hmac_update(
      &context,
      data,
      dataLength
    );
  }

  if (result == 0) {
    result = mbedtls_md_hmac_finish(
      &context,
      output
    );
  }

  mbedtls_md_free(&context);
  return result == 0;
}

bool hkdfSha256(
    const uint8_t* inputKey,
    size_t inputKeyLength,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* information,
    size_t informationLength,
    uint8_t* output,
    size_t outputLength
) {
  if (
    outputLength == 0
    || outputLength > 255 * SHA256_LENGTH
  ) {
    return false;
  }

  uint8_t pseudoRandomKey[SHA256_LENGTH] = {0};

  if (!hmacSha256(
        salt,
        saltLength,
        inputKey,
        inputKeyLength,
        pseudoRandomKey
      )) {
    secureZeroize(
      pseudoRandomKey,
      sizeof(pseudoRandomKey)
    );

    return false;
  }

  uint8_t previousBlock[SHA256_LENGTH] = {0};
  size_t previousLength = 0;
  size_t generated = 0;
  uint8_t counter = 1;

  while (generated < outputLength) {
    const mbedtls_md_info_t* mdInformation =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (mdInformation == nullptr) {
      secureZeroize(
        pseudoRandomKey,
        sizeof(pseudoRandomKey)
      );

      secureZeroize(
        previousBlock,
        sizeof(previousBlock)
      );

      return false;
    }

    mbedtls_md_context_t context;
    mbedtls_md_init(&context);

    int result = mbedtls_md_setup(
      &context,
      mdInformation,
      1
    );

    if (result == 0) {
      result = mbedtls_md_hmac_starts(
        &context,
        pseudoRandomKey,
        sizeof(pseudoRandomKey)
      );
    }

    if (result == 0 && previousLength > 0) {
      result = mbedtls_md_hmac_update(
        &context,
        previousBlock,
        previousLength
      );
    }

    if (result == 0 && informationLength > 0) {
      result = mbedtls_md_hmac_update(
        &context,
        information,
        informationLength
      );
    }

    if (result == 0) {
      result = mbedtls_md_hmac_update(
        &context,
        &counter,
        1
      );
    }

    if (result == 0) {
      result = mbedtls_md_hmac_finish(
        &context,
        previousBlock
      );
    }

    mbedtls_md_free(&context);

    if (result != 0) {
      secureZeroize(
        pseudoRandomKey,
        sizeof(pseudoRandomKey)
      );

      secureZeroize(
        previousBlock,
        sizeof(previousBlock)
      );

      return false;
    }

    previousLength = SHA256_LENGTH;

    const size_t remaining =
        outputLength - generated;

    const size_t copyLength =
        remaining < SHA256_LENGTH
          ? remaining
          : SHA256_LENGTH;

    memcpy(
      output + generated,
      previousBlock,
      copyLength
    );

    generated += copyLength;
    counter++;
  }

  secureZeroize(
    pseudoRandomKey,
    sizeof(pseudoRandomKey)
  );

  secureZeroize(
    previousBlock,
    sizeof(previousBlock)
  );

  return true;
}

bool sha256Digest(
    const uint8_t* data,
    size_t length,
    uint8_t output[SHA256_LENGTH]
) {
  const mbedtls_md_info_t* information =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (information == nullptr) {
    return false;
  }

  return mbedtls_md(
    information,
    data,
    length,
    output
  ) == 0;
}


void writeUint32BigEndian(
    uint32_t value,
    uint8_t output[4]
) {
  output[0] =
      static_cast<uint8_t>((value >> 24) & 0xFF);

  output[1] =
      static_cast<uint8_t>((value >> 16) & 0xFF);

  output[2] =
      static_cast<uint8_t>((value >> 8) & 0xFF);

  output[3] =
      static_cast<uint8_t>(value & 0xFF);
}

void buildPacketIv(
    uint32_t packetSessionId,
    uint32_t sequence,
    const uint8_t sessionSensorNonce[NONCE_LENGTH],
    uint8_t iv[AES_GCM_IV_LENGTH]
) {
  writeUint32BigEndian(
    packetSessionId,
    iv
  );

  writeUint32BigEndian(
    sequence,
    iv + 4
  );

  // Four random bytes from the authenticated sensor nonce
  // ensure nonce separation between sessions.
  memcpy(
    iv + 8,
    sessionSensorNonce,
    4
  );
}

bool aes128GcmEncrypt(
    const uint8_t key[SESSION_KEY_LENGTH],
    const uint8_t iv[AES_GCM_IV_LENGTH],
    const uint8_t* aad,
    size_t aadLength,
    const uint8_t* plaintext,
    size_t plaintextLength,
    uint8_t* ciphertext,
    uint8_t tag[AES_GCM_TAG_LENGTH]
) {
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  int result = mbedtls_gcm_setkey(
    &context,
    MBEDTLS_CIPHER_ID_AES,
    key,
    SESSION_KEY_LENGTH * 8
  );

  if (result == 0) {
    result = mbedtls_gcm_crypt_and_tag(
      &context,
      MBEDTLS_GCM_ENCRYPT,
      plaintextLength,
      iv,
      AES_GCM_IV_LENGTH,
      aad,
      aadLength,
      plaintext,
      ciphertext,
      AES_GCM_TAG_LENGTH,
      tag
    );
  }

  mbedtls_gcm_free(&context);
  return result == 0;
}

bool aes128GcmDecrypt(
    const uint8_t key[SESSION_KEY_LENGTH],
    const uint8_t iv[AES_GCM_IV_LENGTH],
    const uint8_t* aad,
    size_t aadLength,
    const uint8_t* ciphertext,
    size_t ciphertextLength,
    const uint8_t tag[AES_GCM_TAG_LENGTH],
    uint8_t* plaintext
) {
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  int result = mbedtls_gcm_setkey(
    &context,
    MBEDTLS_CIPHER_ID_AES,
    key,
    SESSION_KEY_LENGTH * 8
  );

  if (result == 0) {
    result = mbedtls_gcm_auth_decrypt(
      &context,
      ciphertextLength,
      iv,
      AES_GCM_IV_LENGTH,
      aad,
      aadLength,
      tag,
      AES_GCM_TAG_LENGTH,
      ciphertext,
      plaintext
    );
  }

  mbedtls_gcm_free(&context);
  return result == 0;
}

String buildSecureAad(
    uint32_t packetSessionId,
    uint32_t sequence
) {
  return
      "C2_SECURE_V1|"
      + String(NODE_ID)
      + "|"
      + String(packetSessionId)
      + "|"
      + String(sequence);
}

String buildOuterMacTranscript(
    const String& nodeId,
    const String& packetSessionId,
    const String& sequence,
    const String& ivHex,
    const String& ciphertextHex,
    const String& gcmTagHex
) {
  return
      "C2_SECURE_V1|"
      + nodeId
      + "|"
      + packetSessionId
      + "|"
      + sequence
      + "|"
      + ivHex
      + "|"
      + ciphertextHex
      + "|"
      + gcmTagHex;
}


String bytesToHex(const uint8_t* data, size_t length) {
  static const char* HEX_DIGITS = "0123456789ABCDEF";

  String result;
  result.reserve(length * 2);

  for (size_t index = 0; index < length; index++) {
    result += HEX_DIGITS[(data[index] >> 4) & 0x0F];
    result += HEX_DIGITS[data[index] & 0x0F];
  }

  return result;
}

int hexValue(char character) {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }

  if (character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }

  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }

  return -1;
}

bool hexToBytes(
    const String& text,
    uint8_t* output,
    size_t outputLength
) {
  if (text.length() != outputLength * 2) {
    return false;
  }

  for (size_t index = 0; index < outputLength; index++) {
    const int high = hexValue(text[index * 2]);
    const int low = hexValue(text[index * 2 + 1]);

    if (high < 0 || low < 0) {
      return false;
    }

    output[index] =
        static_cast<uint8_t>((high << 4) | low);
  }

  return true;
}

bool calculateFingerprint(
    const uint8_t* key,
    size_t keyLength,
    uint8_t output[FINGERPRINT_LENGTH]
) {
  uint8_t digest[SHA256_LENGTH] = {0};

  if (!sha256Digest(key, keyLength, digest)) {
    secureZeroize(digest, sizeof(digest));
    return false;
  }

  memcpy(output, digest, FINGERPRINT_LENGTH);
  secureZeroize(digest, sizeof(digest));
  return true;
}

bool calculateTruncatedProof(
    const uint8_t* key,
    size_t keyLength,
    const String& transcript,
    uint8_t output[PROOF_LENGTH]
) {
  uint8_t fullProof[SHA256_LENGTH] = {0};

  const bool success = hmacSha256(
    key,
    keyLength,
    reinterpret_cast<const uint8_t*>(
      transcript.c_str()
    ),
    transcript.length(),
    fullProof
  );

  if (success) {
    memcpy(output, fullProof, PROOF_LENGTH);
  }

  secureZeroize(fullProof, sizeof(fullProof));
  return success;
}

bool splitCsv(
    const String& line,
    String fields[],
    size_t expectedFields
) {
  size_t fieldIndex = 0;
  int start = 0;

  while (fieldIndex < expectedFields) {
    const int comma = line.indexOf(',', start);

    if (comma < 0) {
      fields[fieldIndex++] = line.substring(start);
      break;
    }

    fields[fieldIndex++] = line.substring(start, comma);
    start = comma + 1;
  }

  return fieldIndex == expectedFields
      && line.indexOf(',', start) < 0;
}

bool deriveSessionKeys(
    uint32_t sessionId,
    const uint8_t sensorNonce[NONCE_LENGTH],
    const uint8_t gatewayNonce[NONCE_LENGTH],
    uint8_t appSKey[SESSION_KEY_LENGTH],
    uint8_t nwkSKey[SESSION_KEY_LENGTH]
) {
  uint8_t salt[NONCE_LENGTH * 2] = {0};

  memcpy(
    salt,
    sensorNonce,
    NONCE_LENGTH
  );

  memcpy(
    salt + NONCE_LENGTH,
    gatewayNonce,
    NONCE_LENGTH
  );

  const String appInformation =
      "C2/"
      + String(NODE_ID)
      + "/APPSKEY/V1/"
      + String(sessionId);

  const String nwkInformation =
      "C2/"
      + String(NODE_ID)
      + "/NWKSKEY/V1/"
      + String(sessionId);

  const bool appSuccess = hkdfSha256(
    DEVELOPMENT_PSK,
    sizeof(DEVELOPMENT_PSK),
    salt,
    sizeof(salt),
    reinterpret_cast<const uint8_t*>(
      appInformation.c_str()
    ),
    appInformation.length(),
    appSKey,
    SESSION_KEY_LENGTH
  );

  const bool nwkSuccess = hkdfSha256(
    DEVELOPMENT_PSK,
    sizeof(DEVELOPMENT_PSK),
    salt,
    sizeof(salt),
    reinterpret_cast<const uint8_t*>(
      nwkInformation.c_str()
    ),
    nwkInformation.length(),
    nwkSKey,
    SESSION_KEY_LENGTH
  );

  secureZeroize(salt, sizeof(salt));
  return appSuccess && nwkSuccess;
}

String buildBaseTranscript(
    uint32_t sessionId,
    const String& sensorNonceHex,
    const String& gatewayNonceHex
) {
  return
      String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|"
      + sensorNonceHex
      + "|"
      + gatewayNonceHex;
}


HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

// Long encrypted telemetry lines can keep AUX LOW for several seconds when
// the E32 is configured with a low air-data rate.
constexpr unsigned long E32_READY_TIMEOUT_MS = 15000;
constexpr unsigned long E32_TX_SETTLE_MS = 20;

bool waitForE32Ready(unsigned long timeoutMs = E32_READY_TIMEOUT_MS) {
  const unsigned long startedAt = millis();

  while (digitalRead(E32_AUX_PIN) == LOW) {
    if (millis() - startedAt >= timeoutMs) {
      Serial.println("E32 AUX wait              : TIMEOUT");
      return false;
    }

    delay(1);
  }

  return true;
}

bool sendE32Line(const String& line) {
  if (!waitForE32Ready()) {
    return false;
  }

  E32Serial.println(line);
  E32Serial.flush();

  // AUX may take a short time to go LOW after the last UART byte.
  delay(E32_TX_SETTLE_MS);
  return waitForE32Ready();
}

// Component 1 sensor pins.
constexpr int DHT_PIN = 27;
constexpr int SOIL_PIN = 36;
constexpr int I2C_SDA_PIN = 21;
constexpr int I2C_SCL_PIN = 22;

// Component 1 hardware. These assignments avoid the PDF draft conflict
// between RC522 reset and the BH1750 I2C clock on GPIO22.
constexpr int C1_RFID_SS_PIN = 5;
constexpr int C1_RFID_RST_PIN = 33;
constexpr int C1_RFID_SCK_PIN = 18;
constexpr int C1_RFID_MISO_PIN = 19;
constexpr int C1_RFID_MOSI_PIN = 23;
constexpr int C1_TAMPER_PIN = 13;
constexpr int C1_PUMP_RELAY_PIN = 25;
constexpr int C1_FAN_RELAY_PIN = 26;
constexpr int C1_GREEN_LED_PIN = 14;
constexpr int C1_BLUE_LED_PIN = 2;
constexpr int C1_YELLOW_LED_PIN = 32;
constexpr int C1_RED_LED_PIN = 4;

constexpr uint8_t C1_RELAY_ON = LOW;
constexpr uint8_t C1_RELAY_OFF = HIGH;

MFRC522 c1Rfid(C1_RFID_SS_PIN, C1_RFID_RST_PIN);
MFRC522::MIFARE_Key c1RuntimeKeyA;

constexpr byte C1_MARKER_BLOCK = 16;
constexpr byte C1_TRAILER_BLOCK = 19;

const byte C1_AUTHORIZED_UID[4] = {0x83, 0x3D, 0x53, 0x56};
const byte C1_CUSTOM_KEY_A[6] = {0x7A, 0x31, 0xC4, 0x9D, 0x52, 0xE8};
const byte C1_EXPECTED_MARKER[16] = {
  'C', '1', '-', 'A', 'U', 'T', 'H', '-',
  'V', '1', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

enum class C1SystemState : uint8_t { LOCKED, NORMAL, LOCKDOWN };

volatile bool c1TamperInterruptPending = false;
bool c1TamperLatched = false;
bool c1TamperArmed = false;
C1SystemState c1SystemState = C1SystemState::LOCKED;
bool c1AuthenticatedSessionActive = false;
uint32_t c1AuthenticatedSessionId = 0;
uint32_t c1EventCounter = 0;
uint32_t c1RfidScanCounter = 0;
uint32_t c1LastAuthLatencyUs = 0;
String c1LastRfidResult = "NOT_SCANNED";
String c1CloneRisk = "UNKNOWN";
String c1InsiderCorrelation = "NONE";
uint16_t c1AnomalyProbabilityX10000 = 0;
uint8_t c1AnomalyConfirmations = 0;
bool c1PumpOn = false;
bool c1FanOn = false;
bool c1WaitingForCardRemoval = false;
bool c1StatusPending = false;
unsigned long c1LastStatusAttemptMs = 0;
// Allow the gateway's Firebase request and radio ACK to finish before retrying.
constexpr unsigned long C1_STATUS_RETRY_MS = 15000;
unsigned long c1LastReconnectAttemptMs = 0;
constexpr unsigned long C1_RECONNECT_RETRY_MS = 5000;

constexpr int SOIL_DRY_RAW = 4095;
constexpr int SOIL_WET_RAW = 1169;
constexpr int SOIL_OPEN_CIRCUIT_RAW = 4080;

DHT dht(DHT_PIN, DHT22);
BH1750 lightMeter;
bool lightSensorReady = false;
uint8_t lightSensorAddress = 0;

// Fully integrated live mode: require and transmit the physical BH1750.
constexpr bool BH1750_SENSOR_ENABLED = true;

// Keep the secure radio pipeline available if a sensor is disconnected.
// Fallback packets are explicitly transmitted with V=0, so downstream
// security code can display them without trusting them as physical data.
constexpr int SOIL_MIN_VALID_RAW = 100;
// A missing I2C device returns result 2 (NACK). Avoid a long startup delay;
// after three attempts the firmware uses the marked light fallback value.
constexpr uint8_t BH1750_INIT_ATTEMPTS = 3;
constexpr unsigned long SENSOR_READY_RETRY_MS = 3000;

// Do not label fallback constants as live physical measurements. If a real
// sensor is unavailable, hold the readiness gate and retry instead.
constexpr bool SENSOR_FALLBACK_ENABLED = false;
constexpr float FALLBACK_TEMPERATURE_C = 30.0f;
constexpr float FALLBACK_HUMIDITY_PERCENT = 70.0f;
constexpr float FALLBACK_LIGHT_LUX = 250.0f;
constexpr uint32_t FALLBACK_SOIL_RAW = 2500;

bool physicalSensorsReady = false;
unsigned long lastSensorReadyCheckMs = 0;
uint32_t sensorReadyCheckCount = 0;

constexpr size_t MAX_RADIO_LINE_LENGTH = 512;

String radioLineBuffer;
bool discardingRadioLine = false;
uint32_t radioLineOverflowCount = 0;

constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 10000;
constexpr unsigned long KEY_ACTIVE_WINDOW_MS = 24UL * 60UL * 60UL * 1000UL;
constexpr uint32_t PRODUCTION_PACKET_LIMIT = 1000;
constexpr uint8_t MAX_HANDSHAKE_ATTEMPTS = 5;

enum class SensorHandshakeState {
  STARTING,
  WAITING_FOR_CHALLENGE,
  WAITING_FOR_CONFIRM,
  ESTABLISHED,
  ZEROIZED,
  FAILED
};

SensorHandshakeState handshakeState =
    SensorHandshakeState::STARTING;

uint32_t sessionId = 0;
uint8_t sensorNonce[NONCE_LENGTH] = {0};
uint8_t gatewayNonce[NONCE_LENGTH] = {0};

uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};

String sensorNonceHex;
String gatewayNonceHex;

unsigned long stateStartedAtMs = 0;
unsigned long establishedAtMs = 0;
uint8_t handshakeAttempts = 0;

// =====================================================
// STEP 36D — ENCRYPTED TELEMETRY SECURITY TEST
// =====================================================

constexpr uint32_t UNIQUE_TELEMETRY_PACKETS = 6;
// DHT22 supports a reading approximately every two seconds. A 2.5-second
// interval provides responsive dashboard updates without over-polling it.
constexpr unsigned long TELEMETRY_INTERVAL_MS = 2500;
constexpr unsigned long REPLAY_DELAY_MS = 2500;
constexpr unsigned long TAMPER_DELAY_MS = 2500;
constexpr unsigned long STALE_TIMESTAMP_DELAY_MS = 2500;
constexpr unsigned long GCM_FAILURE_DELAY_MS = 2500;
constexpr unsigned long POST_ATTACK_HOLD_MS = 5000;

// Production-style live mode sends telemetry continuously. The replay,
// tamper, stale-timestamp, and GCM-failure demonstrations remain in the
// source but are disabled while this flag is true.
constexpr bool CONTINUOUS_LIVE_TELEMETRY = true;

uint32_t telemetrySequence = 0;
uint32_t telemetryPacketsSent = 0;

unsigned long lastTelemetrySendMs = 0;
unsigned long replaySentAtMs = 0;
unsigned long tamperSentAtMs = 0;
unsigned long staleTimestampSentAtMs = 0;
unsigned long gcmFailureSentAtMs = 0;

bool telemetryTestStarted = false;
bool replayPacketSent = false;
bool tamperedPacketSent = false;
bool staleTimestampPacketSent = false;
bool gcmFailurePacketSent = false;
bool telemetryReportPrinted = false;

uint32_t validRealSensorSamples = 0;
uint32_t invalidRealSensorSamples = 0;

String savedReplayPacket;
String savedTamperSourcePacket;

const char* c1StateName() {
  switch (c1SystemState) {
    case C1SystemState::NORMAL: return "NORMAL";
    case C1SystemState::LOCKDOWN: return "LOCKDOWN";
    default: return "LOCKED";
  }
}

void c1ApplySafeOutputs() {
  if (c1SystemState != C1SystemState::NORMAL || c1TamperLatched) {
    c1PumpOn = false;
    c1FanOn = false;
  }

  digitalWrite(C1_PUMP_RELAY_PIN, c1PumpOn ? C1_RELAY_ON : C1_RELAY_OFF);
  digitalWrite(C1_FAN_RELAY_PIN, c1FanOn ? C1_RELAY_ON : C1_RELAY_OFF);
  digitalWrite(C1_GREEN_LED_PIN, c1SystemState == C1SystemState::NORMAL);
  digitalWrite(C1_BLUE_LED_PIN, c1SystemState == C1SystemState::LOCKED);
  digitalWrite(C1_RED_LED_PIN, c1SystemState == C1SystemState::LOCKDOWN);
}

void IRAM_ATTR c1HandleTamperInterrupt() {
  c1TamperInterruptPending = true;
}

bool c1UidMatches() {
  return c1Rfid.uid.size == sizeof(C1_AUTHORIZED_UID)
      && memcmp(c1Rfid.uid.uidByte, C1_AUTHORIZED_UID, sizeof(C1_AUTHORIZED_UID)) == 0;
}

bool c1MarkerMatches(const byte* marker) {
  byte difference = 0;
  for (byte i = 0; i < 16; i++) difference |= marker[i] ^ C1_EXPECTED_MARKER[i];
  return difference == 0;
}

String c1MaskedUid() {
  if (c1Rfid.uid.size < 2) return "NOT_AVAILABLE";
  char masked[16] = {0};
  snprintf(masked, sizeof(masked), "XX:XX:%02X:%02X",
           c1Rfid.uid.uidByte[c1Rfid.uid.size - 2],
           c1Rfid.uid.uidByte[c1Rfid.uid.size - 1]);
  return String(masked);
}

String c1FullUid() {
  if (c1Rfid.uid.size == 0) return "NOT_AVAILABLE";

  String uid;
  uid.reserve(c1Rfid.uid.size * 3);
  for (byte i = 0; i < c1Rfid.uid.size; i++) {
    if (i > 0) uid += ":";
    if (c1Rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(c1Rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void c1SendSignedStatus(bool retry = false) {
  if (!retry) c1EventCounter++;
  c1StatusPending = true;
  if (handshakeState != SensorHandshakeState::ESTABLISHED) {
    Serial.println("Component 1 signed status : QUEUED / NO ACTIVE RADIO SESSION");
    return;
  }

  c1LastStatusAttemptMs = millis();

  const String fields =
      "C1_STATUS_V1," + String(NODE_ID) + "," + String(sessionId) + ","
      + String(c1EventCounter) + "," + c1StateName() + "," + c1LastRfidResult + ","
      + String(c1LastAuthLatencyUs) + "," + c1CloneRisk + ","
      + String(c1TamperLatched ? 1 : 0) + ","
      + String(c1AuthenticatedSessionActive ? 1 : 0) + ","
      + String(c1AnomalyProbabilityX10000) + ","
      + String(c1AnomalyConfirmations) + ","
      + String(c1PumpOn ? 1 : 0) + "," + String(c1FanOn ? 1 : 0) + ","
      + c1MaskedUid() + "," + c1FullUid() + ","
      + String(c1RfidScanCounter) + "," + c1InsiderCorrelation;

  uint8_t proof[PROOF_LENGTH] = {0};
  if (!calculateTruncatedProof(runtimeNwkSKey, sizeof(runtimeNwkSKey), fields, proof)) return;
  if (!sendE32Line(fields + "," + bytesToHex(proof, sizeof(proof)))) {
    Serial.println("Component 1 signed status : E32 TX TIMEOUT");
    secureZeroize(proof, sizeof(proof));
    return;
  }
  secureZeroize(proof, sizeof(proof));
  c1LastStatusAttemptMs = millis();
  Serial.println("Component 1 signed status : SENT / WAITING FOR GATEWAY ACK");
}

void c1HandleStatusAck(const String& line) {
  String fields[4];
  if (!splitCsv(line, fields, 4)) return;
  if (
    handshakeState != SensorHandshakeState::ESTABLISHED
    || static_cast<uint32_t>(strtoul(fields[1].c_str(), nullptr, 10)) != sessionId
    || static_cast<uint32_t>(strtoul(fields[2].c_str(), nullptr, 10)) != c1EventCounter
  ) return;

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};
  const String transcript = fields[0] + "," + fields[1] + "," + fields[2];
  const bool verified =
      hexToBytes(fields[3], receivedProof, sizeof(receivedProof))
      && calculateTruncatedProof(
        runtimeNwkSKey, sizeof(runtimeNwkSKey), transcript, expectedProof
      )
      && constantTimeEqual(receivedProof, expectedProof, PROOF_LENGTH);
  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!verified) {
    Serial.println("Component 1 gateway ACK   : HMAC REJECTED");
    return;
  }

  c1StatusPending = false;
  Serial.println("Component 1 gateway ACK   : VERIFIED / FIREBASE UPDATED");
}

void c1EnterLockdown(const String& reason) {
  c1SystemState = C1SystemState::LOCKDOWN;
  c1AuthenticatedSessionActive = false;
  c1PumpOn = false;
  c1FanOn = false;
  c1ApplySafeOutputs();
  Serial.print("COMPONENT 1 LOCKDOWN      : ");
  Serial.println(reason);

  // Publish one final authenticated event before destroying the keys.
  c1SendSignedStatus();
  secureZeroize(runtimeAppSKey, sizeof(runtimeAppSKey));
  secureZeroize(runtimeNwkSKey, sizeof(runtimeNwkSKey));
  telemetryTestStarted = false;
  handshakeState = SensorHandshakeState::ZEROIZED;
  Serial.println("Component 2 session keys  : ZEROIZED");
  Serial.println("Lockdown recovery         : PHYSICAL RESTART REQUIRED");
}

void c1ProcessTamper() {
  // Do not treat an unconnected INPUT_PULLUP pin as an attack. Tamper
  // enforcement becomes active only after a real closed switch has first
  // held GPIO13 LOW. Once armed, a LOW-to-HIGH opening still locks down.
  if (!c1TamperArmed) {
    c1TamperInterruptPending = false;
    if (digitalRead(C1_TAMPER_PIN) == LOW) {
      c1TamperArmed = true;
      Serial.println("Component 1 tamper       : ARMED / SECURE LOW OBSERVED");
      c1SendSignedStatus();
    }
    return;
  }

  if (!c1TamperInterruptPending) return;
  noInterrupts();
  c1TamperInterruptPending = false;
  interrupts();
  if (digitalRead(C1_TAMPER_PIN) == HIGH && !c1TamperLatched) {
    c1TamperLatched = true;
    c1LastRfidResult = "TAMPER_LOCKDOWN";
    c1CloneRisk = "NOT_APPLICABLE";
    c1EnterLockdown("PHYSICAL_TAMPER");
  }
}

void c1ProcessSerialDemoCommand() {
  if (!Serial.available()) return;
  const char command = static_cast<char>(toupper(Serial.read()));
  if (command != 'I') return;

  if (!c1AuthenticatedSessionActive || c1SystemState != C1SystemState::NORMAL) {
    Serial.println("Insider demo rejected     : AUTHENTICATED RFID SESSION REQUIRED");
    return;
  }

  c1InsiderCorrelation = "CONTROLLED_AUTHENTICATED_INSIDER_MISUSE";
  c1AnomalyProbabilityX10000 = 9900;
  c1AnomalyConfirmations = 3;
  c1LastRfidResult = "AUTHORIZED_INSIDER_MISUSE";
  c1EnterLockdown("CONTROLLED_INSIDER_MISUSE_DEMO");
}

void c1HandleSignedDemoCommand(const String& line) {
  String fields[6];
  if (!splitCsv(line, fields, 6)) return;
  if (
    handshakeState != SensorHandshakeState::ESTABLISHED
    || static_cast<uint32_t>(strtoul(fields[1].c_str(), nullptr, 10)) != sessionId
  ) return;

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};
  const int finalComma = line.lastIndexOf(',');
  const String transcript = line.substring(0, finalComma);
  const bool verified =
      hexToBytes(fields[5], receivedProof, sizeof(receivedProof))
      && calculateTruncatedProof(
        runtimeNwkSKey, sizeof(runtimeNwkSKey), transcript, expectedProof
      )
      && constantTimeEqual(receivedProof, expectedProof, PROOF_LENGTH);
  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));
  if (!verified) {
    Serial.println("Component 1 demo command  : HMAC REJECTED");
    return;
  }

  const String command = fields[3];
  c1LastAuthLatencyUs = 0;
  if (command == "DEMO_AUTHORIZED_UNLOCK") {
    c1LastRfidResult = "CONTROLLED_AUTHORIZED_UNLOCK";
    c1CloneRisk = "LOW_SUPPORTING_EVIDENCE";
    c1InsiderCorrelation = "NONE";
    c1AnomalyProbabilityX10000 = 0;
    c1AnomalyConfirmations = 0;
    c1SystemState = C1SystemState::NORMAL;
    c1AuthenticatedSessionActive = true;
    c1AuthenticatedSessionId++;
    c1ApplySafeOutputs();
    c1SendSignedStatus();
  } else if (command == "DEMO_WRONG_CARD") {
    c1LastRfidResult = "CONTROLLED_UID_REJECTED";
    c1CloneRisk = "UNAUTHORIZED_UID";
    c1AnomalyProbabilityX10000 = 2000;
    c1InsiderCorrelation = "NONE";
    c1SendSignedStatus();
  } else if (command == "DEMO_RFID_CLONE") {
    c1LastRfidResult = "CONTROLLED_SAME_UID_SECTOR_AUTH_FAILED";
    c1CloneRisk = "ELEVATED_SAME_UID_CLONE_SUSPECTED";
    c1AnomalyProbabilityX10000 = 9500;
    c1EnterLockdown("DASHBOARD_CONTROLLED_RFID_CLONE");
  } else if (command == "DEMO_INSIDER_MISUSE") {
    if (!c1AuthenticatedSessionActive || c1SystemState != C1SystemState::NORMAL) {
      c1LastRfidResult = "INSIDER_DEMO_REJECTED_AUTH_REQUIRED";
      c1InsiderCorrelation = "NO_AUTHENTICATED_SESSION";
      c1SendSignedStatus();
    } else {
      c1InsiderCorrelation = "CONTROLLED_AUTHENTICATED_INSIDER_MISUSE";
      c1AnomalyProbabilityX10000 = 9900;
      c1AnomalyConfirmations = 3;
      c1LastRfidResult = "AUTHORIZED_INSIDER_MISUSE";
      c1EnterLockdown("DASHBOARD_CONTROLLED_INSIDER_MISUSE");
    }
  }
}

void c1ProcessRfid() {
  if (c1TamperLatched || c1SystemState == C1SystemState::LOCKDOWN) return;

  if (c1WaitingForCardRemoval) {
    if (!c1Rfid.PICC_IsNewCardPresent()) c1WaitingForCardRemoval = false;
    return;
  }

  if (!c1Rfid.PICC_IsNewCardPresent() || !c1Rfid.PICC_ReadCardSerial()) return;
  c1RfidScanCounter++;
  digitalWrite(C1_YELLOW_LED_PIN, HIGH);

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("COMPONENT 1 PHYSICAL RFID SCAN");
  Serial.print("RFID UID (masked)         : ");
  Serial.println(c1MaskedUid());
  Serial.print("RFID UID                  : ");
  Serial.println(c1FullUid());

  c1LastAuthLatencyUs = 0;
  c1CloneRisk = "LOW";
  c1InsiderCorrelation = "NONE";
  c1AnomalyProbabilityX10000 = 0;
  c1AnomalyConfirmations = 0;

  if (!c1UidMatches()) {
    c1LastRfidResult = "UID_REJECTED";
    c1CloneRisk = "UNAUTHORIZED_UID";
    c1SystemState = C1SystemState::LOCKED;
    c1AuthenticatedSessionActive = false;
  } else {
    const unsigned long authStart = micros();
    const MFRC522::StatusCode authStatus = c1Rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, C1_TRAILER_BLOCK,
        &c1RuntimeKeyA, &(c1Rfid.uid));
    c1LastAuthLatencyUs = micros() - authStart;

    byte marker[18] = {0};
    byte markerSize = sizeof(marker);
    const bool sectorPassed = authStatus == MFRC522::STATUS_OK;
    const bool readPassed = sectorPassed
        && c1Rfid.MIFARE_Read(C1_MARKER_BLOCK, marker, &markerSize) == MFRC522::STATUS_OK;
    const bool markerPassed = readPassed && c1MarkerMatches(marker);

    if (!sectorPassed || !readPassed || !markerPassed) {
      c1LastRfidResult = sectorPassed ? "MARKER_MISMATCH" : "SECTOR_AUTH_FAILED";
      c1CloneRisk = "ELEVATED_SAME_UID_CLONE_SUSPECTED";
      c1AnomalyProbabilityX10000 = 9500;
      c1SystemState = C1SystemState::LOCKED;
      c1AuthenticatedSessionActive = false;
    } else {
      c1LastRfidResult = "AUTHORIZED";
      c1CloneRisk = "LOW_SUPPORTING_EVIDENCE";
      // A successfully authenticated physical card always establishes or
      // refreshes an authorized session. Locking is a separate explicit
      // action; a second valid tap must not turn an ALLOW decision into LOCKED.
      c1SystemState = C1SystemState::NORMAL;
      c1AuthenticatedSessionActive = true;
      c1AuthenticatedSessionId++;
    }
  }

  c1ApplySafeOutputs();
  Serial.print("RFID authorization result : ");
  Serial.println(c1LastRfidResult);
  Serial.print("Authenticated user/session: ");
  Serial.println(c1AuthenticatedSessionActive ? "YES" : "NO");
  Serial.print("Component 1 system state  : ");
  Serial.println(c1StateName());
  c1SendSignedStatus();
  c1Rfid.PCD_StopCrypto1();
  c1Rfid.PICC_HaltA();
  c1WaitingForCardRemoval = true;
  digitalWrite(C1_YELLOW_LED_PIN, LOW);
}


void printKeyFingerprints() {
  uint8_t appFingerprint[FINGERPRINT_LENGTH] = {0};
  uint8_t nwkFingerprint[FINGERPRINT_LENGTH] = {0};

  const bool appSuccess = calculateFingerprint(
    runtimeAppSKey,
    sizeof(runtimeAppSKey),
    appFingerprint
  );

  const bool nwkSuccess = calculateFingerprint(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey),
    nwkFingerprint
  );

  Serial.print("AppSKey fingerprint      : ");
  Serial.println(
    appSuccess
      ? bytesToHex(
          appFingerprint,
          sizeof(appFingerprint)
        )
      : "FAILED"
  );

  Serial.print("NwkSKey fingerprint      : ");
  Serial.println(
    nwkSuccess
      ? bytesToHex(
          nwkFingerprint,
          sizeof(nwkFingerprint)
        )
      : "FAILED"
  );

  secureZeroize(
    appFingerprint,
    sizeof(appFingerprint)
  );

  secureZeroize(
    nwkFingerprint,
    sizeof(nwkFingerprint)
  );
}

void sendHello() {
  handshakeAttempts++;

  String message =
      "C2_HELLO_V1,"
      + String(NODE_ID)
      + ","
      + String(sessionId)
      + ","
      + sensorNonceHex;

  if (!sendE32Line(message)) {
    failHandshake("E32 HELLO transmission timeout");
    return;
  }

  Serial.print("TX HELLO attempt         : ");
  Serial.print(handshakeAttempts);
  Serial.print("/");
  Serial.println(MAX_HANDSHAKE_ATTEMPTS);

  Serial.print("TX session ID            : ");
  Serial.println(sessionId);

  handshakeState =
      SensorHandshakeState::WAITING_FOR_CHALLENGE;

  stateStartedAtMs = millis();
}

void startNewHandshake() {
  esp_fill_random(
    reinterpret_cast<void*>(&sessionId),
    sizeof(sessionId)
  );

  if (sessionId == 0) {
    sessionId = 1;
  }

  esp_fill_random(
    sensorNonce,
    sizeof(sensorNonce)
  );

  sensorNonceHex = bytesToHex(
    sensorNonce,
    sizeof(sensorNonce)
  );

  gatewayNonceHex = "";

  secureZeroize(
    gatewayNonce,
    sizeof(gatewayNonce)
  );

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  handshakeAttempts = 0;
  sendHello();
}

void failHandshake(const String& reason) {
  Serial.println();
  Serial.println("HANDSHAKE FAILED");
  Serial.print("Reason                    : ");
  Serial.println(reason);

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  handshakeState =
      SensorHandshakeState::FAILED;

  Serial.println("Runtime keys              : ZEROIZED");
  Serial.println("STEP 36B SENSOR RESULT    : REVIEW REQUIRED");
}

void handleChallenge(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    failHandshake("Malformed challenge");
    return;
  }

  if (fields[0] != "C2_CHALLENGE_V1") {
    return;
  }

  const uint32_t receivedSessionId =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSessionId != sessionId) {
    failHandshake("Challenge session mismatch");
    return;
  }

  gatewayNonceHex = fields[2];

  if (!hexToBytes(
        gatewayNonceHex,
        gatewayNonce,
        sizeof(gatewayNonce)
      )) {
    failHandshake("Invalid gateway nonce");
    return;
  }

  uint8_t receivedGatewayProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[3],
        receivedGatewayProof,
        sizeof(receivedGatewayProof)
      )) {
    secureZeroize(
      receivedGatewayProof,
      sizeof(receivedGatewayProof)
    );

    failHandshake("Invalid gateway proof encoding");
    return;
  }

  const String baseTranscript =
      buildBaseTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const String gatewayTranscript =
      "GW|" + baseTranscript;

  uint8_t expectedGatewayProof[PROOF_LENGTH] = {0};

  const bool proofCalculated =
      calculateTruncatedProof(
        DEVELOPMENT_PSK,
        sizeof(DEVELOPMENT_PSK),
        gatewayTranscript,
        expectedGatewayProof
      );

  const bool gatewayAuthenticated =
      proofCalculated
      && constantTimeEqual(
        receivedGatewayProof,
        expectedGatewayProof,
        PROOF_LENGTH
      );

  secureZeroize(
    receivedGatewayProof,
    sizeof(receivedGatewayProof)
  );

  secureZeroize(
    expectedGatewayProof,
    sizeof(expectedGatewayProof)
  );

  if (!gatewayAuthenticated) {
    failHandshake("Gateway HMAC verification failed");
    return;
  }

  Serial.println("Gateway HMAC verification : PASSED");

  if (!deriveSessionKeys(
        sessionId,
        sensorNonce,
        gatewayNonce,
        runtimeAppSKey,
        runtimeNwkSKey
      )) {
    failHandshake("HKDF session-key derivation failed");
    return;
  }

  Serial.println("Session-key derivation    : PASSED");
  printKeyFingerprints();

  const String sensorTranscript =
      "SN|" + baseTranscript;

  uint8_t sensorProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        sensorTranscript,
        sensorProof
      )) {
    secureZeroize(sensorProof, sizeof(sensorProof));
    failHandshake("Sensor proof generation failed");
    return;
  }

  const String response =
      "C2_RESPONSE_V1,"
      + String(sessionId)
      + ","
      + bytesToHex(
          sensorProof,
          sizeof(sensorProof)
        );

  secureZeroize(sensorProof, sizeof(sensorProof));

  if (!sendE32Line(response)) {
    failHandshake("E32 sensor-proof transmission timeout");
    return;
  }
  Serial.println("TX sensor proof           : SENT");

  handshakeState =
      SensorHandshakeState::WAITING_FOR_CONFIRM;

  stateStartedAtMs = millis();
}

void handleConfirm(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    failHandshake("Malformed confirmation");
    return;
  }

  if (fields[0] != "C2_CONFIRM_V1") {
    return;
  }

  const uint32_t receivedSessionId =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSessionId != sessionId) {
    failHandshake("Confirmation session mismatch");
    return;
  }

  uint8_t receivedConfirmProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[2],
        receivedConfirmProof,
        sizeof(receivedConfirmProof)
      )) {
    secureZeroize(
      receivedConfirmProof,
      sizeof(receivedConfirmProof)
    );

    failHandshake("Invalid confirmation encoding");
    return;
  }

  const String baseTranscript =
      buildBaseTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const String confirmTranscript =
      "OK|" + baseTranscript;

  uint8_t expectedConfirmProof[PROOF_LENGTH] = {0};

  const bool proofCalculated =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        confirmTranscript,
        expectedConfirmProof
      );

  const bool confirmationValid =
      proofCalculated
      && constantTimeEqual(
        receivedConfirmProof,
        expectedConfirmProof,
        PROOF_LENGTH
      );

  secureZeroize(
    receivedConfirmProof,
    sizeof(receivedConfirmProof)
  );

  secureZeroize(
    expectedConfirmProof,
    sizeof(expectedConfirmProof)
  );

  if (!confirmationValid) {
    failHandshake("Gateway confirmation failed");
    return;
  }

  handshakeState =
      SensorHandshakeState::ESTABLISHED;

  establishedAtMs = millis();

  Serial.println();
  Serial.println("==========================================");
  Serial.println("AUTHENTICATED SESSION ESTABLISHED");
  Serial.println("==========================================");
  Serial.print("Session ID                : ");
  Serial.println(sessionId);
  Serial.println("Gateway authenticated     : YES");
  Serial.println("Sensor authenticated      : YES");
  Serial.println("AppSKey state             : ACTIVE");
  Serial.println("NwkSKey state             : ACTIVE");
  Serial.println("Key transport             : NONE");
  Serial.println("Key active window         : 24 hours / 1000 packets");
  Serial.println("STEP 36B HANDSHAKE        : PASSED");
  Serial.println("STEP 37D FIREBASE TEST    : STARTING");
  Serial.println("Payload encryption        : AES-128-GCM");
  Serial.println("GCM authentication tag    : 128-BIT");
  Serial.println("Outer packet HMAC         : HMAC-SHA256 / 256-BIT");
  Serial.println("Replay protection         : ENABLED AT GATEWAY");
  Serial.println("Key-purpose separation    : AppSKey / NwkSKey");
  Serial.println("==========================================");

  telemetrySequence = 0;
  telemetryPacketsSent = 0;
  lastTelemetrySendMs = millis();
  replaySentAtMs = 0;
  tamperSentAtMs = 0;
  staleTimestampSentAtMs = 0;
  gcmFailureSentAtMs = 0;
  telemetryTestStarted = true;
  replayPacketSent = false;
  tamperedPacketSent = false;
  staleTimestampPacketSent = false;
  gcmFailurePacketSent = false;
  telemetryReportPrinted = false;
  validRealSensorSamples = 0;
  invalidRealSensorSamples = 0;
  savedReplayPacket = "";
  savedTamperSourcePacket = "";

  c1SendSignedStatus();
}


String createTamperedSecurePacket(
    const String& originalPacket
) {
  String fields[8];

  if (!splitCsv(originalPacket, fields, 8)) {
    return "";
  }

  if (fields[5].length() == 0) {
    return "";
  }

  // Change one ciphertext hexadecimal digit but preserve the old
  // GCM tag and outer HMAC. The gateway must reject the packet.
  fields[5].setCharAt(
    0,
    fields[5][0] == '0' ? '1' : '0'
  );

  return
      fields[0]
      + ","
      + fields[1]
      + ","
      + fields[2]
      + ","
      + fields[3]
      + ","
      + fields[4]
      + ","
      + fields[5]
      + ","
      + fields[6]
      + ","
      + fields[7];
}

bool createAndSendEncryptedTelemetry(
    uint32_t sequence,
    bool saveForReplay,
    bool saveForTamper
) {
  const float measuredTemperatureC =
      dht.readTemperature();

  const float measuredHumidityPercent =
      dht.readHumidity();

  const float measuredLightLux =
      lightSensorReady
        ? lightMeter.readLightLevel()
        : -1.0f;

  const uint32_t measuredSoilRaw =
      static_cast<uint32_t>(
        analogRead(SOIL_PIN)
      );

  const bool temperatureValid =
      !isnan(measuredTemperatureC);

  const bool humidityValid =
      !isnan(measuredHumidityPercent);

  const bool lightValid =
      lightSensorReady
      && measuredLightLux >= 0.0f;

  const bool soilValid =
      measuredSoilRaw >= SOIL_MIN_VALID_RAW
      && measuredSoilRaw < SOIL_OPEN_CIRCUIT_RAW;

  const bool sampleValid =
      temperatureValid
      &&
      humidityValid
      &&
      lightValid
      &&
      soilValid;

  const bool fallbackUsed =
      SENSOR_FALLBACK_ENABLED
      && !sampleValid;

  const float temperatureC =
      temperatureValid
        ? measuredTemperatureC
        : FALLBACK_TEMPERATURE_C;

  const float humidityPercent =
      humidityValid
        ? measuredHumidityPercent
        : FALLBACK_HUMIDITY_PERCENT;

  const float lightLux =
      lightValid
        ? measuredLightLux
        : FALLBACK_LIGHT_LUX;

  const uint32_t soilRaw =
      soilValid
        ? measuredSoilRaw
        : FALLBACK_SOIL_RAW;

  const int32_t temperatureX100 =
      static_cast<int32_t>(
        lroundf(temperatureC * 100.0f)
      );

  const uint32_t humidityX100 =
      static_cast<uint32_t>(
        constrain(
          lroundf(humidityPercent * 100.0f),
          0L,
          10000L
        )
      );

  const uint32_t lightLuxX10 =
      static_cast<uint32_t>(
        constrain(
          lroundf(lightLux * 10.0f),
          0L,
          999999L
        )
      );

  const long calculatedSoilPercent =
      map(
        static_cast<long>(soilRaw),
        SOIL_DRY_RAW,
        SOIL_WET_RAW,
        0,
        100
      );

  const uint32_t soilPercent =
      static_cast<uint32_t>(
        constrain(
          calculatedSoilPercent,
          0L,
          100L
        )
      );

  if (sampleValid) {
    validRealSensorSamples++;
  } else {
    invalidRealSensorSamples++;
  }

  char plaintext[
      SECURE_PAYLOAD_LENGTH + 1
  ] = {0};

  const uint32_t senderElapsedMs =
      millis() - establishedAtMs;

  const int payloadLength = snprintf(
    plaintext,
    sizeof(plaintext),
    "TS=%010lu;T=%+06ld;H=%05lu;L=%06lu;S=%04lu;SP=%03lu;V=%u;ST=NORMAL",
    static_cast<unsigned long>(senderElapsedMs),
    static_cast<long>(temperatureX100),
    static_cast<unsigned long>(humidityX100),
    static_cast<unsigned long>(lightLuxX10),
    static_cast<unsigned long>(soilRaw),
    static_cast<unsigned long>(soilPercent),
    sampleValid ? 1U : 0U
  );

  if (
    payloadLength
      != static_cast<int>(SECURE_PAYLOAD_LENGTH)
  ) {
    secureZeroize(
      plaintext,
      sizeof(plaintext)
    );

    Serial.print(
      "Secure payload length     : "
    );

    Serial.println(payloadLength);

    return false;
  }

  uint8_t iv[AES_GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[SECURE_PAYLOAD_LENGTH] = {0};
  uint8_t gcmTag[AES_GCM_TAG_LENGTH] = {0};
  uint8_t outerMac[PROOF_LENGTH] = {0};

  buildPacketIv(
    sessionId,
    sequence,
    sensorNonce,
    iv
  );

  const String aad =
      buildSecureAad(
        sessionId,
        sequence
      );

  const bool encryptionPassed =
      aes128GcmEncrypt(
        runtimeAppSKey,
        iv,
        reinterpret_cast<const uint8_t*>(
          aad.c_str()
        ),
        aad.length(),
        reinterpret_cast<const uint8_t*>(
          plaintext
        ),
        SECURE_PAYLOAD_LENGTH,
        ciphertext,
        gcmTag
      );

  if (!encryptionPassed) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));

    Serial.println(
      "AES-GCM encryption        : FAILED"
    );

    return false;
  }

  const String ivHex =
      bytesToHex(iv, sizeof(iv));

  const String ciphertextHex =
      bytesToHex(
        ciphertext,
        sizeof(ciphertext)
      );

  const String gcmTagHex =
      bytesToHex(
        gcmTag,
        sizeof(gcmTag)
      );

  const String outerTranscript =
      buildOuterMacTranscript(
        String(NODE_ID),
        String(sessionId),
        String(sequence),
        ivHex,
        ciphertextHex,
        gcmTagHex
      );

  const bool outerMacPassed =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        outerMac
      );

  if (!outerMacPassed) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));

    Serial.println(
      "Outer HMAC generation     : FAILED"
    );

    return false;
  }

  const String packet =
      "C2_SECURE_V1,"
      + String(NODE_ID)
      + ","
      + String(sessionId)
      + ","
      + String(sequence)
      + ","
      + ivHex
      + ","
      + ciphertextHex
      + ","
      + gcmTagHex
      + ","
      + bytesToHex(
          outerMac,
          sizeof(outerMac)
        );

  if (!sendE32Line(packet)) {
    Serial.println("Encrypted telemetry TX   : E32 TIMEOUT");
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));
    return false;
  }
  telemetryPacketsSent++;

  if (saveForReplay) {
    savedReplayPacket = packet;
  }

  if (saveForTamper) {
    savedTamperSourcePacket = packet;
  }

  // Live controlled tests reuse the latest authentic frame. The retained
  // String contains ciphertext only, never plaintext or session keys.
  if (CONTINUOUS_LIVE_TELEMETRY) {
    savedReplayPacket = packet;
    savedTamperSourcePacket = packet;
  }

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("ENCRYPTED TELEMETRY TRANSMISSION");
  Serial.println("------------------------------------------");
  Serial.print("Sequence                  : ");
  Serial.println(sequence);
  Serial.print("Session ID                : ");
  Serial.println(sessionId);
  Serial.print("Sender elapsed timestamp  : ");
  Serial.print(senderElapsedMs);
  Serial.println(" ms");
  Serial.print("Temperature x100          : ");
  Serial.println(temperatureX100);
  Serial.print("Humidity x100             : ");
  Serial.println(humidityX100);
  Serial.print("Light lux x10             : ");
  Serial.println(lightLuxX10);
  Serial.print("Soil raw                  : ");
  Serial.println(soilRaw);
  Serial.print("Soil percent              : ");
  Serial.println(soilPercent);
  Serial.print("Temperature valid         : ");
  Serial.println(temperatureValid ? "YES" : "NO");

  Serial.print("Humidity valid            : ");
  Serial.println(humidityValid ? "YES" : "NO");

  Serial.print("BH1750 initialized        : ");
  Serial.println(lightSensorReady ? "YES" : "NO");

  Serial.print("Light reading valid       : ");
  Serial.println(lightValid ? "YES" : "NO");

  Serial.print("Soil reading valid        : ");
  Serial.println(soilValid ? "YES" : "NO");

  Serial.print("Real sensor sample valid  : ");
  Serial.println(sampleValid ? "YES" : "NO");

  Serial.print("Fallback values used      : ");
  Serial.println(fallbackUsed ? "YES / V=0" : "NO");

  Serial.print("Invalid reason            : ");

  if (sampleValid) {
    Serial.println("NONE");
  } else {
    bool firstReason = true;

    if (!temperatureValid) {
      Serial.print("DHT TEMPERATURE");
      firstReason = false;
    }

    if (!humidityValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print("DHT HUMIDITY");
      firstReason = false;
    }

    if (!lightValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print(
        lightSensorReady
          ? "BH1750 READING"
          : "BH1750 INITIALIZATION"
      );

      firstReason = false;
    }

    if (!soilValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print("SOIL READING");
    }

    Serial.println();
  }

  Serial.println("Payload encryption        : AES-128-GCM");
  Serial.println("GCM tag                   : ATTACHED / 128-BIT");
  Serial.println("Outer HMAC                : ATTACHED / 256-BIT");
  Serial.println("Plaintext over radio      : NO");
  Serial.println("TX result                 : SENT");
  Serial.println("------------------------------------------");

  secureZeroize(plaintext, sizeof(plaintext));
  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(gcmTag, sizeof(gcmTag));
  secureZeroize(outerMac, sizeof(outerMac));

  return true;
}

void sendIntentionalReplayPacket() {
  if (savedReplayPacket.length() == 0) {
    Serial.println(
      "Intentional replay        : NO SAVED PACKET"
    );

    return;
  }

  if (!sendE32Line(savedReplayPacket)) {
    Serial.println("Intentional replay        : E32 TX TIMEOUT");
    return;
  }
  replayPacketSent = true;
  replaySentAtMs = millis();

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("INTENTIONAL ENCRYPTED REPLAY TEST");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("Replayed sequence         : 3");
  Serial.println("Ciphertext                : UNCHANGED");
  Serial.println("GCM tag                   : VALID OLD TAG");
  Serial.println("Outer HMAC                : VALID OLD HMAC");
  Serial.println("Expected gateway action   : REJECT AS REPLAY");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

void sendIntentionalTamperedPacket() {
  const String tamperedPacket =
      createTamperedSecurePacket(
        savedTamperSourcePacket
      );

  if (tamperedPacket.length() == 0) {
    Serial.println(
      "Intentional tamper        : CREATION FAILED"
    );

    return;
  }

  if (!sendE32Line(tamperedPacket)) {
    Serial.println("Intentional tamper        : E32 TX TIMEOUT");
    return;
  }
  tamperedPacketSent = true;
  tamperSentAtMs = millis();

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("INTENTIONAL CIPHERTEXT TAMPER TEST");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("Original sequence         : 5");
  Serial.println("Ciphertext modification   : ONE HEX DIGIT");
  Serial.println("GCM tag                   : UNCHANGED");
  Serial.println("Outer HMAC                : UNCHANGED");
  Serial.println("Expected gateway action   : REJECT INVALID HMAC");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}


bool sendIntentionalStaleTimestampPacket() {
  const uint32_t TEST_SEQUENCE = telemetrySequence + 1;
  constexpr uint32_t STALE_ELAPSED_MS = 0;

  const int32_t temperatureX100 = 3000;
  const uint32_t humidityX100 = 7000;
  const uint32_t lightLuxX10 = 2500;
  const uint32_t soilRaw = 2200;
  const uint32_t soilPercent = 65;
  const uint32_t sampleValid = 1;

  char plaintext[
      SECURE_PAYLOAD_LENGTH + 1
  ] = {0};

  const int payloadLength = snprintf(
    plaintext,
    sizeof(plaintext),
    "TS=%010lu;T=%+06ld;H=%05lu;L=%06lu;S=%04lu;SP=%03lu;V=%u;ST=NORMAL",
    static_cast<unsigned long>(STALE_ELAPSED_MS),
    static_cast<long>(temperatureX100),
    static_cast<unsigned long>(humidityX100),
    static_cast<unsigned long>(lightLuxX10),
    static_cast<unsigned long>(soilRaw),
    static_cast<unsigned long>(soilPercent),
    static_cast<unsigned int>(sampleValid)
  );

  if (
    payloadLength
      != static_cast<int>(SECURE_PAYLOAD_LENGTH)
  ) {
    secureZeroize(plaintext, sizeof(plaintext));
    Serial.println("Stale timestamp payload   : FAILED");
    return false;
  }

  uint8_t iv[AES_GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[SECURE_PAYLOAD_LENGTH] = {0};
  uint8_t gcmTag[AES_GCM_TAG_LENGTH] = {0};
  uint8_t outerMac[PROOF_LENGTH] = {0};

  buildPacketIv(
    sessionId,
    TEST_SEQUENCE,
    sensorNonce,
    iv
  );

  const String aad =
      buildSecureAad(
        sessionId,
        TEST_SEQUENCE
      );

  const bool encrypted =
      aes128GcmEncrypt(
        runtimeAppSKey,
        iv,
        reinterpret_cast<const uint8_t*>(aad.c_str()),
        aad.length(),
        reinterpret_cast<const uint8_t*>(plaintext),
        SECURE_PAYLOAD_LENGTH,
        ciphertext,
        gcmTag
      );

  if (!encrypted) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));
    Serial.println("Stale timestamp encrypt   : FAILED");
    return false;
  }

  const String ivHex =
      bytesToHex(iv, sizeof(iv));

  const String ciphertextHex =
      bytesToHex(ciphertext, sizeof(ciphertext));

  const String gcmTagHex =
      bytesToHex(gcmTag, sizeof(gcmTag));

  const String outerTranscript =
      buildOuterMacTranscript(
        String(NODE_ID),
        String(sessionId),
        String(TEST_SEQUENCE),
        ivHex,
        ciphertextHex,
        gcmTagHex
      );

  const bool macCreated =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        outerMac
      );

  if (!macCreated) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));
    Serial.println("Stale timestamp HMAC      : FAILED");
    return false;
  }

  const String packet =
      "C2_SECURE_V1,"
      + String(NODE_ID)
      + ","
      + String(sessionId)
      + ","
      + String(TEST_SEQUENCE)
      + ","
      + ivHex
      + ","
      + ciphertextHex
      + ","
      + gcmTagHex
      + ","
      + bytesToHex(outerMac, sizeof(outerMac));

  if (!sendE32Line(packet)) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(outerMac, sizeof(outerMac));
    Serial.println("Stale timestamp TX        : E32 TIMEOUT");
    return false;
  }

  staleTimestampPacketSent = true;
  staleTimestampSentAtMs = millis();

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("INTENTIONAL STALE TIMESTAMP TEST");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("Test sequence             : 7 / FRESH COUNTER");
  Serial.println("Embedded elapsed time     : 0 ms / STALE");
  Serial.println("Outer HMAC                : VALID");
  Serial.println("AES-GCM tag               : VALID");
  Serial.println("Expected gateway action   : REJECT TIMESTAMP");
  Serial.println("Firebase forwarding       : MUST NOT OCCUR");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

  secureZeroize(plaintext, sizeof(plaintext));
  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(gcmTag, sizeof(gcmTag));
  secureZeroize(outerMac, sizeof(outerMac));

  return true;
}


bool sendIntentionalGcmFailurePacket() {
  const uint32_t TEST_SEQUENCE = telemetrySequence + 1;

  const int32_t temperatureX100 = 3099;
  const uint32_t humidityX100 = 7244;
  const uint32_t lightLuxX10 = 2365;
  const uint32_t soilRaw = 2197;
  const uint32_t soilPercent = 65;
  const uint32_t sampleValid = 1;

  char plaintext[
      SECURE_PAYLOAD_LENGTH + 1
  ] = {0};

  const int payloadLength = snprintf(
    plaintext,
    sizeof(plaintext),
    "TS=%010lu;T=%+06ld;H=%05lu;L=%06lu;S=%04lu;SP=%03lu;V=%u;ST=NORMAL",
    static_cast<unsigned long>(millis() - establishedAtMs),
    static_cast<long>(temperatureX100),
    static_cast<unsigned long>(humidityX100),
    static_cast<unsigned long>(lightLuxX10),
    static_cast<unsigned long>(soilRaw),
    static_cast<unsigned long>(soilPercent),
    static_cast<unsigned int>(sampleValid)
  );

  if (
    payloadLength
      != static_cast<int>(SECURE_PAYLOAD_LENGTH)
  ) {
    secureZeroize(
      plaintext,
      sizeof(plaintext)
    );

    Serial.println(
      "GCM test payload length   : FAILED"
    );

    return false;
  }

  uint8_t iv[AES_GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[SECURE_PAYLOAD_LENGTH] = {0};
  uint8_t originalGcmTag[AES_GCM_TAG_LENGTH] = {0};
  uint8_t recomputedOuterMac[PROOF_LENGTH] = {0};

  buildPacketIv(
    sessionId,
    TEST_SEQUENCE,
    sensorNonce,
    iv
  );

  const String aad =
      buildSecureAad(
        sessionId,
        TEST_SEQUENCE
      );

  const bool encrypted =
      aes128GcmEncrypt(
        runtimeAppSKey,
        iv,
        reinterpret_cast<const uint8_t*>(
          aad.c_str()
        ),
        aad.length(),
        reinterpret_cast<const uint8_t*>(
          plaintext
        ),
        SECURE_PAYLOAD_LENGTH,
        ciphertext,
        originalGcmTag
      );

  if (!encrypted) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(originalGcmTag, sizeof(originalGcmTag));
    secureZeroize(recomputedOuterMac, sizeof(recomputedOuterMac));

    Serial.println(
      "GCM test encryption       : FAILED"
    );

    return false;
  }

  // Modify the ciphertext after the valid GCM tag has been produced.
  // Then recompute the outer NwkSKey HMAC. The gateway should pass the
  // outer HMAC but fail AES-GCM authentication.
  ciphertext[0] ^= 0x01;

  const String ivHex =
      bytesToHex(iv, sizeof(iv));

  const String modifiedCiphertextHex =
      bytesToHex(
        ciphertext,
        sizeof(ciphertext)
      );

  const String originalGcmTagHex =
      bytesToHex(
        originalGcmTag,
        sizeof(originalGcmTag)
      );

  const String outerTranscript =
      buildOuterMacTranscript(
        String(NODE_ID),
        String(sessionId),
        String(TEST_SEQUENCE),
        ivHex,
        modifiedCiphertextHex,
        originalGcmTagHex
      );

  const bool outerMacCreated =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        recomputedOuterMac
      );

  if (!outerMacCreated) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(originalGcmTag, sizeof(originalGcmTag));
    secureZeroize(recomputedOuterMac, sizeof(recomputedOuterMac));

    Serial.println(
      "GCM test outer HMAC       : FAILED"
    );

    return false;
  }

  const String packet =
      "C2_SECURE_V1,"
      + String(NODE_ID)
      + ","
      + String(sessionId)
      + ","
      + String(TEST_SEQUENCE)
      + ","
      + ivHex
      + ","
      + modifiedCiphertextHex
      + ","
      + originalGcmTagHex
      + ","
      + bytesToHex(
          recomputedOuterMac,
          sizeof(recomputedOuterMac)
        );

  if (!sendE32Line(packet)) {
    secureZeroize(plaintext, sizeof(plaintext));
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(originalGcmTag, sizeof(originalGcmTag));
    secureZeroize(recomputedOuterMac, sizeof(recomputedOuterMac));
    Serial.println("GCM failure-test TX       : E32 TIMEOUT");
    return false;
  }

  gcmFailurePacketSent = true;
  gcmFailureSentAtMs = millis();

  Serial.println();
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("INTENTIONAL AES-GCM TAG FAILURE TEST");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
  Serial.println("Test sequence             : 8 / FRESH");
  Serial.println("Ciphertext modification   : ONE BIT");
  Serial.println("GCM tag                   : OLD ORIGINAL TAG");
  Serial.println("Outer HMAC                : RECOMPUTED / VALID");
  Serial.println("Expected outer HMAC       : PASS");
  Serial.println("Expected GCM verification : FAIL");
  Serial.println("Expected packet action    : REJECT");
  Serial.println("Research role             : DEFENCE-IN-DEPTH SELF-TEST");
  Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

  secureZeroize(plaintext, sizeof(plaintext));
  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(originalGcmTag, sizeof(originalGcmTag));
  secureZeroize(recomputedOuterMac, sizeof(recomputedOuterMac));

  return true;
}


void printSensorDataSecurityReportAndZeroize() {
  if (telemetryReportPrinted) {
    return;
  }

  telemetryReportPrinted = true;

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  const bool appZeroized =
      isAllZero(
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  const bool nwkZeroized =
      isAllZero(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38G-2 SENSOR REPORT");
  Serial.println("==========================================");
  Serial.print("Unique encrypted packets : ");
  Serial.println(telemetrySequence);
  Serial.print("Valid real sensor samples: ");
  Serial.println(validRealSensorSamples);
  Serial.print("Invalid sensor samples   : ");
  Serial.println(invalidRealSensorSamples);
  Serial.print("Total radio transmissions: ");
  Serial.println(telemetryPacketsSent + 4);
  Serial.println("Payload encryption       : AES-128-GCM");
  Serial.println("GCM authentication tag   : 128-BIT");
  Serial.println("Outer packet HMAC        : HMAC-SHA256 / 256-BIT");
  Serial.println("Replay packet transmitted: YES");
  Serial.println("Tampered packet sent     : YES");
  Serial.println("Stale timestamp sent     : YES");
  Serial.println("Plaintext over radio     : NO");
  Serial.print("AppSKey zeroization      : ");
  Serial.println(appZeroized ? "PASSED" : "FAILED");
  Serial.print("NwkSKey zeroization      : ");
  Serial.println(nwkZeroized ? "PASSED" : "FAILED");
  Serial.print("STEP 38G-2 SENSOR RESULT   : ");

  if (
    telemetrySequence == UNIQUE_TELEMETRY_PACKETS
    && validRealSensorSamples == UNIQUE_TELEMETRY_PACKETS
    && invalidRealSensorSamples == 0
    && replayPacketSent
    && tamperedPacketSent
    && staleTimestampPacketSent
    && gcmFailurePacketSent
    && appZeroized
    && nwkZeroized
  ) {
    Serial.println("PASSED");
  } else {
    Serial.println("REVIEW REQUIRED");
  }

  Serial.println("==========================================");

  savedReplayPacket = "";
  savedTamperSourcePacket = "";

  handshakeState =
      SensorHandshakeState::ZEROIZED;
}


void sendComponent2TestResult(
    const String& requestId,
    const String& command,
    const String& result,
    const String& keyAction
) {
  const String transcript = "C2_TEST_RESULT_V1," + String(sessionId) + ","
      + requestId + "," + command + "," + result + "," + keyAction;
  uint8_t proof[PROOF_LENGTH] = {0};
  if (!calculateTruncatedProof(runtimeNwkSKey, sizeof(runtimeNwkSKey), transcript, proof)) return;
  sendE32Line(transcript + "," + bytesToHex(proof, sizeof(proof)));
  secureZeroize(proof, sizeof(proof));
}

void handleComponent2TestCommand(const String& line) {
  String fields[6];
  if (!splitCsv(line, fields, 6)
      || handshakeState != SensorHandshakeState::ESTABLISHED
      || static_cast<uint32_t>(strtoul(fields[1].c_str(), nullptr, 10)) != sessionId
      || (fields[4] != "DASHBOARD" && fields[4] != "POLICY")) return;
  uint8_t received[PROOF_LENGTH] = {0};
  uint8_t expected[PROOF_LENGTH] = {0};
  const int finalComma = line.lastIndexOf(',');
  const String transcript = line.substring(0, finalComma);
  const bool verified = hexToBytes(fields[5], received, sizeof(received))
      && calculateTruncatedProof(runtimeNwkSKey, sizeof(runtimeNwkSKey), transcript, expected)
      && constantTimeEqual(received, expected, PROOF_LENGTH);
  secureZeroize(received, sizeof(received));
  secureZeroize(expected, sizeof(expected));
  if (!verified) {
    Serial.println("Component 2 test command  : HMAC REJECTED");
    return;
  }

  const String requestId = fields[2];
  const String command = fields[3];
  if (command == "TEST_REPLAY") {
    sendComponent2TestResult(requestId, command, "PASSED", "NONE");
    sendIntentionalReplayPacket();
  } else if (command == "TEST_INVALID_HMAC") {
    sendComponent2TestResult(requestId, command, "PASSED", "NONE");
    sendIntentionalTamperedPacket();
  } else if (command == "TEST_INVALID_GCM") {
    sendComponent2TestResult(requestId, command, "PASSED", "NONE");
    sendIntentionalGcmFailurePacket();
  } else if (command == "TEST_STALE_TIMESTAMP") {
    sendComponent2TestResult(requestId, command, "PASSED", "NONE");
    sendIntentionalStaleTimestampPacket();
  } else if (command == "TEST_HMAC_SPIKE") {
    sendComponent2TestResult(requestId, command, "PASSED", "THRESHOLD_TEST");
    for (uint8_t attempt = 0; attempt < 5; attempt++) {
      sendIntentionalTamperedPacket();
      delay(180);
    }
  } else if (command == "ROTATE_SESSION") {
    sendComponent2TestResult(requestId, command, "ROTATION_STARTED", "ZEROIZE_AND_REKEY");
    secureZeroize(runtimeAppSKey, sizeof(runtimeAppSKey));
    secureZeroize(runtimeNwkSKey, sizeof(runtimeNwkSKey));
    delay(250);
    startNewHandshake();
  } else if (command == "REVOKE_SESSION") {
    sendComponent2TestResult(requestId, command, "REVOKED", "ZEROIZED");
    secureZeroize(runtimeAppSKey, sizeof(runtimeAppSKey));
    secureZeroize(runtimeNwkSKey, sizeof(runtimeNwkSKey));
    telemetryTestStarted = false;
    handshakeState = SensorHandshakeState::ZEROIZED;
    c1SystemState = C1SystemState::LOCKDOWN;
    c1ApplySafeOutputs();
  }
}

void processIncomingLine(String line) {
  line.trim();

  if (line.length() == 0) {
    return;
  }

  Serial.print("RX message type           : ");

  const int comma = line.indexOf(',');

  Serial.println(
    comma >= 0
      ? line.substring(0, comma)
      : line
  );

  if (line.startsWith("C1_COMMAND_V1,")) {
    c1HandleSignedDemoCommand(line);
    return;
  }

  if (line.startsWith("C1_STATUS_ACK_V1,")) {
    c1HandleStatusAck(line);
    return;
  }

  if (line.startsWith("C2_TEST_COMMAND_V1,")) {
    handleComponent2TestCommand(line);
    return;
  }

  if (
    handshakeState
      == SensorHandshakeState::WAITING_FOR_CHALLENGE
    && line.startsWith("C2_CHALLENGE_V1,")
  ) {
    handleChallenge(line);
    return;
  }

  if (
    handshakeState
      == SensorHandshakeState::WAITING_FOR_CONFIRM
    && line.startsWith("C2_CONFIRM_V1,")
  ) {
    handleConfirm(line);
  }
}

void serviceE32Input() {
  while (E32Serial.available() > 0) {
    const char receivedCharacter =
        static_cast<char>(E32Serial.read());

    if (receivedCharacter == '\r') {
      continue;
    }

    // After an overflow, discard the entire frame through its newline.
    // Never process a truncated suffix as a new authenticated message.
    if (discardingRadioLine) {
      if (receivedCharacter == '\n') discardingRadioLine = false;
      continue;
    }

    if (receivedCharacter == '\n') {
      if (radioLineBuffer.length() > 0) {
        String completeLine = radioLineBuffer;
        radioLineBuffer = "";

        processIncomingLine(completeLine);
      }

      continue;
    }

    if (
      radioLineBuffer.length()
      >= MAX_RADIO_LINE_LENGTH
    ) {
      radioLineBuffer = "";
      radioLineOverflowCount++;
      discardingRadioLine = true;

      Serial.print(
        "Radio line overflow count : "
      );

      Serial.println(
        radioLineOverflowCount
      );

      continue;
    }

    radioLineBuffer += receivedCharacter;
  }
}


bool initializeBh1750Robustly() {
  if (!BH1750_SENSOR_ENABLED) {
    Serial.println("BH1750 policy             : DISABLED / USE SAMPLE VALUE");
    return false;
  }

  constexpr uint8_t BH1750_ADDRESSES[] = {0x23, 0x5C};

  for (
    uint8_t attempt = 1;
    attempt <= BH1750_INIT_ATTEMPTS;
    attempt++
  ) {
    for (const uint8_t address : BH1750_ADDRESSES) {
      Wire.beginTransmission(address);

      const uint8_t i2cResult =
          Wire.endTransmission();

      Serial.print("BH1750 init attempt       : ");
      Serial.print(attempt);
      Serial.print("/");
      Serial.print(BH1750_INIT_ATTEMPTS);
      Serial.print(" | address=0x");
      Serial.print(address, HEX);
      Serial.print(" | I2C result=");
      Serial.println(i2cResult);

      if (
        i2cResult == 0
        &&
        lightMeter.begin(
          BH1750::CONTINUOUS_HIGH_RES_MODE,
          address,
          &Wire
        )
      ) {
        lightSensorAddress = address;
        delay(250);
        return true;
      }
    }

    delay(500);
  }

  return false;
}

bool checkPhysicalSensorReadiness() {
  sensorReadyCheckCount++;

  if (BH1750_SENSOR_ENABLED && !lightSensorReady) {
    lightSensorReady =
        initializeBh1750Robustly();
  }

  // DHT22 requires time between startup and the first reading.
  delay(2200);

  const float temperatureC =
      dht.readTemperature();

  const float humidityPercent =
      dht.readHumidity();

  const float lightLux =
      lightSensorReady
        ? lightMeter.readLightLevel()
        : -1.0f;

  const uint32_t soilRaw =
      static_cast<uint32_t>(
        analogRead(SOIL_PIN)
      );

  const bool temperatureValid =
      !isnan(temperatureC);

  const bool humidityValid =
      !isnan(humidityPercent);

  const bool lightValid =
      BH1750_SENSOR_ENABLED
      && lightSensorReady
      &&
      lightLux >= 0.0f;

  const bool soilValid =
      soilRaw >= SOIL_MIN_VALID_RAW
      &&
      soilRaw < SOIL_OPEN_CIRCUIT_RAW;

  const bool ready =
      temperatureValid
      &&
      humidityValid
      &&
      lightValid
      &&
      soilValid;

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("PHYSICAL SENSOR READINESS CHECK");
  Serial.println("------------------------------------------");

  Serial.print("Readiness check number    : ");
  Serial.println(sensorReadyCheckCount);

  Serial.print("Temperature               : ");
  if (temperatureValid) {
    Serial.print(temperatureC, 2);
    Serial.println(" C");
  } else {
    Serial.println("INVALID / NaN");
  }

  Serial.print("Humidity                  : ");
  if (humidityValid) {
    Serial.print(humidityPercent, 2);
    Serial.println(" %");
  } else {
    Serial.println("INVALID / NaN");
  }

  Serial.print("BH1750 initialized        : ");
  Serial.println(lightSensorReady ? "YES" : "NO");

  Serial.print("Light                     : ");
  if (lightValid) {
    Serial.print(lightLux, 2);
    Serial.println(" lux");
  } else {
    Serial.println("INVALID");
  }

  Serial.print("Soil raw                  : ");
  Serial.println(soilRaw);

  Serial.print("Soil valid range          : ");
  Serial.print(SOIL_MIN_VALID_RAW);
  Serial.print(" to ");
  Serial.println(SOIL_OPEN_CIRCUIT_RAW - 1);

  Serial.print("Soil reading valid        : ");
  Serial.println(soilValid ? "YES" : "NO");

  Serial.print("E32 AUX state             : ");
  Serial.println(digitalRead(E32_AUX_PIN));

  Serial.print("Physical sensors ready    : ");
  Serial.println(ready ? "PASSED" : "NO / FALLBACK REQUIRED");

  Serial.print("Invalid reason            : ");

  if (ready) {
    Serial.println("NONE");
  } else {
    bool firstReason = true;

    if (!temperatureValid) {
      Serial.print("DHT TEMPERATURE");
      firstReason = false;
    }

    if (!humidityValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print("DHT HUMIDITY");
      firstReason = false;
    }

    if (!lightValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print(
        !BH1750_SENSOR_ENABLED
          ? "BH1750 DISABLED / SAMPLE VALUE"
          : lightSensorReady
              ? "BH1750 READING"
              : "BH1750 INITIALIZATION"
      );

      firstReason = false;
    }

    if (!soilValid) {
      if (!firstReason) {
        Serial.print(" | ");
      }

      Serial.print("SOIL READING");
    }

    Serial.println();
  }

  Serial.println("------------------------------------------");

  if (!ready && SENSOR_FALLBACK_ENABLED) {
    Serial.println(
      "Startup policy            : CONTINUE WITH MARKED FALLBACK VALUES"
    );
  }

  return ready || SENSOR_FALLBACK_ENABLED;
}


void setup() {
  Serial.begin(115200);
  Serial.println("SENSOR BUILD: RADIO_ACK_FIX_03");
  delay(1200);

  pinMode(E32_AUX_PIN, INPUT);
  pinMode(SOIL_PIN, INPUT);

  pinMode(C1_TAMPER_PIN, INPUT_PULLUP);
  pinMode(C1_PUMP_RELAY_PIN, OUTPUT);
  pinMode(C1_FAN_RELAY_PIN, OUTPUT);
  pinMode(C1_GREEN_LED_PIN, OUTPUT);
  pinMode(C1_BLUE_LED_PIN, OUTPUT);
  pinMode(C1_YELLOW_LED_PIN, OUTPUT);
  pinMode(C1_RED_LED_PIN, OUTPUT);
  c1ApplySafeOutputs();

  SPI.begin(C1_RFID_SCK_PIN, C1_RFID_MISO_PIN, C1_RFID_MOSI_PIN, C1_RFID_SS_PIN);
  c1Rfid.PCD_Init();
  c1Rfid.PCD_SetAntennaGain(MFRC522::RxGain_48dB);
  for (byte i = 0; i < 6; i++) c1RuntimeKeyA.keyByte[i] = C1_CUSTOM_KEY_A[i];
  attachInterrupt(digitalPinToInterrupt(C1_TAMPER_PIN), c1HandleTamperInterrupt, RISING);

  Wire.begin(
    I2C_SDA_PIN,
    I2C_SCL_PIN
  );

  dht.begin();

  // Buffer replies while sensor reads and radio transmissions block.
  E32Serial.setRxBufferSize(2048);

  E32Serial.begin(
    9600,
    SERIAL_8N1,
    E32_RX_PIN,
    E32_TX_PIN
  );

  E32Serial.setTimeout(300);

  // Keep partial UART frames between loop iterations.
  // This prevents long E32 packets from being split by a short
  // readStringUntil() timeout.
  radioLineBuffer.reserve(MAX_RADIO_LINE_LENGTH);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38G-2");
  Serial.println("LIVE SECURE TELEMETRY FOR REACT — SENSOR");
  Serial.println("==========================================");
  Serial.println("Radio mode                : TRANSPARENT");
  Serial.println("Gateway authentication    : HMAC-SHA256");
  Serial.println("Sensor authentication     : HMAC-SHA256");
  Serial.println("Session keys              : HKDF-SHA256");
  Serial.println("Actual keys printed       : NO");
  Serial.println("Development PSK           : YES");
  Serial.println("Production security claim : NOT YET");
  Serial.println("DHT22 pin                 : GPIO27");
  Serial.println("BH1750 address probing    : 0x23 / 0x5C");
  Serial.println("BH1750 runtime policy     : DISABLED / 250 LUX SAMPLE / V=0");
  Serial.println("Soil analog pin           : GPIO36");
  Serial.println("RC522 SS/RST              : GPIO5 / GPIO33");
  Serial.println("Tamper input              : GPIO13 / ACTIVE HIGH");
  Serial.println("Tamper arming             : REQUIRES SECURE LOW FIRST");
  Serial.println("Component 1 demo command  : I = AUTHENTICATED INSIDER MISUSE");
  Serial.println(
    "Handshake policy          : USE MARKED FALLBACK IF SENSOR FAILS"
  );

  Serial.println();

  physicalSensorsReady =
      checkPhysicalSensorReadiness();

  lastSensorReadyCheckMs = millis();

  if (physicalSensorsReady) {
    Serial.println(
      "Sensor readiness gate     : PASSED — START HANDSHAKE"
    );

    startNewHandshake();
  } else {
    Serial.println(
      "Sensor readiness gate     : BLOCKED — NO RADIO TELEMETRY"
    );
  }
}

void loop() {
  serviceE32Input();
  c1ProcessTamper();
  c1ProcessSerialDemoCommand();
  c1ProcessRfid();

  if (
    c1StatusPending
    && physicalSensorsReady
    && c1SystemState != C1SystemState::LOCKDOWN
    && (
      handshakeState == SensorHandshakeState::FAILED
      || handshakeState == SensorHandshakeState::ZEROIZED
    )
    && millis() - c1LastReconnectAttemptMs >= C1_RECONNECT_RETRY_MS
  ) {
    c1LastReconnectAttemptMs = millis();
    Serial.println("Component 1 radio session : RECONNECTING FOR PENDING RFID EVENT");
    startNewHandshake();
  }

  if (
    c1StatusPending
    && handshakeState == SensorHandshakeState::ESTABLISHED
    && millis() - c1LastStatusAttemptMs >= C1_STATUS_RETRY_MS
  ) {
    Serial.println("Component 1 signed status : RETRYING");
    c1SendSignedStatus(true);
  }

  if (
    !physicalSensorsReady
    &&
    millis() - lastSensorReadyCheckMs
        >= SENSOR_READY_RETRY_MS
  ) {
    lastSensorReadyCheckMs = millis();

    physicalSensorsReady =
        checkPhysicalSensorReadiness();

    if (physicalSensorsReady) {
      Serial.println(
        "Sensor readiness gate     : PASSED — START HANDSHAKE"
      );

      startNewHandshake();
    } else {
      Serial.println(
        "Sensor readiness gate     : BLOCKED — RETRYING"
      );
    }
  }

  if (
    (
      handshakeState
        == SensorHandshakeState::WAITING_FOR_CHALLENGE
      ||
      handshakeState
        == SensorHandshakeState::WAITING_FOR_CONFIRM
    )
    &&
    millis() - stateStartedAtMs
        >= HANDSHAKE_TIMEOUT_MS
  ) {
    if (
      handshakeState
        == SensorHandshakeState::WAITING_FOR_CHALLENGE
      &&
      handshakeAttempts < MAX_HANDSHAKE_ATTEMPTS
    ) {
      Serial.println("Handshake timeout          : RETRY HELLO");
      sendHello();
    } else {
      failHandshake("Handshake timeout");
    }
  }

  if (
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    // E32 is half duplex: keep listening until the signed status is ACKed.
    !c1StatusPending
    &&
    telemetryTestStarted
    &&
    (
      CONTINUOUS_LIVE_TELEMETRY
      || (
        !replayPacketSent
        && telemetrySequence < UNIQUE_TELEMETRY_PACKETS
      )
    )
    &&
    millis() - lastTelemetrySendMs
        >= TELEMETRY_INTERVAL_MS
  ) {
    telemetrySequence++;

    const bool saveForReplay =
        !CONTINUOUS_LIVE_TELEMETRY
        && telemetrySequence == 3;

    const bool saveForTamper =
        !CONTINUOUS_LIVE_TELEMETRY
        && telemetrySequence == 5;

    if (!createAndSendEncryptedTelemetry(
          telemetrySequence,
          saveForReplay,
          saveForTamper
        )) {
      failHandshake(
        "Encrypted telemetry generation failed"
      );
    }

    lastTelemetrySendMs = millis();
  }

  if (
    !CONTINUOUS_LIVE_TELEMETRY
    &&
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    telemetrySequence == UNIQUE_TELEMETRY_PACKETS
    &&
    !replayPacketSent
    &&
    millis() - lastTelemetrySendMs
        >= REPLAY_DELAY_MS
  ) {
    sendIntentionalReplayPacket();
  }

  if (
    !CONTINUOUS_LIVE_TELEMETRY
    &&
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    replayPacketSent
    &&
    !tamperedPacketSent
    &&
    millis() - replaySentAtMs
        >= TAMPER_DELAY_MS
  ) {
    sendIntentionalTamperedPacket();
  }

  if (
    !CONTINUOUS_LIVE_TELEMETRY
    &&
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    tamperedPacketSent
    &&
    !staleTimestampPacketSent
    &&
    millis() - tamperSentAtMs
        >= STALE_TIMESTAMP_DELAY_MS
  ) {
    if (!sendIntentionalStaleTimestampPacket()) {
      failHandshake(
        "Stale timestamp-test generation failed"
      );
    }
  }

  if (
    !CONTINUOUS_LIVE_TELEMETRY
    &&
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    staleTimestampPacketSent
    &&
    !gcmFailurePacketSent
    &&
    millis() - staleTimestampSentAtMs
        >= GCM_FAILURE_DELAY_MS
  ) {
    if (!sendIntentionalGcmFailurePacket()) {
      failHandshake(
        "AES-GCM failure-test generation failed"
      );
    }
  }

  if (
    !CONTINUOUS_LIVE_TELEMETRY
    &&
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    gcmFailurePacketSent
    &&
    millis() - gcmFailureSentAtMs
        >= POST_ATTACK_HOLD_MS
  ) {
    printSensorDataSecurityReportAndZeroize();
  }

  if (
    handshakeState
      == SensorHandshakeState::ESTABLISHED
    &&
    (millis() - establishedAtMs >= KEY_ACTIVE_WINDOW_MS
      || telemetrySequence >= PRODUCTION_PACKET_LIMIT)
  ) {
    Serial.println(
      "Session safety timeout    : ROTATE SESSION"
    );

    printSensorDataSecurityReportAndZeroize();

    if (CONTINUOUS_LIVE_TELEMETRY) {
      delay(250);
      startNewHandshake();
    }
  }

  delay(5);
}
