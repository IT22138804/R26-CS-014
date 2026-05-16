/*
  Component 2 — Step 36B
  Authenticated handshake — Sensor ESP32
*/


#include <Arduino.h>
#include <Wire.h>
#include <BH1750.h>
#include <DHT.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
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

// Component 1 sensor pins.
constexpr int DHT_PIN = 27;
constexpr int SOIL_PIN = 36;
constexpr int I2C_SDA_PIN = 21;
constexpr int I2C_SCL_PIN = 22;

constexpr int SOIL_DRY_RAW = 4095;
constexpr int SOIL_WET_RAW = 1169;
constexpr int SOIL_OPEN_CIRCUIT_RAW = 4080;

DHT dht(DHT_PIN, DHT22);
BH1750 lightMeter;
bool lightSensorReady = false;

// Robust startup gate: the radio handshake will not start until all
// physical sensors produce one valid sample.
constexpr int SOIL_MIN_VALID_RAW = 100;
constexpr uint8_t BH1750_INIT_ATTEMPTS = 10;
constexpr unsigned long SENSOR_READY_RETRY_MS = 3000;

bool physicalSensorsReady = false;
unsigned long lastSensorReadyCheckMs = 0;
uint32_t sensorReadyCheckCount = 0;

constexpr size_t MAX_RADIO_LINE_LENGTH = 320;

String radioLineBuffer;
uint32_t radioLineOverflowCount = 0;

constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 10000;
constexpr unsigned long KEY_ACTIVE_WINDOW_MS = 150000;
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
constexpr unsigned long TELEMETRY_INTERVAL_MS = 8000;
constexpr unsigned long REPLAY_DELAY_MS = 2500;
constexpr unsigned long TAMPER_DELAY_MS = 2500;
constexpr unsigned long STALE_TIMESTAMP_DELAY_MS = 2500;
constexpr unsigned long GCM_FAILURE_DELAY_MS = 2500;
constexpr unsigned long POST_ATTACK_HOLD_MS = 5000;

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

  E32Serial.println(message);

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

  E32Serial.println(response);
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
  Serial.println("Key active window         : 150 seconds");
  Serial.println("STEP 36B HANDSHAKE        : PASSED");
  Serial.println("STEP 37D FIREBASE TEST    : STARTING");
  Serial.println("Payload encryption        : AES-128-GCM");
  Serial.println("GCM authentication tag    : 128-BIT");
  Serial.println("Outer packet HMAC         : HMAC-SHA256 / 128-BIT");
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
      lightSensorReady
      &&
      lightLux >= 0.0f;

  const bool soilValid =
      soilRaw >= SOIL_MIN_VALID_RAW
      &&
      soilRaw < SOIL_OPEN_CIRCUIT_RAW;

  const bool sampleValid =
      temperatureValid
      &&
      humidityValid
      &&
      lightValid
      &&
      soilValid;

  const int32_t temperatureX100 =
      isnan(temperatureC)
        ? -9999
        : static_cast<int32_t>(
            lroundf(temperatureC * 100.0f)
          );

  const uint32_t humidityX100 =
      isnan(humidityPercent)
        ? 0
        : static_cast<uint32_t>(
            constrain(
              lroundf(humidityPercent * 100.0f),
              0L,
              10000L
            )
          );

  const uint32_t lightLuxX10 =
      lightLux < 0.0f
        ? 0
        : static_cast<uint32_t>(
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

  E32Serial.println(packet);
  telemetryPacketsSent++;

  if (saveForReplay) {
    savedReplayPacket = packet;
  }

  if (saveForTamper) {
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
  Serial.println("Outer HMAC                : ATTACHED / 128-BIT");
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

  E32Serial.println(savedReplayPacket);
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

  E32Serial.println(tamperedPacket);
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
  constexpr uint32_t TEST_SEQUENCE = 7;
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

  E32Serial.println(packet);

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
  constexpr uint32_t TEST_SEQUENCE = 8;

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

  E32Serial.println(packet);

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
  Serial.println("Outer packet HMAC        : HMAC-SHA256 / 128-BIT");
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
  for (
    uint8_t attempt = 1;
    attempt <= BH1750_INIT_ATTEMPTS;
    attempt++
  ) {
    Wire.beginTransmission(0x23);

    const uint8_t i2cResult =
        Wire.endTransmission();

    Serial.print("BH1750 init attempt       : ");
    Serial.print(attempt);
    Serial.print("/");
    Serial.print(BH1750_INIT_ATTEMPTS);
    Serial.print(" | I2C result=");
    Serial.println(i2cResult);

    if (
      i2cResult == 0
      &&
      lightMeter.begin(
        BH1750::CONTINUOUS_HIGH_RES_MODE,
        0x23,
        &Wire
      )
    ) {
      delay(250);
      return true;
    }

    delay(500);
  }

  return false;
}

bool checkPhysicalSensorReadiness() {
  sensorReadyCheckCount++;

  if (!lightSensorReady) {
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
      lightSensorReady
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
  Serial.println(ready ? "PASSED" : "RETRY REQUIRED");

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

  Serial.println("------------------------------------------");

  return ready;
}


void setup() {
  Serial.begin(115200);
  delay(1200);

  pinMode(E32_AUX_PIN, INPUT);
  pinMode(SOIL_PIN, INPUT);

  Wire.begin(
    I2C_SDA_PIN,
    I2C_SCL_PIN
  );

  dht.begin();

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
  Serial.println("BH1750 address            : 0x23");
  Serial.println("Soil analog pin           : GPIO36");
  Serial.println(
    "Handshake policy          : WAIT FOR VALID PHYSICAL SENSORS"
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
    telemetryTestStarted
    &&
    !replayPacketSent
    &&
    telemetrySequence < UNIQUE_TELEMETRY_PACKETS
    &&
    millis() - lastTelemetrySendMs
        >= TELEMETRY_INTERVAL_MS
  ) {
    telemetrySequence++;

    const bool saveForReplay =
        telemetrySequence == 3;

    const bool saveForTamper =
        telemetrySequence == 5;

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
    millis() - establishedAtMs
        >= KEY_ACTIVE_WINDOW_MS
  ) {
    Serial.println(
      "Session safety timeout    : ZEROIZE"
    );

    printSensorDataSecurityReportAndZeroize();
  }

  delay(5);
}
