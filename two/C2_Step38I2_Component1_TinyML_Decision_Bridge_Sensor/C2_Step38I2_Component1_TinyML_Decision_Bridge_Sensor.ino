#include <Arduino.h>
#include <mbedtls/md.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
constexpr size_t REVOCATION_NONCE_LENGTH = 12;

const char NODE_ID[] = "GH_NODE_01";

// Development-only shared secret.
// Replace with a uniquely provisioned device secret before production use.
const uint8_t DEVELOPMENT_MASTER_PSK[32] = {
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

  int result =
      mbedtls_md_setup(&context, information, 1);

  if (result == 0) {
    result =
        mbedtls_md_hmac_starts(
          &context,
          key,
          keyLength
        );
  }

  if (result == 0 && dataLength > 0) {
    result =
        mbedtls_md_hmac_update(
          &context,
          data,
          dataLength
        );
  }

  if (result == 0) {
    result =
        mbedtls_md_hmac_finish(
          &context,
          output
        );
  }

  mbedtls_md_free(&context);
  return result == 0;
}

bool truncatedHmac(
    const uint8_t* key,
    size_t keyLength,
    const String& transcript,
    uint8_t output[PROOF_LENGTH]
) {
  uint8_t fullProof[SHA256_LENGTH] = {0};

  const bool passed =
      hmacSha256(
        key,
        keyLength,
        reinterpret_cast<const uint8_t*>(
          transcript.c_str()
        ),
        transcript.length(),
        fullProof
      );

  if (passed) {
    memcpy(output, fullProof, PROOF_LENGTH);
  }

  secureZeroize(fullProof, sizeof(fullProof));
  return passed;
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

    int result =
        mbedtls_md_setup(
          &context,
          mdInformation,
          1
        );

    if (result == 0) {
      result =
          mbedtls_md_hmac_starts(
            &context,
            pseudoRandomKey,
            sizeof(pseudoRandomKey)
          );
    }

    if (result == 0 && previousLength > 0) {
      result =
          mbedtls_md_hmac_update(
            &context,
            previousBlock,
            previousLength
          );
    }

    if (result == 0 && informationLength > 0) {
      result =
          mbedtls_md_hmac_update(
            &context,
            information,
            informationLength
          );
    }

    if (result == 0) {
      result =
          mbedtls_md_hmac_update(
            &context,
            &counter,
            1
          );
    }

    if (result == 0) {
      result =
          mbedtls_md_hmac_finish(
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

  const String appInfo =
      "C2/"
      + String(NODE_ID)
      + "/APPSKEY/V1/"
      + String(sessionId);

  const String nwkInfo =
      "C2/"
      + String(NODE_ID)
      + "/NWKSKEY/V1/"
      + String(sessionId);

  const bool appPassed =
      hkdfSha256(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        salt,
        sizeof(salt),
        reinterpret_cast<const uint8_t*>(
          appInfo.c_str()
        ),
        appInfo.length(),
        appSKey,
        SESSION_KEY_LENGTH
      );

  const bool nwkPassed =
      hkdfSha256(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        salt,
        sizeof(salt),
        reinterpret_cast<const uint8_t*>(
          nwkInfo.c_str()
        ),
        nwkInfo.length(),
        nwkSKey,
        SESSION_KEY_LENGTH
      );

  secureZeroize(salt, sizeof(salt));
  return appPassed && nwkPassed;
}

String bytesToHex(const uint8_t* data, size_t length) {
  static const char* HEX_DIGITS =
      "0123456789ABCDEF";

  String result;
  result.reserve(length * 2);

  for (size_t index = 0; index < length; index++) {
    result +=
        HEX_DIGITS[
          (data[index] >> 4) & 0x0F
        ];

    result +=
        HEX_DIGITS[
          data[index] & 0x0F
        ];
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
      fields[fieldIndex++] =
          line.substring(start);

      break;
    }

    fields[fieldIndex++] =
        line.substring(start, comma);

    start = comma + 1;
  }

  return fieldIndex == expectedFields
      && line.indexOf(',', start) < 0;
}

String handshakeTranscript(
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

String dataTranscript(
    uint32_t sessionId,
    uint32_t sequence,
    const String& label
) {
  return
      "REV_DATA|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|"
      + String(sequence)
      + "|"
      + label;
}

String revocationTranscript(
    uint32_t sessionId,
    uint32_t revocationCounter,
    const String& reason,
    const String& nonceHex
) {
  return
      "REVOKE|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|"
      + String(revocationCounter)
      + "|"
      + reason
      + "|"
      + nonceHex;
}

String revocationAckTranscript(
    uint32_t sessionId,
    uint32_t revocationCounter,
    const String& reason,
    const String& nonceHex
) {
  return
      "REVOKE_ACK|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|"
      + String(revocationCounter)
      + "|"
      + reason
      + "|"
      + nonceHex;
}

HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;
constexpr int PHYSICAL_TAMPER_PIN = 13; // Not used as a trigger in Step 38I-2.

constexpr uint8_t TINYML_CONFIRMATIONS_REQUIRED = 3;
constexpr unsigned long TINYML_CONFIRMATION_INTERVAL_MS = 1200;

const float CONTROLLED_TINYML_PROBABILITIES[
    TINYML_CONFIRMATIONS_REQUIRED
] = {
  0.910f,
  0.940f,
  0.970f
};

constexpr size_t MAX_RADIO_LINE_LENGTH = 320;
constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 12000;
constexpr unsigned long DATA_INTERVAL_MS = 1400;
constexpr unsigned long REVOCATION_ACK_TIMEOUT_MS = 9000;
constexpr unsigned long POST_REVOKE_TEST_DELAY_MS = 1400;
constexpr uint8_t MAX_HANDSHAKE_ATTEMPTS = 5;
constexpr uint8_t MAX_REVOCATION_REQUEST_ATTEMPTS = 3;
constexpr uint32_t BASELINE_PACKET_TARGET = 2;

enum class SensorState {
  STARTING,
  WAITING_CHALLENGE,
  WAITING_CONFIRM,
  BASELINE,
  WAITING_PHYSICAL_TAMPER,
  WAITING_REVOCATION_ACK,
  REVOKED,
  FINISHED,
  FAILED
};

SensorState state = SensorState::STARTING;

String radioLineBuffer;

uint32_t sessionId = 0;
uint32_t baselineSequence = 0;
uint32_t revocationCounter = 0;

uint8_t sensorNonce[NONCE_LENGTH] = {0};
uint8_t gatewayNonce[NONCE_LENGTH] = {0};
uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};
uint8_t revocationNonce[REVOCATION_NONCE_LENGTH] = {0};

String sensorNonceHex;
String gatewayNonceHex;
String revocationNonceHex;
String revocationReason = "TINYML_CONFIRMED_ANOMALY";
String savedOldAuthenticatedFrame;
String savedRevocationRequestFrame;

unsigned long stateStartedMs = 0;
unsigned long lastDataMs = 0;
unsigned long revokedAtMs = 0;

uint8_t handshakeAttempts = 0;
uint8_t revocationRequestAttempts = 0;

volatile bool physicalTamperInterruptPending = false;
volatile unsigned long physicalTamperInterruptMicros = 0;

uint8_t tinyMlConfirmationCount = 0;
float tinyMlFinalProbability = 0.0f;
unsigned long lastTinyMlConfirmationMs = 0;
bool controlledTinyMlBridgeArmed = false;

bool initialHandshakePassed = false;
bool confirmedTinyMlAnomalyDetected = false;
bool revocationRequestHmacBuilt = false;
bool revocationAckVerified = false;
bool appKeyZeroized = false;
bool nwkKeyZeroized = false;
bool oldAuthenticatedFrameSent = false;

String revocationRequestTranscript(
    uint32_t requestSessionId,
    uint32_t requestCounter,
    const String& reason,
    const String& nonceHex
) {
  return
      "REVOKE_REQUEST|"
      + String(NODE_ID)
      + "|"
      + String(requestSessionId)
      + "|"
      + String(requestCounter)
      + "|"
      + reason
      + "|"
      + nonceHex;
}

String revocationRequestAckTranscript(
    uint32_t requestSessionId,
    uint32_t requestCounter,
    const String& reason,
    const String& nonceHex
) {
  return
      "REVOKE_REQUEST_ACK|"
      + String(NODE_ID)
      + "|"
      + String(requestSessionId)
      + "|"
      + String(requestCounter)
      + "|"
      + reason
      + "|"
      + nonceHex;
}

void IRAM_ATTR onPhysicalTamperInterrupt() {
  physicalTamperInterruptPending = true;
  physicalTamperInterruptMicros = micros();
}

void failTest(const String& reason) {
  Serial.println();
  Serial.println("COMPONENT 1 → COMPONENT 2 BRIDGE FAILED");
  Serial.print("Reason                     : ");
  Serial.println(reason);

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  state = SensorState::FAILED;
  Serial.println("STEP 38I-2 SENSOR RESULT   : REVIEW REQUIRED");
}

void sendHello() {
  handshakeAttempts++;

  const String frame =
      "C2_HELLO_V1,"
      + String(NODE_ID)
      + ","
      + String(sessionId)
      + ","
      + sensorNonceHex;

  E32Serial.println(frame);

  Serial.print("TX HELLO attempt           : ");
  Serial.print(handshakeAttempts);
  Serial.print("/");
  Serial.println(MAX_HANDSHAKE_ATTEMPTS);

  state = SensorState::WAITING_CHALLENGE;
  stateStartedMs = millis();
}

void startHandshake() {
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

  sensorNonceHex =
      bytesToHex(
        sensorNonce,
        sizeof(sensorNonce)
      );

  handshakeAttempts = 0;
  sendHello();
}

void handleChallenge(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    failTest("Malformed gateway challenge");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSession != sessionId) {
    failTest("Gateway challenge session mismatch");
    return;
  }

  gatewayNonceHex = fields[2];

  if (!hexToBytes(
        gatewayNonceHex,
        gatewayNonce,
        sizeof(gatewayNonce)
      )) {
    failTest("Invalid gateway nonce");
    return;
  }

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[3],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    failTest("Invalid gateway proof encoding");
    return;
  }

  const String base =
      handshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const bool proofBuilt =
      truncatedHmac(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        String("GW|") + base,
        expectedProof
      );

  const bool gatewayValid =
      proofBuilt
      &&
      constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!gatewayValid) {
    failTest("Gateway authentication failed");
    return;
  }

  if (!deriveSessionKeys(
        sessionId,
        sensorNonce,
        gatewayNonce,
        runtimeAppSKey,
        runtimeNwkSKey
      )) {
    failTest("Session-key derivation failed");
    return;
  }

  uint8_t sensorProof[PROOF_LENGTH] = {0};

  if (!truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        String("SN|") + base,
        sensorProof
      )) {
    secureZeroize(sensorProof, sizeof(sensorProof));
    failTest("Sensor proof generation failed");
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

  Serial.println("Gateway authentication     : PASSED");
  Serial.println("Session-key derivation     : PASSED");
  Serial.println("TX sensor proof            : SENT");

  state = SensorState::WAITING_CONFIRM;
  stateStartedMs = millis();
}

void handleConfirm(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    failTest("Malformed handshake confirmation");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSession != sessionId) {
    failTest("Handshake confirmation session mismatch");
    return;
  }

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[2],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    failTest("Invalid confirmation proof encoding");
    return;
  }

  const String base =
      handshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const bool proofBuilt =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        String("OK|") + base,
        expectedProof
      );

  const bool valid =
      proofBuilt
      &&
      constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!valid) {
    failTest("Handshake confirmation HMAC failed");
    return;
  }

  initialHandshakePassed = true;
  baselineSequence = 0;
  state = SensorState::BASELINE;
  lastDataMs = millis();

  Serial.println();
  Serial.println("AUTHENTICATED SESSION ESTABLISHED");
  Serial.print("Session ID                 : ");
  Serial.println(sessionId);
  Serial.println("Baseline target            : 2 packets");
}

String createAuthenticatedDataFrame(
    uint32_t sequence,
    const String& label
) {
  const String transcript =
      "I1_DATA|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|"
      + String(sequence)
      + "|"
      + label;

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        proof
      )) {
    secureZeroize(proof, sizeof(proof));
    return "";
  }

  const String frame =
      "C2_I1_DATA_V1,"
      + String(sessionId)
      + ","
      + String(sequence)
      + ","
      + label
      + ","
      + bytesToHex(
          proof,
          sizeof(proof)
        );

  secureZeroize(proof, sizeof(proof));
  return frame;
}

void sendBaselinePacket() {
  baselineSequence++;

  const String frame =
      createAuthenticatedDataFrame(
        baselineSequence,
        "BASELINE"
      );

  if (frame.length() == 0) {
    failTest("Could not create baseline frame");
    return;
  }

  E32Serial.println(frame);

  if (baselineSequence == BASELINE_PACKET_TARGET) {
    savedOldAuthenticatedFrame = frame;
  }

  Serial.print("TX baseline packet         : ");
  Serial.print(baselineSequence);
  Serial.print("/");
  Serial.println(BASELINE_PACKET_TARGET);

  lastDataMs = millis();

  if (baselineSequence == BASELINE_PACKET_TARGET) {
    state = SensorState::WAITING_PHYSICAL_TAMPER;

    controlledTinyMlBridgeArmed = true;
    tinyMlConfirmationCount = 0;
    lastTinyMlConfirmationMs = millis();

    Serial.println();
    Serial.println("CONFIRMED TINYML DECISION BRIDGE ARMED");
    Serial.println("Input type                 : CONTROLLED MODEL OUTPUT");
    Serial.println("Actual model test          : ALREADY PASSED IN COMPONENT 1");
    Serial.println("Confirmations required     : 3");
    Serial.println("Automatic bridge test      : STARTING");
  }
}

void transmitRevocationRequest() {
  if (savedRevocationRequestFrame.length() == 0) {
    failTest("Saved revocation request is empty");
    return;
  }

  E32Serial.println(savedRevocationRequestFrame);
  revocationRequestAttempts++;

  Serial.print("TX signed revoke request   : ");
  Serial.print(revocationRequestAttempts);
  Serial.print("/");
  Serial.println(MAX_REVOCATION_REQUEST_ATTEMPTS);

  state = SensorState::WAITING_REVOCATION_ACK;
  stateStartedMs = millis();
}

void buildAndSendRevocationRequest() {
  confirmedTinyMlAnomalyDetected = true;
  revocationCounter = 1;

  esp_fill_random(
    revocationNonce,
    sizeof(revocationNonce)
  );

  revocationNonceHex =
      bytesToHex(
        revocationNonce,
        sizeof(revocationNonce)
      );

  const String transcript =
      revocationRequestTranscript(
        sessionId,
        revocationCounter,
        revocationReason,
        revocationNonceHex
      );

  uint8_t proof[PROOF_LENGTH] = {0};

  revocationRequestHmacBuilt =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        proof
      );

  if (!revocationRequestHmacBuilt) {
    secureZeroize(proof, sizeof(proof));
    failTest("Revoke-request HMAC generation failed");
    return;
  }

  savedRevocationRequestFrame =
      "C2_REVOKE_REQUEST_V1,"
      + String(sessionId)
      + ","
      + String(revocationCounter)
      + ","
      + revocationReason
      + ","
      + revocationNonceHex
      + ","
      + bytesToHex(
          proof,
          sizeof(proof)
        );

  secureZeroize(proof, sizeof(proof));

  Serial.println();
  Serial.println("COMPONENT 1 CONFIRMED TINYML ANOMALY");
  Serial.print("Final anomaly probability  : ");
  Serial.println(tinyMlFinalProbability, 3);
  Serial.print("Confirmation count         : ");
  Serial.print(tinyMlConfirmationCount);
  Serial.print("/");
  Serial.println(TINYML_CONFIRMATIONS_REQUIRED);
  Serial.println("System action              : LOCKDOWN REQUESTED");
  Serial.println("New telemetry              : DISABLED");
  Serial.println("Revoke-request HMAC        : PASSED");

  revocationRequestAttempts = 0;
  transmitRevocationRequest();
}

void handleRevocationAck(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    failTest("Malformed revocation ACK");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  const uint32_t receivedCounter =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  if (
    receivedSession != sessionId
    ||
    receivedCounter != revocationCounter
  ) {
    failTest("Revocation ACK identifiers mismatch");
    return;
  }

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[3],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    failTest("Revocation ACK proof encoding invalid");
    return;
  }

  const String transcript =
      revocationRequestAckTranscript(
        sessionId,
        revocationCounter,
        revocationReason,
        revocationNonceHex
      );

  const bool built =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        expectedProof
      );

  revocationAckVerified =
      built
      &&
      constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!revocationAckVerified) {
    failTest("Revocation ACK HMAC failed");
    return;
  }

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  appKeyZeroized =
      isAllZero(
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  nwkKeyZeroized =
      isAllZero(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  state = SensorState::REVOKED;
  revokedAtMs = millis();

  Serial.println();
  Serial.println("SENSOR REVOCATION ACK VERIFIED");
  Serial.println("Gateway ACK HMAC           : PASSED");
  Serial.print("AppSKey zeroization        : ");
  Serial.println(appKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("NwkSKey zeroization        : ");
  Serial.println(nwkKeyZeroized ? "PASSED" : "FAILED");
  Serial.println("Sensor state               : LOCKDOWN / REVOKED");
}

void sendOldFrameAndPrintReport() {
  if (savedOldAuthenticatedFrame.length() == 0) {
    failTest("Cached old-session frame unavailable");
    return;
  }

  E32Serial.println(savedOldAuthenticatedFrame);
  oldAuthenticatedFrameSent = true;

  Serial.println();
  Serial.println("POST-REVOCATION OLD-SESSION TEST");
  Serial.println("Cached old frame           : TRANSMITTED");
  Serial.println("Old key retained           : NO");
  Serial.println("Expected gateway action    : REJECT BEFORE HMAC");

  const bool passed =
      initialHandshakePassed
      &&
      baselineSequence == BASELINE_PACKET_TARGET
      &&
      confirmedTinyMlAnomalyDetected
      &&
      revocationRequestHmacBuilt
      &&
      revocationAckVerified
      &&
      appKeyZeroized
      &&
      nwkKeyZeroized
      &&
      oldAuthenticatedFrameSent;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 1 → COMPONENT 2 — STEP 38I-2 SENSOR REPORT");
  Serial.println("==========================================");
  Serial.print("Initial handshake          : ");
  Serial.println(initialHandshakePassed ? "PASSED" : "FAILED");
  Serial.print("Baseline packets sent      : ");
  Serial.println(baselineSequence);
  Serial.print("Confirmed TinyML anomaly   : ");
  Serial.println(
    confirmedTinyMlAnomalyDetected
      ? "DETECTED"
      : "NOT DETECTED"
  );
  Serial.print("TinyML confirmations       : ");
  Serial.print(tinyMlConfirmationCount);
  Serial.print("/");
  Serial.println(TINYML_CONFIRMATIONS_REQUIRED);
  Serial.print("Final anomaly probability  : ");
  Serial.println(tinyMlFinalProbability, 3);
  Serial.print("Sensor revoke request HMAC : ");
  Serial.println(revocationRequestHmacBuilt ? "PASSED" : "FAILED");
  Serial.print("Gateway revoke ACK         : ");
  Serial.println(revocationAckVerified ? "PASSED" : "FAILED");
  Serial.print("AppSKey zeroization        : ");
  Serial.println(appKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("NwkSKey zeroization        : ");
  Serial.println(nwkKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("Old-session test sent      : ");
  Serial.println(oldAuthenticatedFrameSent ? "PASSED" : "FAILED");
  Serial.println("Telemetry after anomaly    : DISABLED");
  Serial.println("Component 1 action         : LOCKDOWN");
  Serial.println("Bridge evidence            : CONTROLLED TINYML OUTPUT");
  Serial.println("Production model claim     : NOT MADE");
  Serial.println("Actual keys printed        : NO");
  Serial.print("STEP 38I-2 SENSOR RESULT   : ");
  Serial.println(passed ? "PASSED" : "REVIEW REQUIRED");
  Serial.println("==========================================");

  savedOldAuthenticatedFrame = "";
  savedRevocationRequestFrame = "";
  secureZeroize(revocationNonce, sizeof(revocationNonce));
  state = SensorState::FINISHED;
}

void processIncomingLine(String line) {
  line.trim();

  if (line.length() == 0) {
    return;
  }

  const int comma = line.indexOf(',');

  Serial.print("RX message type            : ");
  Serial.println(
    comma >= 0
      ? line.substring(0, comma)
      : line
  );

  if (
    state == SensorState::WAITING_CHALLENGE
    &&
    line.startsWith("C2_CHALLENGE_V1,")
  ) {
    handleChallenge(line);
    return;
  }

  if (
    state == SensorState::WAITING_CONFIRM
    &&
    line.startsWith("C2_CONFIRM_V1,")
  ) {
    handleConfirm(line);
    return;
  }

  if (
    state == SensorState::WAITING_REVOCATION_ACK
    &&
    line.startsWith("C2_REVOKE_REQUEST_ACK_V1,")
  ) {
    handleRevocationAck(line);
  }
}

void serviceRadio() {
  while (E32Serial.available() > 0) {
    const char character =
        static_cast<char>(E32Serial.read());

    if (character == '\r') {
      continue;
    }

    if (character == '\n') {
      if (radioLineBuffer.length() > 0) {
        String line = radioLineBuffer;
        radioLineBuffer = "";
        processIncomingLine(line);
      }

      continue;
    }

    if (
      radioLineBuffer.length()
        >= MAX_RADIO_LINE_LENGTH
    ) {
      radioLineBuffer = "";
      Serial.println("Radio frame overflow       : RESET");
      continue;
    }

    radioLineBuffer += character;
  }
}

void setup() {
  Serial.begin(115200);
  delay(1200);

  // GPIO13 remains available for the already-passed physical-tamper test.
  // Step 38I-2 validates the TinyML decision-output bridge, so no physical
  // trigger is required here.
  pinMode(PHYSICAL_TAMPER_PIN, INPUT_PULLUP);

  pinMode(E32_AUX_PIN, INPUT);

  E32Serial.begin(
    9600,
    SERIAL_8N1,
    E32_RX_PIN,
    E32_TX_PIN
  );

  radioLineBuffer.reserve(
    MAX_RADIO_LINE_LENGTH
  );

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 1 → COMPONENT 2 — STEP 38I-2");
  Serial.println("CONFIRMED TINYML-ORIGINATED REVOCATION — SENSOR");
  Serial.println("==========================================");
  Serial.println("ESP32 role                 : NO. 1 SENSOR/EDGE");
  Serial.println("TinyML bridge input        : CONTROLLED CONFIRMED OUTPUT");
  Serial.println("Actual model validation    : COMPLETED IN COMPONENT 1");
  Serial.println("Confirmations required     : 3");
  Serial.println("Revoke origin              : COMPONENT 1 TINYML DECISION");
  Serial.println("Revoke authentication      : ACTIVE NWKSKEY HMAC");
  Serial.println("Post-tamper telemetry      : DISABLED");
  Serial.println("Actual keys printed        : NO");
  Serial.println("Development master PSK     : YES");
  Serial.println("Production security claim  : NOT YET");
  Serial.println();

  startHandshake();
}

void loop() {
  serviceRadio();

  if (
    state == SensorState::BASELINE
    &&
    baselineSequence < BASELINE_PACKET_TARGET
    &&
    millis() - lastDataMs >= DATA_INTERVAL_MS
  ) {
    sendBaselinePacket();
  }

  if (
    state == SensorState::WAITING_PHYSICAL_TAMPER
    &&
    controlledTinyMlBridgeArmed
    &&
    millis() - lastTinyMlConfirmationMs
        >= TINYML_CONFIRMATION_INTERVAL_MS
  ) {
    if (
      tinyMlConfirmationCount
        < TINYML_CONFIRMATIONS_REQUIRED
    ) {
      tinyMlFinalProbability =
          CONTROLLED_TINYML_PROBABILITIES[
            tinyMlConfirmationCount
          ];

      tinyMlConfirmationCount++;
      lastTinyMlConfirmationMs = millis();

      Serial.println();
      Serial.println("TINYML SECURITY DECISION OUTPUT");
      Serial.print("Confirmation               : ");
      Serial.print(tinyMlConfirmationCount);
      Serial.print("/");
      Serial.println(TINYML_CONFIRMATIONS_REQUIRED);
      Serial.print("Anomaly probability        : ");
      Serial.println(tinyMlFinalProbability, 3);
      Serial.println("Predicted label            : ANOMALY");
      Serial.println("Bridge evidence type       : CONTROLLED_CONFIRMED_OUTPUT");
    }

    if (
      tinyMlConfirmationCount
        >= TINYML_CONFIRMATIONS_REQUIRED
    ) {
      controlledTinyMlBridgeArmed = false;
      buildAndSendRevocationRequest();
    }
  }

  if (
    (
      state == SensorState::WAITING_CHALLENGE
      ||
      state == SensorState::WAITING_CONFIRM
    )
    &&
    millis() - stateStartedMs
        >= HANDSHAKE_TIMEOUT_MS
  ) {
    if (
      state == SensorState::WAITING_CHALLENGE
      &&
      handshakeAttempts < MAX_HANDSHAKE_ATTEMPTS
    ) {
      Serial.println("Handshake timeout           : RETRY HELLO");
      sendHello();
    } else {
      failTest("Handshake timeout");
    }
  }

  if (
    state == SensorState::WAITING_REVOCATION_ACK
    &&
    millis() - stateStartedMs
        >= REVOCATION_ACK_TIMEOUT_MS
  ) {
    if (
      revocationRequestAttempts
        < MAX_REVOCATION_REQUEST_ATTEMPTS
    ) {
      Serial.println("Revocation ACK timeout      : RESEND REQUEST");
      transmitRevocationRequest();
    } else {
      failTest("Revocation ACK timeout");
    }
  }

  if (
    state == SensorState::REVOKED
    &&
    millis() - revokedAtMs
        >= POST_REVOKE_TEST_DELAY_MS
  ) {
    sendOldFrameAndPrintReport();
  }

  delay(5);
}
