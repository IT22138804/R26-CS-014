/*
  Component 2 — Step 36B
  Authenticated handshake — Sensor ESP32
*/


#include <Arduino.h>
#include <mbedtls/md.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
constexpr size_t FINGERPRINT_LENGTH = 8;

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

constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 5000;
constexpr unsigned long KEY_ACTIVE_WINDOW_MS = 15000;
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
  Serial.println("Key active window         : 15 seconds");
  Serial.println("STEP 36B SENSOR RESULT    : PASSED");
  Serial.println("==========================================");
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

void setup() {
  Serial.begin(115200);
  delay(1200);

  pinMode(E32_AUX_PIN, INPUT);

  E32Serial.begin(
    9600,
    SERIAL_8N1,
    E32_RX_PIN,
    E32_TX_PIN
  );

  E32Serial.setTimeout(300);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 36B");
  Serial.println("AUTHENTICATED HANDSHAKE — SENSOR");
  Serial.println("==========================================");
  Serial.println("Radio mode                : TRANSPARENT");
  Serial.println("Gateway authentication    : HMAC-SHA256");
  Serial.println("Sensor authentication     : HMAC-SHA256");
  Serial.println("Session keys              : HKDF-SHA256");
  Serial.println("Actual keys printed       : NO");
  Serial.println("Development PSK           : YES");
  Serial.println("Production security claim : NOT YET");
  Serial.println();

  delay(1000);
  startNewHandshake();
}

void loop() {
  while (E32Serial.available() > 0) {
    String line =
        E32Serial.readStringUntil('\n');

    processIncomingLine(line);
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
    millis() - establishedAtMs
        >= KEY_ACTIVE_WINDOW_MS
  ) {
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
    Serial.println("SESSION EXPIRY ZEROIZATION");
    Serial.print("AppSKey zeroization       : ");
    Serial.println(appZeroized ? "PASSED" : "FAILED");
    Serial.print("NwkSKey zeroization       : ");
    Serial.println(nwkZeroized ? "PASSED" : "FAILED");

    handshakeState =
        SensorHandshakeState::ZEROIZED;
  }

  delay(5);
}
