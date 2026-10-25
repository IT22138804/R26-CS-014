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

constexpr size_t MAX_RADIO_LINE_LENGTH = 300;
constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 12000;
constexpr unsigned long REVOCATION_ACK_TIMEOUT_MS = 10000;
constexpr uint8_t MAX_REVOCATION_ATTEMPTS = 3;
constexpr uint32_t BASELINE_PACKET_TARGET = 2;

enum class GatewayState {
  LISTENING,
  WAITING_RESPONSE,
  ESTABLISHED,
  WAITING_REVOKE_ACK,
  REVOKED_WAIT_OLD_FRAME,
  FINISHED,
  FAILED
};

GatewayState state = GatewayState::LISTENING;

String radioLineBuffer;

uint32_t sessionId = 0;
uint32_t revokedSessionId = 0;
uint32_t lastBaselineSequence = 0;
uint32_t baselinePacketsAccepted = 0;
uint32_t revocationCounter = 0;
uint32_t revokedSessionPacketsRejected = 0;

uint8_t sensorNonce[NONCE_LENGTH] = {0};
uint8_t gatewayNonce[NONCE_LENGTH] = {0};
uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};

String sensorNonceHex;
String gatewayNonceHex;
String revocationReason =
    "EMERGENCY_SECURITY_EVENT";
String revocationNonceHex;
String lastRevocationCommand;

unsigned long stateStartedMs = 0;
uint8_t revocationAttempts = 0;

bool initialHandshakePassed = false;
bool revocationTriggered = false;
bool revocationCommandHmacBuilt = false;
bool sensorRevocationAckVerified = false;
bool appKeyZeroized = false;
bool nwkKeyZeroized = false;
bool revokedSessionStateActive = false;

void failTest(const String& reason) {
  Serial.println();
  Serial.println("EMERGENCY REVOCATION TEST FAILED");
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

  state = GatewayState::FAILED;
  Serial.println("STEP 38C GATEWAY RESULT   : REVIEW REQUIRED");
}

void handleHello(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    failTest("Malformed HELLO");
    return;
  }

  if (fields[1] != NODE_ID) {
    failTest("Unknown node ID");
    return;
  }

  sessionId =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  if (
    sessionId == 0
    ||
    !hexToBytes(
      fields[3],
      sensorNonce,
      sizeof(sensorNonce)
    )
  ) {
    failTest("Invalid HELLO values");
    return;
  }

  sensorNonceHex = fields[3];

  esp_fill_random(
    gatewayNonce,
    sizeof(gatewayNonce)
  );

  gatewayNonceHex =
      bytesToHex(
        gatewayNonce,
        sizeof(gatewayNonce)
      );

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

  const String base =
      handshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!truncatedHmac(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        "GW|" + base,
        proof
      )) {
    secureZeroize(proof, sizeof(proof));
    failTest("Gateway proof generation failed");
    return;
  }

  const String challenge =
      "C2_CHALLENGE_V1,"
      + String(sessionId)
      + ","
      + gatewayNonceHex
      + ","
      + bytesToHex(
          proof,
          sizeof(proof)
        );

  secureZeroize(proof, sizeof(proof));

  E32Serial.println(challenge);

  Serial.println("HELLO validation          : PASSED");
  Serial.print("Session ID                : ");
  Serial.println(sessionId);
  Serial.println("TX gateway challenge      : SENT");

  state = GatewayState::WAITING_RESPONSE;
  stateStartedMs = millis();
}

void handleResponse(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    failTest("Malformed response");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSession != sessionId) {
    failTest("Response session mismatch");
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
    failTest("Invalid response proof");
    return;
  }

  const String base =
      handshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const bool built =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        "SN|" + base,
        expectedProof
      );

  const bool valid =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!valid) {
    failTest("Sensor authentication failed");
    return;
  }

  uint8_t confirmationProof[PROOF_LENGTH] = {0};

  if (!truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        "OK|" + base,
        confirmationProof
      )) {
    secureZeroize(
      confirmationProof,
      sizeof(confirmationProof)
    );

    failTest("Confirmation generation failed");
    return;
  }

  const String confirmation =
      "C2_CONFIRM_V1,"
      + String(sessionId)
      + ","
      + bytesToHex(
          confirmationProof,
          sizeof(confirmationProof)
        );

  secureZeroize(
    confirmationProof,
    sizeof(confirmationProof)
  );

  E32Serial.println(confirmation);

  initialHandshakePassed = true;
  state = GatewayState::ESTABLISHED;

  Serial.println("Sensor authentication     : PASSED");
  Serial.println("Authenticated session     : ESTABLISHED");
  Serial.println("Waiting for 2 baseline packets...");
}

bool verifyDataFrame(const String fields[]) {
  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[4],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    return false;
  }

  const String transcript =
      dataTranscript(
        sessionId,
        static_cast<uint32_t>(
          strtoul(fields[2].c_str(), nullptr, 10)
        ),
        fields[3]
      );

  const bool built =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        expectedProof
      );

  const bool valid =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));
  return valid;
}

void sendRevocationCommand() {
  revocationCounter = 1;

  uint8_t revocationNonce[
      REVOCATION_NONCE_LENGTH
  ] = {0};

  esp_fill_random(
    revocationNonce,
    sizeof(revocationNonce)
  );

  revocationNonceHex =
      bytesToHex(
        revocationNonce,
        sizeof(revocationNonce)
      );

  secureZeroize(
    revocationNonce,
    sizeof(revocationNonce)
  );

  const String transcript =
      revocationTranscript(
        sessionId,
        revocationCounter,
        revocationReason,
        revocationNonceHex
      );

  uint8_t proof[PROOF_LENGTH] = {0};

  revocationCommandHmacBuilt =
      truncatedHmac(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        proof
      );

  if (!revocationCommandHmacBuilt) {
    secureZeroize(proof, sizeof(proof));
    failTest("Revocation command HMAC generation failed");
    return;
  }

  lastRevocationCommand =
      "C2_REVOKE_V1,"
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

  E32Serial.println(lastRevocationCommand);

  revocationAttempts = 1;
  revocationTriggered = true;
  state = GatewayState::WAITING_REVOKE_ACK;
  stateStartedMs = millis();

  Serial.println();
  Serial.println("EMERGENCY REVOCATION TRIGGERED");
  Serial.print("Revoked session ID        : ");
  Serial.println(sessionId);
  Serial.print("Revocation counter        : ");
  Serial.println(revocationCounter);
  Serial.print("Reason code               : ");
  Serial.println(revocationReason);
  Serial.println("Command HMAC              : PASSED");
  Serial.println("TX revocation command     : SENT");
}

void handleBaselineData(const String& line) {
  String fields[5];

  if (!splitCsv(line, fields, 5)) {
    failTest("Malformed baseline data");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  const uint32_t sequence =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  if (
    receivedSession != sessionId
    || fields[3] != "BASELINE"
    || sequence != lastBaselineSequence + 1
  ) {
    failTest("Baseline identifiers invalid");
    return;
  }

  if (!verifyDataFrame(fields)) {
    failTest("Baseline HMAC verification failed");
    return;
  }

  lastBaselineSequence = sequence;
  baselinePacketsAccepted++;

  Serial.print("Baseline packet accepted  : ");
  Serial.print(baselinePacketsAccepted);
  Serial.print("/");
  Serial.println(BASELINE_PACKET_TARGET);

  if (
    baselinePacketsAccepted
      == BASELINE_PACKET_TARGET
  ) {
    sendRevocationCommand();
  }
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
    || receivedCounter != revocationCounter
  ) {
    failTest("Revocation ACK identifiers invalid");
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
      revocationAckTranscript(
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

  sensorRevocationAckVerified =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!sensorRevocationAckVerified) {
    failTest("Sensor revocation ACK verification failed");
    return;
  }

  revokedSessionId = sessionId;

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

  revokedSessionStateActive = true;
  state = GatewayState::REVOKED_WAIT_OLD_FRAME;

  Serial.println();
  Serial.println("REVOCATION ACK VERIFIED");
  Serial.println("Sensor ACK HMAC           : PASSED");
  Serial.print("Gateway AppSKey zeroized  : ");
  Serial.println(appKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("Gateway NwkSKey zeroized  : ");
  Serial.println(nwkKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("Revoked-session marker    : ");
  Serial.println(
    revokedSessionStateActive ? "ACTIVE" : "FAILED"
  );
  Serial.println("Waiting for old-session test frame...");
}

void handlePostRevocationOldFrame(const String& line) {
  String fields[5];

  if (!splitCsv(line, fields, 5)) {
    failTest("Malformed old-session test frame");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (
    !revokedSessionStateActive
    || receivedSession != revokedSessionId
  ) {
    failTest("Old-session test did not use revoked session");
    return;
  }

  revokedSessionPacketsRejected++;

  Serial.println();
  Serial.println("REVOKED SESSION TRAFFIC REJECTED");
  Serial.print("Received session ID       : ");
  Serial.println(receivedSession);
  Serial.print("Revoked session ID        : ");
  Serial.println(revokedSessionId);
  Serial.println("HMAC verification         : NOT ATTEMPTED");
  Serial.println("Packet accepted           : NO");
  Serial.println("Reason                    : SESSION REVOKED");

  const bool passed =
      initialHandshakePassed
      &&
      baselinePacketsAccepted
          == BASELINE_PACKET_TARGET
      &&
      revocationTriggered
      &&
      revocationCommandHmacBuilt
      &&
      sensorRevocationAckVerified
      &&
      appKeyZeroized
      &&
      nwkKeyZeroized
      &&
      revokedSessionStateActive
      &&
      revokedSessionPacketsRejected == 1;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38C GATEWAY REPORT");
  Serial.println("==========================================");
  Serial.print("Initial handshake         : ");
  Serial.println(initialHandshakePassed ? "PASSED" : "FAILED");
  Serial.print("Baseline packets accepted : ");
  Serial.println(baselinePacketsAccepted);
  Serial.print("Emergency revoke trigger  : ");
  Serial.println(revocationTriggered ? "PASSED" : "FAILED");
  Serial.print("Revocation command HMAC   : ");
  Serial.println(
    revocationCommandHmacBuilt ? "PASSED" : "FAILED"
  );
  Serial.print("Sensor revocation ACK     : ");
  Serial.println(
    sensorRevocationAckVerified ? "PASSED" : "FAILED"
  );
  Serial.print("Gateway App key zeroized  : ");
  Serial.println(appKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("Gateway Nwk key zeroized  : ");
  Serial.println(nwkKeyZeroized ? "PASSED" : "FAILED");
  Serial.print("Revoked-session state     : ");
  Serial.println(
    revokedSessionStateActive ? "PASSED" : "FAILED"
  );
  Serial.print("Old-session packets reject: ");
  Serial.println(revokedSessionPacketsRejected);
  Serial.println("Post-revoke forwarding    : BLOCKED");
  Serial.println("Actual keys printed       : NO");
  Serial.print("STEP 38C GATEWAY RESULT   : ");
  Serial.println(passed ? "PASSED" : "REVIEW REQUIRED");
  Serial.println("==========================================");

  state = GatewayState::FINISHED;
}

void processIncomingLine(String line) {
  line.trim();

  if (line.length() == 0) {
    return;
  }

  const int comma = line.indexOf(',');

  Serial.print("RX message type           : ");
  Serial.println(
    comma >= 0
      ? line.substring(0, comma)
      : line
  );

  if (
    (
      state == GatewayState::LISTENING
      ||
      state == GatewayState::WAITING_RESPONSE
    )
    &&
    line.startsWith("C2_HELLO_V1,")
  ) {
    handleHello(line);
    return;
  }

  if (
    state == GatewayState::WAITING_RESPONSE
    &&
    line.startsWith("C2_RESPONSE_V1,")
  ) {
    handleResponse(line);
    return;
  }

  if (
    state == GatewayState::ESTABLISHED
    &&
    line.startsWith("C2_REV_DATA_V1,")
  ) {
    handleBaselineData(line);
    return;
  }

  if (
    state == GatewayState::WAITING_REVOKE_ACK
    &&
    line.startsWith("C2_REVOKE_ACK_V1,")
  ) {
    handleRevocationAck(line);
    return;
  }

  if (
    state == GatewayState::REVOKED_WAIT_OLD_FRAME
    &&
    line.startsWith("C2_REV_DATA_V1,")
  ) {
    handlePostRevocationOldFrame(line);
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
      Serial.println("Radio frame overflow      : RESET");
      continue;
    }

    radioLineBuffer += character;
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

  radioLineBuffer.reserve(
    MAX_RADIO_LINE_LENGTH
  );

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38C");
  Serial.println("EMERGENCY SESSION REVOCATION — GATEWAY");
  Serial.println("==========================================");
  Serial.println("Trigger                    : EMERGENCY SECURITY EVENT");
  Serial.println("Command authentication     : CURRENT NWKSKEY HMAC");
  Serial.println("Revocation counter         : MONOTONIC");
  Serial.println("Gateway revocation marker  : SRAM TEST ENTRY");
  Serial.println("Post-revoke forwarding     : BLOCKED");
  Serial.println("Actual keys printed        : NO");
  Serial.println("Development master PSK     : YES");
  Serial.println("Production security claim  : NOT YET");
  Serial.println("Waiting for sensor HELLO...");
  Serial.println();
}

void loop() {
  serviceRadio();

  if (
    state == GatewayState::WAITING_RESPONSE
    &&
    millis() - stateStartedMs
        >= HANDSHAKE_TIMEOUT_MS
  ) {
    failTest("Initial response timeout");
  }

  if (
    state == GatewayState::WAITING_REVOKE_ACK
    &&
    millis() - stateStartedMs
        >= REVOCATION_ACK_TIMEOUT_MS
  ) {
    if (
      revocationAttempts < MAX_REVOCATION_ATTEMPTS
      &&
      lastRevocationCommand.length() > 0
    ) {
      E32Serial.println(lastRevocationCommand);
      revocationAttempts++;
      stateStartedMs = millis();

      Serial.println("Revocation ACK timeout    : COMMAND RESENT");
    } else {
      failTest("Revocation ACK timeout");
    }
  }

  delay(5);
}
