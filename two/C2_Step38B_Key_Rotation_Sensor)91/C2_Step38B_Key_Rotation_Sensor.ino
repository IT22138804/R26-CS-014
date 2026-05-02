#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
constexpr size_t FINGERPRINT_LENGTH = 8;
constexpr size_t ROTATION_SEED_LENGTH = 16;
constexpr size_t ROTATION_KEK_LENGTH = 16;
constexpr size_t GCM_IV_LENGTH = 12;
constexpr size_t GCM_TAG_LENGTH = 16;

const char NODE_ID[] = "GH_NODE_01";

// Development-only master PSK.
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

bool calculateTruncatedProof(
    const uint8_t* key,
    size_t keyLength,
    const String& transcript,
    uint8_t output[PROOF_LENGTH]
) {
  uint8_t completeProof[SHA256_LENGTH] = {0};

  const bool success =
      hmacSha256(
        key,
        keyLength,
        reinterpret_cast<const uint8_t*>(
          transcript.c_str()
        ),
        transcript.length(),
        completeProof
      );

  if (success) {
    memcpy(output, completeProof, PROOF_LENGTH);
  }

  secureZeroize(
    completeProof,
    sizeof(completeProof)
  );

  return success;
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

  return
      mbedtls_md(
        information,
        data,
        length,
        output
      ) == 0;
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
      fields[fieldIndex++] = line.substring(start);
      break;
    }

    fields[fieldIndex++] =
        line.substring(start, comma);

    start = comma + 1;
  }

  return fieldIndex == expectedFields
      && line.indexOf(',', start) < 0;
}

bool aesGcmEncrypt(
    const uint8_t key[ROTATION_KEK_LENGTH],
    const uint8_t iv[GCM_IV_LENGTH],
    const String& aad,
    const uint8_t plaintext[ROTATION_SEED_LENGTH],
    uint8_t ciphertext[ROTATION_SEED_LENGTH],
    uint8_t tag[GCM_TAG_LENGTH]
) {
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  int result =
      mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        ROTATION_KEK_LENGTH * 8
      );

  if (result == 0) {
    result =
        mbedtls_gcm_crypt_and_tag(
          &context,
          MBEDTLS_GCM_ENCRYPT,
          ROTATION_SEED_LENGTH,
          iv,
          GCM_IV_LENGTH,
          reinterpret_cast<const uint8_t*>(
            aad.c_str()
          ),
          aad.length(),
          plaintext,
          ciphertext,
          GCM_TAG_LENGTH,
          tag
        );
  }

  mbedtls_gcm_free(&context);
  return result == 0;
}

bool aesGcmDecrypt(
    const uint8_t key[ROTATION_KEK_LENGTH],
    const uint8_t iv[GCM_IV_LENGTH],
    const String& aad,
    const uint8_t ciphertext[ROTATION_SEED_LENGTH],
    const uint8_t tag[GCM_TAG_LENGTH],
    uint8_t plaintext[ROTATION_SEED_LENGTH]
) {
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);

  int result =
      mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        ROTATION_KEK_LENGTH * 8
      );

  if (result == 0) {
    result =
        mbedtls_gcm_auth_decrypt(
          &context,
          ROTATION_SEED_LENGTH,
          iv,
          GCM_IV_LENGTH,
          reinterpret_cast<const uint8_t*>(
            aad.c_str()
          ),
          aad.length(),
          tag,
          GCM_TAG_LENGTH,
          ciphertext,
          plaintext
        );
  }

  mbedtls_gcm_free(&context);
  return result == 0;
}

bool deriveInitialSessionKeys(
    uint32_t initialSessionId,
    const uint8_t sensorNonce[NONCE_LENGTH],
    const uint8_t gatewayNonce[NONCE_LENGTH],
    uint8_t appSKey[SESSION_KEY_LENGTH],
    uint8_t nwkSKey[SESSION_KEY_LENGTH]
) {
  uint8_t salt[NONCE_LENGTH * 2] = {0};

  memcpy(salt, sensorNonce, NONCE_LENGTH);
  memcpy(
    salt + NONCE_LENGTH,
    gatewayNonce,
    NONCE_LENGTH
  );

  const String appInfo =
      "C2/"
      + String(NODE_ID)
      + "/APPSKEY/V1/"
      + String(initialSessionId);

  const String nwkInfo =
      "C2/"
      + String(NODE_ID)
      + "/NWKSKEY/V1/"
      + String(initialSessionId);

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

bool deriveRotationKek(
    uint32_t oldSessionId,
    uint32_t rotationCounter,
    const uint8_t currentNwkSKey[SESSION_KEY_LENGTH],
    uint8_t outputKek[ROTATION_KEK_LENGTH]
) {
  const String info =
      "C2/ROTATION/KEK/V1/"
      + String(oldSessionId)
      + "/"
      + String(rotationCounter);

  return hkdfSha256(
    DEVELOPMENT_MASTER_PSK,
    sizeof(DEVELOPMENT_MASTER_PSK),
    currentNwkSKey,
    SESSION_KEY_LENGTH,
    reinterpret_cast<const uint8_t*>(
      info.c_str()
    ),
    info.length(),
    outputKek,
    ROTATION_KEK_LENGTH
  );
}

bool deriveRotatedSessionKeys(
    uint32_t newSessionId,
    uint32_t rotationCounter,
    const uint8_t rotationSeed[ROTATION_SEED_LENGTH],
    uint8_t appSKey[SESSION_KEY_LENGTH],
    uint8_t nwkSKey[SESSION_KEY_LENGTH]
) {
  const String appInfo =
      "C2/"
      + String(NODE_ID)
      + "/APPSKEY/ROT/V1/"
      + String(newSessionId)
      + "/"
      + String(rotationCounter);

  const String nwkInfo =
      "C2/"
      + String(NODE_ID)
      + "/NWKSKEY/ROT/V1/"
      + String(newSessionId)
      + "/"
      + String(rotationCounter);

  const bool appPassed =
      hkdfSha256(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        rotationSeed,
        ROTATION_SEED_LENGTH,
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
        rotationSeed,
        ROTATION_SEED_LENGTH,
        reinterpret_cast<const uint8_t*>(
          nwkInfo.c_str()
        ),
        nwkInfo.length(),
        nwkSKey,
        SESSION_KEY_LENGTH
      );

  return appPassed && nwkPassed;
}

String buildHandshakeTranscript(
    uint32_t handshakeSessionId,
    const String& sensorNonceHex,
    const String& gatewayNonceHex
) {
  return
      String(NODE_ID)
      + "|"
      + String(handshakeSessionId)
      + "|"
      + sensorNonceHex
      + "|"
      + gatewayNonceHex;
}

String buildRotationAad(
    uint32_t oldSessionId,
    uint32_t newSessionId,
    uint32_t rotationCounter
) {
  return
      "ROTATE|"
      + String(NODE_ID)
      + "|"
      + String(oldSessionId)
      + "|"
      + String(newSessionId)
      + "|"
      + String(rotationCounter);
}

String buildRotationOuterTranscript(
    const String& aad,
    const String& ivHex,
    const String& ciphertextHex,
    const String& tagHex
) {
  return
      aad
      + "|"
      + ivHex
      + "|"
      + ciphertextHex
      + "|"
      + tagHex;
}

String buildRotationAckTranscript(
    uint32_t oldSessionId,
    uint32_t newSessionId,
    uint32_t rotationCounter,
    const String& appFingerprint,
    const String& nwkFingerprint
) {
  return
      "ROT_ACK|"
      + String(NODE_ID)
      + "|"
      + String(oldSessionId)
      + "|"
      + String(newSessionId)
      + "|"
      + String(rotationCounter)
      + "|"
      + appFingerprint
      + "|"
      + nwkFingerprint;
}

String buildRotationConfirmTranscript(
    uint32_t oldSessionId,
    uint32_t newSessionId,
    uint32_t rotationCounter
) {
  return
      "ROT_OK|"
      + String(NODE_ID)
      + "|"
      + String(oldSessionId)
      + "|"
      + String(newSessionId)
      + "|"
      + String(rotationCounter);
}


HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

constexpr size_t MAX_RADIO_LINE_LENGTH = 360;
constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 10000;
constexpr unsigned long DATA_INTERVAL_MS = 1200;
constexpr unsigned long ROTATION_TIMEOUT_MS = 10000;
constexpr uint8_t MAX_HANDSHAKE_ATTEMPTS = 5;
constexpr uint8_t MAX_ROTATION_ACK_ATTEMPTS = 3;
constexpr uint32_t TEST_ROTATION_THRESHOLD_PACKETS = 3;
constexpr uint32_t PRODUCTION_ROTATION_PACKET_LIMIT = 1000;
constexpr uint32_t PRODUCTION_ROTATION_HOURS = 24;

String radioLineBuffer;

enum class SensorState {
  STARTING,
  WAITING_CHALLENGE,
  WAITING_CONFIRM,
  BASELINE_DATA,
  WAITING_ROTATE_CONFIRM,
  POST_ROTATION_DATA,
  WAITING_POST_ACK,
  FINISHED,
  FAILED
};

SensorState state = SensorState::STARTING;

uint32_t sessionId = 0;
uint32_t pendingNewSessionId = 0;
uint32_t rotationCounter = 0;
uint32_t baselineSequence = 0;
uint32_t postRotationSequence = 0;

uint8_t sensorNonce[NONCE_LENGTH] = {0};
uint8_t gatewayNonce[NONCE_LENGTH] = {0};

uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};

uint8_t pendingAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t pendingNwkSKey[SESSION_KEY_LENGTH] = {0};

uint8_t oldAppSKeyCopy[SESSION_KEY_LENGTH] = {0};
uint8_t oldNwkSKeyCopy[SESSION_KEY_LENGTH] = {0};

String sensorNonceHex;
String gatewayNonceHex;

String initialAppFingerprint;
String initialNwkFingerprint;
String rotatedAppFingerprint;
String rotatedNwkFingerprint;
String lastRotationAckFrame;
String lastPostRotationDataFrame;

unsigned long stateStartedMs = 0;
unsigned long lastDataSentMs = 0;

uint8_t handshakeAttempts = 0;
uint8_t rotationAckAttempts = 0;
uint8_t postDataAttempts = 0;

bool initialKeysDerived = false;
bool gatewayAuthenticated = false;
bool rotationOuterHmacPassed = false;
bool rotationSeedDecryptPassed = false;
bool rotatedKeysDerived = false;
bool rotationConfirmPassed = false;
bool initialAppKeyZeroized = false;
bool initialNwkKeyZeroized = false;
bool fingerprintsChanged = false;
bool postRotationAckPassed = false;

void failTest(const String& reason) {
  Serial.println();
  Serial.println("KEY ROTATION TEST FAILED");
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

  secureZeroize(
    pendingAppSKey,
    sizeof(pendingAppSKey)
  );

  secureZeroize(
    pendingNwkSKey,
    sizeof(pendingNwkSKey)
  );

  state = SensorState::FAILED;
  Serial.println("STEP 38B SENSOR RESULT    : REVIEW REQUIRED");
}

String fingerprintOf(
    const uint8_t* key,
    size_t keyLength
) {
  uint8_t fingerprint[FINGERPRINT_LENGTH] = {0};

  if (!calculateFingerprint(
        key,
        keyLength,
        fingerprint
      )) {
    secureZeroize(
      fingerprint,
      sizeof(fingerprint)
    );

    return "FAILED";
  }

  const String value =
      bytesToHex(
        fingerprint,
        sizeof(fingerprint)
      );

  secureZeroize(
    fingerprint,
    sizeof(fingerprint)
  );

  return value;
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

  Serial.print("TX HELLO attempt          : ");
  Serial.print(handshakeAttempts);
  Serial.print("/");
  Serial.println(MAX_HANDSHAKE_ATTEMPTS);

  Serial.print("Initial session ID        : ");
  Serial.println(sessionId);

  state = SensorState::WAITING_CHALLENGE;
  stateStartedMs = millis();
}

void startInitialHandshake() {
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
    failTest("Challenge session mismatch");
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
      buildHandshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const bool proofBuilt =
      calculateTruncatedProof(
        DEVELOPMENT_MASTER_PSK,
        sizeof(DEVELOPMENT_MASTER_PSK),
        "GW|" + base,
        expectedProof
      );

  gatewayAuthenticated =
      proofBuilt
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!gatewayAuthenticated) {
    failTest("Gateway authentication failed");
    return;
  }

  initialKeysDerived =
      deriveInitialSessionKeys(
        sessionId,
        sensorNonce,
        gatewayNonce,
        runtimeAppSKey,
        runtimeNwkSKey
      );

  if (!initialKeysDerived) {
    failTest("Initial key derivation failed");
    return;
  }

  initialAppFingerprint =
      fingerprintOf(
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  initialNwkFingerprint =
      fingerprintOf(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  uint8_t sensorProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        "SN|" + base,
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

  Serial.println("Gateway authentication    : PASSED");
  Serial.println("Initial key derivation    : PASSED");
  Serial.print("Initial App fingerprint   : ");
  Serial.println(initialAppFingerprint);
  Serial.print("Initial Nwk fingerprint   : ");
  Serial.println(initialNwkFingerprint);
  Serial.println("TX sensor proof           : SENT");

  state = SensorState::WAITING_CONFIRM;
  stateStartedMs = millis();
}

void handleInitialConfirm(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    failTest("Malformed initial confirmation");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSession != sessionId) {
    failTest("Initial confirmation session mismatch");
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
    failTest("Invalid initial confirmation proof");
    return;
  }

  const String base =
      buildHandshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const bool built =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        "OK|" + base,
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
    failTest("Initial confirmation authentication failed");
    return;
  }

  Serial.println();
  Serial.println("INITIAL AUTHENTICATED SESSION ESTABLISHED");
  Serial.print("Initial session ID        : ");
  Serial.println(sessionId);
  Serial.println("Key transport             : NONE");
  Serial.println("Baseline packet target    : 3");
  Serial.println();

  state = SensorState::BASELINE_DATA;
  baselineSequence = 0;
  lastDataSentMs = millis();
}

String createDataFrame(
    uint32_t frameSessionId,
    uint32_t sequence,
    const String& label,
    const uint8_t nwkKey[SESSION_KEY_LENGTH]
) {
  const String transcript =
      "ROT_DATA|"
      + String(NODE_ID)
      + "|"
      + String(frameSessionId)
      + "|"
      + String(sequence)
      + "|"
      + label;

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        nwkKey,
        SESSION_KEY_LENGTH,
        transcript,
        proof
      )) {
    secureZeroize(proof, sizeof(proof));
    return "";
  }

  const String frame =
      "C2_ROT_DATA_V1,"
      + String(frameSessionId)
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

void sendBaselineData() {
  baselineSequence++;

  const String frame =
      createDataFrame(
        sessionId,
        baselineSequence,
        "BASELINE",
        runtimeNwkSKey
      );

  if (frame.length() == 0) {
    failTest("Baseline data proof generation failed");
    return;
  }

  E32Serial.println(frame);

  Serial.print("TX baseline packet        : ");
  Serial.print(baselineSequence);
  Serial.print("/");
  Serial.println(TEST_ROTATION_THRESHOLD_PACKETS);

  lastDataSentMs = millis();

  if (
    baselineSequence
      == TEST_ROTATION_THRESHOLD_PACKETS
  ) {
    Serial.println("Waiting for gateway KEY_ROTATE...");
  }
}

void sendRotationAck() {
  rotatedAppFingerprint =
      fingerprintOf(
        pendingAppSKey,
        sizeof(pendingAppSKey)
      );

  rotatedNwkFingerprint =
      fingerprintOf(
        pendingNwkSKey,
        sizeof(pendingNwkSKey)
      );

  const String transcript =
      buildRotationAckTranscript(
        sessionId,
        pendingNewSessionId,
        rotationCounter,
        rotatedAppFingerprint,
        rotatedNwkFingerprint
      );

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        pendingNwkSKey,
        sizeof(pendingNwkSKey),
        transcript,
        proof
      )) {
    secureZeroize(proof, sizeof(proof));
    failTest("Rotation ACK proof generation failed");
    return;
  }

  lastRotationAckFrame =
      "C2_KEY_ROTATE_ACK_V1,"
      + String(sessionId)
      + ","
      + String(pendingNewSessionId)
      + ","
      + String(rotationCounter)
      + ","
      + rotatedAppFingerprint
      + ","
      + rotatedNwkFingerprint
      + ","
      + bytesToHex(
          proof,
          sizeof(proof)
        );

  secureZeroize(proof, sizeof(proof));

  E32Serial.println(lastRotationAckFrame);
  rotationAckAttempts++;

  Serial.println("TX rotation ACK           : SENT");
  Serial.print("Rotated App fingerprint   : ");
  Serial.println(rotatedAppFingerprint);
  Serial.print("Rotated Nwk fingerprint   : ");
  Serial.println(rotatedNwkFingerprint);

  state = SensorState::WAITING_ROTATE_CONFIRM;
  stateStartedMs = millis();
}

void handleRotationCommand(const String& line) {
  String fields[8];

  if (!splitCsv(line, fields, 8)) {
    failTest("Malformed KEY_ROTATE frame");
    return;
  }

  const uint32_t oldSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  pendingNewSessionId =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  rotationCounter =
      static_cast<uint32_t>(
        strtoul(fields[3].c_str(), nullptr, 10)
      );

  if (
    oldSession != sessionId
    || pendingNewSessionId == 0
    || rotationCounter == 0
  ) {
    failTest("KEY_ROTATE identifiers invalid");
    return;
  }

  uint8_t iv[GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[ROTATION_SEED_LENGTH] = {0};
  uint8_t gcmTag[GCM_TAG_LENGTH] = {0};
  uint8_t receivedOuter[PROOF_LENGTH] = {0};
  uint8_t expectedOuter[PROOF_LENGTH] = {0};
  uint8_t rotationKek[ROTATION_KEK_LENGTH] = {0};
  uint8_t rotationSeed[ROTATION_SEED_LENGTH] = {0};

  const bool decoded =
      hexToBytes(fields[4], iv, sizeof(iv))
      &&
      hexToBytes(
        fields[5],
        ciphertext,
        sizeof(ciphertext)
      )
      &&
      hexToBytes(
        fields[6],
        gcmTag,
        sizeof(gcmTag)
      )
      &&
      hexToBytes(
        fields[7],
        receivedOuter,
        sizeof(receivedOuter)
      );

  if (!decoded) {
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    secureZeroize(receivedOuter, sizeof(receivedOuter));
    failTest("KEY_ROTATE hex decoding failed");
    return;
  }

  const String aad =
      buildRotationAad(
        sessionId,
        pendingNewSessionId,
        rotationCounter
      );

  const String outerTranscript =
      buildRotationOuterTranscript(
        aad,
        fields[4],
        fields[5],
        fields[6]
      );

  const bool outerBuilt =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        expectedOuter
      );

  rotationOuterHmacPassed =
      outerBuilt
      && constantTimeEqual(
        receivedOuter,
        expectedOuter,
        PROOF_LENGTH
      );

  secureZeroize(
    receivedOuter,
    sizeof(receivedOuter)
  );

  secureZeroize(
    expectedOuter,
    sizeof(expectedOuter)
  );

  if (!rotationOuterHmacPassed) {
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(gcmTag, sizeof(gcmTag));
    failTest("KEY_ROTATE outer HMAC failed");
    return;
  }

  const bool kekPassed =
      deriveRotationKek(
        sessionId,
        rotationCounter,
        runtimeNwkSKey,
        rotationKek
      );

  rotationSeedDecryptPassed =
      kekPassed
      &&
      aesGcmDecrypt(
        rotationKek,
        iv,
        aad,
        ciphertext,
        gcmTag,
        rotationSeed
      );

  secureZeroize(rotationKek, sizeof(rotationKek));
  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(gcmTag, sizeof(gcmTag));

  if (!rotationSeedDecryptPassed) {
    secureZeroize(
      rotationSeed,
      sizeof(rotationSeed)
    );

    failTest("Rotation seed AES-GCM decryption failed");
    return;
  }

  rotatedKeysDerived =
      deriveRotatedSessionKeys(
        pendingNewSessionId,
        rotationCounter,
        rotationSeed,
        pendingAppSKey,
        pendingNwkSKey
      );

  secureZeroize(
    rotationSeed,
    sizeof(rotationSeed)
  );

  if (!rotatedKeysDerived) {
    failTest("Rotated key derivation failed");
    return;
  }

  Serial.println();
  Serial.println("KEY ROTATION COMMAND VALIDATED");
  Serial.println("Outer HMAC verification   : PASSED");
  Serial.println("Rotation KEK derivation   : PASSED");
  Serial.println("Seed AES-GCM decryption   : PASSED");
  Serial.println("Rotated key derivation    : PASSED");
  Serial.print("Pending new session ID    : ");
  Serial.println(pendingNewSessionId);

  rotationAckAttempts = 0;
  sendRotationAck();
}

void handleRotationConfirm(const String& line) {
  String fields[5];

  if (!splitCsv(line, fields, 5)) {
    failTest("Malformed rotation confirmation");
    return;
  }

  const uint32_t oldSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  const uint32_t newSession =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  const uint32_t receivedCounter =
      static_cast<uint32_t>(
        strtoul(fields[3].c_str(), nullptr, 10)
      );

  if (
    oldSession != sessionId
    || newSession != pendingNewSessionId
    || receivedCounter != rotationCounter
  ) {
    failTest("Rotation confirmation identifiers invalid");
    return;
  }

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[4],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    failTest("Rotation confirmation proof encoding invalid");
    return;
  }

  const String transcript =
      buildRotationConfirmTranscript(
        sessionId,
        pendingNewSessionId,
        rotationCounter
      );

  const bool built =
      calculateTruncatedProof(
        pendingNwkSKey,
        sizeof(pendingNwkSKey),
        transcript,
        expectedProof
      );

  rotationConfirmPassed =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!rotationConfirmPassed) {
    failTest("Rotation confirmation authentication failed");
    return;
  }

  memcpy(
    oldAppSKeyCopy,
    runtimeAppSKey,
    sizeof(oldAppSKeyCopy)
  );

  memcpy(
    oldNwkSKeyCopy,
    runtimeNwkSKey,
    sizeof(oldNwkSKeyCopy)
  );

  memcpy(
    runtimeAppSKey,
    pendingAppSKey,
    sizeof(runtimeAppSKey)
  );

  memcpy(
    runtimeNwkSKey,
    pendingNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  secureZeroize(
    oldAppSKeyCopy,
    sizeof(oldAppSKeyCopy)
  );

  secureZeroize(
    oldNwkSKeyCopy,
    sizeof(oldNwkSKeyCopy)
  );

  secureZeroize(
    pendingAppSKey,
    sizeof(pendingAppSKey)
  );

  secureZeroize(
    pendingNwkSKey,
    sizeof(pendingNwkSKey)
  );

  initialAppKeyZeroized =
      isAllZero(
        oldAppSKeyCopy,
        sizeof(oldAppSKeyCopy)
      );

  initialNwkKeyZeroized =
      isAllZero(
        oldNwkSKeyCopy,
        sizeof(oldNwkSKeyCopy)
      );

  fingerprintsChanged =
      initialAppFingerprint
          != rotatedAppFingerprint
      &&
      initialNwkFingerprint
          != rotatedNwkFingerprint;

  sessionId = pendingNewSessionId;
  pendingNewSessionId = 0;
  postRotationSequence = 0;

  Serial.println();
  Serial.println("ATOMIC KEY ROTATION COMPLETED");
  Serial.print("New active session ID     : ");
  Serial.println(sessionId);
  Serial.print("Initial App key zeroized  : ");
  Serial.println(
    initialAppKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Initial Nwk key zeroized  : ");
  Serial.println(
    initialNwkKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Key fingerprints changed  : ");
  Serial.println(
    fingerprintsChanged
      ? "PASSED"
      : "FAILED"
  );

  state = SensorState::POST_ROTATION_DATA;
  lastDataSentMs = millis();
}

void sendPostRotationData() {
  postRotationSequence = 1;

  lastPostRotationDataFrame =
      createDataFrame(
        sessionId,
        postRotationSequence,
        "POST_ROTATION",
        runtimeNwkSKey
      );

  if (lastPostRotationDataFrame.length() == 0) {
    failTest("Post-rotation proof generation failed");
    return;
  }

  E32Serial.println(lastPostRotationDataFrame);
  postDataAttempts++;

  Serial.println();
  Serial.println("POST-ROTATION DATA SENT");
  Serial.print("New session ID            : ");
  Serial.println(sessionId);
  Serial.println("Sequence                  : 1");
  Serial.println("Protected with new NwkSKey: YES");

  state = SensorState::WAITING_POST_ACK;
  stateStartedMs = millis();
}

void printFinalReport() {
  const bool passed =
      initialKeysDerived
      &&
      gatewayAuthenticated
      &&
      rotationOuterHmacPassed
      &&
      rotationSeedDecryptPassed
      &&
      rotatedKeysDerived
      &&
      rotationConfirmPassed
      &&
      initialAppKeyZeroized
      &&
      initialNwkKeyZeroized
      &&
      fingerprintsChanged
      &&
      postRotationAckPassed;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38B SENSOR REPORT");
  Serial.println("==========================================");
  Serial.println("Initial handshake         : PASSED");
  Serial.print("Baseline packets sent     : ");
  Serial.println(baselineSequence);
  Serial.println("Rotation command HMAC     : PASSED");
  Serial.println("Rotation seed decryption  : PASSED");
  Serial.println("Rotated key derivation    : PASSED");
  Serial.println("Rotation confirmation     : PASSED");
  Serial.print("Initial App key zeroized  : ");
  Serial.println(
    initialAppKeyZeroized ? "PASSED" : "FAILED"
  );
  Serial.print("Initial Nwk key zeroized  : ");
  Serial.println(
    initialNwkKeyZeroized ? "PASSED" : "FAILED"
  );
  Serial.print("Key fingerprints changed  : ");
  Serial.println(
    fingerprintsChanged ? "PASSED" : "FAILED"
  );
  Serial.print("Post-rotation packet ACK  : ");
  Serial.println(
    postRotationAckPassed ? "PASSED" : "FAILED"
  );
  Serial.print("Test rotation threshold   : ");
  Serial.println(TEST_ROTATION_THRESHOLD_PACKETS);
  Serial.print("Production packet limit   : ");
  Serial.println(PRODUCTION_ROTATION_PACKET_LIMIT);
  Serial.print("Production time limit     : ");
  Serial.print(PRODUCTION_ROTATION_HOURS);
  Serial.println(" hours");
  Serial.println("Actual keys printed       : NO");
  Serial.print("STEP 38B SENSOR RESULT    : ");
  Serial.println(
    passed ? "PASSED" : "REVIEW REQUIRED"
  );
  Serial.println("==========================================");

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  state = SensorState::FINISHED;
}

void handlePostRotationAck(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    failTest("Malformed post-rotation ACK");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  const uint32_t receivedSequence =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  if (
    receivedSession != sessionId
    || receivedSequence != 1
  ) {
    failTest("Post-rotation ACK identifiers invalid");
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
    failTest("Post-rotation ACK proof invalid");
    return;
  }

  const String transcript =
      "POST_ACK|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|1";

  const bool built =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        expectedProof
      );

  postRotationAckPassed =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  if (!postRotationAckPassed) {
    failTest("Post-rotation ACK authentication failed");
    return;
  }

  printFinalReport();
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
    handleInitialConfirm(line);
    return;
  }

  if (
    (
      state == SensorState::BASELINE_DATA
      ||
      state == SensorState::WAITING_ROTATE_CONFIRM
    )
    &&
    line.startsWith("C2_KEY_ROTATE_V1,")
  ) {
    if (
      state
        == SensorState::WAITING_ROTATE_CONFIRM
      &&
      lastRotationAckFrame.length() > 0
    ) {
      E32Serial.println(lastRotationAckFrame);
      Serial.println("Duplicate KEY_ROTATE      : ACK RESENT");
    } else {
      handleRotationCommand(line);
    }

    return;
  }

  if (
    state == SensorState::WAITING_ROTATE_CONFIRM
    &&
    line.startsWith("C2_KEY_ROTATE_CONFIRM_V1,")
  ) {
    handleRotationConfirm(line);
    return;
  }

  if (
    state == SensorState::WAITING_POST_ACK
    &&
    line.startsWith("C2_POST_ROT_ACK_V1,")
  ) {
    handlePostRotationAck(line);
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
  Serial.println("COMPONENT 2 — STEP 38B");
  Serial.println("AUTOMATED SESSION-KEY ROTATION — SENSOR");
  Serial.println("==========================================");
  Serial.println("Radio mode                : TRANSPARENT");
  Serial.println("Initial keys              : HKDF-SHA256");
  Serial.println("Rotation seed protection  : MASTER-DERIVED AES-GCM KEK");
  Serial.println("Rotation command auth     : CURRENT NWKSKEY HMAC");
  Serial.println("Rotated keys              : HKDF-SHA256");
  Serial.println("Test trigger              : 3 accepted packets");
  Serial.println("Production trigger        : 1000 packets OR 24 hours");
  Serial.println("Actual keys printed       : NO");
  Serial.println("Development master PSK    : YES");
  Serial.println("Production security claim : NOT YET");
  Serial.println();

  startInitialHandshake();
}

void loop() {
  serviceRadio();

  if (
    state == SensorState::BASELINE_DATA
    &&
    baselineSequence
      < TEST_ROTATION_THRESHOLD_PACKETS
    &&
    millis() - lastDataSentMs
        >= DATA_INTERVAL_MS
  ) {
    sendBaselineData();
  }

  if (
    state == SensorState::POST_ROTATION_DATA
    &&
    millis() - lastDataSentMs
        >= DATA_INTERVAL_MS
  ) {
    sendPostRotationData();
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
      Serial.println("Initial handshake timeout : RETRY HELLO");
      sendHello();
    } else {
      failTest("Initial handshake timeout");
    }
  }

  if (
    state == SensorState::WAITING_ROTATE_CONFIRM
    &&
    millis() - stateStartedMs
        >= ROTATION_TIMEOUT_MS
  ) {
    if (
      rotationAckAttempts
        < MAX_ROTATION_ACK_ATTEMPTS
      &&
      lastRotationAckFrame.length() > 0
    ) {
      E32Serial.println(lastRotationAckFrame);
      rotationAckAttempts++;
      stateStartedMs = millis();

      Serial.println("Rotation confirm timeout  : ACK RESENT");
    } else {
      failTest("Rotation confirmation timeout");
    }
  }

  if (
    state == SensorState::WAITING_POST_ACK
    &&
    millis() - stateStartedMs
        >= ROTATION_TIMEOUT_MS
  ) {
    if (
      postDataAttempts < 3
      &&
      lastPostRotationDataFrame.length() > 0
    ) {
      E32Serial.println(lastPostRotationDataFrame);
      postDataAttempts++;
      stateStartedMs = millis();

      Serial.println("Post-rotation ACK timeout : DATA RESENT");
    } else {
      failTest("Post-rotation ACK timeout");
    }
  }

  delay(5);
}
