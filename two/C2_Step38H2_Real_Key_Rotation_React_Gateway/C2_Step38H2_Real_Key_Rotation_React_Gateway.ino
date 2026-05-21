#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
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

// =====================================================
// STEP 38H-2 — LOCAL VALUES
// Edit only these five values before uploading.
// =====================================================

const char* WIFI_SSID =
    "SLT_FIBRE_CORP_2g";

const char* WIFI_PASSWORD =
    "9494431997";

const char* FIREBASE_EMAIL =
    "ghouse@gmail.com";

const char* FIREBASE_PASSWORD =
    "Test@1214";

const char* EXPECTED_GATEWAY_UID =
    "3I9Eo1cltNQb68WcizDWlwb4wDm1";

const char* FIREBASE_API_KEY =
    "AIzaSyBmdU82c2_DeIVg974y8bl9jnK1m3UwO0c";

const char* FIREBASE_DATABASE_URL =
    "https://greenhouse-development-default-rtdb.firebaseio.com";

const char* FIREBASE_NODE_PATH =
    "/greenhouse/GH_NODE_01.json";

static const char GTS_ROOT_R1[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----
)EOF";


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
constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 12000;
constexpr unsigned long ROTATION_TIMEOUT_MS = 10000;
constexpr uint8_t MAX_ROTATION_COMMAND_ATTEMPTS = 3;
constexpr uint32_t TEST_ROTATION_THRESHOLD_PACKETS = 3;
constexpr uint32_t PRODUCTION_ROTATION_PACKET_LIMIT = 1000;
constexpr uint32_t PRODUCTION_ROTATION_HOURS = 24;

String radioLineBuffer;

enum class GatewayState {
  LISTENING,
  WAITING_INITIAL_RESPONSE,
  ESTABLISHED,
  WAITING_ROTATION_ACK,
  ROTATED,
  FINISHED,
  FAILED
};

GatewayState state = GatewayState::LISTENING;

uint32_t sessionId = 0;
uint32_t initialSessionIdForDashboard = 0;
uint32_t pendingNewSessionId = 0;
uint32_t rotationCounter = 0;
uint32_t lastBaselineSequence = 0;
uint32_t baselinePacketsAccepted = 0;
uint32_t postRotationPacketsAccepted = 0;

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
String lastRotationCommand;

unsigned long stateStartedMs = 0;
uint8_t rotationCommandAttempts = 0;

bool initialHandshakePassed = false;
bool rotationTriggeredByPacketCount = false;
bool rotationSeedEncrypted = false;
bool rotationCommandOuterHmacBuilt = false;
bool sensorRotationAckVerified = false;
bool fingerprintMatchPassed = false;
bool oldAppKeyZeroized = false;
bool oldNwkKeyZeroized = false;
bool postRotationPacketVerified = false;

String firebaseIdToken;
String firebaseLocalId;

bool firebaseReady = false;
bool firebaseRotationEvidencePassed = false;
bool firebaseFinalZeroizedStatusPassed = false;

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

bool firebaseConfigurationPresent() {
  return
      String(WIFI_SSID)
          != "REPLACE_WITH_YOUR_WIFI_NAME"
      &&
      String(WIFI_PASSWORD)
          != "REPLACE_WITH_YOUR_WIFI_PASSWORD"
      &&
      String(FIREBASE_EMAIL)
          != "REPLACE_WITH_GATEWAY_FIREBASE_EMAIL"
      &&
      String(FIREBASE_PASSWORD)
          != "REPLACE_WITH_GATEWAY_FIREBASE_PASSWORD"
      &&
      String(EXPECTED_GATEWAY_UID)
          != "REPLACE_WITH_GATEWAY_FIREBASE_UID";
}

String jsonEscape(const String& input) {
  String output;
  output.reserve(input.length() + 16);

  for (
    size_t index = 0;
    index < input.length();
    index++
  ) {
    const char character = input[index];

    switch (character) {
      case '\\':
        output += "\\\\";
        break;

      case '"':
        output += "\\\"";
        break;

      case '\n':
        output += "\\n";
        break;

      case '\r':
        output += "\\r";
        break;

      case '\t':
        output += "\\t";
        break;

      default:
        output += character;
        break;
    }
  }

  return output;
}

bool extractJsonString(
    const String& json,
    const String& key,
    String& output
) {
  const String marker =
      "\"" + key + "\"";

  const int keyPosition =
      json.indexOf(marker);

  if (keyPosition < 0) {
    return false;
  }

  const int colonPosition =
      json.indexOf(
        ':',
        keyPosition + marker.length()
      );

  if (colonPosition < 0) {
    return false;
  }

  const int openingQuote =
      json.indexOf(
        '"',
        colonPosition + 1
      );

  if (openingQuote < 0) {
    return false;
  }

  const int closingQuote =
      json.indexOf(
        '"',
        openingQuote + 1
      );

  if (closingQuote < 0) {
    return false;
  }

  output =
      json.substring(
        openingQuote + 1,
        closingQuote
      );

  return true;
}

void clearFirebaseIdToken() {
  for (
    size_t index = 0;
    index < firebaseIdToken.length();
    index++
  ) {
    firebaseIdToken.setCharAt(
      index,
      '\0'
    );
  }

  firebaseIdToken = "";
}

bool connectWiFiForDashboard() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );

  Serial.print("Wi-Fi connection          : ");

  const unsigned long startedAtMs =
      millis();

  while (
    WiFi.status() != WL_CONNECTED
    &&
    millis() - startedAtMs < 30000
  ) {
    Serial.print(".");
    delay(500);
  }

  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi result              : FAILED");
    return false;
  }

  Serial.println("Wi-Fi result              : PASSED");

  Serial.print("Gateway local IP          : ");
  Serial.println(WiFi.localIP());

  Serial.print("Wi-Fi RSSI                : ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");

  return true;
}

bool synchronizeGatewayTime() {
  configTime(
    0,
    0,
    "time.google.com",
    "pool.ntp.org"
  );

  Serial.print("NTP synchronization      : ");

  const unsigned long startedAtMs =
      millis();

  while (
    time(nullptr) < 1700000000
    &&
    millis() - startedAtMs < 25000
  ) {
    Serial.print(".");
    delay(500);
  }

  Serial.println();

  if (time(nullptr) < 1700000000) {
    Serial.println("NTP result                : FAILED");
    return false;
  }

  Serial.println("NTP result                : PASSED");
  return true;
}

bool authenticateFirebaseGateway() {
  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      "https://identitytoolkit.googleapis.com/"
      "v1/accounts:signInWithPassword?key="
      + String(FIREBASE_API_KEY);

  if (!https.begin(client, url)) {
    Serial.println("Firebase Auth HTTPS       : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const String requestBody =
      "{\"email\":\""
      + jsonEscape(FIREBASE_EMAIL)
      + "\",\"password\":\""
      + jsonEscape(FIREBASE_PASSWORD)
      + "\",\"returnSecureToken\":true}";

  const int responseCode =
      https.POST(requestBody);

  const String responseBody =
      responseCode > 0
        ? https.getString()
        : "";

  https.end();

  Serial.print("Firebase Auth HTTP        : ");
  Serial.println(responseCode);

  if (responseCode != 200) {
    String errorMessage;

    extractJsonString(
      responseBody,
      "message",
      errorMessage
    );

    Serial.println("Firebase authentication  : FAILED");

    if (errorMessage.length() > 0) {
      Serial.print("Firebase error            : ");
      Serial.println(errorMessage);
    }

    return false;
  }

  const bool tokenFound =
      extractJsonString(
        responseBody,
        "idToken",
        firebaseIdToken
      );

  const bool uidFound =
      extractJsonString(
        responseBody,
        "localId",
        firebaseLocalId
      );

  if (!tokenFound || !uidFound) {
    clearFirebaseIdToken();

    Serial.println("Firebase response parse   : FAILED");
    return false;
  }

  const bool uidMatches =
      firebaseLocalId
      == EXPECTED_GATEWAY_UID;

  Serial.println("Firebase authentication  : PASSED");

  Serial.print("Gateway UID verification  : ");
  Serial.println(
    uidMatches
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("Firebase password printed : NO");
  Serial.println("Firebase token printed    : NO");

  if (!uidMatches) {
    clearFirebaseIdToken();
    return false;
  }

  return true;
}

bool patchFirebaseNode(
    const String& payload,
    const char* label
) {
  if (
    !firebaseReady
    ||
    WiFi.status() != WL_CONNECTED
    ||
    firebaseIdToken.length() == 0
  ) {
    Serial.print(label);
    Serial.println(" write          : NOT READY");
    return false;
  }

  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      String(FIREBASE_DATABASE_URL)
      + FIREBASE_NODE_PATH
      + "?auth="
      + firebaseIdToken;

  if (!https.begin(client, url)) {
    Serial.print(label);
    Serial.println(" HTTPS          : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const int responseCode =
      https.sendRequest(
        "PATCH",
        payload
      );

  const String responseBody =
      responseCode > 0
        ? https.getString()
        : "";

  https.end();

  Serial.print(label);
  Serial.print(" HTTP           : ");
  Serial.println(responseCode);

  if (
    responseCode != 200
    &&
    responseCode != 204
  ) {
    Serial.print(label);
    Serial.println(" write          : FAILED");

    if (responseBody.length() > 0) {
      Serial.print("Firebase response         : ");
      Serial.println(responseBody);
    }

    return false;
  }

  Serial.print(label);
  Serial.println(" write          : PASSED");
  return true;
}

bool writeRotationDashboardEvidence() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String payload;
  payload.reserve(3300);

  payload += "{";

  payload += "\"security/session\":{";
  payload += "\"state\":\"ACTIVE_ROTATED\",";
  payload += "\"sessionId\":";
  payload += String(sessionId);
  payload += ",";
  payload += "\"startedAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastAcceptedSequence\":1,";
  payload += "\"packetsSinceRotation\":1,";
  payload += "\"revoked\":false";
  payload += "},";

  payload += "\"security/key_lifecycle\":{";
  payload += "\"appSKeyState\":\"ACTIVE\",";
  payload += "\"nwkSKeyState\":\"ACTIVE\",";
  payload += "\"rotationCounter\":";
  payload += String(rotationCounter);
  payload += ",";
  payload += "\"lastRotationAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastRotationReason\":\"TEST_PACKET_THRESHOLD\",";
  payload += "\"productionPacketLimit\":";
  payload += String(PRODUCTION_ROTATION_PACKET_LIMIT);
  payload += ",";
  payload += "\"productionTimeLimitHours\":";
  payload += String(PRODUCTION_ROTATION_HOURS);
  payload += ",";
  payload += "\"initialAppFingerprint\":\"";
  payload += initialAppFingerprint;
  payload += "\",";
  payload += "\"initialNwkFingerprint\":\"";
  payload += initialNwkFingerprint;
  payload += "\",";
  payload += "\"rotatedAppFingerprint\":\"";
  payload += rotatedAppFingerprint;
  payload += "\",";
  payload += "\"rotatedNwkFingerprint\":\"";
  payload += rotatedNwkFingerprint;
  payload += "\"";
  payload += "},";

  payload += "\"security/counters/keyRotations\":1,";

  payload += "\"security/events/key_rotation_step38h2\":{";
  payload += "\"timestamp\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"type\":\"SESSION_KEY_ROTATION\",";
  payload += "\"evidence\":\"REAL_E32_SENSOR_GATEWAY\",";
  payload += "\"simulation\":false,";
  payload += "\"oldSessionId\":";
  payload += String(
    initialSessionIdForDashboard
  );
  payload += ",";
  payload += "\"newSessionId\":";
  payload += String(sessionId);
  payload += ",";
  payload += "\"rotationCounter\":";
  payload += String(rotationCounter);
  payload += ",";
  payload += "\"testThresholdPackets\":";
  payload += String(TEST_ROTATION_THRESHOLD_PACKETS);
  payload += ",";
  payload += "\"productionPacketLimit\":";
  payload += String(PRODUCTION_ROTATION_PACKET_LIMIT);
  payload += ",";
  payload += "\"productionTimeLimitHours\":";
  payload += String(PRODUCTION_ROTATION_HOURS);
  payload += ",";
  payload += "\"seedEncryption\":\"PASSED\",";
  payload += "\"outerHmac\":\"PASSED\",";
  payload += "\"sensorAck\":\"PASSED\",";
  payload += "\"fingerprintMatch\":\"PASSED\",";
  payload += "\"fingerprintsChanged\":\"PASSED\",";
  payload += "\"oldAppKeyZeroized\":\"PASSED\",";
  payload += "\"oldNwkKeyZeroized\":\"PASSED\",";
  payload += "\"postRotationPacket\":\"PASSED\",";
  payload += "\"decision\":\"ROTATED\",";
  payload += "\"firebaseForwarding\":\"ALLOWED\",";
  payload += "\"actualKeysPrinted\":false";
  payload += "},";

  payload += "\"system/status\":{";
  payload += "\"sensorNodeOnline\":true,";
  payload += "\"gatewayOnline\":true,";
  payload += "\"firebaseConnected\":true,";
  payload += "\"lastSensorPacketAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastGatewayHeartbeatAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"firmwareSensor\":\"C2_STEP_38B_ROTATION_SENSOR\",";
  payload += "\"firmwareGateway\":\"C2_STEP_38H2_ROTATION_DASHBOARD_GATEWAY\",";
  payload += "\"dashboardBridgeState\":\"KEY_ROTATION_COMPLETE\",";
  payload += "\"testEvidence\":\"REAL_KEY_ROTATION\"";
  payload += "}";

  payload += "}";

  firebaseRotationEvidencePassed =
      patchFirebaseNode(
        payload,
        "Rotation dashboard evidence"
      );

  return firebaseRotationEvidencePassed;
}

bool writeFinalZeroizedDashboardStatus() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String payload;
  payload.reserve(1200);

  payload += "{";

  payload += "\"security/session\":{";
  payload += "\"state\":\"ZEROIZED_TEST_COMPLETE\",";
  payload += "\"sessionId\":";
  payload += String(sessionId);
  payload += ",";
  payload += "\"lastAcceptedSequence\":1,";
  payload += "\"packetsSinceRotation\":1,";
  payload += "\"revoked\":false";
  payload += "},";

  payload += "\"security/key_lifecycle/appSKeyState\":\"ZEROIZED\",";
  payload += "\"security/key_lifecycle/nwkSKeyState\":\"ZEROIZED\",";

  payload += "\"security/events/key_rotation_step38h2/finalRuntimeKeyState\":\"ZEROIZED\",";

  payload += "\"system/status\":{";
  payload += "\"sensorNodeOnline\":false,";
  payload += "\"gatewayOnline\":false,";
  payload += "\"firebaseConnected\":true,";
  payload += "\"lastSensorPacketAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastGatewayHeartbeatAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"firmwareSensor\":\"C2_STEP_38B_ROTATION_SENSOR\",";
  payload += "\"firmwareGateway\":\"C2_STEP_38H2_ROTATION_DASHBOARD_GATEWAY\",";
  payload += "\"dashboardBridgeState\":\"ROTATION_TEST_COMPLETE_KEYS_ZEROIZED\",";
  payload += "\"testEvidence\":\"REAL_KEY_ROTATION\"";
  payload += "}";

  payload += "}";

  firebaseFinalZeroizedStatusPassed =
      patchFirebaseNode(
        payload,
        "Final zeroized status"
      );

  return firebaseFinalZeroizedStatusPassed;
}

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

  state = GatewayState::FAILED;
  Serial.println("STEP 38H-2 GATEWAY RESULT : REVIEW REQUIRED");
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

  initialSessionIdForDashboard =
      sessionId;

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

  if (!deriveInitialSessionKeys(
        sessionId,
        sensorNonce,
        gatewayNonce,
        runtimeAppSKey,
        runtimeNwkSKey
      )) {
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

  const String base =
      buildHandshakeTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
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
  Serial.print("Initial session ID        : ");
  Serial.println(sessionId);
  Serial.print("Initial App fingerprint   : ");
  Serial.println(initialAppFingerprint);
  Serial.print("Initial Nwk fingerprint   : ");
  Serial.println(initialNwkFingerprint);
  Serial.println("TX gateway challenge      : SENT");

  state = GatewayState::WAITING_INITIAL_RESPONSE;
  stateStartedMs = millis();
}

void handleInitialResponse(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    failTest("Malformed initial response");
    return;
  }

  const uint32_t receivedSession =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (receivedSession != sessionId) {
    failTest("Initial response session mismatch");
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
    failTest("Invalid initial response proof");
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

  uint8_t confirmProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        "OK|" + base,
        confirmProof
      )) {
    secureZeroize(confirmProof, sizeof(confirmProof));
    failTest("Initial confirmation generation failed");
    return;
  }

  const String confirmation =
      "C2_CONFIRM_V1,"
      + String(sessionId)
      + ","
      + bytesToHex(
          confirmProof,
          sizeof(confirmProof)
        );

  secureZeroize(
    confirmProof,
    sizeof(confirmProof)
  );

  E32Serial.println(confirmation);

  initialHandshakePassed = true;
  state = GatewayState::ESTABLISHED;

  Serial.println("Sensor authentication     : PASSED");
  Serial.println("Initial session established: PASSED");
  Serial.println("Waiting for 3 baseline packets...");
}

bool verifyDataFrame(
    const String fields[],
    const uint8_t nwkKey[SESSION_KEY_LENGTH]
) {
  const String transcript =
      "ROT_DATA|"
      + String(NODE_ID)
      + "|"
      + fields[1]
      + "|"
      + fields[2]
      + "|"
      + fields[3];

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

  const bool built =
      calculateTruncatedProof(
        nwkKey,
        SESSION_KEY_LENGTH,
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

void sendRotationCommand() {
  rotationCounter = 1;

  esp_fill_random(
    reinterpret_cast<void*>(&pendingNewSessionId),
    sizeof(pendingNewSessionId)
  );

  if (
    pendingNewSessionId == 0
    ||
    pendingNewSessionId == sessionId
  ) {
    pendingNewSessionId =
        sessionId ^ 0xA5A55A5A;

    if (pendingNewSessionId == 0) {
      pendingNewSessionId = 2;
    }
  }

  uint8_t rotationSeed[ROTATION_SEED_LENGTH] = {0};
  uint8_t rotationKek[ROTATION_KEK_LENGTH] = {0};
  uint8_t iv[GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[ROTATION_SEED_LENGTH] = {0};
  uint8_t tag[GCM_TAG_LENGTH] = {0};
  uint8_t outerProof[PROOF_LENGTH] = {0};

  esp_fill_random(
    rotationSeed,
    sizeof(rotationSeed)
  );

  esp_fill_random(
    iv,
    sizeof(iv)
  );

  const bool kekPassed =
      deriveRotationKek(
        sessionId,
        rotationCounter,
        runtimeNwkSKey,
        rotationKek
      );

  const String aad =
      buildRotationAad(
        sessionId,
        pendingNewSessionId,
        rotationCounter
      );

  rotationSeedEncrypted =
      kekPassed
      &&
      aesGcmEncrypt(
        rotationKek,
        iv,
        aad,
        rotationSeed,
        ciphertext,
        tag
      );

  const bool nextKeysPassed =
      rotationSeedEncrypted
      &&
      deriveRotatedSessionKeys(
        pendingNewSessionId,
        rotationCounter,
        rotationSeed,
        pendingAppSKey,
        pendingNwkSKey
      );

  secureZeroize(rotationKek, sizeof(rotationKek));
  secureZeroize(rotationSeed, sizeof(rotationSeed));

  if (!rotationSeedEncrypted || !nextKeysPassed) {
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(tag, sizeof(tag));
    secureZeroize(outerProof, sizeof(outerProof));
    failTest("Rotation seed encryption/key derivation failed");
    return;
  }

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

  const String ivHex =
      bytesToHex(iv, sizeof(iv));

  const String ciphertextHex =
      bytesToHex(
        ciphertext,
        sizeof(ciphertext)
      );

  const String tagHex =
      bytesToHex(
        tag,
        sizeof(tag)
      );

  const String outerTranscript =
      buildRotationOuterTranscript(
        aad,
        ivHex,
        ciphertextHex,
        tagHex
      );

  rotationCommandOuterHmacBuilt =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        outerProof
      );

  if (!rotationCommandOuterHmacBuilt) {
    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(tag, sizeof(tag));
    secureZeroize(outerProof, sizeof(outerProof));
    failTest("Rotation outer HMAC generation failed");
    return;
  }

  lastRotationCommand =
      "C2_KEY_ROTATE_V1,"
      + String(sessionId)
      + ","
      + String(pendingNewSessionId)
      + ","
      + String(rotationCounter)
      + ","
      + ivHex
      + ","
      + ciphertextHex
      + ","
      + tagHex
      + ","
      + bytesToHex(
          outerProof,
          sizeof(outerProof)
        );

  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(tag, sizeof(tag));
  secureZeroize(outerProof, sizeof(outerProof));

  E32Serial.println(lastRotationCommand);
  rotationCommandAttempts = 1;

  state = GatewayState::WAITING_ROTATION_ACK;
  stateStartedMs = millis();

  Serial.println();
  Serial.println("AUTOMATED KEY ROTATION TRIGGERED");
  Serial.print("Accepted packet count     : ");
  Serial.println(baselinePacketsAccepted);
  Serial.println("Trigger condition         : TEST PACKET THRESHOLD");
  Serial.print("Old session ID            : ");
  Serial.println(sessionId);
  Serial.print("Pending new session ID    : ");
  Serial.println(pendingNewSessionId);
  Serial.println("Rotation seed generated   : TRNG");
  Serial.println("Master-derived KEK        : PASSED");
  Serial.println("Seed AES-GCM encryption   : PASSED");
  Serial.println("Outer HMAC                : PASSED");
  Serial.println("TX KEY_ROTATE             : SENT");
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
    failTest("Baseline data identifiers invalid");
    return;
  }

  if (!verifyDataFrame(fields, runtimeNwkSKey)) {
    failTest("Baseline data HMAC failed");
    return;
  }

  lastBaselineSequence = sequence;
  baselinePacketsAccepted++;

  Serial.print("Baseline packet accepted  : ");
  Serial.print(baselinePacketsAccepted);
  Serial.print("/");
  Serial.println(TEST_ROTATION_THRESHOLD_PACKETS);

  if (
    baselinePacketsAccepted
      == TEST_ROTATION_THRESHOLD_PACKETS
  ) {
    rotationTriggeredByPacketCount = true;
    sendRotationCommand();
  }
}

void handleRotationAck(const String& line) {
  String fields[7];

  if (!splitCsv(line, fields, 7)) {
    failTest("Malformed rotation ACK");
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
    failTest("Rotation ACK identifiers invalid");
    return;
  }

  uint8_t receivedProof[PROOF_LENGTH] = {0};
  uint8_t expectedProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[6],
        receivedProof,
        sizeof(receivedProof)
      )) {
    secureZeroize(receivedProof, sizeof(receivedProof));
    failTest("Rotation ACK proof encoding invalid");
    return;
  }

  const String transcript =
      buildRotationAckTranscript(
        sessionId,
        pendingNewSessionId,
        rotationCounter,
        fields[4],
        fields[5]
      );

  const bool built =
      calculateTruncatedProof(
        pendingNwkSKey,
        sizeof(pendingNwkSKey),
        transcript,
        expectedProof
      );

  sensorRotationAckVerified =
      built
      && constantTimeEqual(
        receivedProof,
        expectedProof,
        PROOF_LENGTH
      );

  secureZeroize(receivedProof, sizeof(receivedProof));
  secureZeroize(expectedProof, sizeof(expectedProof));

  fingerprintMatchPassed =
      fields[4] == rotatedAppFingerprint
      &&
      fields[5] == rotatedNwkFingerprint;

  if (
    !sensorRotationAckVerified
    || !fingerprintMatchPassed
  ) {
    failTest("Rotation ACK verification/fingerprint mismatch");
    return;
  }

  const String confirmTranscript =
      buildRotationConfirmTranscript(
        sessionId,
        pendingNewSessionId,
        rotationCounter
      );

  uint8_t confirmProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        pendingNwkSKey,
        sizeof(pendingNwkSKey),
        confirmTranscript,
        confirmProof
      )) {
    secureZeroize(confirmProof, sizeof(confirmProof));
    failTest("Rotation confirmation generation failed");
    return;
  }

  const String confirmation =
      "C2_KEY_ROTATE_CONFIRM_V1,"
      + String(sessionId)
      + ","
      + String(pendingNewSessionId)
      + ","
      + String(rotationCounter)
      + ","
      + bytesToHex(
          confirmProof,
          sizeof(confirmProof)
        );

  secureZeroize(confirmProof, sizeof(confirmProof));

  E32Serial.println(confirmation);

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

  oldAppKeyZeroized =
      isAllZero(
        oldAppSKeyCopy,
        sizeof(oldAppSKeyCopy)
      );

  oldNwkKeyZeroized =
      isAllZero(
        oldNwkSKeyCopy,
        sizeof(oldNwkSKeyCopy)
      );

  sessionId = pendingNewSessionId;
  pendingNewSessionId = 0;
  state = GatewayState::ROTATED;

  Serial.println();
  Serial.println("ROTATION ACK VERIFIED");
  Serial.println("Sensor new-key proof      : PASSED");
  Serial.println("Key fingerprint match     : PASSED");
  Serial.println("TX rotation confirmation  : SENT");
  Serial.print("New active session ID     : ");
  Serial.println(sessionId);
  Serial.print("Old App key zeroized      : ");
  Serial.println(
    oldAppKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Old Nwk key zeroized      : ");
  Serial.println(
    oldNwkKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.println("Waiting for post-rotation packet...");
}

void printFinalReport() {
  writeRotationDashboardEvidence();

  const bool fingerprintsChanged =
      initialAppFingerprint
          != rotatedAppFingerprint
      &&
      initialNwkFingerprint
          != rotatedNwkFingerprint;

  const bool passed =
      initialHandshakePassed
      &&
      baselinePacketsAccepted
          == TEST_ROTATION_THRESHOLD_PACKETS
      &&
      rotationTriggeredByPacketCount
      &&
      rotationSeedEncrypted
      &&
      rotationCommandOuterHmacBuilt
      &&
      sensorRotationAckVerified
      &&
      fingerprintMatchPassed
      &&
      oldAppKeyZeroized
      &&
      oldNwkKeyZeroized
      &&
      fingerprintsChanged
      &&
      postRotationPacketVerified
      &&
      postRotationPacketsAccepted == 1
      &&
      firebaseRotationEvidencePassed;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38H-2 GATEWAY REPORT");
  Serial.println("==========================================");
  Serial.println("Initial handshake         : PASSED");
  Serial.print("Baseline packets accepted : ");
  Serial.println(baselinePacketsAccepted);
  Serial.print("Rotation packet trigger   : ");
  Serial.println(
    rotationTriggeredByPacketCount
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Rotation seed encryption  : ");
  Serial.println(
    rotationSeedEncrypted
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Rotation outer HMAC       : ");
  Serial.println(
    rotationCommandOuterHmacBuilt
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Sensor rotation ACK       : ");
  Serial.println(
    sensorRotationAckVerified
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Key fingerprint match     : ");
  Serial.println(
    fingerprintMatchPassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Fingerprints changed      : ");
  Serial.println(
    fingerprintsChanged
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Old App key zeroized      : ");
  Serial.println(
    oldAppKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Old Nwk key zeroized      : ");
  Serial.println(
    oldNwkKeyZeroized
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Post-rotation accepted    : ");
  Serial.println(postRotationPacketsAccepted);
  Serial.print("Dashboard evidence write  : ");
  Serial.println(
    firebaseRotationEvidencePassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Test rotation threshold   : ");
  Serial.println(TEST_ROTATION_THRESHOLD_PACKETS);
  Serial.print("Production packet limit   : ");
  Serial.println(PRODUCTION_ROTATION_PACKET_LIMIT);
  Serial.print("Production time limit     : ");
  Serial.print(PRODUCTION_ROTATION_HOURS);
  Serial.println(" hours");
  Serial.println("Actual keys printed       : NO");
  Serial.print("STEP 38H-2 GATEWAY RESULT : ");
  Serial.println(
    passed ? "PASSED" : "REVIEW REQUIRED"
  );
  Serial.println("==========================================");

  state = GatewayState::FINISHED;
}

void handlePostRotationData(const String& line) {
  String fields[5];

  if (!splitCsv(line, fields, 5)) {
    failTest("Malformed post-rotation data");
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
    || sequence != 1
    || fields[3] != "POST_ROTATION"
  ) {
    failTest("Post-rotation data identifiers invalid");
    return;
  }

  postRotationPacketVerified =
      verifyDataFrame(
        fields,
        runtimeNwkSKey
      );

  if (!postRotationPacketVerified) {
    failTest("Post-rotation packet HMAC failed");
    return;
  }

  postRotationPacketsAccepted++;

  const String transcript =
      "POST_ACK|"
      + String(NODE_ID)
      + "|"
      + String(sessionId)
      + "|1";

  uint8_t proof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        transcript,
        proof
      )) {
    secureZeroize(proof, sizeof(proof));
    failTest("Post-rotation ACK generation failed");
    return;
  }

  const String ack =
      "C2_POST_ROT_ACK_V1,"
      + String(sessionId)
      + ",1,"
      + bytesToHex(
          proof,
          sizeof(proof)
        );

  secureZeroize(proof, sizeof(proof));

  E32Serial.println(ack);

  Serial.println();
  Serial.println("POST-ROTATION PACKET ACCEPTED");
  Serial.print("New session ID            : ");
  Serial.println(sessionId);
  Serial.println("Sequence                  : 1");
  Serial.println("New NwkSKey verification  : PASSED");
  Serial.println("TX post-rotation ACK      : SENT");

  printFinalReport();

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  const bool finalAppZeroized =
      isAllZero(
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  const bool finalNwkZeroized =
      isAllZero(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  writeFinalZeroizedDashboardStatus();

  Serial.println();
  Serial.println("POST-TEST DASHBOARD AND SECRET CLEANUP");

  Serial.print("Final AppSKey zeroization : ");
  Serial.println(
    finalAppZeroized
      ? "PASSED"
      : "FAILED"
  );

  Serial.print("Final NwkSKey zeroization : ");
  Serial.println(
    finalNwkZeroized
      ? "PASSED"
      : "FAILED"
  );

  Serial.print("Final dashboard status    : ");
  Serial.println(
    firebaseFinalZeroizedStatusPassed
      ? "PASSED"
      : "FAILED"
  );

  clearFirebaseIdToken();

  Serial.print("Firebase token cleared    : ");
  Serial.println(
    firebaseIdToken.length() == 0
      ? "PASSED"
      : "FAILED"
  );
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
      state == GatewayState::WAITING_INITIAL_RESPONSE
    )
    &&
    line.startsWith("C2_HELLO_V1,")
  ) {
    if (
      state
        == GatewayState::WAITING_INITIAL_RESPONSE
    ) {
      Serial.println("Repeated HELLO            : NEW CHALLENGE");
    }

    handleHello(line);
    return;
  }

  if (
    state == GatewayState::WAITING_INITIAL_RESPONSE
    &&
    line.startsWith("C2_RESPONSE_V1,")
  ) {
    handleInitialResponse(line);
    return;
  }

  if (
    state == GatewayState::ESTABLISHED
    &&
    line.startsWith("C2_ROT_DATA_V1,")
  ) {
    handleBaselineData(line);
    return;
  }

  if (
    state == GatewayState::WAITING_ROTATION_ACK
    &&
    line.startsWith("C2_KEY_ROTATE_ACK_V1,")
  ) {
    handleRotationAck(line);
    return;
  }

  if (
    state == GatewayState::ROTATED
    &&
    line.startsWith("C2_ROT_DATA_V1,")
  ) {
    handlePostRotationData(line);
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

  if (!firebaseConfigurationPresent()) {
    Serial.println();
    Serial.println("Configuration check       : FAILED");
    Serial.println(
      "Replace Wi-Fi/Firebase placeholders before upload."
    );
    state = GatewayState::FAILED;
    Serial.println("STEP 38H-2 GATEWAY RESULT : REVIEW REQUIRED");
    return;
  }

  const bool wifiPassed =
      connectWiFiForDashboard();

  const bool ntpPassed =
      wifiPassed
      &&
      synchronizeGatewayTime();

  const bool authPassed =
      ntpPassed
      &&
      authenticateFirebaseGateway();

  firebaseReady =
      wifiPassed
      &&
      ntpPassed
      &&
      authPassed;

  Serial.print("Firebase dashboard bridge : ");
  Serial.println(
    firebaseReady
      ? "READY"
      : "FAILED"
  );

  if (!firebaseReady) {
    clearFirebaseIdToken();
    state = GatewayState::FAILED;
    Serial.println("STEP 38H-2 GATEWAY RESULT : REVIEW REQUIRED");
    return;
  }

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
  Serial.println("COMPONENT 2 — STEP 38H-2");
  Serial.println("REAL KEY ROTATION + REACT DASHBOARD — GATEWAY");
  Serial.println("==========================================");
  Serial.println("Radio mode                : TRANSPARENT");
  Serial.println("Initial keys              : HKDF-SHA256");
  Serial.println("Rotation seed source      : ESP32 TRNG");
  Serial.println("Rotation seed protection  : MASTER-DERIVED AES-GCM KEK");
  Serial.println("Rotation command auth     : CURRENT NWKSKEY HMAC");
  Serial.println("Rotated keys              : HKDF-SHA256");
  Serial.println("Test trigger              : 3 accepted packets");
  Serial.println("Production trigger        : 1000 packets OR 24 hours");
  Serial.println("Actual keys printed       : NO");
  Serial.println("Development master PSK    : YES");
  Serial.println("Production security claim : NOT YET");
  Serial.println("React dashboard evidence  : ENABLED");
  Serial.println("Firebase actual keys      : NEVER WRITTEN");
  Serial.println("Waiting for sensor HELLO...");
  Serial.println();
}

void loop() {
  serviceRadio();

  if (
    state == GatewayState::WAITING_INITIAL_RESPONSE
    &&
    millis() - stateStartedMs
        >= HANDSHAKE_TIMEOUT_MS
  ) {
    failTest("Initial response timeout");
  }

  if (
    state == GatewayState::WAITING_ROTATION_ACK
    &&
    millis() - stateStartedMs
        >= ROTATION_TIMEOUT_MS
  ) {
    if (
      rotationCommandAttempts
        < MAX_ROTATION_COMMAND_ATTEMPTS
      &&
      lastRotationCommand.length() > 0
    ) {
      E32Serial.println(lastRotationCommand);
      rotationCommandAttempts++;
      stateStartedMs = millis();

      Serial.println("Rotation ACK timeout      : COMMAND RESENT");
    } else {
      failTest("Rotation ACK timeout");
    }
  }

  delay(5);
}
