/*
  Component 2 — Step 36B
  Authenticated handshake — Gateway ESP32
*/


#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
constexpr size_t FINGERPRINT_LENGTH = 8;
constexpr size_t AES_GCM_IV_LENGTH = 12;
constexpr size_t AES_GCM_TAG_LENGTH = 16;
constexpr size_t SECURE_PAYLOAD_LENGTH = 67;

const char NODE_ID[] = "GH_NODE_01";


// =====================================================
// STEP 37D — LOCAL NETWORK/FIREBASE VALUES
// Edit only these five values before upload.
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

const char* FIREBASE_CURRENT_PATH =
    "/greenhouse/GH_NODE_01/current.json";

// Google Trust Services Root R1.
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

String firebaseIdToken;
String firebaseLocalId;

bool firebaseReady = false;

uint32_t firebaseCurrentWritePassed = 0;
uint32_t firebaseCurrentWriteFailed = 0;


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



// =====================================================
// STEP 37D — FIREBASE HELPERS
// =====================================================

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

String firebaseJsonEscape(const String& input) {
  String output;
  output.reserve(input.length() + 12);

  for (size_t index = 0; index < input.length(); index++) {
    const char character = input[index];

    if (character == '\\') {
      output += "\\\\";
    } else if (character == '"') {
      output += "\\\"";
    } else {
      output += character;
    }
  }

  return output;
}

bool extractFirebaseJsonString(
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
      json.indexOf(':', keyPosition);

  const int openingQuote =
      json.indexOf('"', colonPosition + 1);

  const int closingQuote =
      json.indexOf('"', openingQuote + 1);

  if (
    colonPosition < 0
    || openingQuote < 0
    || closingQuote < 0
  ) {
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
    firebaseIdToken.setCharAt(index, '\0');
  }

  firebaseIdToken = "";
}

bool connectGatewayWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);

  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );

  Serial.print("Wi-Fi connection          : ");

  const unsigned long startMs =
      millis();

  while (
    WiFi.status() != WL_CONNECTED
    &&
    millis() - startMs < 30000
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

  const unsigned long startMs =
      millis();

  while (
    time(nullptr) < 1700000000
    &&
    millis() - startMs < 25000
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

bool authenticateGatewayFirebase() {
  WiFiClientSecure secureClient;
  secureClient.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      "https://identitytoolkit.googleapis.com/"
      "v1/accounts:signInWithPassword?key="
      + String(FIREBASE_API_KEY);

  if (!https.begin(secureClient, url)) {
    Serial.println("Firebase Auth HTTPS begin : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const String requestBody =
      "{\"email\":\""
      + firebaseJsonEscape(FIREBASE_EMAIL)
      + "\",\"password\":\""
      + firebaseJsonEscape(FIREBASE_PASSWORD)
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

    extractFirebaseJsonString(
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

  if (
    !extractFirebaseJsonString(
      responseBody,
      "idToken",
      firebaseIdToken
    )
    ||
    !extractFirebaseJsonString(
      responseBody,
      "localId",
      firebaseLocalId
    )
  ) {
    clearFirebaseIdToken();

    Serial.println("Firebase response parse   : FAILED");
    return false;
  }

  const bool uidMatches =
      firebaseLocalId == EXPECTED_GATEWAY_UID;

  Serial.println("Firebase authentication  : PASSED");

  Serial.print("Expected UID match        : ");
  Serial.println(uidMatches ? "PASSED" : "FAILED");

  Serial.println("Firebase token printed    : NO");

  if (!uidMatches) {
    clearFirebaseIdToken();
    return false;
  }

  return true;
}

String buildFirebaseCurrentJson(
    uint32_t packetSessionId,
    uint32_t sequence,
    long temperatureX100,
    unsigned long humidityX100,
    unsigned long lightLuxX10,
    unsigned long soilRaw,
    unsigned long soilPercent,
    unsigned int sampleValid,
    const char* systemState
) {
  String json;
  json.reserve(760);

  json += "{";

  json += "\"nodeId\":\"";
  json += NODE_ID;
  json += "\",";

  json += "\"timestamp\":";
  json += String(
    static_cast<unsigned long>(
      time(nullptr)
    )
  );
  json += ",";

  json += "\"connection\":\"online\",";
  json += "\"systemState\":\"";
  json += systemState;
  json += "\",";

  json += "\"sessionId\":";
  json += String(packetSessionId);
  json += ",";

  json += "\"sequence\":";
  json += String(sequence);
  json += ",";

  json += "\"sensors\":{";

  json += "\"temperature\":";
  json += String(
    static_cast<float>(temperatureX100) / 100.0f,
    2
  );
  json += ",";

  json += "\"humidity\":";
  json += String(
    static_cast<float>(humidityX100) / 100.0f,
    2
  );
  json += ",";

  json += "\"light\":";
  json += String(
    static_cast<float>(lightLuxX10) / 10.0f,
    1
  );
  json += ",";

  json += "\"soilRaw\":";
  json += String(soilRaw);
  json += ",";

  json += "\"soilPercent\":";
  json += String(soilPercent);
  json += ",";

  json += "\"sampleValid\":";
  json += sampleValid == 1U ? "true" : "false";

  json += "},";

  json += "\"security\":{";

  json += "\"radioAuthenticated\":true,";
  json += "\"outerHmac\":\"PASSED\",";
  json += "\"replayWindow\":\"FRESH\",";
  json += "\"ivValidation\":\"PASSED\",";
  json += "\"aesGcm\":\"PASSED\",";
  json += "\"gcmTag\":\"PASSED\",";
  json += "\"firebaseAuthentication\":\"PASSED\",";
  json += "\"uidAuthorization\":\"PASSED\",";
  json += "\"tlsCertificateValidation\":\"ENABLED\",";
  json += "\"gatewayUid\":\"";
  json += firebaseLocalId;
  json += "\"";

  json += "}";

  json += "}";

  return json;
}

bool writeAcceptedTelemetryToFirebase(
    uint32_t packetSessionId,
    uint32_t sequence,
    long temperatureX100,
    unsigned long humidityX100,
    unsigned long lightLuxX10,
    unsigned long soilRaw,
    unsigned long soilPercent,
    unsigned int sampleValid,
    const char* systemState
) {
  if (
    !firebaseReady
    || WiFi.status() != WL_CONNECTED
    || firebaseIdToken.length() == 0
  ) {
    firebaseCurrentWriteFailed++;

    Serial.println(
      "Firebase current write    : NOT READY"
    );

    return false;
  }

  WiFiClientSecure secureClient;
  secureClient.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      String(FIREBASE_DATABASE_URL)
      + FIREBASE_CURRENT_PATH
      + "?auth="
      + firebaseIdToken;

  if (!https.begin(secureClient, url)) {
    firebaseCurrentWriteFailed++;

    Serial.println(
      "Firebase current HTTPS    : FAILED"
    );

    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const String payload =
      buildFirebaseCurrentJson(
        packetSessionId,
        sequence,
        temperatureX100,
        humidityX100,
        lightLuxX10,
        soilRaw,
        soilPercent,
        sampleValid,
        systemState
      );

  const int responseCode =
      https.PUT(payload);

  const String responseBody =
      responseCode > 0
        ? https.getString()
        : "";

  https.end();

  Serial.print("Firebase current HTTP     : ");
  Serial.println(responseCode);

  if (
    responseCode != 200
    &&
    responseCode != 204
  ) {
    firebaseCurrentWriteFailed++;

    Serial.println("Firebase current write    : FAILED");

    if (responseBody.length() > 0) {
      Serial.print("Firebase response         : ");
      Serial.println(responseBody);
    }

    return false;
  }

  firebaseCurrentWritePassed++;

  Serial.println("Firebase current write    : PASSED");

  return true;
}


HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

constexpr size_t MAX_RADIO_LINE_LENGTH = 320;

String radioLineBuffer;
uint32_t radioLineOverflowCount = 0;

constexpr unsigned long HANDSHAKE_TIMEOUT_MS = 12000;
constexpr unsigned long KEY_ACTIVE_WINDOW_MS = 150000;

enum class GatewayHandshakeState {
  LISTENING,
  WAITING_FOR_RESPONSE,
  ESTABLISHED,
  ZEROIZED,
  FAILED
};

GatewayHandshakeState handshakeState =
    GatewayHandshakeState::LISTENING;

uint32_t sessionId = 0;
uint8_t sensorNonce[NONCE_LENGTH] = {0};
uint8_t gatewayNonce[NONCE_LENGTH] = {0};

uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};

String sensorNonceHex;
String gatewayNonceHex;

unsigned long stateStartedAtMs = 0;
unsigned long establishedAtMs = 0;

// =====================================================
// STEP 36D — ENCRYPTED DATA + REPLAY/TAMPER DEFENCE
// =====================================================

constexpr uint32_t EXPECTED_UNIQUE_PACKETS = 6;
constexpr unsigned long REPORT_ZEROIZE_DELAY_MS = 5000;
constexpr unsigned long TIMESTAMP_WINDOW_MS = 30000;

uint32_t lastAcceptedSequence = 0;
uint32_t encryptedPacketsAccepted = 0;
uint32_t replayPacketsRejected = 0;
uint32_t invalidOuterMacRejected = 0;
uint32_t invalidGcmTagRejected = 0;
uint32_t staleTimestampRejected = 0;
uint32_t malformedDataPackets = 0;
uint32_t wrongSessionPackets = 0;
uint32_t ivMismatchPackets = 0;
uint32_t sequenceGapCount = 0;
uint32_t validRealSensorSamples = 0;
uint32_t invalidRealSensorSamples = 0;

bool dataSecurityReportPrinted = false;
bool postReportKeysZeroized = false;

unsigned long dataSecurityReportAtMs = 0;


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

void resetToListening(const String& reason) {
  Serial.print("Gateway reset reason      : ");
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
    sensorNonce,
    sizeof(sensorNonce)
  );

  secureZeroize(
    gatewayNonce,
    sizeof(gatewayNonce)
  );

  sessionId = 0;
  sensorNonceHex = "";
  gatewayNonceHex = "";

  lastAcceptedSequence = 0;
  encryptedPacketsAccepted = 0;
  replayPacketsRejected = 0;
  invalidOuterMacRejected = 0;
  invalidGcmTagRejected = 0;
  staleTimestampRejected = 0;
  malformedDataPackets = 0;
  wrongSessionPackets = 0;
  ivMismatchPackets = 0;
  sequenceGapCount = 0;
  validRealSensorSamples = 0;
  invalidRealSensorSamples = 0;
  dataSecurityReportPrinted = false;
  postReportKeysZeroized = false;
  dataSecurityReportAtMs = 0;

  handshakeState =
      GatewayHandshakeState::LISTENING;
}

void handleHello(const String& line) {
  String fields[4];

  if (!splitCsv(line, fields, 4)) {
    Serial.println("HELLO result              : MALFORMED");
    return;
  }

  if (fields[0] != "C2_HELLO_V1") {
    return;
  }

  if (fields[1] != NODE_ID) {
    Serial.println("HELLO result              : UNKNOWN NODE");
    return;
  }

  const uint32_t receivedSessionId =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  if (receivedSessionId == 0) {
    Serial.println("HELLO result              : INVALID SESSION");
    return;
  }

  uint8_t receivedSensorNonce[NONCE_LENGTH] = {0};

  if (!hexToBytes(
        fields[3],
        receivedSensorNonce,
        sizeof(receivedSensorNonce)
      )) {
    secureZeroize(
      receivedSensorNonce,
      sizeof(receivedSensorNonce)
    );

    Serial.println("HELLO result              : INVALID NONCE");
    return;
  }

  if (
    handshakeState
      == GatewayHandshakeState::WAITING_FOR_RESPONSE
    &&
    receivedSessionId == sessionId
    &&
    fields[3] == sensorNonceHex
  ) {
    Serial.println("Repeated HELLO            : RESEND CHALLENGE");
  } else {
    resetToListening("New authenticated-handshake request");

    sessionId = receivedSessionId;

    memcpy(
      sensorNonce,
      receivedSensorNonce,
      sizeof(sensorNonce)
    );

    sensorNonceHex = fields[3];

    esp_fill_random(
      gatewayNonce,
      sizeof(gatewayNonce)
    );

    gatewayNonceHex = bytesToHex(
      gatewayNonce,
      sizeof(gatewayNonce)
    );
  }

  secureZeroize(
    receivedSensorNonce,
    sizeof(receivedSensorNonce)
  );

  const String baseTranscript =
      buildBaseTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const String gatewayTranscript =
      "GW|" + baseTranscript;

  uint8_t gatewayProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        DEVELOPMENT_PSK,
        sizeof(DEVELOPMENT_PSK),
        gatewayTranscript,
        gatewayProof
      )) {
    secureZeroize(
      gatewayProof,
      sizeof(gatewayProof)
    );

    Serial.println("Gateway proof generation  : FAILED");
    return;
  }

  const String challenge =
      "C2_CHALLENGE_V1,"
      + String(sessionId)
      + ","
      + gatewayNonceHex
      + ","
      + bytesToHex(
          gatewayProof,
          sizeof(gatewayProof)
        );

  secureZeroize(
    gatewayProof,
    sizeof(gatewayProof)
  );

  E32Serial.println(challenge);

  Serial.println("HELLO validation          : PASSED");
  Serial.print("Session ID                : ");
  Serial.println(sessionId);
  Serial.println("TX gateway challenge      : SENT");

  handshakeState =
      GatewayHandshakeState::WAITING_FOR_RESPONSE;

  stateStartedAtMs = millis();
}

void handleResponse(const String& line) {
  String fields[3];

  if (!splitCsv(line, fields, 3)) {
    Serial.println("RESPONSE result           : MALFORMED");
    return;
  }

  if (fields[0] != "C2_RESPONSE_V1") {
    return;
  }

  const uint32_t receivedSessionId =
      static_cast<uint32_t>(
        strtoul(fields[1].c_str(), nullptr, 10)
      );

  if (
    handshakeState
      != GatewayHandshakeState::WAITING_FOR_RESPONSE
    ||
    receivedSessionId != sessionId
  ) {
    Serial.println("RESPONSE result           : SESSION MISMATCH");
    return;
  }

  uint8_t receivedSensorProof[PROOF_LENGTH] = {0};

  if (!hexToBytes(
        fields[2],
        receivedSensorProof,
        sizeof(receivedSensorProof)
      )) {
    secureZeroize(
      receivedSensorProof,
      sizeof(receivedSensorProof)
    );

    Serial.println("RESPONSE result           : INVALID PROOF");
    return;
  }

  if (!deriveSessionKeys(
        sessionId,
        sensorNonce,
        gatewayNonce,
        runtimeAppSKey,
        runtimeNwkSKey
      )) {
    secureZeroize(
      receivedSensorProof,
      sizeof(receivedSensorProof)
    );

    Serial.println("Session-key derivation    : FAILED");
    handshakeState =
        GatewayHandshakeState::FAILED;
    return;
  }

  const String baseTranscript =
      buildBaseTranscript(
        sessionId,
        sensorNonceHex,
        gatewayNonceHex
      );

  const String sensorTranscript =
      "SN|" + baseTranscript;

  uint8_t expectedSensorProof[PROOF_LENGTH] = {0};

  const bool proofCalculated =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        sensorTranscript,
        expectedSensorProof
      );

  const bool sensorAuthenticated =
      proofCalculated
      && constantTimeEqual(
        receivedSensorProof,
        expectedSensorProof,
        PROOF_LENGTH
      );

  secureZeroize(
    receivedSensorProof,
    sizeof(receivedSensorProof)
  );

  secureZeroize(
    expectedSensorProof,
    sizeof(expectedSensorProof)
  );

  if (!sensorAuthenticated) {
    Serial.println("Sensor HMAC verification  : FAILED");

    secureZeroize(
      runtimeAppSKey,
      sizeof(runtimeAppSKey)
    );

    secureZeroize(
      runtimeNwkSKey,
      sizeof(runtimeNwkSKey)
    );

    handshakeState =
        GatewayHandshakeState::FAILED;

    Serial.println("STEP 36B GATEWAY RESULT   : REVIEW REQUIRED");
    return;
  }

  Serial.println("Sensor HMAC verification  : PASSED");
  Serial.println("Session-key derivation    : PASSED");
  printKeyFingerprints();

  const String confirmTranscript =
      "OK|" + baseTranscript;

  uint8_t confirmProof[PROOF_LENGTH] = {0};

  if (!calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        confirmTranscript,
        confirmProof
      )) {
    secureZeroize(
      confirmProof,
      sizeof(confirmProof)
    );

    Serial.println("Confirmation generation   : FAILED");
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

  handshakeState =
      GatewayHandshakeState::ESTABLISHED;

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
  Serial.println("STEP 37D FIREBASE TEST    : WAITING");
  Serial.println("Payload encryption        : AES-128-GCM");
  Serial.println("GCM authentication tag    : 128-BIT");
  Serial.println("Outer packet HMAC         : HMAC-SHA256 / 128-BIT");
  Serial.println("Replay protection         : ENABLED");
  Serial.println("Key-purpose separation    : AppSKey / NwkSKey");
  Serial.println("==========================================");
}


void printGatewayDataSecurityReport() {
  if (dataSecurityReportPrinted) {
    return;
  }

  dataSecurityReportPrinted = true;
  dataSecurityReportAtMs = millis();

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38A GATEWAY REPORT");
  Serial.println("==========================================");
  Serial.print("Encrypted packets accepted: ");
  Serial.println(encryptedPacketsAccepted);
  Serial.print("Last accepted sequence   : ");
  Serial.println(lastAcceptedSequence);
  Serial.print("Replay packets rejected  : ");
  Serial.println(replayPacketsRejected);
  Serial.print("Invalid outer HMAC reject: ");
  Serial.println(invalidOuterMacRejected);
  Serial.print("Invalid GCM tag rejected : ");
  Serial.println(invalidGcmTagRejected);
  Serial.print("Stale timestamp rejected : ");
  Serial.println(staleTimestampRejected);
  Serial.print("Timestamp window         : +/-");
  Serial.print(TIMESTAMP_WINDOW_MS / 1000);
  Serial.println(" seconds");
  Serial.print("Wrong session rejected   : ");
  Serial.println(wrongSessionPackets);
  Serial.print("IV mismatch rejected     : ");
  Serial.println(ivMismatchPackets);
  Serial.print("Malformed data packets   : ");
  Serial.println(malformedDataPackets);
  Serial.print("Sequence gaps observed   : ");
  Serial.println(sequenceGapCount);
  Serial.print("Valid real sensor samples: ");
  Serial.println(validRealSensorSamples);
  Serial.print("Invalid sensor samples   : ");
  Serial.println(invalidRealSensorSamples);
  Serial.print("Firebase current writes  : ");
  Serial.println(firebaseCurrentWritePassed);
  Serial.print("Firebase write failures  : ");
  Serial.println(firebaseCurrentWriteFailed);
  Serial.println("Firebase target path     : current.json");
  Serial.println("Payload encryption       : AES-128-GCM");
  Serial.println("Plaintext over radio     : NO");
  Serial.print("STEP 38A GATEWAY RESULT  : ");

  if (
    encryptedPacketsAccepted
        == EXPECTED_UNIQUE_PACKETS
    && lastAcceptedSequence
        == EXPECTED_UNIQUE_PACKETS
    && replayPacketsRejected >= 1
    && invalidOuterMacRejected >= 1
    && invalidGcmTagRejected >= 1
    && staleTimestampRejected >= 1
    && validRealSensorSamples == EXPECTED_UNIQUE_PACKETS
    && invalidRealSensorSamples == 0
    && firebaseCurrentWritePassed == EXPECTED_UNIQUE_PACKETS
    && firebaseCurrentWriteFailed == 0
    && malformedDataPackets == 0
    && wrongSessionPackets == 0
    && ivMismatchPackets == 0
    && sequenceGapCount == 0
  ) {
    Serial.println("PASSED");
  } else {
    Serial.println("REVIEW REQUIRED");
  }

  Serial.println("==========================================");
}

void handleEncryptedTelemetry(
    const String& line
) {
  if (
    handshakeState
      != GatewayHandshakeState::ESTABLISHED
  ) {
    Serial.println(
      "SECURE DATA result        : NO ACTIVE SESSION"
    );

    return;
  }

  String fields[8];

  if (!splitCsv(line, fields, 8)) {
    malformedDataPackets++;

    Serial.println(
      "SECURE DATA result        : MALFORMED"
    );

    return;
  }

  if (fields[0] != "C2_SECURE_V1") {
    return;
  }

  if (fields[1] != NODE_ID) {
    wrongSessionPackets++;

    Serial.println(
      "SECURE DATA result        : UNKNOWN NODE"
    );

    return;
  }

  const uint32_t packetSessionId =
      static_cast<uint32_t>(
        strtoul(fields[2].c_str(), nullptr, 10)
      );

  const uint32_t sequence =
      static_cast<uint32_t>(
        strtoul(fields[3].c_str(), nullptr, 10)
      );

  if (
    packetSessionId != sessionId
    || sequence == 0
  ) {
    wrongSessionPackets++;

    Serial.println(
      "SECURE DATA result        : SESSION/SEQUENCE INVALID"
    );

    return;
  }

  uint8_t iv[AES_GCM_IV_LENGTH] = {0};
  uint8_t ciphertext[SECURE_PAYLOAD_LENGTH] = {0};
  uint8_t receivedGcmTag[AES_GCM_TAG_LENGTH] = {0};
  uint8_t receivedOuterMac[PROOF_LENGTH] = {0};

  const bool fieldsDecoded =
      hexToBytes(
        fields[4],
        iv,
        sizeof(iv)
      )
      &&
      hexToBytes(
        fields[5],
        ciphertext,
        sizeof(ciphertext)
      )
      &&
      hexToBytes(
        fields[6],
        receivedGcmTag,
        sizeof(receivedGcmTag)
      )
      &&
      hexToBytes(
        fields[7],
        receivedOuterMac,
        sizeof(receivedOuterMac)
      );

  if (!fieldsDecoded) {
    malformedDataPackets++;

    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(receivedGcmTag, sizeof(receivedGcmTag));
    secureZeroize(receivedOuterMac, sizeof(receivedOuterMac));

    Serial.println(
      "SECURE DATA result        : INVALID HEX FIELD"
    );

    return;
  }

  const String outerTranscript =
      buildOuterMacTranscript(
        fields[1],
        fields[2],
        fields[3],
        fields[4],
        fields[5],
        fields[6]
      );

  uint8_t expectedOuterMac[PROOF_LENGTH] = {0};

  const bool outerMacCalculated =
      calculateTruncatedProof(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        outerTranscript,
        expectedOuterMac
      );

  const bool outerMacValid =
      outerMacCalculated
      && constantTimeEqual(
        receivedOuterMac,
        expectedOuterMac,
        PROOF_LENGTH
      );

  secureZeroize(
    receivedOuterMac,
    sizeof(receivedOuterMac)
  );

  secureZeroize(
    expectedOuterMac,
    sizeof(expectedOuterMac)
  );

  if (!outerMacValid) {
    invalidOuterMacRejected++;

    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(receivedGcmTag, sizeof(receivedGcmTag));

    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println("ENCRYPTED PACKET TAMPER REJECTED");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.print("Rejected sequence         : ");
    Serial.println(sequence);
    Serial.println("Outer HMAC verification   : FAILED");
    Serial.println("Decryption attempted      : NO");
    Serial.println("Packet accepted           : NO");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    return;
  }

  if (sequence <= lastAcceptedSequence) {
    replayPacketsRejected++;

    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(receivedGcmTag, sizeof(receivedGcmTag));

    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println("ENCRYPTED REPLAY ATTACK REJECTED");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.print("Received sequence         : ");
    Serial.println(sequence);
    Serial.print("Last accepted sequence    : ");
    Serial.println(lastAcceptedSequence);
    Serial.println("Outer HMAC verification   : PASSED");
    Serial.println("Replay-window result      : REJECTED");
    Serial.println("Decryption attempted      : NO");
    Serial.println("Packet accepted           : NO");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    return;
  }

  uint8_t expectedIv[AES_GCM_IV_LENGTH] = {0};

  buildPacketIv(
    packetSessionId,
    sequence,
    sensorNonce,
    expectedIv
  );

  const bool ivValid =
      constantTimeEqual(
        iv,
        expectedIv,
        sizeof(iv)
      );

  secureZeroize(
    expectedIv,
    sizeof(expectedIv)
  );

  if (!ivValid) {
    ivMismatchPackets++;

    secureZeroize(iv, sizeof(iv));
    secureZeroize(ciphertext, sizeof(ciphertext));
    secureZeroize(receivedGcmTag, sizeof(receivedGcmTag));

    Serial.println(
      "SECURE DATA result        : IV MISMATCH"
    );

    return;
  }

  const String aad =
      buildSecureAad(
        packetSessionId,
        sequence
      );

  uint8_t plaintext[
      SECURE_PAYLOAD_LENGTH + 1
  ] = {0};

  const bool decryptionPassed =
      aes128GcmDecrypt(
        runtimeAppSKey,
        iv,
        reinterpret_cast<const uint8_t*>(
          aad.c_str()
        ),
        aad.length(),
        ciphertext,
        sizeof(ciphertext),
        receivedGcmTag,
        plaintext
      );

  secureZeroize(iv, sizeof(iv));
  secureZeroize(ciphertext, sizeof(ciphertext));
  secureZeroize(receivedGcmTag, sizeof(receivedGcmTag));

  if (!decryptionPassed) {
    invalidGcmTagRejected++;

    secureZeroize(
      plaintext,
      sizeof(plaintext)
    );

    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println("AES-GCM AUTHENTICATION FAILURE");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.print("Rejected sequence         : ");
    Serial.println(sequence);
    Serial.println("Outer HMAC verification   : PASSED");
    Serial.println("GCM tag verification      : FAILED");
    Serial.println("Packet accepted           : NO");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    if (
      encryptedPacketsAccepted
          >= EXPECTED_UNIQUE_PACKETS
      &&
      replayPacketsRejected >= 1
      &&
      invalidOuterMacRejected >= 1
      &&
      staleTimestampRejected >= 1
    ) {
      printGatewayDataSecurityReport();
    }

    return;
  }

  plaintext[SECURE_PAYLOAD_LENGTH] = '\0';

  long temperatureX100 = 0;
  unsigned long senderElapsedMs = 0;
  unsigned long humidityX100 = 0;
  unsigned long lightLuxX10 = 0;
  unsigned long soilRaw = 0;
  unsigned long soilPercent = 0;
  unsigned int sampleValid = 0;
  char systemState[16] = {0};

  const int parsedFields = sscanf(
    reinterpret_cast<const char*>(plaintext),
    "TS=%lu;T=%ld;H=%lu;L=%lu;S=%lu;SP=%lu;V=%u;ST=%15s",
    &senderElapsedMs,
    &temperatureX100,
    &humidityX100,
    &lightLuxX10,
    &soilRaw,
    &soilPercent,
    &sampleValid,
    systemState
  );

  if (parsedFields != 8) {
    malformedDataPackets++;

    secureZeroize(
      plaintext,
      sizeof(plaintext)
    );

    secureZeroize(
      systemState,
      sizeof(systemState)
    );

    Serial.println(
      "SECURE DATA result        : DECRYPTED PAYLOAD MALFORMED"
    );

    return;
  }

  const unsigned long gatewayElapsedMs =
      millis() - establishedAtMs;

  const unsigned long timestampDeltaMs =
      senderElapsedMs > gatewayElapsedMs
        ? senderElapsedMs - gatewayElapsedMs
        : gatewayElapsedMs - senderElapsedMs;

  if (timestampDeltaMs > TIMESTAMP_WINDOW_MS) {
    staleTimestampRejected++;

    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println("STALE TIMESTAMP ATTACK REJECTED");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.print("Received sequence         : ");
    Serial.println(sequence);
    Serial.print("Sender elapsed timestamp  : ");
    Serial.print(senderElapsedMs);
    Serial.println(" ms");
    Serial.print("Gateway elapsed timestamp : ");
    Serial.print(gatewayElapsedMs);
    Serial.println(" ms");
    Serial.print("Timestamp delta           : ");
    Serial.print(timestampDeltaMs);
    Serial.println(" ms");
    Serial.print("Allowed window            : +/-");
    Serial.print(TIMESTAMP_WINDOW_MS);
    Serial.println(" ms");
    Serial.println("Outer HMAC verification   : PASSED");
    Serial.println("AES-GCM verification      : PASSED");
    Serial.println("Timestamp result          : REJECTED");
    Serial.println("Firebase forwarding       : BLOCKED");
    Serial.println("Packet accepted           : NO");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    secureZeroize(
      plaintext,
      sizeof(plaintext)
    );

    secureZeroize(
      systemState,
      sizeof(systemState)
    );

    return;
  }

  if (sampleValid == 1U) {
    validRealSensorSamples++;
  } else {
    invalidRealSensorSamples++;
  }

  if (
    lastAcceptedSequence > 0
    && sequence > lastAcceptedSequence + 1
  ) {
    sequenceGapCount +=
        sequence - lastAcceptedSequence - 1;
  }

  lastAcceptedSequence = sequence;
  encryptedPacketsAccepted++;

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("ENCRYPTED TELEMETRY ACCEPTED");
  Serial.println("------------------------------------------");
  Serial.print("Session ID                : ");
  Serial.println(packetSessionId);
  Serial.print("Sequence                  : ");
  Serial.println(sequence);
  Serial.println("Outer HMAC verification   : PASSED");
  Serial.println("Replay-window result      : FRESH");
  Serial.println("IV validation             : PASSED");
  Serial.println("AES-GCM decryption        : PASSED");
  Serial.println("GCM tag verification      : PASSED");
  Serial.print("Sender elapsed timestamp  : ");
  Serial.print(senderElapsedMs);
  Serial.println(" ms");
  Serial.print("Gateway elapsed timestamp : ");
  Serial.print(gatewayElapsedMs);
  Serial.println(" ms");
  Serial.print("Timestamp delta           : ");
  Serial.print(timestampDeltaMs);
  Serial.println(" ms");
  Serial.println("Timestamp freshness       : PASSED");
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
  Serial.print("Real sensor sample valid  : ");
  Serial.println(sampleValid == 1U ? "YES" : "NO");
  Serial.print("System state              : ");
  Serial.println(systemState);
  Serial.println("Packet accepted           : YES");

  const bool firebaseWritePassed =
      writeAcceptedTelemetryToFirebase(
        packetSessionId,
        sequence,
        temperatureX100,
        humidityX100,
        lightLuxX10,
        soilRaw,
        soilPercent,
        sampleValid,
        systemState
      );

  Serial.print("Firebase forwarding       : ");
  Serial.println(
    firebaseWritePassed
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("------------------------------------------");

  secureZeroize(
    plaintext,
    sizeof(plaintext)
  );

  secureZeroize(
    systemState,
    sizeof(systemState)
  );
}


void zeroizeGatewayKeysAfterReport() {
  if (postReportKeysZeroized) {
    return;
  }

  postReportKeysZeroized = true;

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
  Serial.println("POST-TEST KEY ZEROIZATION");
  Serial.print("AppSKey zeroization      : ");
  Serial.println(appZeroized ? "PASSED" : "FAILED");
  Serial.print("NwkSKey zeroization      : ");
  Serial.println(nwkZeroized ? "PASSED" : "FAILED");

  clearFirebaseIdToken();

  Serial.print("Firebase token cleared   : ");
  Serial.println(
    firebaseIdToken.length() == 0
      ? "PASSED"
      : "FAILED"
  );

  handshakeState =
      GatewayHandshakeState::ZEROIZED;
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

  if (line.startsWith("C2_HELLO_V1,")) {
    handleHello(line);
    return;
  }

  if (line.startsWith("C2_RESPONSE_V1,")) {
    handleResponse(line);
    return;
  }

  if (line.startsWith("C2_SECURE_V1,")) {
    handleEncryptedTelemetry(line);
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

  // Keep partial UART frames between loop iterations.
  // This prevents long E32 packets from being split by a short
  // readStringUntil() timeout.
  radioLineBuffer.reserve(MAX_RADIO_LINE_LENGTH);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 37D");
  Serial.println("TIMESTAMP FRESHNESS + FIREBASE — GATEWAY");
  Serial.println("==========================================");
  Serial.println("Radio mode                : TRANSPARENT");
  Serial.println("Gateway authentication    : HMAC-SHA256");
  Serial.println("Sensor authentication     : HMAC-SHA256");
  Serial.println("Session keys              : HKDF-SHA256");
  Serial.println("Actual keys printed       : NO");
  Serial.println("Development PSK           : YES");
  Serial.println("Production security claim : NOT YET");
  Serial.println("Firebase path             : /greenhouse/GH_NODE_01/current");
  Serial.println("Firebase token printed    : NO");
  Serial.println();

  if (!firebaseConfigurationPresent()) {
    Serial.println("CONFIGURATION RESULT      : REVIEW REQUIRED");
    Serial.println(
      "Replace Wi-Fi, Firebase email/password and gateway UID."
    );

    handshakeState =
        GatewayHandshakeState::FAILED;

    return;
  }

  const bool wifiPassed =
      connectGatewayWiFi();

  const bool timePassed =
      wifiPassed
      && synchronizeGatewayTime();

  const bool authPassed =
      timePassed
      && authenticateGatewayFirebase();

  firebaseReady =
      wifiPassed
      && timePassed
      && authPassed;

  Serial.print("Firebase gateway ready    : ");
  Serial.println(
    firebaseReady
      ? "PASSED"
      : "FAILED"
  );

  if (!firebaseReady) {
    handshakeState =
        GatewayHandshakeState::FAILED;

    return;
  }

  Serial.println("Waiting for sensor HELLO...");
  Serial.println();
}

void loop() {
  serviceE32Input();

  if (
    handshakeState
      == GatewayHandshakeState::WAITING_FOR_RESPONSE
    &&
    millis() - stateStartedAtMs
        >= HANDSHAKE_TIMEOUT_MS
  ) {
    resetToListening("Response timeout");
  }

  if (
    handshakeState
      == GatewayHandshakeState::ESTABLISHED
    &&
    dataSecurityReportPrinted
    &&
    !postReportKeysZeroized
    &&
    millis() - dataSecurityReportAtMs
        >= REPORT_ZEROIZE_DELAY_MS
  ) {
    zeroizeGatewayKeysAfterReport();
  }

  if (
    handshakeState
      == GatewayHandshakeState::ESTABLISHED
    &&
    millis() - establishedAtMs
        >= KEY_ACTIVE_WINDOW_MS
  ) {
    Serial.println(
      "Session safety timeout    : ZEROIZE"
    );

    if (!dataSecurityReportPrinted) {
      printGatewayDataSecurityReport();
    }

    zeroizeGatewayKeysAfterReport();
  }

  delay(5);
}
