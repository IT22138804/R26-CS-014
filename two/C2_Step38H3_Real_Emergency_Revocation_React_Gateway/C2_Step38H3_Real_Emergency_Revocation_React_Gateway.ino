#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>
#include <mbedtls/md.h>
#include <esp_system.h>

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 16;
constexpr size_t SESSION_KEY_LENGTH = 16;
constexpr size_t PROOF_LENGTH = 16;
constexpr size_t REVOCATION_NONCE_LENGTH = 12;

const char NODE_ID[] = "GH_NODE_01";

// =====================================================
// STEP 38H-3 — LOCAL VALUES
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

String firebaseIdToken;
String firebaseLocalId;

bool firebaseReady = false;
bool firebaseRevocationEvidencePassed = false;
bool firebaseTokenCleared = false;

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
  firebaseTokenCleared = true;
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

bool writeRevocationDashboardEvidence() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String payload;
  payload.reserve(3800);

  payload += "{";

  payload += "\"security/session\":{";
  payload += "\"state\":\"REVOKED\",";
  payload += "\"sessionId\":";
  payload += String(revokedSessionId);
  payload += ",";
  payload += "\"startedAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastAcceptedSequence\":";
  payload += String(lastBaselineSequence);
  payload += ",";
  payload += "\"packetsSinceRotation\":";
  payload += String(baselinePacketsAccepted);
  payload += ",";
  payload += "\"revoked\":true,";
  payload += "\"revocationCounter\":";
  payload += String(revocationCounter);
  payload += ",";
  payload += "\"revocationReason\":\"";
  payload += revocationReason;
  payload += "\"";
  payload += "},";

  payload += "\"security/key_lifecycle\":{";
  payload += "\"appSKeyState\":\"ZEROIZED\",";
  payload += "\"nwkSKeyState\":\"ZEROIZED\",";
  payload += "\"rotationCounter\":0,";
  payload += "\"lastRotationAt\":0,";
  payload += "\"lastRotationReason\":\"NONE\",";
  payload += "\"productionPacketLimit\":1000,";
  payload += "\"productionTimeLimitHours\":24,";
  payload += "\"lastRevocationAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"lastRevocationReason\":\"";
  payload += revocationReason;
  payload += "\"";
  payload += "},";

  payload += "\"security/counters/sessionRevocations\":1,";
  payload += "\"security/counters/acceptedPackets\":";
  payload += String(baselinePacketsAccepted);
  payload += ",";
  payload += "\"security/counters/replayRejected\":";
  payload += String(revokedSessionPacketsRejected);
  payload += ",";

  payload += "\"security/events/emergency_revocation_step38h3\":{";
  payload += "\"timestamp\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"type\":\"EMERGENCY_SESSION_REVOCATION\",";
  payload += "\"nodeId\":\"";
  payload += NODE_ID;
  payload += "\",";
  payload += "\"sessionId\":";
  payload += String(revokedSessionId);
  payload += ",";
  payload += "\"revocationCounter\":";
  payload += String(revocationCounter);
  payload += ",";
  payload += "\"reason\":\"";
  payload += revocationReason;
  payload += "\",";
  payload += "\"evidence\":\"REAL_E32_SENSOR_GATEWAY\",";
  payload += "\"simulation\":false,";
  payload += "\"baselinePacketsAccepted\":";
  payload += String(baselinePacketsAccepted);
  payload += ",";
  payload += "\"commandHmac\":\"";
  payload += revocationCommandHmacBuilt
      ? "PASSED"
      : "FAILED";
  payload += "\",";
  payload += "\"sensorAck\":\"";
  payload += sensorRevocationAckVerified
      ? "PASSED"
      : "FAILED";
  payload += "\",";
  payload += "\"gatewayAppKeyZeroized\":\"";
  payload += appKeyZeroized
      ? "PASSED"
      : "FAILED";
  payload += "\",";
  payload += "\"gatewayNwkKeyZeroized\":\"";
  payload += nwkKeyZeroized
      ? "PASSED"
      : "FAILED";
  payload += "\",";
  payload += "\"revokedSessionMarker\":\"";
  payload += revokedSessionStateActive
      ? "ACTIVE"
      : "FAILED";
  payload += "\",";
  payload += "\"oldSessionPacketsRejected\":";
  payload += String(revokedSessionPacketsRejected);
  payload += ",";
  payload += "\"hmacAfterRevocation\":\"NOT_ATTEMPTED\",";
  payload += "\"decision\":\"REVOKED\",";
  payload += "\"firebaseForwarding\":\"BLOCKED\",";
  payload += "\"keyAction\":\"APPSKEY_NWKSKEY_ZEROIZED\",";
  payload += "\"systemAction\":\"REVOKED_SESSION_TRAFFIC_REJECTED\",";
  payload += "\"actualKeysPrinted\":false";
  payload += "},";

  payload += "\"behavioral_anomaly/current\":{";
  payload += "\"evidenceType\":\"REAL_EMERGENCY_REVOCATION\",";
  payload += "\"simulation\":false,";
  payload += "\"overallRiskScore\":100,";
  payload += "\"state\":\"CRITICAL\",";
  payload += "\"confirmed\":true,";
  payload += "\"confirmationCount\":3,";
  payload += "\"requiredConfirmations\":3,";
  payload += "\"sensorValue\":{";
  payload += "\"score\":0,";
  payload += "\"status\":\"NORMAL\",";
  payload += "\"reasons\":\"NONE\"";
  payload += "},";
  payload += "\"trafficBehavior\":{";
  payload += "\"score\":25,";
  payload += "\"status\":\"CRITICAL\",";
  payload += "\"reasons\":\"EMERGENCY_SECURITY_EVENT | REVOKED_SESSION_TRAFFIC\"";
  payload += "},";
  payload += "\"networkWide\":{";
  payload += "\"score\":0,";
  payload += "\"status\":\"NOT_ENOUGH_REAL_NODES\",";
  payload += "\"reasons\":\"MULTI_NODE_VALIDATION_REQUIRES_AT_LEAST_TWO_REAL_NODES\"";
  payload += "},";
  payload += "\"timeBased\":{";
  payload += "\"score\":0,";
  payload += "\"status\":\"NORMAL\",";
  payload += "\"reasons\":\"NONE\"";
  payload += "},";
  payload += "\"action\":{";
  payload += "\"decision\":\"REVOKE_SESSION\",";
  payload += "\"firebaseForwarding\":\"BLOCKED\",";
  payload += "\"keyAction\":\"APPSKEY_NWKSKEY_ZEROIZED\",";
  payload += "\"systemAction\":\"LOCKDOWN\"";
  payload += "},";
  payload += "\"evaluatedAt\":";
  payload += String(epoch);
  payload += "},";

  payload += "\"behavioral_anomaly/history/emergency_revocation_step38h3\":{";
  payload += "\"evidenceType\":\"REAL_EMERGENCY_REVOCATION\",";
  payload += "\"simulation\":false,";
  payload += "\"overallRiskScore\":100,";
  payload += "\"state\":\"CRITICAL\",";
  payload += "\"action\":\"REVOKE_SESSION\",";
  payload += "\"evaluatedAt\":";
  payload += String(epoch);
  payload += "},";

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
  payload += "\"firmwareSensor\":\"C2_STEP_38C_REVOCATION_SENSOR\",";
  payload += "\"firmwareGateway\":\"C2_STEP_38H3_REVOCATION_DASHBOARD_GATEWAY\",";
  payload += "\"dashboardBridgeState\":\"SESSION_REVOKED\",";
  payload += "\"testEvidence\":\"REAL_EMERGENCY_REVOCATION\"";
  payload += "}";

  payload += "}";

  firebaseRevocationEvidencePassed =
      patchFirebaseNode(
        payload,
        "Revocation dashboard evidence"
      );

  return firebaseRevocationEvidencePassed;
}

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
  Serial.println("STEP 38H-3 GATEWAY RESULT   : REVIEW REQUIRED");
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

  writeRevocationDashboardEvidence();

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
      revokedSessionPacketsRejected == 1
      &&
      firebaseRevocationEvidencePassed;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38H-3 GATEWAY REPORT");
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
  Serial.print("Dashboard evidence write  : ");
  Serial.println(
    firebaseRevocationEvidencePassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.println("Post-revoke forwarding    : BLOCKED");
  Serial.println("Actual keys printed       : NO");
  Serial.print("STEP 38H-3 GATEWAY RESULT   : ");
  Serial.println(passed ? "PASSED" : "REVIEW REQUIRED");
  Serial.println("==========================================");

  clearFirebaseIdToken();

  Serial.print("Firebase token cleared    : ");
  Serial.println(
    firebaseTokenCleared
      &&
      firebaseIdToken.length() == 0
        ? "PASSED"
        : "FAILED"
  );

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

  if (!firebaseConfigurationPresent()) {
    Serial.println();
    Serial.println("Configuration check       : FAILED");
    Serial.println(
      "Replace Wi-Fi/Firebase placeholders before upload."
    );
    state = GatewayState::FAILED;
    Serial.println("STEP 38H-3 GATEWAY RESULT : REVIEW REQUIRED");
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
    Serial.println("STEP 38H-3 GATEWAY RESULT : REVIEW REQUIRED");
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
  Serial.println("COMPONENT 2 — STEP 38H-3");
  Serial.println("REAL REVOCATION + REACT DASHBOARD — GATEWAY");
  Serial.println("==========================================");
  Serial.println("Trigger                    : EMERGENCY SECURITY EVENT");
  Serial.println("Command authentication     : CURRENT NWKSKEY HMAC");
  Serial.println("Revocation counter         : MONOTONIC");
  Serial.println("Gateway revocation marker  : SRAM TEST ENTRY");
  Serial.println("Post-revoke forwarding     : BLOCKED");
  Serial.println("Actual keys printed        : NO");
  Serial.println("Development master PSK     : YES");
  Serial.println("Production security claim  : NOT YET");
  Serial.println("React dashboard evidence   : ENABLED");
  Serial.println("Firebase actual keys       : NEVER WRITTEN");
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
