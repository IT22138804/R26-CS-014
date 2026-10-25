/*
  Component 2 — Step 37C
  Gateway Firebase Authentication + protected RTDB test write

  Upload only to ESP32 No. 2 — Gateway.

  Before upload, edit locally:
    WIFI_SSID
    WIFI_PASSWORD
    FIREBASE_EMAIL
    FIREBASE_PASSWORD
    EXPECTED_GATEWAY_UID

  Serial Monitor: 115200
*/

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// =====================================================
// LOCAL VALUES — EDIT THESE
// =====================================================

const char* WIFI_SSID =
    "Abz";

const char* WIFI_PASSWORD =
    "12345678";

const char* FIREBASE_EMAIL =
    "REPLACE_WITH_GATEWAY_FIREBASE_EMAIL";

const char* FIREBASE_PASSWORD =
    "REPLACE_WITH_GATEWAY_FIREBASE_PASSWORD";

const char* EXPECTED_GATEWAY_UID =
    "REPLACE_WITH_GATEWAY_FIREBASE_UID";

// =====================================================
// PROVIDED FIREBASE CONFIGURATION
// =====================================================

const char* FIREBASE_API_KEY =
    "AIzaSyBmdU82c2_DeIVg974y8bl9jnK1m3UwO0c";

const char* FIREBASE_DATABASE_URL =
    "https://greenhouse-development-default-rtdb.firebaseio.com";

const char* NODE_ID =
    "GH_NODE_01";

const char* TEST_PATH =
    "/greenhouse/GH_NODE_01/tests/firebase_auth_write.json";

// =====================================================
// GOOGLE TRUST SERVICES ROOT R1
// =====================================================

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

String idToken;
String localId;

// =====================================================
// HELPERS
// =====================================================

bool configured() {
  return
      String(WIFI_SSID) != "REPLACE_WITH_YOUR_WIFI_NAME"
      &&
      String(WIFI_PASSWORD) != "REPLACE_WITH_YOUR_WIFI_PASSWORD"
      &&
      String(FIREBASE_EMAIL) != "REPLACE_WITH_GATEWAY_FIREBASE_EMAIL"
      &&
      String(FIREBASE_PASSWORD) != "REPLACE_WITH_GATEWAY_FIREBASE_PASSWORD"
      &&
      String(EXPECTED_GATEWAY_UID) != "REPLACE_WITH_GATEWAY_FIREBASE_UID";
}

String jsonEscape(const String& input) {
  String output;

  for (size_t i = 0; i < input.length(); i++) {
    const char c = input[i];

    if (c == '\\') {
      output += "\\\\";
    } else if (c == '"') {
      output += "\\\"";
    } else {
      output += c;
    }
  }

  return output;
}

bool extractJsonString(
    const String& json,
    const String& key,
    String& output
) {
  const String marker = "\"" + key + "\"";
  const int keyPosition = json.indexOf(marker);

  if (keyPosition < 0) {
    return false;
  }

  const int colon = json.indexOf(':', keyPosition);
  const int startQuote = json.indexOf('"', colon + 1);
  const int endQuote = json.indexOf('"', startQuote + 1);

  if (colon < 0 || startQuote < 0 || endQuote < 0) {
    return false;
  }

  output = json.substring(startQuote + 1, endQuote);
  return true;
}

void clearIdToken() {
  for (size_t i = 0; i < idToken.length(); i++) {
    idToken.setCharAt(i, '\0');
  }

  idToken = "";
}

// =====================================================
// WI-FI AND TIME
// =====================================================

bool connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Wi-Fi connection          : ");

  const unsigned long startMs = millis();

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
  Serial.print("Local IP                  : ");
  Serial.println(WiFi.localIP());
  Serial.print("RSSI                      : ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");

  return true;
}

bool synchronizeTime() {
  configTime(
    0,
    0,
    "time.google.com",
    "pool.ntp.org"
  );

  Serial.print("NTP synchronization      : ");

  const unsigned long startMs = millis();

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

// =====================================================
// FIREBASE AUTH
// =====================================================

bool firebaseSignIn() {
  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      "https://identitytoolkit.googleapis.com/"
      "v1/accounts:signInWithPassword?key="
      + String(FIREBASE_API_KEY);

  if (!https.begin(client, url)) {
    Serial.println("Auth HTTPS begin          : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const String body =
      "{\"email\":\""
      + jsonEscape(FIREBASE_EMAIL)
      + "\",\"password\":\""
      + jsonEscape(FIREBASE_PASSWORD)
      + "\",\"returnSecureToken\":true}";

  Serial.println();
  Serial.println("FIREBASE EMAIL/PASSWORD AUTH");
  Serial.println("Email printed             : NO");
  Serial.println("Password printed          : NO");
  Serial.println("ID token printed          : NO");

  const int code = https.POST(body);
  const String response =
      code > 0 ? https.getString() : "";

  https.end();

  Serial.print("Auth HTTP response        : ");
  Serial.println(code);

  if (code != 200) {
    String message;
    extractJsonString(response, "message", message);

    Serial.println("Firebase authentication  : FAILED");

    if (message.length() > 0) {
      Serial.print("Firebase error            : ");
      Serial.println(message);
    }

    return false;
  }

  if (
    !extractJsonString(response, "idToken", idToken)
    ||
    !extractJsonString(response, "localId", localId)
  ) {
    Serial.println("Auth response parsing     : FAILED");
    clearIdToken();
    return false;
  }

  const bool uidMatches =
      localId == EXPECTED_GATEWAY_UID;

  Serial.println("Firebase authentication  : PASSED");
  Serial.print("Authenticated UID         : ");
  Serial.println(localId);
  Serial.print("Expected UID match        : ");
  Serial.println(uidMatches ? "PASSED" : "FAILED");
  Serial.println("ID token stored in SRAM   : YES");

  if (!uidMatches) {
    clearIdToken();
    return false;
  }

  return true;
}

// =====================================================
// PROTECTED RTDB WRITE
// =====================================================

bool protectedWrite() {
  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      String(FIREBASE_DATABASE_URL)
      + TEST_PATH
      + "?auth="
      + idToken;

  if (!https.begin(client, url)) {
    Serial.println("RTDB HTTPS begin          : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const String payload =
      "{"
      "\"nodeId\":\""
      + String(NODE_ID)
      + "\","
      "\"test\":\"FIREBASE_AUTH_PROTECTED_WRITE\","
      "\"timestamp\":"
      + String(
          static_cast<unsigned long>(
            time(nullptr)
          )
        )
      + ","
      "\"gatewayUid\":\""
      + localId
      + "\","
      "\"connection\":\"online\","
      "\"systemState\":\"GATEWAY_TEST\","
      "\"security\":{"
      "\"firebaseAuthentication\":\"PASSED\","
      "\"uidAuthorization\":\"PASSED\","
      "\"tlsCertificateValidation\":\"ENABLED\","
      "\"idTokenPrinted\":false,"
      "\"passwordPrinted\":false"
      "}"
      "}";

  Serial.println();
  Serial.println("PROTECTED REALTIME DATABASE WRITE");
  Serial.print("Test path                 : ");
  Serial.println(TEST_PATH);
  Serial.println("Authorization             : FIREBASE ID TOKEN");
  Serial.println("ID token printed          : NO");

  const int code = https.PUT(payload);
  const String response =
      code > 0 ? https.getString() : "";

  https.end();

  Serial.print("Write HTTP response       : ");
  Serial.println(code);

  if (code != 200 && code != 204) {
    Serial.println("Protected RTDB write      : FAILED");

    if (response.length() > 0) {
      Serial.print("Firebase response         : ");
      Serial.println(response);
    }

    return false;
  }

  Serial.println("Protected RTDB write      : PASSED");
  return true;
}

// =====================================================
// SETUP
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 37C");
  Serial.println("FIREBASE AUTH + PROTECTED WRITE");
  Serial.println("==========================================");
  Serial.println("Target                    : GATEWAY ESP32");
  Serial.println("Sensor ESP32              : MAY REMAIN OFF");
  Serial.println("E32 modules               : MAY REMAIN OFF");
  Serial.println("TLS certificate checking  : ENABLED");
  Serial.println("Passwords printed         : NO");
  Serial.println();

  if (!configured()) {
    Serial.println("CONFIGURATION RESULT      : REVIEW REQUIRED");
    Serial.println(
      "Replace Wi-Fi, Firebase email/password and gateway UID."
    );
    return;
  }

  const bool wifiPassed = connectWiFi();

  if (!wifiPassed) {
    Serial.println("STEP 37C RESULT           : REVIEW REQUIRED");
    return;
  }

  const bool timePassed = synchronizeTime();

  if (!timePassed) {
    Serial.println("STEP 37C RESULT           : REVIEW REQUIRED");
    return;
  }

  const bool authPassed = firebaseSignIn();

  if (!authPassed) {
    Serial.println("STEP 37C RESULT           : REVIEW REQUIRED");
    return;
  }

  const bool writePassed = protectedWrite();

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 37C REPORT");
  Serial.println("==========================================");
  Serial.print("Wi-Fi connection          : ");
  Serial.println(wifiPassed ? "PASSED" : "FAILED");
  Serial.print("NTP synchronization       : ");
  Serial.println(timePassed ? "PASSED" : "FAILED");
  Serial.print("Firebase authentication   : ");
  Serial.println(authPassed ? "PASSED" : "FAILED");
  Serial.print("Protected RTDB write      : ");
  Serial.println(writePassed ? "PASSED" : "FAILED");
  Serial.println("Password printed          : NO");
  Serial.println("ID token printed          : NO");
  Serial.print("STEP 37C RESULT           : ");
  Serial.println(
    wifiPassed
    && timePassed
    && authPassed
    && writePassed
      ? "PASSED"
      : "REVIEW REQUIRED"
  );
  Serial.println("==========================================");

  clearIdToken();

  Serial.print("Runtime ID token cleared  : ");
  Serial.println(
    idToken.length() == 0
      ? "PASSED"
      : "FAILED"
  );
}

void loop() {
  delay(1000);
}
