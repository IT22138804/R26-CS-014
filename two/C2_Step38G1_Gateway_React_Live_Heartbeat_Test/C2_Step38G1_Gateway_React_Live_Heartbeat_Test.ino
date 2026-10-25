/*
  Component 2 — Step 38G-1
  Gateway-to-React Dashboard Live Heartbeat Test

  Upload only to:
    ESP32 No. 2 — Gateway ESP32

  This test verifies:
    1. Gateway Wi-Fi connection
    2. NTP time synchronization
    3. Firebase email/password authentication
    4. Gateway UID verification
    5. Repeated live writes to the dashboard status path
    6. Dashboard-visible heartbeat counter and timestamps
    7. Final offline state and Firebase token zeroization

  Hardware:
    - Sensor ESP32 may remain OFF.
    - Both E32 modules may remain OFF.
    - Serial Monitor: 115200.

  Security:
    - The password and ID token are never printed.
    - This uses the gateway Firebase account, not the dashboard account.
    - Only the system/status and dashboard_bridge_test paths are modified.
*/

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// =====================================================
// LOCAL VALUES — EDIT THESE FIVE VALUES
// =====================================================

const char* WIFI_SSID =
    "chathu_s";

const char* WIFI_PASSWORD =
    "Movi@1114";

const char* FIREBASE_EMAIL =
    "ghouse@gmail.com";

const char* FIREBASE_PASSWORD =
    "Test@1214";

const char* EXPECTED_GATEWAY_UID =
    "3I9Eo1cltNQb68WcizDWlwb4wDm1";

// =====================================================
// FIREBASE PROJECT CONFIGURATION
// =====================================================

const char* FIREBASE_API_KEY =
    "AIzaSyBmdU82c2_DeIVg974y8bl9jnK1m3UwO0c";

const char* FIREBASE_DATABASE_URL =
    "https://greenhouse-development-default-rtdb.firebaseio.com";

const char* NODE_ID =
    "GH_NODE_01";

const char* FIRMWARE_VERSION =
    "C2_STEP_38G1_DASHBOARD_HEARTBEAT";

const char* STATUS_PATH =
    "/greenhouse/GH_NODE_01/system/status.json";

const char* TEST_PATH =
    "/greenhouse/GH_NODE_01/system/dashboard_bridge_test.json";

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

String firebaseIdToken;
String firebaseLocalId;

constexpr uint8_t HEARTBEAT_TARGET = 10;
constexpr unsigned long HEARTBEAT_INTERVAL_MS = 5000;

uint8_t heartbeatAttempts = 0;
uint8_t heartbeatWritesPassed = 0;
uint8_t heartbeatWritesFailed = 0;

unsigned long lastHeartbeatMs = 0;

bool setupCompleted = false;
bool finalReportPrinted = false;

// =====================================================
// CONFIGURATION AND STRING HELPERS
// =====================================================

bool configurationPresent() {
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

  for (size_t index = 0; index < input.length(); index++) {
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

void clearFirebaseToken() {
  for (
    size_t index = 0;
    index < firebaseIdToken.length();
    index++
  ) {
    firebaseIdToken.setCharAt(index, '\0');
  }

  firebaseIdToken = "";
}

// =====================================================
// WI-FI AND NTP
// =====================================================

bool connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

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

bool synchronizeTime() {
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

// =====================================================
// FIREBASE AUTHENTICATION
// =====================================================

bool authenticateFirebase() {
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
    clearFirebaseToken();
    Serial.println("Firebase response parse   : FAILED");
    return false;
  }

  const bool uidMatches =
      firebaseLocalId == EXPECTED_GATEWAY_UID;

  Serial.println("Firebase authentication  : PASSED");

  Serial.print("Expected UID match        : ");
  Serial.println(
    uidMatches
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("Firebase password printed : NO");
  Serial.println("Firebase token printed    : NO");

  if (!uidMatches) {
    clearFirebaseToken();
    return false;
  }

  return true;
}

// =====================================================
// FIREBASE HTTPS WRITE
// =====================================================

String authenticatedUrl(const char* relativePath) {
  return
      String(FIREBASE_DATABASE_URL)
      + String(relativePath)
      + "?auth="
      + firebaseIdToken;
}

bool putJson(
    const char* relativePath,
    const String& payload,
    const char* label
) {
  if (
    WiFi.status() != WL_CONNECTED
    ||
    firebaseIdToken.length() == 0
  ) {
    Serial.print(label);
    Serial.println(" write            : FAILED — NOT CONNECTED");
    return false;
  }

  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      authenticatedUrl(relativePath);

  if (!https.begin(client, url)) {
    Serial.print(label);
    Serial.println(" HTTPS            : FAILED");
    return false;
  }

  https.addHeader(
    "Content-Type",
    "application/json"
  );

  const int responseCode =
      https.PUT(payload);

  const String responseBody =
      responseCode > 0
        ? https.getString()
        : "";

  https.end();

  Serial.print(label);
  Serial.print(" HTTP             : ");
  Serial.println(responseCode);

  if (
    responseCode != 200
    &&
    responseCode != 204
  ) {
    Serial.print(label);
    Serial.println(" write            : FAILED");

    if (responseBody.length() > 0) {
      Serial.print("Firebase response         : ");
      Serial.println(responseBody);
    }

    return false;
  }

  Serial.print(label);
  Serial.println(" write            : PASSED");
  return true;
}

// =====================================================
// DASHBOARD HEARTBEAT
// =====================================================

String buildStatusJson(
    bool gatewayOnline,
    bool firebaseConnected,
    uint8_t heartbeatNumber
) {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String payload;
  payload.reserve(650);

  payload += "{";
  payload += "\"sensorNodeOnline\":false,";
  payload += "\"gatewayOnline\":";
  payload += gatewayOnline ? "true" : "false";
  payload += ",";
  payload += "\"firebaseConnected\":";
  payload += firebaseConnected ? "true" : "false";
  payload += ",";
  payload += "\"lastSensorPacketAt\":0,";
  payload += "\"lastGatewayHeartbeatAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"firmwareSensor\":\"NOT_RUNNING_IN_THIS_TEST\",";
  payload += "\"firmwareGateway\":\"";
  payload += FIRMWARE_VERSION;
  payload += "\",";
  payload += "\"dashboardBridgeState\":\"";
  payload += gatewayOnline
      ? "LIVE"
      : "TEST_COMPLETED";
  payload += "\",";
  payload += "\"heartbeatNumber\":";
  payload += String(heartbeatNumber);
  payload += ",";
  payload += "\"heartbeatTarget\":";
  payload += String(HEARTBEAT_TARGET);
  payload += ",";
  payload += "\"wifiRssiDbm\":";
  payload += String(WiFi.RSSI());
  payload += ",";
  payload += "\"testEvidence\":\"REAL_GATEWAY_TO_FIREBASE_TO_REACT\"";
  payload += "}";

  return payload;
}

String buildBridgeTestJson(
    const char* result
) {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String payload;
  payload.reserve(500);

  payload += "{";
  payload += "\"step\":\"38G-1\",";
  payload += "\"test\":\"GATEWAY_REACT_LIVE_HEARTBEAT\",";
  payload += "\"nodeId\":\"";
  payload += NODE_ID;
  payload += "\",";
  payload += "\"heartbeatsAttempted\":";
  payload += String(heartbeatAttempts);
  payload += ",";
  payload += "\"heartbeatsPassed\":";
  payload += String(heartbeatWritesPassed);
  payload += ",";
  payload += "\"heartbeatsFailed\":";
  payload += String(heartbeatWritesFailed);
  payload += ",";
  payload += "\"lastHeartbeatAt\":";
  payload += String(epoch);
  payload += ",";
  payload += "\"realHardware\":true,";
  payload += "\"dashboardReadExpected\":true,";
  payload += "\"result\":\"";
  payload += result;
  payload += "\"";
  payload += "}";

  return payload;
}

void sendHeartbeat() {
  heartbeatAttempts++;

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.print("Heartbeat                  : ");
  Serial.print(heartbeatAttempts);
  Serial.print("/");
  Serial.println(HEARTBEAT_TARGET);

  const String statusPayload =
      buildStatusJson(
        true,
        true,
        heartbeatAttempts
      );

  const bool statusPassed =
      putJson(
        STATUS_PATH,
        statusPayload,
        "System status"
      );

  const String testPayload =
      buildBridgeTestJson(
        statusPassed
          ? "RUNNING"
          : "WRITE_FAILED"
      );

  const bool testPassed =
      putJson(
        TEST_PATH,
        testPayload,
        "Bridge evidence"
      );

  if (statusPassed && testPassed) {
    heartbeatWritesPassed++;

    Serial.println(
      "Dashboard heartbeat result : PASSED"
    );
  } else {
    heartbeatWritesFailed++;

    Serial.println(
      "Dashboard heartbeat result : FAILED"
    );
  }

  lastHeartbeatMs = millis();
}

void finalizeTest() {
  const bool heartbeatResult =
      heartbeatAttempts == HEARTBEAT_TARGET
      &&
      heartbeatWritesPassed == HEARTBEAT_TARGET
      &&
      heartbeatWritesFailed == 0;

  const String finalStatus =
      buildStatusJson(
        false,
        true,
        heartbeatAttempts
      );

  const bool offlineStatusPassed =
      putJson(
        STATUS_PATH,
        finalStatus,
        "Final offline status"
      );

  const bool preliminaryPassed =
      heartbeatResult
      &&
      offlineStatusPassed;

  const String finalEvidence =
      buildBridgeTestJson(
        preliminaryPassed
          ? "PASSED"
          : "REVIEW_REQUIRED"
      );

  const bool finalEvidencePassed =
      putJson(
        TEST_PATH,
        finalEvidence,
        "Final evidence"
      );

  const bool finalPassed =
      preliminaryPassed
      &&
      finalEvidencePassed;

  clearFirebaseToken();

  const bool tokenCleared =
      firebaseIdToken.length() == 0;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38G-1 FINAL REPORT");
  Serial.println("==========================================");

  Serial.print("Wi-Fi connection          : ");
  Serial.println(
    WiFi.status() == WL_CONNECTED
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("NTP synchronization       : PASSED");
  Serial.println("Firebase authentication   : PASSED");
  Serial.println("Gateway UID verification  : PASSED");

  Serial.print("Heartbeats attempted      : ");
  Serial.println(heartbeatAttempts);

  Serial.print("Heartbeats passed         : ");
  Serial.println(heartbeatWritesPassed);

  Serial.print("Heartbeats failed         : ");
  Serial.println(heartbeatWritesFailed);

  Serial.print("Final offline status      : ");
  Serial.println(
    offlineStatusPassed
      ? "PASSED"
      : "FAILED"
  );

  Serial.print("Final evidence write      : ");
  Serial.println(
    finalEvidencePassed
      ? "PASSED"
      : "FAILED"
  );

  Serial.print("Firebase token cleared    : ");
  Serial.println(
    tokenCleared
      ? "PASSED"
      : "FAILED"
  );

  Serial.println(
    "React dashboard path      : /greenhouse/GH_NODE_01/system/status"
  );

  Serial.println(
    "Bridge evidence path      : /greenhouse/GH_NODE_01/system/dashboard_bridge_test"
  );

  Serial.print("STEP 38G-1 RESULT         : ");
  Serial.println(
    finalPassed && tokenCleared
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println("==========================================");

  finalReportPrinted = true;
}

// =====================================================
// ARDUINO
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1400);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 38G-1");
  Serial.println("GATEWAY → FIREBASE → REACT HEARTBEAT TEST");
  Serial.println("==========================================");
  Serial.println("Target board              : ESP32 NO. 2 GATEWAY");
  Serial.println("Sensor ESP32              : MAY REMAIN OFF");
  Serial.println("E32 modules               : MAY REMAIN OFF");
  Serial.println("Heartbeat interval        : 5 seconds");
  Serial.println("Heartbeat target          : 10");
  Serial.println("Real hardware evidence    : YES");
  Serial.println("Actual keys printed       : NOT APPLICABLE");
  Serial.println();

  if (!configurationPresent()) {
    Serial.println("Configuration check       : FAILED");
    Serial.println(
      "Replace the five Wi-Fi/Firebase placeholder values."
    );
    Serial.println("STEP 38G-1 RESULT         : REVIEW REQUIRED");
    return;
  }

  const bool wifiPassed =
      connectWiFi();

  const bool timePassed =
      wifiPassed
      &&
      synchronizeTime();

  const bool authPassed =
      timePassed
      &&
      authenticateFirebase();

  setupCompleted =
      wifiPassed
      &&
      timePassed
      &&
      authPassed;

  Serial.print("Gateway dashboard bridge  : ");
  Serial.println(
    setupCompleted
      ? "READY"
      : "FAILED"
  );

  if (!setupCompleted) {
    clearFirebaseToken();
    Serial.println("STEP 38G-1 RESULT         : REVIEW REQUIRED");
    return;
  }

  sendHeartbeat();
}

void loop() {
  if (
    !setupCompleted
    ||
    finalReportPrinted
  ) {
    delay(1000);
    return;
  }

  if (
    heartbeatAttempts < HEARTBEAT_TARGET
    &&
    millis() - lastHeartbeatMs
        >= HEARTBEAT_INTERVAL_MS
  ) {
    sendHeartbeat();
  }

  if (
    heartbeatAttempts >= HEARTBEAT_TARGET
    &&
    !finalReportPrinted
  ) {
    delay(800);
    finalizeTest();
  }

  delay(20);
}
