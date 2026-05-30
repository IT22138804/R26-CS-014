/*
  Component 2 — Step 38I-4
  Network-Wide Coordinated Attack Demonstration

  Upload only to:
    ESP32 No. 2 — Gateway ESP32

  Purpose:
    Demonstrate the handwritten requirement:
      "When an attacker attacks all nodes"

    The current project has one real sensor node. Therefore:
      - GH_NODE_01 is labelled REAL.
      - SIM_NODE_02, SIM_NODE_03 and SIM_NODE_04 are labelled SIMULATION.
      - The coordinated all-node attack is a controlled simulation.
      - No real actuator command is sent.
      - No real cryptographic session is revoked.

  Dashboard outputs:
    /network/summary
    /network/nodes
    /greenhouse/GH_NODE_01/behavioral_anomaly/current
    /greenhouse/GH_NODE_01/behavioral_anomaly/history/network_wide_attack_step38i4
    /greenhouse/GH_NODE_01/security/events/network_wide_attack_step38i4
    /greenhouse/GH_NODE_01/system/status

  Serial Monitor:
    115200
*/

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// =====================================================
// LOCAL VALUES — EDIT ONLY THESE FIVE VALUES
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

// =====================================================
// FIREBASE PROJECT
// =====================================================

const char* FIREBASE_API_KEY =
    "AIzaSyBmdU82c2_DeIVg974y8bl9jnK1m3UwO0c";

const char* FIREBASE_DATABASE_URL =
    "https://greenhouse-development-default-rtdb.firebaseio.com";

const char* NETWORK_PATH =
    "/network.json";

const char* NODE_PATH =
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

String firebaseIdToken;
String firebaseLocalId;

bool baselineNetworkWritePassed = false;
bool attackNetworkWritePassed = false;
bool attackNodeEvidenceWritePassed = false;
bool firebaseTokenCleared = false;

// =====================================================
// HELPERS
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
    firebaseIdToken.setCharAt(index, '\0');
  }

  firebaseIdToken = "";
  firebaseTokenCleared = true;
}

bool connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Wi-Fi connection           : ");

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
    Serial.println("Wi-Fi result               : FAILED");
    return false;
  }

  Serial.println("Wi-Fi result               : PASSED");

  Serial.print("Gateway local IP           : ");
  Serial.println(WiFi.localIP());

  Serial.print("Wi-Fi RSSI                 : ");
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

  Serial.print("NTP synchronization       : ");

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
    Serial.println("NTP result                 : FAILED");
    return false;
  }

  Serial.println("NTP result                 : PASSED");
  return true;
}

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
    Serial.println("Firebase Auth HTTPS        : FAILED");
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

  Serial.print("Firebase Auth HTTP         : ");
  Serial.println(responseCode);

  if (responseCode != 200) {
    String errorMessage;

    extractJsonString(
      responseBody,
      "message",
      errorMessage
    );

    Serial.println("Firebase authentication   : FAILED");

    if (errorMessage.length() > 0) {
      Serial.print("Firebase error             : ");
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

    Serial.println("Firebase response parse    : FAILED");
    return false;
  }

  const bool uidMatches =
      firebaseLocalId == EXPECTED_GATEWAY_UID;

  Serial.println("Firebase authentication   : PASSED");

  Serial.print("Gateway UID verification   : ");
  Serial.println(uidMatches ? "PASSED" : "FAILED");

  Serial.println("Firebase password printed  : NO");
  Serial.println("Firebase token printed     : NO");

  if (!uidMatches) {
    clearFirebaseIdToken();
    return false;
  }

  return true;
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
    Serial.println(" write           : NOT READY");
    return false;
  }

  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      String(FIREBASE_DATABASE_URL)
      + String(relativePath)
      + "?auth="
      + firebaseIdToken;

  if (!https.begin(client, url)) {
    Serial.print(label);
    Serial.println(" HTTPS           : FAILED");
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
  Serial.print(" HTTP            : ");
  Serial.println(responseCode);

  if (
    responseCode != 200
    &&
    responseCode != 204
  ) {
    Serial.print(label);
    Serial.println(" write           : FAILED");

    if (responseBody.length() > 0) {
      Serial.print("Firebase response          : ");
      Serial.println(responseBody);
    }

    return false;
  }

  Serial.print(label);
  Serial.println(" write           : PASSED");
  return true;
}

bool patchJson(
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
    Serial.println(" write           : NOT READY");
    return false;
  }

  WiFiClientSecure client;
  client.setCACert(GTS_ROOT_R1);

  HTTPClient https;
  https.setTimeout(25000);

  const String url =
      String(FIREBASE_DATABASE_URL)
      + String(relativePath)
      + "?auth="
      + firebaseIdToken;

  if (!https.begin(client, url)) {
    Serial.print(label);
    Serial.println(" HTTPS           : FAILED");
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
  Serial.print(" HTTP            : ");
  Serial.println(responseCode);

  if (
    responseCode != 200
    &&
    responseCode != 204
  ) {
    Serial.print(label);
    Serial.println(" write           : FAILED");

    if (responseBody.length() > 0) {
      Serial.print("Firebase response          : ");
      Serial.println(responseBody);
    }

    return false;
  }

  Serial.print(label);
  Serial.println(" write           : PASSED");
  return true;
}

// =====================================================
// DEMONSTRATION DATA
// =====================================================

String baselineNetworkJson() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String json;
  json.reserve(1800);

  json += "{";

  json += "\"summary\":{";
  json += "\"realNodeCount\":1,";
  json += "\"simulatedNodeCount\":3,";
  json += "\"onlineNodeCount\":4,";
  json += "\"anomalousNodeCount\":0,";
  json += "\"affectedRatio\":0,";
  json += "\"networkRiskScore\":0,";
  json += "\"networkState\":\"NORMAL\",";
  json += "\"evidence\":\"MIXED_REAL_AND_SIMULATED\",";
  json += "\"lastEvaluatedAt\":";
  json += String(epoch);
  json += "},";

  json += "\"nodes\":{";

  json += "\"GH_NODE_01\":{";
  json += "\"source\":\"REAL\",";
  json += "\"online\":true,";
  json += "\"riskScore\":0,";
  json += "\"state\":\"NORMAL\"";
  json += "},";

  json += "\"SIM_NODE_02\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":0,";
  json += "\"state\":\"NORMAL\"";
  json += "},";

  json += "\"SIM_NODE_03\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":0,";
  json += "\"state\":\"NORMAL\"";
  json += "},";

  json += "\"SIM_NODE_04\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":0,";
  json += "\"state\":\"NORMAL\"";
  json += "}";

  json += "}";
  json += "}";

  return json;
}

String attackNetworkJson() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String json;
  json.reserve(2300);

  json += "{";

  json += "\"summary\":{";
  json += "\"realNodeCount\":1,";
  json += "\"simulatedNodeCount\":3,";
  json += "\"onlineNodeCount\":4,";
  json += "\"anomalousNodeCount\":4,";
  json += "\"affectedNodeCount\":4,";
  json += "\"totalNodeCount\":4,";
  json += "\"affectedRatio\":1.0,";
  json += "\"networkRiskScore\":25,";
  json += "\"networkState\":\"CRITICAL\",";
  json += "\"coordinatedPattern\":true,";
  json += "\"commonAnomalyType\":\"TRAFFIC_BURST_AUTH_FAILURE_STALE_TIME\",";
  json += "\"evidence\":\"CONTROLLED_NETWORK_WIDE_SIMULATION\",";
  json += "\"realHardwareNodeCount\":1,";
  json += "\"simulationRequired\":true,";
  json += "\"lastEvaluatedAt\":";
  json += String(epoch);
  json += "},";

  json += "\"nodes\":{";

  json += "\"GH_NODE_01\":{";
  json += "\"source\":\"REAL_NODE_SIMULATED_ATTACK_INPUT\",";
  json += "\"online\":true,";
  json += "\"riskScore\":85,";
  json += "\"state\":\"ANOMALOUS\",";
  json += "\"anomalyType\":\"COORDINATED_ATTACK_PATTERN\"";
  json += "},";

  json += "\"SIM_NODE_02\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":88,";
  json += "\"state\":\"ANOMALOUS\",";
  json += "\"anomalyType\":\"COORDINATED_ATTACK_PATTERN\"";
  json += "},";

  json += "\"SIM_NODE_03\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":92,";
  json += "\"state\":\"ANOMALOUS\",";
  json += "\"anomalyType\":\"COORDINATED_ATTACK_PATTERN\"";
  json += "},";

  json += "\"SIM_NODE_04\":{";
  json += "\"source\":\"SIMULATION\",";
  json += "\"online\":true,";
  json += "\"riskScore\":90,";
  json += "\"state\":\"ANOMALOUS\",";
  json += "\"anomalyType\":\"COORDINATED_ATTACK_PATTERN\"";
  json += "}";

  json += "}";
  json += "}";

  return json;
}

String attackNodePatchJson() {
  const unsigned long epoch =
      static_cast<unsigned long>(
        time(nullptr)
      );

  String json;
  json.reserve(4800);

  json += "{";

  json += "\"behavioral_anomaly/current\":{";
  json += "\"evidenceType\":\"NETWORK_WIDE_ATTACK_SIMULATION\",";
  json += "\"simulation\":true,";
  json += "\"nodeId\":\"GH_NODE_01\",";
  json += "\"evaluatedAt\":";
  json += String(epoch);
  json += ",";
  json += "\"sensorValue\":{";
  json += "\"score\":10,";
  json += "\"status\":\"SUSPICIOUS\",";
  json += "\"reasons\":\"COORDINATED_SENSOR_DEVIATION\"";
  json += "},";
  json += "\"trafficBehavior\":{";
  json += "\"score\":25,";
  json += "\"status\":\"CRITICAL\",";
  json += "\"reasons\":\"PACKET_BURST_RATE | AUTHENTICATION_FAILURE_SPIKE\"";
  json += "},";
  json += "\"networkWide\":{";
  json += "\"score\":25,";
  json += "\"status\":\"CRITICAL\",";
  json += "\"affectedNodeCount\":4,";
  json += "\"totalNodeCount\":4,";
  json += "\"affectedRatio\":1.0,";
  json += "\"reasons\":\"ALL_NODES_AFFECTED | COORDINATED_PATTERN | COMMON_ANOMALY_TYPE | SIMULATION_ONLY\"";
  json += "},";
  json += "\"timeBased\":{";
  json += "\"score\":20,";
  json += "\"status\":\"CRITICAL\",";
  json += "\"packetIntervalMs\":1000,";
  json += "\"timestampDeltaMs\":65000,";
  json += "\"missingHeartbeat\":false,";
  json += "\"reasons\":\"STALE_TIMESTAMP | PACKET_INTERVAL_DRIFT\"";
  json += "},";
  json += "\"overallRiskScore\":80,";
  json += "\"state\":\"CRITICAL\",";
  json += "\"confirmed\":true,";
  json += "\"confirmationCount\":3,";
  json += "\"requiredConfirmations\":3,";
  json += "\"action\":{";
  json += "\"decision\":\"ISOLATE_SIMULATED_NODES\",";
  json += "\"firebaseForwarding\":\"BLOCKED_FOR_SIMULATED_ATTACK\",";
  json += "\"keyAction\":\"SIMULATED_NETWORK_REVOCATION\",";
  json += "\"systemAction\":\"NETWORK_WIDE_CONTAINMENT\"";
  json += "}";
  json += "},";

  json += "\"behavioral_anomaly/history/network_wide_attack_step38i4\":{";
  json += "\"evidenceType\":\"NETWORK_WIDE_ATTACK_SIMULATION\",";
  json += "\"simulation\":true,";
  json += "\"realNodeCount\":1,";
  json += "\"simulatedNodeCount\":3,";
  json += "\"affectedNodeCount\":4,";
  json += "\"totalNodeCount\":4,";
  json += "\"affectedRatio\":1.0,";
  json += "\"networkWideScore\":25,";
  json += "\"overallRiskScore\":80,";
  json += "\"classification\":\"CRITICAL\",";
  json += "\"action\":\"NETWORK_WIDE_CONTAINMENT\",";
  json += "\"evaluatedAt\":";
  json += String(epoch);
  json += "},";

  json += "\"security/events/network_wide_attack_step38i4\":{";
  json += "\"timestamp\":";
  json += String(epoch);
  json += ",";
  json += "\"type\":\"NETWORK_WIDE_COORDINATED_ATTACK\",";
  json += "\"simulation\":true,";
  json += "\"realNodeCount\":1,";
  json += "\"simulatedNodeCount\":3,";
  json += "\"affectedNodeCount\":4,";
  json += "\"totalNodeCount\":4,";
  json += "\"affectedRatio\":1.0,";
  json += "\"input\":\"TRAFFIC_BURST_AUTH_FAILURE_STALE_TIME\",";
  json += "\"validationResult\":\"COORDINATED_PATTERN_DETECTED\",";
  json += "\"decision\":\"CONTAINMENT\",";
  json += "\"firebaseForwarding\":\"BLOCKED_FOR_SIMULATED_ATTACK\",";
  json += "\"keyAction\":\"SIMULATED_NETWORK_REVOCATION\",";
  json += "\"systemAction\":\"ISOLATE_SIMULATED_NODES\",";
  json += "\"realActuatorCommand\":false,";
  json += "\"researchLimitation\":\"REQUIRES_AT_LEAST_TWO_REAL_SENSOR_NODES_FOR_REAL_VALIDATION\"";
  json += "},";

  json += "\"system/status\":{";
  json += "\"sensorNodeOnline\":true,";
  json += "\"gatewayOnline\":true,";
  json += "\"firebaseConnected\":true,";
  json += "\"lastSensorPacketAt\":0,";
  json += "\"lastGatewayHeartbeatAt\":";
  json += String(epoch);
  json += ",";
  json += "\"firmwareSensor\":\"NOT_USED_IN_STEP_38I4\",";
  json += "\"firmwareGateway\":\"C2_STEP_38I4_NETWORK_WIDE_SIMULATION\",";
  json += "\"dashboardBridgeState\":\"NETWORK_WIDE_ATTACK_SIMULATION\",";
  json += "\"testEvidence\":\"CONTROLLED_NETWORK_WIDE_SIMULATION\"";
  json += "}";

  json += "}";

  return json;
}

// =====================================================
// ARDUINO
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1200);

  Serial.println();
  Serial.println("====================================================");
  Serial.println("COMPONENT 2 — STEP 38I-4");
  Serial.println("NETWORK-WIDE COORDINATED ATTACK DEMONSTRATION");
  Serial.println("====================================================");
  Serial.println("Target board               : ESP32 NO. 2 GATEWAY");
  Serial.println("Sensor ESP32               : NOT REQUIRED");
  Serial.println("E32 modules                : NOT REQUIRED");
  Serial.println("Real sensor nodes          : 1");
  Serial.println("Simulated sensor nodes     : 3");
  Serial.println("All-node attack evidence   : SIMULATION");
  Serial.println("Real actuator commands     : DISABLED");
  Serial.println("Actual keys printed        : NOT APPLICABLE");
  Serial.println();

  if (!configurationPresent()) {
    Serial.println("Configuration check        : FAILED");
    Serial.println(
      "Replace the five Wi-Fi/Firebase placeholder values."
    );
    Serial.println("STEP 38I-4 RESULT          : REVIEW REQUIRED");
    return;
  }

  const bool wifiPassed = connectWiFi();
  const bool ntpPassed =
      wifiPassed && synchronizeTime();
  const bool authPassed =
      ntpPassed && authenticateFirebase();

  if (!authPassed) {
    clearFirebaseIdToken();
    Serial.println("STEP 38I-4 RESULT          : REVIEW REQUIRED");
    return;
  }

  Serial.println();
  Serial.println("PHASE 1 — NORMAL MULTI-NODE BASELINE");

  baselineNetworkWritePassed =
      putJson(
        NETWORK_PATH,
        baselineNetworkJson(),
        "Baseline network"
      );

  delay(4000);

  Serial.println();
  Serial.println("PHASE 2 — COORDINATED ALL-NODE ATTACK INPUT");
  Serial.println("Affected nodes             : 4/4");
  Serial.println("Affected ratio             : 100%");
  Serial.println("Common anomaly             : TRAFFIC BURST + AUTH FAILURE + STALE TIME");

  attackNetworkWritePassed =
      putJson(
        NETWORK_PATH,
        attackNetworkJson(),
        "Attack network"
      );

  attackNodeEvidenceWritePassed =
      patchJson(
        NODE_PATH,
        attackNodePatchJson(),
        "Attack dashboard evidence"
      );

  const bool finalPassed =
      baselineNetworkWritePassed
      &&
      attackNetworkWritePassed
      &&
      attackNodeEvidenceWritePassed;

  Serial.println();
  Serial.println("====================================================");
  Serial.println("COMPONENT 2 — STEP 38I-4 FINAL REPORT");
  Serial.println("====================================================");
  Serial.print("Baseline network write     : ");
  Serial.println(
    baselineNetworkWritePassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Attack network write       : ");
  Serial.println(
    attackNetworkWritePassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.print("Dashboard evidence write   : ");
  Serial.println(
    attackNodeEvidenceWritePassed
      ? "PASSED"
      : "FAILED"
  );
  Serial.println("Total nodes                : 4");
  Serial.println("Real nodes                 : 1");
  Serial.println("Simulated nodes            : 3");
  Serial.println("Affected nodes             : 4");
  Serial.println("Affected ratio             : 100%");
  Serial.println("Network-wide score         : 25/25");
  Serial.println("Overall risk score         : 80/100");
  Serial.println("Classification             : CRITICAL");
  Serial.println("Decision                   : NETWORK-WIDE CONTAINMENT");
  Serial.println("Firebase forwarding        : BLOCKED FOR SIMULATED ATTACK");
  Serial.println("Real actuator commands     : DISABLED");
  Serial.println("Evidence type              : SIMULATION");
  Serial.println(
    "Research limitation        : NEED 2+ REAL SENSOR NODES"
  );
  Serial.print("STEP 38I-4 RESULT          : ");
  Serial.println(
    finalPassed
      ? "PASSED"
      : "REVIEW REQUIRED"
  );
  Serial.println("====================================================");

  clearFirebaseIdToken();

  Serial.print("Firebase token cleared     : ");
  Serial.println(
    firebaseTokenCleared
      &&
      firebaseIdToken.length() == 0
        ? "PASSED"
        : "FAILED"
  );
}

void loop() {
  delay(1000);
}
