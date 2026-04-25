/*
  Component 2 — Step 37B
  Gateway ESP32 Wi-Fi connectivity baseline

  Upload to:
    ESP32 No. 2 — Gateway ESP32 only

  For this step:
    - Sensor ESP32 may remain OFF.
    - Both E32 modules may remain OFF.
    - Connect the gateway ESP32 through USB.
    - Edit WIFI_SSID and WIFI_PASSWORD locally.
    - Serial Monitor: 115200

  Security:
    - The password is never printed.
    - This step performs Wi-Fi connectivity only.
    - Firebase and HTTPS are added in the next step.
*/

#include <Arduino.h>
#include <WiFi.h>

// =====================================================
// EDIT THESE TWO VALUES LOCALLY
// =====================================================

const char* WIFI_SSID =
    "SLT-FIBRE-CORP-5G";

const char* WIFI_PASSWORD =
    "9494431997";

// =====================================================
// CONNECTION SETTINGS
// =====================================================

constexpr unsigned long
    WIFI_CONNECT_TIMEOUT_MS = 30000;

constexpr unsigned long
    WIFI_STATUS_INTERVAL_MS = 5000;

constexpr unsigned long
    WIFI_RETRY_INTERVAL_MS = 5000;

unsigned long lastStatusAtMs = 0;
unsigned long lastRetryAtMs = 0;

uint32_t connectionAttemptCount = 0;
uint32_t reconnectCount = 0;

bool initialConnectionPassed = false;

// =====================================================
// HELPERS
// =====================================================

const char* wifiStatusName(
    wl_status_t status
) {
  switch (status) {
    case WL_IDLE_STATUS:
      return "IDLE";

    case WL_NO_SSID_AVAIL:
      return "SSID NOT FOUND";

    case WL_SCAN_COMPLETED:
      return "SCAN COMPLETED";

    case WL_CONNECTED:
      return "CONNECTED";

    case WL_CONNECT_FAILED:
      return "CONNECT FAILED";

    case WL_CONNECTION_LOST:
      return "CONNECTION LOST";

    case WL_DISCONNECTED:
      return "DISCONNECTED";

    default:
      return "UNKNOWN";
  }
}

void printNetworkDetails() {
  Serial.println();
  Serial.println("------------------------------------------");
  Serial.println("GATEWAY WI-FI CONNECTION DETAILS");
  Serial.println("------------------------------------------");

  Serial.print("Wi-Fi status             : ");
  Serial.println(
    wifiStatusName(WiFi.status())
  );

  Serial.print("SSID                     : ");
  Serial.println(WiFi.SSID());

  Serial.print("Gateway MAC address      : ");
  Serial.println(WiFi.macAddress());

  Serial.print("Local IP address         : ");
  Serial.println(WiFi.localIP());

  Serial.print("Gateway IP               : ");
  Serial.println(WiFi.gatewayIP());

  Serial.print("Subnet mask              : ");
  Serial.println(WiFi.subnetMask());

  Serial.print("Primary DNS              : ");
  Serial.println(WiFi.dnsIP(0));

  Serial.print("Secondary DNS            : ");
  Serial.println(WiFi.dnsIP(1));

  Serial.print("Signal strength          : ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");

  Serial.print("Wi-Fi channel            : ");
  Serial.println(WiFi.channel());

  Serial.print("Connection attempts      : ");
  Serial.println(connectionAttemptCount);

  Serial.print("Reconnect count          : ");
  Serial.println(reconnectCount);

  Serial.println("Password printed         : NO");
  Serial.println("Firebase connection      : NOT TESTED YET");
  Serial.println("------------------------------------------");
}

bool connectToWiFi() {
  connectionAttemptCount++;

  Serial.println();
  Serial.println("Starting Wi-Fi connection...");

  Serial.print("Connection attempt       : ");
  Serial.println(connectionAttemptCount);

  WiFi.disconnect(
    true,
    true
  );

  delay(500);

  WiFi.mode(WIFI_STA);

  // Disable Wi-Fi sleep during the gateway baseline.
  WiFi.setSleep(false);

  WiFi.begin(
    WIFI_SSID,
    WIFI_PASSWORD
  );

  const unsigned long startedAtMs =
      millis();

  while (
    WiFi.status() != WL_CONNECTED
    &&
    millis() - startedAtMs
        < WIFI_CONNECT_TIMEOUT_MS
  ) {
    Serial.print(".");
    delay(500);
  }

  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("Connection result         : FAILED / ");
    Serial.println(
      wifiStatusName(WiFi.status())
    );

    return false;
  }

  Serial.println("Connection result         : PASSED");

  printNetworkDetails();

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
  Serial.println("COMPONENT 2 — STEP 37B");
  Serial.println("GATEWAY WI-FI CONNECTIVITY BASELINE");
  Serial.println("==========================================");
  Serial.println("Target board              : GATEWAY ESP32");
  Serial.println("Sensor ESP32              : MAY REMAIN OFF");
  Serial.println("E32 radio power           : MAY REMAIN OFF");
  Serial.println("Firebase                  : NOT USED IN THIS STEP");
  Serial.println("Wi-Fi password printed    : NO");
  Serial.println();

  if (
    String(WIFI_SSID)
      == "REPLACE_WITH_YOUR_WIFI_NAME"
    ||
    String(WIFI_PASSWORD)
      == "REPLACE_WITH_YOUR_WIFI_PASSWORD"
  ) {
    Serial.println("CONFIGURATION RESULT      : REVIEW REQUIRED");
    Serial.println(
      "Replace WIFI_SSID and WIFI_PASSWORD before uploading."
    );

    return;
  }

  initialConnectionPassed =
      connectToWiFi();

  Serial.println();
  Serial.print("STEP 37B INITIAL RESULT   : ");

  Serial.println(
    initialConnectionPassed
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println("==========================================");
}

// =====================================================
// LOOP
// =====================================================

void loop() {
  if (
    String(WIFI_SSID)
      == "REPLACE_WITH_YOUR_WIFI_NAME"
  ) {
    delay(1000);
    return;
  }

  const unsigned long nowMs =
      millis();

  if (
    WiFi.status() == WL_CONNECTED
    &&
    nowMs - lastStatusAtMs
        >= WIFI_STATUS_INTERVAL_MS
  ) {
    lastStatusAtMs = nowMs;

    Serial.print("Wi-Fi heartbeat          : CONNECTED, RSSI=");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
  }

  if (
    WiFi.status() != WL_CONNECTED
    &&
    nowMs - lastRetryAtMs
        >= WIFI_RETRY_INTERVAL_MS
  ) {
    lastRetryAtMs = nowMs;
    reconnectCount++;

    Serial.println();
    Serial.println("Wi-Fi connection lost.");

    Serial.print("Reconnect attempt        : ");
    Serial.println(reconnectCount);

    connectToWiFi();
  }

  delay(50);
}
