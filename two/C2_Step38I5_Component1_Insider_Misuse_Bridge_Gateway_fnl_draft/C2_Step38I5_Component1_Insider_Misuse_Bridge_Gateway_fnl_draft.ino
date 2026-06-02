#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>
#include <Preferences.h>
#include "mbedtls/md.h"

#define DHT_PIN 4
#define DHT_TYPE DHT11

#define FLAME_PIN 27
#define PIR_PIN 26

#define DEVICE_ID "SN-ENV-01"

DHT dht(DHT_PIN, DHT_TYPE);

Preferences preferences;


// -------------------------
// CHANGE THESE
// -------------------------

const char* WIFI_SSID =
    "chathu_s";

const char* WIFI_PASSWORD =
    "Movi@1114";

const char* GATEWAY_URL =
    "http://192.168.1.12:8000/telemetry";

const char* DEVICE_SECRET =
    "bc859b79a2166b2763c9d1b66a993ecb6032099da307d46532508a79130d172d";


// -------------------------
// SEQUENCE
// -------------------------

uint64_t sequenceNumber = 0;


// Reserve sequence numbers so that
// rebooting does not reuse old numbers.

void initialiseSequence() {

  preferences.begin(
      "sn-sec",
      false
  );

  uint64_t reservedEnd =
      preferences.getULong64(
          "seqend",
          0
      );

  sequenceNumber =
      reservedEnd + 1;

  uint64_t newReservedEnd =
      reservedEnd + 1000;

  preferences.putULong64(
      "seqend",
      newReservedEnd
  );

  preferences.end();


  Serial.print(
      "Starting sequence: "
  );

  Serial.println(
      (unsigned long long)
      sequenceNumber
  );
}


// -------------------------
// HMAC SHA256
// -------------------------

String createHMAC(
    const String& payload
) {

  byte output[32];

  const mbedtls_md_info_t* mdInfo =
      mbedtls_md_info_from_type(
          MBEDTLS_MD_SHA256
      );

  mbedtls_md_hmac(
      mdInfo,

      (const unsigned char*)
          DEVICE_SECRET,

      strlen(
          DEVICE_SECRET
      ),

      (const unsigned char*)
          payload.c_str(),

      payload.length(),

      output
  );


  char hexResult[65];

  for (
      int i = 0;
      i < 32;
      i++
  ) {

    sprintf(
        hexResult + (i * 2),
        "%02x",
        output[i]
    );
  }

  hexResult[64] = '\0';

  return String(hexResult);
}


// -------------------------
// WIFI
// -------------------------

void connectWiFi() {

  WiFi.begin(
      WIFI_SSID,
      WIFI_PASSWORD
  );

  Serial.print(
      "Connecting WiFi"
  );

  while (
      WiFi.status()
      != WL_CONNECTED
  ) {

    delay(500);
    Serial.print(".");
  }

  Serial.println();

  Serial.println(
      "WiFi connected"
  );

  Serial.print(
      "IP: "
  );

  Serial.println(
      WiFi.localIP()
  );
}


// -------------------------
// SETUP
// -------------------------

void setup() {

  Serial.begin(115200);

  dht.begin();

  pinMode(
      FLAME_PIN,
      INPUT
  );

  pinMode(
      PIR_PIN,
      INPUT
  );

  initialiseSequence();

  connectWiFi();

  Serial.println(
      "SECURENEST SN-ENV-01 SECURE"
  );
}


// -------------------------
// LOOP
// -------------------------

void loop() {

  if (
      WiFi.status()
      != WL_CONNECTED
  ) {

    connectWiFi();
  }


  float temperature =
      dht.readTemperature();

  float humidity =
      dht.readHumidity();

  int flameRaw =
      digitalRead(
          FLAME_PIN
      );

  int motionRaw =
      digitalRead(
          PIR_PIN
      );


  uint64_t currentSeq =
      sequenceNumber++;


  char seqBuffer[32];

  snprintf(
      seqBuffer,
      sizeof(seqBuffer),
      "%llu",
      (unsigned long long)
          currentSeq
  );


  String payload = "{";

  payload +=
      "\"schema_version\":\"1.1\",";

  payload +=
      "\"device_id\":\"SN-ENV-01\",";

  payload +=
      "\"device_type\":\"environment_sensor\",";

  payload +=
      "\"seq\":";

  payload += seqBuffer;

  payload += ",";


  payload +=
      "\"temperature_c\":";

  if (
      isnan(temperature)
  ) {

    payload += "null";

  } else {

    payload +=
        String(
            temperature,
            1
        );
  }


  payload += ",";

  payload +=
      "\"humidity_pct\":";

  if (
      isnan(humidity)
  ) {

    payload += "null";

  } else {

    payload +=
        String(
            humidity,
            1
        );
  }


  payload += ",";

  payload +=
      "\"flame_raw\":";

  payload +=
      String(
          flameRaw
      );


  payload += ",";

  payload +=
      "\"motion_raw\":";

  payload +=
      String(
          motionRaw
      );


  payload += ",";

  payload +=
      "\"uptime_ms\":";

  payload +=
      String(
          millis()
      );

  payload += "}";


  String signature =
      createHMAC(
          payload
      );


  HTTPClient http;

  http.begin(
      GATEWAY_URL
  );


  http.addHeader(
      "Content-Type",
      "application/json"
  );


  http.addHeader(
      "X-SN-Device-ID",
      DEVICE_ID
  );


  http.addHeader(
      "X-SN-Signature",
      signature
  );


  int statusCode =
      http.POST(
          payload
      );


  Serial.println();
  Serial.println(
      "----------------------------"
  );

  Serial.print(
      "SEQ: "
  );

  Serial.println(
      seqBuffer
  );

  Serial.print(
      "HMAC: "
  );

  Serial.println(
      signature
  );

  Serial.print(
      "HTTP: "
  );

  Serial.println(
      statusCode
  );


  if (
      statusCode > 0
  ) {

    Serial.println(
        http.getString()
    );
  }


  http.end();

  delay(5000);
}