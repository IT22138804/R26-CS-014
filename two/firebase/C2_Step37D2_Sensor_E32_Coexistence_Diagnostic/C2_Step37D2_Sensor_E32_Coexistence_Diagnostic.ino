/*
  Component 2 — Step 37D-2
  Sensor + E32 coexistence diagnostic

  Upload ONLY to ESP32 No. 1 — the sensor-connected ESP32.

  Keep connected and powered:
    DHT22 data -> GPIO27
    BH1750 SDA -> GPIO21
    BH1750 SCL -> GPIO22
    Soil AO    -> GPIO36

    E32 TXD -> GPIO16
    E32 RXD -> GPIO17
    E32 AUX -> GPIO35
    E32 M0  -> GND
    E32 M1  -> GND
    E32 VCC -> external regulated 5V
    E32 GND -> common GND

  Gateway ESP32 may remain OFF.
  Serial Monitor: 115200
*/

#include <Arduino.h>
#include <Wire.h>
#include <BH1750.h>
#include <DHT.h>

HardwareSerial E32Serial(2);

constexpr int DHT_PIN = 27;
constexpr int SOIL_PIN = 36;
constexpr int I2C_SDA_PIN = 21;
constexpr int I2C_SCL_PIN = 22;

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

constexpr int SOIL_DRY_RAW = 4095;
constexpr int SOIL_WET_RAW = 1169;
constexpr int SOIL_MIN_VALID_RAW = 100;
constexpr int SOIL_MAX_VALID_RAW = 4079;

DHT dht(DHT_PIN, DHT22);
BH1750 lightMeter;

bool lightSensorReady = false;
uint32_t sampleNumber = 0;

void printInvalidReason(
    bool temperatureValid,
    bool humidityValid,
    bool lightValid,
    bool soilValid
) {
  Serial.print("Invalid reason            : ");

  if (
    temperatureValid
    && humidityValid
    && lightValid
    && soilValid
  ) {
    Serial.println("NONE");
    return;
  }

  bool first = true;

  if (!temperatureValid) {
    Serial.print("DHT TEMPERATURE");
    first = false;
  }

  if (!humidityValid) {
    if (!first) {
      Serial.print(" | ");
    }

    Serial.print("DHT HUMIDITY");
    first = false;
  }

  if (!lightValid) {
    if (!first) {
      Serial.print(" | ");
    }

    Serial.print(
      lightSensorReady
        ? "BH1750 READING"
        : "BH1750 INITIALIZATION"
    );

    first = false;
  }

  if (!soilValid) {
    if (!first) {
      Serial.print(" | ");
    }

    Serial.print("SOIL READING");
  }

  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  pinMode(SOIL_PIN, INPUT);
  pinMode(E32_AUX_PIN, INPUT);

  Wire.begin(
    I2C_SDA_PIN,
    I2C_SCL_PIN
  );

  dht.begin();

  lightSensorReady =
      lightMeter.begin(
        BH1750::CONTINUOUS_HIGH_RES_MODE,
        0x23,
        &Wire
      );

  E32Serial.begin(
    9600,
    SERIAL_8N1,
    E32_RX_PIN,
    E32_TX_PIN
  );

  delay(2200);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 37D-2");
  Serial.println("SENSOR + E32 COEXISTENCE DIAGNOSTIC");
  Serial.println("==========================================");
  Serial.print("BH1750 initialization     : ");
  Serial.println(lightSensorReady ? "PASSED" : "FAILED");
  Serial.print("E32 AUX state             : ");
  Serial.println(digitalRead(E32_AUX_PIN));
  Serial.println("Gateway ESP32             : MAY REMAIN OFF");
  Serial.println("Sampling every 3 seconds...");
  Serial.println();
}

void loop() {
  sampleNumber++;

  const float temperatureC =
      dht.readTemperature();

  const float humidityPercent =
      dht.readHumidity();

  const float lightLux =
      lightSensorReady
        ? lightMeter.readLightLevel()
        : -1.0f;

  const int soilRaw =
      analogRead(SOIL_PIN);

  const long soilPercent =
      constrain(
        map(
          soilRaw,
          SOIL_DRY_RAW,
          SOIL_WET_RAW,
          0,
          100
        ),
        0L,
        100L
      );

  const bool temperatureValid =
      !isnan(temperatureC);

  const bool humidityValid =
      !isnan(humidityPercent);

  const bool lightValid =
      lightSensorReady
      && lightLux >= 0.0f;

  const bool soilValid =
      soilRaw >= SOIL_MIN_VALID_RAW
      && soilRaw <= SOIL_MAX_VALID_RAW;

  const bool sampleValid =
      temperatureValid
      && humidityValid
      && lightValid
      && soilValid;

  Serial.println("------------------------------------------");
  Serial.print("Sample number             : ");
  Serial.println(sampleNumber);

  Serial.print("Temperature               : ");
  if (temperatureValid) {
    Serial.print(temperatureC, 2);
    Serial.println(" C");
  } else {
    Serial.println("INVALID / NaN");
  }

  Serial.print("Humidity                  : ");
  if (humidityValid) {
    Serial.print(humidityPercent, 2);
    Serial.println(" %");
  } else {
    Serial.println("INVALID / NaN");
  }

  Serial.print("BH1750 initialized        : ");
  Serial.println(lightSensorReady ? "YES" : "NO");

  Serial.print("Light                     : ");
  if (lightValid) {
    Serial.print(lightLux, 2);
    Serial.println(" lux");
  } else {
    Serial.println("INVALID");
  }

  Serial.print("Soil raw                  : ");
  Serial.println(soilRaw);

  Serial.print("Soil percentage           : ");
  Serial.print(soilPercent);
  Serial.println(" %");

  Serial.print("Soil valid range          : ");
  Serial.print(SOIL_MIN_VALID_RAW);
  Serial.print(" to ");
  Serial.println(SOIL_MAX_VALID_RAW);

  Serial.print("Soil reading valid        : ");
  Serial.println(soilValid ? "YES" : "NO");

  Serial.print("E32 AUX state             : ");
  Serial.println(digitalRead(E32_AUX_PIN));

  Serial.print("Complete sample valid     : ");
  Serial.println(sampleValid ? "YES" : "NO");

  printInvalidReason(
    temperatureValid,
    humidityValid,
    lightValid,
    soilValid
  );

  Serial.println("------------------------------------------");

  delay(3000);
}
