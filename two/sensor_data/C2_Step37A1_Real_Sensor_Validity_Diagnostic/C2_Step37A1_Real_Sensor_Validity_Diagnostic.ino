/*
  Component 2 — Step 37A-1
  Real sensor validity diagnostic

  Upload only to the SENSOR ESP32.

  Connected hardware:
    DHT22 data -> GPIO27
    BH1750 SDA -> GPIO21
    BH1750 SCL -> GPIO22
    Soil AO    -> GPIO36

  E32 power may remain OFF for this diagnostic.

  Serial Monitor: 115200
*/

#include <Arduino.h>
#include <Wire.h>
#include <BH1750.h>
#include <DHT.h>

constexpr int DHT_PIN = 27;
constexpr int SOIL_PIN = 36;
constexpr int I2C_SDA_PIN = 21;
constexpr int I2C_SCL_PIN = 22;

constexpr int SOIL_DRY_RAW = 4095;
constexpr int SOIL_WET_RAW = 1169;
constexpr int SOIL_OPEN_CIRCUIT_RAW = 4080;

DHT dht(DHT_PIN, DHT22);
BH1750 lightMeter;

bool lightSensorReady = false;
uint32_t sampleNumber = 0;

void printReason(
    bool dhtTemperatureValid,
    bool dhtHumidityValid,
    bool lightValid,
    bool soilValid
) {
  if (
    dhtTemperatureValid
    && dhtHumidityValid
    && lightValid
    && soilValid
  ) {
    Serial.println("Invalid reason            : NONE");
    return;
  }

  Serial.print("Invalid reason            : ");

  bool first = true;

  if (!dhtTemperatureValid) {
    Serial.print("DHT TEMPERATURE");
    first = false;
  }

  if (!dhtHumidityValid) {
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

    Serial.print("BH1750");
    first = false;
  }

  if (!soilValid) {
    if (!first) {
      Serial.print(" | ");
    }

    Serial.print("SOIL OPEN-CIRCUIT/IMPLAUSIBLE");
  }

  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1200);

  pinMode(SOIL_PIN, INPUT);

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

  delay(2200);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 37A-1");
  Serial.println("REAL SENSOR VALIDITY DIAGNOSTIC");
  Serial.println("==========================================");

  Serial.print("BH1750 initialization     : ");
  Serial.println(
    lightSensorReady
      ? "PASSED"
      : "FAILED"
  );

  Serial.println("Soil valid requirement    : RAW < 4080");
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
      soilRaw < SOIL_OPEN_CIRCUIT_RAW;

  const bool completeSampleValid =
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
    Serial.println(" °C");
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
  Serial.println(
    lightSensorReady
      ? "YES"
      : "NO"
  );

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

  Serial.print("Soil sensor valid         : ");
  Serial.println(
    soilValid
      ? "YES"
      : "NO"
  );

  Serial.print("Complete sample valid     : ");
  Serial.println(
    completeSampleValid
      ? "YES"
      : "NO"
  );

  printReason(
    temperatureValid,
    humidityValid,
    lightValid,
    soilValid
  );

  Serial.println("------------------------------------------");

  delay(3000);
}
