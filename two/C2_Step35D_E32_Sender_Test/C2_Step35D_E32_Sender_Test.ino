/*
  Component 2 — Step 35D
  E32-433T20D transparent-link sender test

  Board: Sensor ESP32 / Component 1 node
  E32 wiring:
    E32 TXD -> ESP32 GPIO16
    E32 RXD -> ESP32 GPIO17
    E32 AUX -> ESP32 GPIO35
    E32 M0  -> GND
    E32 M1  -> GND
    E32 VCC -> External regulated 5V
    E32 GND -> External supply GND and ESP32 GND

  Serial Monitor: 115200
  E32 UART: 9600 8N1
*/

#include <Arduino.h>

HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

uint32_t packetCounter = 0;
unsigned long lastSendMs = 0;

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

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 35D");
  Serial.println("E32 TRANSPARENT-LINK SENDER");
  Serial.println("==========================================");
  Serial.println("M0/M1 must both be LOW.");
  Serial.println("Sending one packet every 2 seconds.");
  Serial.println();
}

void loop() {
  if (millis() - lastSendMs >= 2000) {
    lastSendMs = millis();
    packetCounter++;

    const int auxState = digitalRead(E32_AUX_PIN);

    String packet =
      "C2_TEST,"
      + String(packetCounter)
      + ",SENSOR_NODE,"
      + String(millis())
      + ",AUX="
      + String(auxState);

    E32Serial.println(packet);

    Serial.print("TX -> ");
    Serial.println(packet);
  }

  while (E32Serial.available()) {
    const String reply = E32Serial.readStringUntil('\n');

    Serial.print("RX reply <- ");
    Serial.println(reply);
  }
}
