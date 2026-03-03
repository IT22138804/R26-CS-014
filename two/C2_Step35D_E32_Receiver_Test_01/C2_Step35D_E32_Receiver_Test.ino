/*
  Component 2 — Step 35D
  E32-433T20D transparent-link receiver test

  Board: Gateway ESP32

  E32 wiring:
    E32 TXD -> ESP32 GPIO16
    E32 RXD -> ESP32 GPIO17
    E32 AUX -> ESP32 GPIO35
    E32 M0  -> GND
    E32 M1  -> GND
    E32 VCC -> External regulated 5V
    E32 GND -> External supply GND and ESP32 GND

  Serial Monitor: 115200
  E32 UART: 9600, 8N1
*/

#include <Arduino.h>

HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

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

  // Prevent readStringUntil() from waiting too long.
  E32Serial.setTimeout(300);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 35D");
  Serial.println("E32 TRANSPARENT-LINK RECEIVER");
  Serial.println("==========================================");
  Serial.println("M0/M1 must both be LOW.");
  Serial.println("Waiting for packets...");
  Serial.println();
}

void loop() {
  while (E32Serial.available() > 0) {

    // Do not use const because trim() modifies the String.
    String packet =
      E32Serial.readStringUntil('\n');

    packet.trim();

    if (packet.length() == 0) {
      continue;
    }

    Serial.print("RX <- ");
    Serial.println(packet);

    String acknowledgement =
      "ACK,"
      + String(millis())
      + ","
      + packet;

    E32Serial.println(acknowledgement);

    Serial.print("TX ACK -> ");
    Serial.println(acknowledgement);

    Serial.print("AUX state -> ");
    Serial.println(digitalRead(E32_AUX_PIN));

    Serial.println("------------------------------------------");
  }
}