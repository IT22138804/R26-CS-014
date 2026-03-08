/*
  Component 2 — Step 35E
  E32 raw-link reliability baseline — SENSOR NODE

  Purpose:
  - Send exactly 100 plaintext test packets.
  - Measure ACK success, packet loss and round-trip time.
  - Establish a radio baseline before adding encryption, HMAC,
    replay protection or NwkSKey derivation.

  This is NOT a secure protocol.
*/

#include <Arduino.h>

HardwareSerial E32Serial(2);

constexpr int E32_RX_PIN = 16;
constexpr int E32_TX_PIN = 17;
constexpr int E32_AUX_PIN = 35;

constexpr uint32_t TOTAL_PACKETS = 100;
constexpr unsigned long ACK_TIMEOUT_MS = 1500;
constexpr unsigned long INTER_PACKET_DELAY_MS = 500;

uint32_t nextSequence = 1;
uint32_t currentSequence = 0;
uint32_t sentPackets = 0;
uint32_t acknowledgedPackets = 0;
uint32_t lostPackets = 0;
uint32_t malformedReplies = 0;
uint32_t unexpectedReplies = 0;

bool waitingForAck = false;
bool testFinished = false;

unsigned long sentAtMs = 0;
unsigned long nextSendAtMs = 0;
unsigned long minimumRttMs = ULONG_MAX;
unsigned long maximumRttMs = 0;
uint64_t totalRttMs = 0;

void printFinalReport() {
  const float deliveryRate = sentPackets > 0
      ? (100.0f * acknowledgedPackets / sentPackets)
      : 0.0f;

  const float lossRate = sentPackets > 0
      ? (100.0f * lostPackets / sentPackets)
      : 0.0f;

  const float averageRtt = acknowledgedPackets > 0
      ? static_cast<float>(totalRttMs) / acknowledgedPackets
      : 0.0f;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 35E SENSOR REPORT");
  Serial.println("==========================================");
  Serial.print("Packets scheduled       : ");
  Serial.println(TOTAL_PACKETS);
  Serial.print("Packets sent            : ");
  Serial.println(sentPackets);
  Serial.print("ACKs received           : ");
  Serial.println(acknowledgedPackets);
  Serial.print("ACK timeouts / lost     : ");
  Serial.println(lostPackets);
  Serial.print("Delivery rate           : ");
  Serial.print(deliveryRate, 2);
  Serial.println("%");
  Serial.print("Loss rate               : ");
  Serial.print(lossRate, 2);
  Serial.println("%");
  Serial.print("Malformed replies       : ");
  Serial.println(malformedReplies);
  Serial.print("Unexpected replies      : ");
  Serial.println(unexpectedReplies);

  if (acknowledgedPackets > 0) {
    Serial.print("Minimum RTT             : ");
    Serial.print(minimumRttMs);
    Serial.println(" ms");
    Serial.print("Average RTT             : ");
    Serial.print(averageRtt, 2);
    Serial.println(" ms");
    Serial.print("Maximum RTT             : ");
    Serial.print(maximumRttMs);
    Serial.println(" ms");
  }

  Serial.println();
  Serial.print("STEP 35E SENSOR RESULT  : ");

  if (
    sentPackets == TOTAL_PACKETS
    && acknowledgedPackets >= 95
    && lostPackets <= 5
    && malformedReplies == 0
  ) {
    Serial.println("PASSED");
  } else {
    Serial.println("REVIEW REQUIRED");
  }

  Serial.println("==========================================");
}

void sendNextPacket() {
  currentSequence = nextSequence;
  nextSequence++;
  sentAtMs = millis();

  String packet =
      "C2_BASELINE,"
      + String(currentSequence)
      + ","
      + String(sentAtMs);

  E32Serial.println(packet);
  sentPackets++;
  waitingForAck = true;

  Serial.print("TX [");
  Serial.print(currentSequence);
  Serial.print("/");
  Serial.print(TOTAL_PACKETS);
  Serial.print("] -> ");
  Serial.println(packet);
}

void processReply(String reply) {
  reply.trim();

  if (reply.length() == 0) {
    return;
  }

  unsigned long ackSequence = 0;
  unsigned long gatewayTimestamp = 0;

  const int fieldsRead = sscanf(
    reply.c_str(),
    "C2_ACK,%lu,%lu",
    &ackSequence,
    &gatewayTimestamp
  );

  if (fieldsRead != 2) {
    malformedReplies++;
    Serial.print("Malformed reply <- ");
    Serial.println(reply);
    return;
  }

  if (!waitingForAck || ackSequence != currentSequence) {
    unexpectedReplies++;
    Serial.print("Unexpected ACK <- ");
    Serial.println(reply);
    return;
  }

  const unsigned long rttMs = millis() - sentAtMs;

  acknowledgedPackets++;
  totalRttMs += rttMs;

  if (rttMs < minimumRttMs) {
    minimumRttMs = rttMs;
  }

  if (rttMs > maximumRttMs) {
    maximumRttMs = rttMs;
  }

  waitingForAck = false;
  nextSendAtMs = millis() + INTER_PACKET_DELAY_MS;

  Serial.print("ACK [");
  Serial.print(ackSequence);
  Serial.print("] RTT=");
  Serial.print(rttMs);
  Serial.print(" ms, gateway_ms=");
  Serial.println(gatewayTimestamp);
}

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

  E32Serial.setTimeout(250);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 35E");
  Serial.println("RAW E32 LINK BASELINE — SENSOR NODE");
  Serial.println("==========================================");
  Serial.println("Security                : PLAINTEXT TEST ONLY");
  Serial.println("Packet retries          : DISABLED");
  Serial.println("Packet total            : 100");
  Serial.println("ACK timeout             : 1500 ms");
  Serial.println("M0/M1                   : LOW / LOW");
  Serial.println("Starting in 2 seconds...");
  Serial.println();

  nextSendAtMs = millis() + 2000;
}

void loop() {
  if (testFinished) {
    delay(1000);
    return;
  }

  while (E32Serial.available() > 0) {
    String reply = E32Serial.readStringUntil('\n');
    processReply(reply);
  }

  if (waitingForAck && millis() - sentAtMs >= ACK_TIMEOUT_MS) {
    Serial.print("ACK TIMEOUT [");
    Serial.print(currentSequence);
    Serial.println("]");

    lostPackets++;
    waitingForAck = false;
    nextSendAtMs = millis() + INTER_PACKET_DELAY_MS;
  }

  if (
    !waitingForAck
    && nextSequence <= TOTAL_PACKETS
    && millis() >= nextSendAtMs
  ) {
    sendNextPacket();
  }

  if (!waitingForAck && nextSequence > TOTAL_PACKETS) {
    testFinished = true;
    printFinalReport();
  }
}
