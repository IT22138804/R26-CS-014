/*
  COMPONENT 1 CLOSURE — STEP 34B-3B
  SAME-UID RESEARCH CLONE REJECTION TEST

  Purpose:
  - Test a same-UID RFID clone that belongs to the research setup.
  - Repeat until 30 conclusive credential decisions are collected.
  - Separate deterministic credential rejection from temporary
    card-selection failures.
  - Use only one bounded retry for communication/read failures.

  IMPORTANT:
  - This is for the user's own laboratory research credential.
  - It does not control greenhouse actuators.
  - It does not claim universal RFID clone-proof security.
*/

#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>

constexpr uint8_t RFID_SS_PIN   = 5;
constexpr uint8_t RFID_RST_PIN  = 33;
constexpr uint8_t RFID_SCK_PIN  = 18;
constexpr uint8_t RFID_MISO_PIN = 19;
constexpr uint8_t RFID_MOSI_PIN = 23;
constexpr uint8_t YELLOW_LED_PIN = 32;

constexpr uint16_t TARGET_CONCLUSIVE_ATTEMPTS = 30;
constexpr uint8_t REQUIRED_ABSENT_CHECKS = 3;
constexpr byte MARKER_BLOCK  = 16;
constexpr byte TRAILER_BLOCK = 19;

const byte AUTHORIZED_UID[4] = {0x83, 0x3D, 0x53, 0x56};
const byte CUSTOM_KEY_A_BYTES[6] = {0x7A, 0x31, 0xC4, 0x9D, 0x52, 0xE8};
const byte EXPECTED_MARKER[16] = {
  'C', '1', '-', 'A', 'U', 'T', 'H', '-',
  'V', '1', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

enum class AuthResult : uint8_t {
  AUTHORIZED = 1,
  UID_REJECTED = 2,
  SECTOR_COMMUNICATION_FAILURE = 3,
  BLOCK_READ_FAILURE = 4,
  MARKER_MISMATCH = 5,
  CARD_SELECTION_FAILURE = 6
};

struct AuthMetrics {
  unsigned long uidLatencyUs = 0;
  unsigned long authLatencyUs = 0;
  unsigned long readLatencyUs = 0;
  unsigned long pipelineLatencyUs = 0;
  MFRC522::StatusCode authStatus = MFRC522::STATUS_ERROR;
  MFRC522::StatusCode readStatus = MFRC522::STATUS_ERROR;
};

MFRC522 rfid(RFID_SS_PIN, RFID_RST_PIN);
MFRC522::MIFARE_Key runtimeKeyA;

uint32_t presentationNumber = 0;
uint16_t conclusiveAttemptCount = 0;
uint16_t authorizedCount = 0;
uint16_t uidRejectedCount = 0;
uint16_t sectorFailureCount = 0;
uint16_t blockReadFailureCount = 0;
uint16_t markerMismatchCount = 0;
uint16_t cardSelectionFailureCount = 0;
uint16_t boundedRetryCount = 0;
uint16_t sameUidObservedCount = 0;

bool waitingForCardRemoval = false;
uint8_t consecutiveAbsentChecks = 0;
bool testComplete = false;

const char* resultName(AuthResult result) {
  switch (result) {
    case AuthResult::AUTHORIZED: return "AUTHORIZED";
    case AuthResult::UID_REJECTED: return "UID_REJECTED";
    case AuthResult::SECTOR_COMMUNICATION_FAILURE: return "SECTOR_COMMUNICATION_FAILURE";
    case AuthResult::BLOCK_READ_FAILURE: return "BLOCK_READ_FAILURE";
    case AuthResult::MARKER_MISMATCH: return "MARKER_MISMATCH";
    case AuthResult::CARD_SELECTION_FAILURE: return "CARD_SELECTION_FAILURE";
    default: return "UNKNOWN";
  }
}

uint8_t resultCode(AuthResult result) {
  return static_cast<uint8_t>(result);
}

bool isConclusive(AuthResult result) {
  return result != AuthResult::CARD_SELECTION_FAILURE;
}

bool isSecurityRejection(AuthResult result) {
  return result == AuthResult::UID_REJECTED ||
         result == AuthResult::SECTOR_COMMUNICATION_FAILURE ||
         result == AuthResult::BLOCK_READ_FAILURE ||
         result == AuthResult::MARKER_MISMATCH;
}

const char* securityDecision(AuthResult result) {
  if (result == AuthResult::AUTHORIZED) return "ACCEPT";
  if (isSecurityRejection(result)) return "REJECT";
  return "INCONCLUSIVE";
}

void initializeReader() {
  rfid.PCD_StopCrypto1();
  rfid.PCD_Reset();
  delay(50);
  rfid.PCD_Init();
  delay(150);
  rfid.PCD_SetAntennaGain(MFRC522::RxGain_48dB);
}

bool uidMatches() {
  return rfid.uid.size == sizeof(AUTHORIZED_UID) &&
         memcmp(rfid.uid.uidByte, AUTHORIZED_UID, sizeof(AUTHORIZED_UID)) == 0;
}

bool markerMatches(const byte* marker) {
  byte difference = 0;
  for (byte i = 0; i < 16; i++) {
    difference |= marker[i] ^ EXPECTED_MARKER[i];
  }
  return difference == 0;
}

void printUid() {
  if (rfid.uid.size == 0) {
    Serial.print("NOT_AVAILABLE");
    return;
  }
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (i > 0) Serial.print(":");
    if (rfid.uid.uidByte[i] < 0x10) Serial.print("0");
    Serial.print(rfid.uid.uidByte[i], HEX);
  }
}

AuthResult authenticateSelectedCard(AuthMetrics& metrics) {
  if (!uidMatches()) return AuthResult::UID_REJECTED;

  unsigned long pipelineStartUs = micros();
  unsigned long authStartUs = micros();

  metrics.authStatus = rfid.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A,
    TRAILER_BLOCK,
    &runtimeKeyA,
    &(rfid.uid)
  );

  metrics.authLatencyUs = micros() - authStartUs;

  if (metrics.authStatus != MFRC522::STATUS_OK) {
    metrics.pipelineLatencyUs = micros() - pipelineStartUs;
    return AuthResult::SECTOR_COMMUNICATION_FAILURE;
  }

  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);
  unsigned long readStartUs = micros();

  metrics.readStatus = rfid.MIFARE_Read(
    MARKER_BLOCK,
    markerBuffer,
    &markerBufferSize
  );

  metrics.readLatencyUs = micros() - readStartUs;
  metrics.pipelineLatencyUs = micros() - pipelineStartUs;

  if (metrics.readStatus != MFRC522::STATUS_OK) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

AuthResult retrySectorAuthentication(AuthMetrics& retryMetrics) {
  rfid.PCD_StopCrypto1();
  delay(5);
  return authenticateSelectedCard(retryMetrics);
}

AuthResult retryMarkerRead(AuthMetrics& retryMetrics) {
  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);
  unsigned long readStartUs = micros();

  retryMetrics.readStatus = rfid.MIFARE_Read(
    MARKER_BLOCK,
    markerBuffer,
    &markerBufferSize
  );

  retryMetrics.readLatencyUs = micros() - readStartUs;
  retryMetrics.pipelineLatencyUs = retryMetrics.readLatencyUs;

  if (retryMetrics.readStatus != MFRC522::STATUS_OK) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

void countResult(AuthResult finalResult) {
  switch (finalResult) {
    case AuthResult::AUTHORIZED: authorizedCount++; break;
    case AuthResult::UID_REJECTED: uidRejectedCount++; break;
    case AuthResult::SECTOR_COMMUNICATION_FAILURE: sectorFailureCount++; break;
    case AuthResult::BLOCK_READ_FAILURE: blockReadFailureCount++; break;
    case AuthResult::MARKER_MISMATCH: markerMismatchCount++; break;
    case AuthResult::CARD_SELECTION_FAILURE: cardSelectionFailureCount++; break;
  }
}

void printCsvHeader() {
  Serial.println(
    "CSV_RFID_CLONE_TEST_HEADER,"
    "timestamp_ms,presentation_number,"
    "conclusive_attempt_number,target_conclusive_attempts,"
    "uid_match,first_result_code,final_result_code,"
    "first_result_name,final_result_name,retry_used,"
    "uid_latency_us,auth_latency_us,"
    "block_read_latency_us,pipeline_latency_us,"
    "security_decision"
  );
}

void printCsvRow(
    AuthResult firstResult,
    AuthResult finalResult,
    const AuthMetrics& firstMetrics,
    const AuthMetrics& retryMetrics,
    bool retryUsed
) {
  const AuthMetrics& effective =
      retryUsed && finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  Serial.print("CSV_RFID_CLONE_TEST,");
  Serial.print(millis()); Serial.print(",");
  Serial.print(presentationNumber); Serial.print(",");
  Serial.print(conclusiveAttemptCount); Serial.print(",");
  Serial.print(TARGET_CONCLUSIVE_ATTEMPTS); Serial.print(",");
  Serial.print(uidMatches() ? 1 : 0); Serial.print(",");
  Serial.print(resultCode(firstResult)); Serial.print(",");
  Serial.print(resultCode(finalResult)); Serial.print(",");
  Serial.print(resultName(firstResult)); Serial.print(",");
  Serial.print(resultName(finalResult)); Serial.print(",");
  Serial.print(retryUsed ? 1 : 0); Serial.print(",");
  Serial.print(firstMetrics.uidLatencyUs); Serial.print(",");
  Serial.print(effective.authLatencyUs); Serial.print(",");
  Serial.print(effective.readLatencyUs); Serial.print(",");
  Serial.print(effective.pipelineLatencyUs); Serial.print(",");
  Serial.println(securityDecision(finalResult));
}

void printFinalSummary() {
  uint16_t securityRejectedCount =
      uidRejectedCount + sectorFailureCount +
      blockReadFailureCount + markerMismatchCount;

  float rejectionRate = conclusiveAttemptCount > 0
      ? 100.0f * static_cast<float>(securityRejectedCount) /
        static_cast<float>(conclusiveAttemptCount)
      : 0.0f;

  Serial.println();
  Serial.println("==========================================");
  Serial.println("STEP 34B-3B — SAME-UID CLONE TEST SUMMARY");
  Serial.println("==========================================");

  Serial.print("Total presentations       : "); Serial.println(presentationNumber);
  Serial.print("Conclusive attempts       : ");
  Serial.print(conclusiveAttemptCount); Serial.print("/");
  Serial.println(TARGET_CONCLUSIVE_ATTEMPTS);
  Serial.print("Same UID observed         : "); Serial.println(sameUidObservedCount);
  Serial.print("Authorized                : "); Serial.println(authorizedCount);
  Serial.print("UID rejected              : "); Serial.println(uidRejectedCount);
  Serial.print("Sector failures           : "); Serial.println(sectorFailureCount);
  Serial.print("Block-read failures       : "); Serial.println(blockReadFailureCount);
  Serial.print("Marker mismatches         : "); Serial.println(markerMismatchCount);
  Serial.print("Card-selection failures   : "); Serial.println(cardSelectionFailureCount);
  Serial.print("Bounded retries used      : "); Serial.println(boundedRetryCount);
  Serial.print("Security rejections       : "); Serial.println(securityRejectedCount);
  Serial.print("Conclusive rejection rate : ");
  Serial.print(rejectionRate, 2); Serial.println("%");

  Serial.print("FINAL INTERPRETATION      : ");
  if (authorizedCount == 0) {
    Serial.println("DETERMINISTIC PROTECTED-SECTOR REJECTION CONFIRMED");
  } else {
    Serial.println("AUTHORIZED CLONE PATH OBSERVED — TIMING COMPARISON REQUIRED");
  }

  Serial.println();
  Serial.println(
    "This result applies only to this laboratory clone and current reader/card setup."
  );
  Serial.println(
    "It must not be described as universal clone-proof security."
  );
  Serial.println("==========================================");

  Serial.print("CSV_RFID_CLONE_TEST_SUMMARY,");
  Serial.print(presentationNumber); Serial.print(",");
  Serial.print(conclusiveAttemptCount); Serial.print(",");
  Serial.print(sameUidObservedCount); Serial.print(",");
  Serial.print(authorizedCount); Serial.print(",");
  Serial.print(uidRejectedCount); Serial.print(",");
  Serial.print(sectorFailureCount); Serial.print(",");
  Serial.print(blockReadFailureCount); Serial.print(",");
  Serial.print(markerMismatchCount); Serial.print(",");
  Serial.print(cardSelectionFailureCount); Serial.print(",");
  Serial.print(boundedRetryCount); Serial.print(",");
  Serial.print(securityRejectedCount); Serial.print(",");
  Serial.println(rejectionRate, 2);
}

void finishPresentation() {
  rfid.PCD_StopCrypto1();
  rfid.PICC_HaltA();
  waitingForCardRemoval = true;
  consecutiveAbsentChecks = 0;
  Serial.println("Remove the research clone completely.");
}

bool cardRespondsToWakeup() {
  byte atqa[2] = {0};
  byte atqaSize = sizeof(atqa);

  MFRC522::StatusCode status = rfid.PICC_WakeupA(atqa, &atqaSize);
  bool cardPresent =
      status == MFRC522::STATUS_OK ||
      status == MFRC522::STATUS_COLLISION;

  if (cardPresent) {
    if (rfid.PICC_ReadCardSerial()) rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
  }

  return cardPresent;
}

void processCardRemoval() {
  if (cardRespondsToWakeup()) {
    consecutiveAbsentChecks = 0;
    delay(100);
    return;
  }

  consecutiveAbsentChecks++;

  if (consecutiveAbsentChecks >= REQUIRED_ABSENT_CHECKS) {
    waitingForCardRemoval = false;
    consecutiveAbsentChecks = 0;
    initializeReader();
    Serial.println("Clone removal confirmed. Present it again.");
  }

  delay(100);
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  pinMode(YELLOW_LED_PIN, OUTPUT);
  digitalWrite(YELLOW_LED_PIN, LOW);

  for (byte i = 0; i < 6; i++) {
    runtimeKeyA.keyByte[i] = CUSTOM_KEY_A_BYTES[i];
  }

  SPI.begin(
    RFID_SCK_PIN,
    RFID_MISO_PIN,
    RFID_MOSI_PIN,
    RFID_SS_PIN
  );

  initializeReader();

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 1 CLOSURE — STEP 34B-3B");
  Serial.println("SAME-UID RESEARCH CLONE REJECTION TEST");
  Serial.println("==========================================");
  Serial.print("Target conclusive attempts: ");
  Serial.println(TARGET_CONCLUSIVE_ATTEMPTS);
  Serial.println("Use only the same-UID clone belonging to this research setup.");
  Serial.println("Card-selection failures are inconclusive and do not count toward 30.");
  Serial.println("The protected-sector flow uses at most one bounded retry.");
  Serial.println("No greenhouse actuator or relay is controlled.");
  Serial.println("==========================================");

  printCsvHeader();
  Serial.println();
  Serial.println("Present the same-UID research clone.");
}

void loop() {
  if (testComplete) {
    delay(1000);
    return;
  }

  if (waitingForCardRemoval) {
    processCardRemoval();
    return;
  }

  if (!rfid.PICC_IsNewCardPresent()) {
    delay(20);
    return;
  }

  digitalWrite(YELLOW_LED_PIN, HIGH);
  presentationNumber++;

  AuthMetrics firstMetrics;
  AuthMetrics retryMetrics;
  unsigned long uidStartUs = micros();

  if (!rfid.PICC_ReadCardSerial()) {
    firstMetrics.uidLatencyUs = micros() - uidStartUs;

    AuthResult firstResult = AuthResult::CARD_SELECTION_FAILURE;
    AuthResult finalResult = AuthResult::CARD_SELECTION_FAILURE;
    countResult(finalResult);

    digitalWrite(YELLOW_LED_PIN, LOW);

    Serial.println();
    Serial.println("------------------------------------------");
    Serial.print("Presentation             : "); Serial.println(presentationNumber);
    Serial.println("Final authentication     : CARD_SELECTION_FAILURE");
    Serial.println("Security decision        : INCONCLUSIVE");
    Serial.print("Conclusive attempts      : ");
    Serial.print(conclusiveAttemptCount); Serial.print("/");
    Serial.println(TARGET_CONCLUSIVE_ATTEMPTS);

    printCsvRow(
      firstResult,
      finalResult,
      firstMetrics,
      retryMetrics,
      false
    );

    Serial.println("------------------------------------------");
    initializeReader();
    delay(100);
    return;
  }

  firstMetrics.uidLatencyUs = micros() - uidStartUs;
  bool sameUid = uidMatches();
  if (sameUid) sameUidObservedCount++;

  AuthResult firstResult = authenticateSelectedCard(firstMetrics);
  AuthResult finalResult = firstResult;
  bool retryUsed = false;

  if (firstResult == AuthResult::SECTOR_COMMUNICATION_FAILURE) {
    retryUsed = true;
    boundedRetryCount++;
    finalResult = retrySectorAuthentication(retryMetrics);
  } else if (firstResult == AuthResult::BLOCK_READ_FAILURE) {
    retryUsed = true;
    boundedRetryCount++;
    delay(5);
    finalResult = retryMarkerRead(retryMetrics);
  }

  digitalWrite(YELLOW_LED_PIN, LOW);

  if (isConclusive(finalResult)) conclusiveAttemptCount++;
  countResult(finalResult);

  const AuthMetrics& effective =
      retryUsed && finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  Serial.println();
  Serial.println("------------------------------------------");
  Serial.print("Presentation             : "); Serial.println(presentationNumber);
  Serial.print("Detected UID             : "); printUid(); Serial.println();
  Serial.print("Same UID as reference    : "); Serial.println(sameUid ? "YES" : "NO");
  Serial.print("First result             : "); Serial.println(resultName(firstResult));
  Serial.print("Final authentication     : "); Serial.println(resultName(finalResult));
  Serial.print("Bounded retry used       : "); Serial.println(retryUsed ? "YES" : "NO");
  Serial.print("UID latency              : "); Serial.print(firstMetrics.uidLatencyUs); Serial.println(" microseconds");
  Serial.print("Sector auth latency      : "); Serial.print(effective.authLatencyUs); Serial.println(" microseconds");
  Serial.print("Block-read latency       : "); Serial.print(effective.readLatencyUs); Serial.println(" microseconds");
  Serial.print("Pipeline latency         : "); Serial.print(effective.pipelineLatencyUs); Serial.println(" microseconds");
  Serial.print("Security decision        : "); Serial.println(securityDecision(finalResult));
  Serial.print("Conclusive attempts      : ");
  Serial.print(conclusiveAttemptCount); Serial.print("/");
  Serial.println(TARGET_CONCLUSIVE_ATTEMPTS);

  printCsvRow(
    firstResult,
    finalResult,
    firstMetrics,
    retryMetrics,
    retryUsed
  );

  Serial.println("------------------------------------------");

  if (conclusiveAttemptCount >= TARGET_CONCLUSIVE_ATTEMPTS) {
    testComplete = true;
    rfid.PCD_StopCrypto1();
    rfid.PICC_HaltA();
    printFinalSummary();
    return;
  }

  finishPresentation();
}
