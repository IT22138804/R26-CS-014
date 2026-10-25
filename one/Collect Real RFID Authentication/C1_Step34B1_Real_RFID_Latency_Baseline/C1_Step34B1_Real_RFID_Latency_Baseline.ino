
/*
  COMPONENT 1 CLOSURE — STEP 34B-1
  REAL RFID AUTHENTICATION-LATENCY BASELINE COLLECTOR

  Purpose:
  - Collect 100 real protected-sector authentication samples from the
    authorized reference MIFARE Classic tag.
  - Record UID-selection, Sector 4 authentication, protected-block read,
    and complete pipeline latency.
  - Produce a CSV dataset and an online summary.

  IMPORTANT:
  - This is a dedicated laboratory data-collection sketch.
  - It does not control greenhouse relays or actuators.
  - It does not claim that timing alone proves a card is genuine.
  - It uses the same UID, custom Sector 4 Key A, and protected marker
    already provisioned for Component 1.
*/

#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <math.h>

// =====================================================
// RC522 GPIO MAP
// =====================================================

constexpr uint8_t RFID_SS_PIN   = 5;
constexpr uint8_t RFID_RST_PIN  = 33;
constexpr uint8_t RFID_SCK_PIN  = 18;
constexpr uint8_t RFID_MISO_PIN = 19;
constexpr uint8_t RFID_MOSI_PIN = 23;

// Optional status LED from the validated greenhouse map.
constexpr uint8_t YELLOW_LED_PIN = 32;

// =====================================================
// DATA-COLLECTION CONFIGURATION
// =====================================================

constexpr uint16_t TARGET_AUTHORIZED_SAMPLES = 100;

// Require several consecutive absence checks before accepting
// the same physical tag as a new presentation.
constexpr uint8_t REQUIRED_ABSENT_CHECKS = 3;

constexpr byte MARKER_BLOCK  = 16;
constexpr byte TRAILER_BLOCK = 19;

// Authorized reference UID.
const byte AUTHORIZED_UID[4] = {
  0x83, 0x3D, 0x53, 0x56
};

// Prototype Component 1 Sector 4 Key A.
// Replace before any real deployment.
const byte CUSTOM_KEY_A_BYTES[6] = {
  0x7A, 0x31, 0xC4, 0x9D, 0x52, 0xE8
};

const byte EXPECTED_MARKER[16] = {
  'C', '1', '-', 'A',
  'U', 'T', 'H', '-',
  'V', '1',
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

// =====================================================
// TYPES
// =====================================================

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

struct RunningStats {
  uint32_t count = 0;
  double mean = 0.0;
  double m2 = 0.0;
  unsigned long minimum = 0;
  unsigned long maximum = 0;

  void add(unsigned long value) {
    count++;

    if (count == 1) {
      minimum = value;
      maximum = value;
      mean = static_cast<double>(value);
      m2 = 0.0;
      return;
    }

    if (value < minimum) {
      minimum = value;
    }

    if (value > maximum) {
      maximum = value;
    }

    double numericValue = static_cast<double>(value);
    double delta = numericValue - mean;

    mean += delta / static_cast<double>(count);

    double delta2 = numericValue - mean;
    m2 += delta * delta2;
  }

  double standardDeviation() const {
    if (count < 2) {
      return 0.0;
    }

    return sqrt(
      m2 / static_cast<double>(count - 1)
    );
  }
};

// =====================================================
// GLOBAL RUNTIME
// =====================================================

MFRC522 rfid(RFID_SS_PIN, RFID_RST_PIN);
MFRC522::MIFARE_Key runtimeKeyA;

uint32_t presentationNumber = 0;
uint16_t authorizedSampleCount = 0;

uint32_t uidRejectedCount = 0;
uint32_t sectorFailureCount = 0;
uint32_t blockFailureCount = 0;
uint32_t markerMismatchCount = 0;
uint32_t cardSelectionFailureCount = 0;
uint32_t boundedRetryCount = 0;

bool waitingForCardRemoval = false;
uint8_t consecutiveAbsentChecks = 0;
bool collectionComplete = false;

RunningStats uidLatencyStats;
RunningStats authLatencyStats;
RunningStats readLatencyStats;
RunningStats pipelineLatencyStats;

// =====================================================
// HELPERS
// =====================================================

const char* authResultName(AuthResult result) {
  switch (result) {
    case AuthResult::AUTHORIZED:
      return "AUTHORIZED";

    case AuthResult::UID_REJECTED:
      return "UID_REJECTED";

    case AuthResult::SECTOR_COMMUNICATION_FAILURE:
      return "SECTOR_COMMUNICATION_FAILURE";

    case AuthResult::BLOCK_READ_FAILURE:
      return "BLOCK_READ_FAILURE";

    case AuthResult::MARKER_MISMATCH:
      return "MARKER_MISMATCH";

    case AuthResult::CARD_SELECTION_FAILURE:
      return "CARD_SELECTION_FAILURE";

    default:
      return "UNKNOWN";
  }
}

uint8_t authResultCode(AuthResult result) {
  return static_cast<uint8_t>(result);
}

void initializeReader() {
  rfid.PCD_StopCrypto1();
  rfid.PCD_Reset();

  delay(50);

  rfid.PCD_Init();
  delay(150);

  rfid.PCD_SetAntennaGain(
    MFRC522::RxGain_48dB
  );
}

bool uidMatches() {
  return
      rfid.uid.size == sizeof(AUTHORIZED_UID) &&
      memcmp(
        rfid.uid.uidByte,
        AUTHORIZED_UID,
        sizeof(AUTHORIZED_UID)
      ) == 0;
}

bool markerMatches(const byte* marker) {
  byte difference = 0;

  for (byte i = 0; i < 16; i++) {
    difference |=
        marker[i] ^
        EXPECTED_MARKER[i];
  }

  return difference == 0;
}

void printUID() {
  if (rfid.uid.size == 0) {
    Serial.print("NOT_AVAILABLE");
    return;
  }

  for (byte i = 0; i < rfid.uid.size; i++) {
    if (i > 0) {
      Serial.print(":");
    }

    if (rfid.uid.uidByte[i] < 0x10) {
      Serial.print("0");
    }

    Serial.print(
      rfid.uid.uidByte[i],
      HEX
    );
  }
}

// =====================================================
// PROTECTED-SECTOR AUTHENTICATION
// =====================================================

AuthResult authenticateSelectedCard(
    AuthMetrics& metrics
) {
  if (!uidMatches()) {
    return AuthResult::UID_REJECTED;
  }

  unsigned long pipelineStartUs = micros();
  unsigned long authenticationStartUs = micros();

  metrics.authStatus =
      rfid.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A,
        TRAILER_BLOCK,
        &runtimeKeyA,
        &(rfid.uid)
      );

  metrics.authLatencyUs =
      micros() -
      authenticationStartUs;

  if (
    metrics.authStatus !=
    MFRC522::STATUS_OK
  ) {
    metrics.pipelineLatencyUs =
        micros() -
        pipelineStartUs;

    return AuthResult::SECTOR_COMMUNICATION_FAILURE;
  }

  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);

  unsigned long readStartUs = micros();

  metrics.readStatus =
      rfid.MIFARE_Read(
        MARKER_BLOCK,
        markerBuffer,
        &markerBufferSize
      );

  metrics.readLatencyUs =
      micros() -
      readStartUs;

  metrics.pipelineLatencyUs =
      micros() -
      pipelineStartUs;

  if (
    metrics.readStatus !=
    MFRC522::STATUS_OK
  ) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

AuthResult retrySectorAuthentication(
    AuthMetrics& retryMetrics
) {
  rfid.PCD_StopCrypto1();
  delay(5);

  return authenticateSelectedCard(
    retryMetrics
  );
}

AuthResult retryMarkerReadInCurrentSession(
    AuthMetrics& retryMetrics
) {
  byte markerBuffer[18] = {0};
  byte markerBufferSize = sizeof(markerBuffer);

  unsigned long retryStartUs = micros();

  retryMetrics.readStatus =
      rfid.MIFARE_Read(
        MARKER_BLOCK,
        markerBuffer,
        &markerBufferSize
      );

  retryMetrics.readLatencyUs =
      micros() -
      retryStartUs;

  retryMetrics.pipelineLatencyUs =
      retryMetrics.readLatencyUs;

  if (
    retryMetrics.readStatus !=
    MFRC522::STATUS_OK
  ) {
    return AuthResult::BLOCK_READ_FAILURE;
  }

  if (!markerMatches(markerBuffer)) {
    return AuthResult::MARKER_MISMATCH;
  }

  return AuthResult::AUTHORIZED;
}

// =====================================================
// CSV AND SUMMARY
// =====================================================

void printCsvHeader() {
  Serial.println(
    "CSV_RFID_LATENCY_HEADER,"
    "timestamp_ms,presentation_number,"
    "authorized_sample_number,target_sample_count,"
    "uid_match,first_result_code,final_result_code,"
    "first_result_name,final_result_name,retry_used,"
    "uid_latency_us,auth_latency_us,"
    "block_read_latency_us,pipeline_latency_us"
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
      retryUsed &&
      finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  Serial.print("CSV_RFID_LATENCY,");
  Serial.print(millis());
  Serial.print(",");
  Serial.print(presentationNumber);
  Serial.print(",");
  Serial.print(authorizedSampleCount);
  Serial.print(",");
  Serial.print(TARGET_AUTHORIZED_SAMPLES);
  Serial.print(",");
  Serial.print(uidMatches() ? 1 : 0);
  Serial.print(",");
  Serial.print(authResultCode(firstResult));
  Serial.print(",");
  Serial.print(authResultCode(finalResult));
  Serial.print(",");
  Serial.print(authResultName(firstResult));
  Serial.print(",");
  Serial.print(authResultName(finalResult));
  Serial.print(",");
  Serial.print(retryUsed ? 1 : 0);
  Serial.print(",");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.print(",");
  Serial.print(effective.authLatencyUs);
  Serial.print(",");
  Serial.print(effective.readLatencyUs);
  Serial.print(",");
  Serial.println(effective.pipelineLatencyUs);
}

void printStatsLine(
    const char* label,
    const RunningStats& stats
) {
  Serial.print(label);
  Serial.print(" mean/min/max/std : ");

  Serial.print(stats.mean, 3);
  Serial.print(" / ");

  Serial.print(stats.minimum);
  Serial.print(" / ");

  Serial.print(stats.maximum);
  Serial.print(" / ");

  Serial.print(
    stats.standardDeviation(),
    3
  );

  Serial.println(" us");
}

void printFinalSummary() {
  Serial.println();
  Serial.println("==========================================");
  Serial.println("STEP 34B-1 — REAL RFID BASELINE SUMMARY");
  Serial.println("==========================================");

  Serial.print("Target authorized samples : ");
  Serial.println(TARGET_AUTHORIZED_SAMPLES);

  Serial.print("Authorized samples        : ");
  Serial.println(authorizedSampleCount);

  Serial.print("Total presentations       : ");
  Serial.println(presentationNumber);

  Serial.print("Bounded retries used      : ");
  Serial.println(boundedRetryCount);

  Serial.print("UID rejections            : ");
  Serial.println(uidRejectedCount);

  Serial.print("Sector failures           : ");
  Serial.println(sectorFailureCount);

  Serial.print("Block-read failures       : ");
  Serial.println(blockFailureCount);

  Serial.print("Marker mismatches         : ");
  Serial.println(markerMismatchCount);

  Serial.print("Card-selection failures   : ");
  Serial.println(cardSelectionFailureCount);

  Serial.println();
  Serial.println(
    "Latency statistics: mean / min / max / sample std"
  );

  printStatsLine(
    "UID selection",
    uidLatencyStats
  );

  printStatsLine(
    "Sector authentication",
    authLatencyStats
  );

  printStatsLine(
    "Protected block read",
    readLatencyStats
  );

  printStatsLine(
    "Protected pipeline",
    pipelineLatencyStats
  );

  Serial.println();
  Serial.print("STEP 34B-1 RESULT         : ");

  Serial.println(
    authorizedSampleCount >=
        TARGET_AUTHORIZED_SAMPLES
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println();
  Serial.println(
    "Interpretation: this is a real latency baseline "
    "for the authorized reference tag."
  );

  Serial.println(
    "It is not proof that timing alone can identify "
    "all RFID clones or emulators."
  );

  Serial.println("==========================================");

  Serial.print(
    "CSV_RFID_LATENCY_SUMMARY,"
  );
  Serial.print(authorizedSampleCount);
  Serial.print(",");
  Serial.print(presentationNumber);
  Serial.print(",");
  Serial.print(authLatencyStats.mean, 3);
  Serial.print(",");
  Serial.print(authLatencyStats.minimum);
  Serial.print(",");
  Serial.print(authLatencyStats.maximum);
  Serial.print(",");
  Serial.print(
    authLatencyStats.standardDeviation(),
    3
  );
  Serial.print(",");
  Serial.print(readLatencyStats.mean, 3);
  Serial.print(",");
  Serial.print(readLatencyStats.minimum);
  Serial.print(",");
  Serial.print(readLatencyStats.maximum);
  Serial.print(",");
  Serial.print(
    readLatencyStats.standardDeviation(),
    3
  );
  Serial.print(",");
  Serial.print(pipelineLatencyStats.mean, 3);
  Serial.print(",");
  Serial.print(pipelineLatencyStats.minimum);
  Serial.print(",");
  Serial.print(pipelineLatencyStats.maximum);
  Serial.print(",");
  Serial.println(
    pipelineLatencyStats.standardDeviation(),
    3
  );
}

// =====================================================
// CARD REMOVAL CONTROL
// =====================================================

void finishPresentation() {
  rfid.PCD_StopCrypto1();
  rfid.PICC_HaltA();

  waitingForCardRemoval = true;
  consecutiveAbsentChecks = 0;

  Serial.println(
    "Remove the tag completely before the next sample."
  );
}

bool cardRespondsToWakeup() {
  byte atqa[2] = {0};
  byte atqaSize = sizeof(atqa);

  MFRC522::StatusCode status =
      rfid.PICC_WakeupA(
        atqa,
        &atqaSize
      );

  bool cardPresent =
      status == MFRC522::STATUS_OK ||
      status == MFRC522::STATUS_COLLISION;

  if (cardPresent) {
    if (rfid.PICC_ReadCardSerial()) {
      rfid.PICC_HaltA();
    }

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

  if (
    consecutiveAbsentChecks >=
    REQUIRED_ABSENT_CHECKS
  ) {
    waitingForCardRemoval = false;
    consecutiveAbsentChecks = 0;

    initializeReader();

    Serial.println(
      "Card removal confirmed. Present the authorized tag again."
    );
  }

  delay(100);
}

// =====================================================
// RESULT COUNTERS
// =====================================================

void countFailure(
    AuthResult finalResult
) {
  switch (finalResult) {
    case AuthResult::UID_REJECTED:
      uidRejectedCount++;
      break;

    case AuthResult::SECTOR_COMMUNICATION_FAILURE:
      sectorFailureCount++;
      break;

    case AuthResult::BLOCK_READ_FAILURE:
      blockFailureCount++;
      break;

    case AuthResult::MARKER_MISMATCH:
      markerMismatchCount++;
      break;

    case AuthResult::CARD_SELECTION_FAILURE:
      cardSelectionFailureCount++;
      break;

    case AuthResult::AUTHORIZED:
      break;
  }
}

// =====================================================
// SETUP
// =====================================================

void setup() {
  Serial.begin(115200);
  delay(1500);

  pinMode(
    YELLOW_LED_PIN,
    OUTPUT
  );

  digitalWrite(
    YELLOW_LED_PIN,
    LOW
  );

  for (byte i = 0; i < 6; i++) {
    runtimeKeyA.keyByte[i] =
        CUSTOM_KEY_A_BYTES[i];
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
  Serial.println("COMPONENT 1 CLOSURE — STEP 34B-1");
  Serial.println("REAL RFID AUTHENTICATION-LATENCY BASELINE");
  Serial.println("==========================================");

  Serial.print("Target successful samples : ");
  Serial.println(TARGET_AUTHORIZED_SAMPLES);

  Serial.println(
    "Use only the authorized reference tag."
  );

  Serial.println(
    "Remove the tag fully after every presentation."
  );

  Serial.println(
    "The sketch performs at most one bounded retry "
    "for a communication fault."
  );

  Serial.println(
    "No greenhouse relay or actuator is controlled."
  );

  Serial.println("==========================================");

  printCsvHeader();

  Serial.println();
  Serial.println(
    "Present the authorized RFID tag for sample 1."
  );
}

// =====================================================
// LOOP
// =====================================================

void loop() {
  if (collectionComplete) {
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

  digitalWrite(
    YELLOW_LED_PIN,
    HIGH
  );

  presentationNumber++;

  AuthMetrics firstMetrics;
  AuthMetrics retryMetrics;

  unsigned long uidStartUs = micros();

  if (!rfid.PICC_ReadCardSerial()) {
    firstMetrics.uidLatencyUs =
        micros() - uidStartUs;

    digitalWrite(
      YELLOW_LED_PIN,
      LOW
    );

    cardSelectionFailureCount++;

    Serial.println();
    Serial.println("------------------------------------------");
    Serial.print("Presentation             : ");
    Serial.println(presentationNumber);
    Serial.println(
      "Final authentication     : CARD_SELECTION_FAILURE"
    );
    Serial.println(
      "Successful baseline count: unchanged"
    );

    printCsvRow(
      AuthResult::CARD_SELECTION_FAILURE,
      AuthResult::CARD_SELECTION_FAILURE,
      firstMetrics,
      retryMetrics,
      false
    );

    Serial.println("------------------------------------------");

    initializeReader();
    delay(100);
    return;
  }

  firstMetrics.uidLatencyUs =
      micros() - uidStartUs;

  AuthResult firstResult =
      authenticateSelectedCard(
        firstMetrics
      );

  AuthResult finalResult = firstResult;
  bool retryUsed = false;

  if (
    firstResult ==
    AuthResult::SECTOR_COMMUNICATION_FAILURE
  ) {
    retryUsed = true;
    boundedRetryCount++;

    finalResult =
        retrySectorAuthentication(
          retryMetrics
        );
  } else if (
    firstResult ==
    AuthResult::BLOCK_READ_FAILURE
  ) {
    retryUsed = true;
    boundedRetryCount++;

    delay(5);

    finalResult =
        retryMarkerReadInCurrentSession(
          retryMetrics
        );
  }

  digitalWrite(
    YELLOW_LED_PIN,
    LOW
  );

  const AuthMetrics& effective =
      retryUsed &&
      finalResult == AuthResult::AUTHORIZED
        ? retryMetrics
        : firstMetrics;

  if (finalResult == AuthResult::AUTHORIZED) {
    authorizedSampleCount++;

    uidLatencyStats.add(
      firstMetrics.uidLatencyUs
    );

    authLatencyStats.add(
      effective.authLatencyUs
    );

    readLatencyStats.add(
      effective.readLatencyUs
    );

    pipelineLatencyStats.add(
      effective.pipelineLatencyUs
    );
  } else {
    countFailure(finalResult);
  }

  Serial.println();
  Serial.println("------------------------------------------");

  Serial.print("Presentation             : ");
  Serial.println(presentationNumber);

  Serial.print("Detected UID             : ");
  printUID();
  Serial.println();

  Serial.print("First result             : ");
  Serial.println(authResultName(firstResult));

  Serial.print("Final authentication     : ");
  Serial.println(authResultName(finalResult));

  Serial.print("Bounded retry used       : ");
  Serial.println(retryUsed ? "YES" : "NO");

  Serial.print("UID latency              : ");
  Serial.print(firstMetrics.uidLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Sector auth latency      : ");
  Serial.print(effective.authLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Block-read latency       : ");
  Serial.print(effective.readLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Pipeline latency         : ");
  Serial.print(effective.pipelineLatencyUs);
  Serial.println(" microseconds");

  Serial.print("Successful baseline count: ");
  Serial.print(authorizedSampleCount);
  Serial.print("/");
  Serial.println(TARGET_AUTHORIZED_SAMPLES);

  printCsvRow(
    firstResult,
    finalResult,
    firstMetrics,
    retryMetrics,
    retryUsed
  );

  Serial.println("------------------------------------------");

  if (
    authorizedSampleCount >=
    TARGET_AUTHORIZED_SAMPLES
  ) {
    collectionComplete = true;

    rfid.PCD_StopCrypto1();
    rfid.PICC_HaltA();

    printFinalSummary();
    return;
  }

  finishPresentation();
}
