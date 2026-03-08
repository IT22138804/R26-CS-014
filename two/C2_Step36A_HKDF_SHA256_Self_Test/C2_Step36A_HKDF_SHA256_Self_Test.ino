/*
  Component 2 — Step 36A
  HKDF-SHA256 cryptographic self-test

  Upload this identical sketch to BOTH ESP32 boards:
    1. Sensor / Edge ESP32
    2. Gateway ESP32

  Purpose:
  - Verify the ESP32 mbedTLS HMAC-SHA256 implementation.
  - Verify HKDF-SHA256 against RFC 5869 Test Case 1.
  - Derive separate 128-bit AppSKey and NwkSKey values.
  - Compare only short SHA-256 fingerprints between the two boards.
  - Verify runtime key zeroization.

  This sketch uses public TEST key material only.
  It does not transmit keys and must not be treated as the final handshake.
*/

#include <Arduino.h>
#include <mbedtls/md.h>

// =====================================================
// CRYPTO CONSTANTS
// =====================================================

constexpr size_t SHA256_LENGTH = 32;
constexpr size_t SESSION_KEY_LENGTH = 16;

// RFC 5869 Test Case 1.
const uint8_t RFC_IKM[22] = {
  0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
  0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
  0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
  0x0B, 0x0B, 0x0B, 0x0B
};

const uint8_t RFC_SALT[13] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
};

const uint8_t RFC_INFO[10] = {
  0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
  0xF5, 0xF6, 0xF7, 0xF8, 0xF9
};

const uint8_t RFC_EXPECTED_PRK[32] = {
  0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF,
  0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA, 0x63,
  0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31,
  0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2, 0xB3, 0xE5
};

const uint8_t RFC_EXPECTED_OKM[42] = {
  0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A,
  0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F, 0x2A,
  0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C,
  0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4, 0xC5, 0xBF,
  0x34, 0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18,
  0x58, 0x65
};

// Public prototype material for same-result testing on both ESP32s.
// Replace this architecture later with a real authenticated handshake.
const uint8_t TEST_MASTER_KEY[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

const uint8_t TEST_SESSION_SALT[16] = {
  0x7C, 0x41, 0xB2, 0x09, 0xE6, 0x53, 0x18, 0xAF, 0x32, 0xD0, 0x77, 0x94, 0x5B, 0xC8, 0x21, 0x6E
};

const uint8_t APP_INFO[] =
    "C2/GH_NODE_01/APPSKEY/V1";

const uint8_t NWK_INFO[] =
    "C2/GH_NODE_01/NWKSKEY/V1";

const uint8_t EXPECTED_APP_FINGERPRINT[8] = {
  0xA6, 0xEE, 0x3B, 0xDD, 0x39, 0x7B, 0xF6, 0xCA
};

const uint8_t EXPECTED_NWK_FINGERPRINT[8] = {
  0x39, 0x50, 0x17, 0xCC, 0x97, 0x3E, 0x1D, 0xED
};

// Runtime-only key containers.
uint8_t runtimeAppSKey[SESSION_KEY_LENGTH] = {0};
uint8_t runtimeNwkSKey[SESSION_KEY_LENGTH] = {0};

// =====================================================
// SECURE MEMORY UTILITIES
// =====================================================

void secureZeroize(
    void* memory,
    size_t length
) {
  volatile uint8_t* pointer =
      static_cast<volatile uint8_t*>(memory);

  while (length > 0) {
    *pointer = 0;
    pointer++;
    length--;
  }
}

bool isAllZero(
    const uint8_t* data,
    size_t length
) {
  uint8_t accumulator = 0;

  for (size_t i = 0; i < length; i++) {
    accumulator |= data[i];
  }

  return accumulator == 0;
}

bool constantTimeEqual(
    const uint8_t* first,
    const uint8_t* second,
    size_t length
) {
  uint8_t difference = 0;

  for (size_t i = 0; i < length; i++) {
    difference |= first[i] ^ second[i];
  }

  return difference == 0;
}

// =====================================================
// HMAC-SHA256
// =====================================================

bool hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t output[SHA256_LENGTH]
) {
  const mbedtls_md_info_t* info =
      mbedtls_md_info_from_type(
        MBEDTLS_MD_SHA256
      );

  if (info == nullptr) {
    return false;
  }

  mbedtls_md_context_t context;
  mbedtls_md_init(&context);

  int result =
      mbedtls_md_setup(
        &context,
        info,
        1
      );

  if (result == 0) {
    result =
        mbedtls_md_hmac_starts(
          &context,
          key,
          keyLength
        );
  }

  if (result == 0 && dataLength > 0) {
    result =
        mbedtls_md_hmac_update(
          &context,
          data,
          dataLength
        );
  }

  if (result == 0) {
    result =
        mbedtls_md_hmac_finish(
          &context,
          output
        );
  }

  mbedtls_md_free(&context);

  return result == 0;
}

// =====================================================
// HKDF-SHA256 EXTRACT
// =====================================================

bool hkdfExtractSha256(
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* ikm,
    size_t ikmLength,
    uint8_t prk[SHA256_LENGTH]
) {
  uint8_t zeroSalt[SHA256_LENGTH] = {0};

  const uint8_t* effectiveSalt =
      saltLength > 0
        ? salt
        : zeroSalt;

  const size_t effectiveSaltLength =
      saltLength > 0
        ? saltLength
        : sizeof(zeroSalt);

  const bool success =
      hmacSha256(
        effectiveSalt,
        effectiveSaltLength,
        ikm,
        ikmLength,
        prk
      );

  secureZeroize(
    zeroSalt,
    sizeof(zeroSalt)
  );

  return success;
}

// =====================================================
// HKDF-SHA256 EXPAND
// =====================================================

bool hkdfExpandSha256(
    const uint8_t prk[SHA256_LENGTH],
    const uint8_t* info,
    size_t infoLength,
    uint8_t* output,
    size_t outputLength
) {
  if (
    outputLength == 0
    || outputLength > 255 * SHA256_LENGTH
  ) {
    return false;
  }

  const mbedtls_md_info_t* mdInfo =
      mbedtls_md_info_from_type(
        MBEDTLS_MD_SHA256
      );

  if (mdInfo == nullptr) {
    return false;
  }

  uint8_t previousBlock[SHA256_LENGTH] = {0};
  size_t previousLength = 0;
  size_t generatedLength = 0;
  uint8_t counter = 1;

  while (generatedLength < outputLength) {
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);

    int result =
        mbedtls_md_setup(
          &context,
          mdInfo,
          1
        );

    if (result == 0) {
      result =
          mbedtls_md_hmac_starts(
            &context,
            prk,
            SHA256_LENGTH
          );
    }

    if (
      result == 0
      && previousLength > 0
    ) {
      result =
          mbedtls_md_hmac_update(
            &context,
            previousBlock,
            previousLength
          );
    }

    if (
      result == 0
      && infoLength > 0
    ) {
      result =
          mbedtls_md_hmac_update(
            &context,
            info,
            infoLength
          );
    }

    if (result == 0) {
      result =
          mbedtls_md_hmac_update(
            &context,
            &counter,
            1
          );
    }

    if (result == 0) {
      result =
          mbedtls_md_hmac_finish(
            &context,
            previousBlock
          );
    }

    mbedtls_md_free(&context);

    if (result != 0) {
      secureZeroize(
        previousBlock,
        sizeof(previousBlock)
      );

      return false;
    }

    previousLength = SHA256_LENGTH;

    const size_t remaining =
        outputLength - generatedLength;

    const size_t copyLength =
        remaining < SHA256_LENGTH
          ? remaining
          : SHA256_LENGTH;

    memcpy(
      output + generatedLength,
      previousBlock,
      copyLength
    );

    generatedLength += copyLength;
    counter++;
  }

  secureZeroize(
    previousBlock,
    sizeof(previousBlock)
  );

  return true;
}

bool hkdfSha256(
    const uint8_t* ikm,
    size_t ikmLength,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* info,
    size_t infoLength,
    uint8_t* output,
    size_t outputLength
) {
  uint8_t prk[SHA256_LENGTH] = {0};

  const bool extractSuccess =
      hkdfExtractSha256(
        salt,
        saltLength,
        ikm,
        ikmLength,
        prk
      );

  if (!extractSuccess) {
    secureZeroize(prk, sizeof(prk));
    return false;
  }

  const bool expandSuccess =
      hkdfExpandSha256(
        prk,
        info,
        infoLength,
        output,
        outputLength
      );

  secureZeroize(prk, sizeof(prk));

  return expandSuccess;
}

// =====================================================
// SHA-256 FINGERPRINT
// =====================================================

bool sha256Digest(
    const uint8_t* data,
    size_t length,
    uint8_t output[SHA256_LENGTH]
) {
  const mbedtls_md_info_t* info =
      mbedtls_md_info_from_type(
        MBEDTLS_MD_SHA256
      );

  if (info == nullptr) {
    return false;
  }

  return
      mbedtls_md(
        info,
        data,
        length,
        output
      ) == 0;
}

void printHex(
    const uint8_t* data,
    size_t length
) {
  for (size_t i = 0; i < length; i++) {
    if (data[i] < 0x10) {
      Serial.print("0");
    }

    Serial.print(data[i], HEX);
  }
}

bool calculateFingerprint(
    const uint8_t* key,
    size_t keyLength,
    uint8_t outputFingerprint[8]
) {
  uint8_t digest[SHA256_LENGTH] = {0};

  if (!sha256Digest(key, keyLength, digest)) {
    secureZeroize(digest, sizeof(digest));
    return false;
  }

  memcpy(outputFingerprint, digest, 8);
  secureZeroize(digest, sizeof(digest));

  return true;
}

// =====================================================
// TESTS
// =====================================================

bool runRfc5869Test() {
  uint8_t actualPrk[SHA256_LENGTH] = {0};
  uint8_t actualOkm[42] = {0};

  const bool extractSuccess =
      hkdfExtractSha256(
        RFC_SALT,
        sizeof(RFC_SALT),
        RFC_IKM,
        sizeof(RFC_IKM),
        actualPrk
      );

  const bool expandSuccess =
      extractSuccess
      && hkdfExpandSha256(
        actualPrk,
        RFC_INFO,
        sizeof(RFC_INFO),
        actualOkm,
        sizeof(actualOkm)
      );

  const bool prkMatches =
      extractSuccess
      && constantTimeEqual(
        actualPrk,
        RFC_EXPECTED_PRK,
        sizeof(actualPrk)
      );

  const bool okmMatches =
      expandSuccess
      && constantTimeEqual(
        actualOkm,
        RFC_EXPECTED_OKM,
        sizeof(actualOkm)
      );

  Serial.print("RFC 5869 PRK result      : ");
  Serial.println(
    prkMatches ? "PASSED" : "FAILED"
  );

  Serial.print("RFC 5869 OKM result      : ");
  Serial.println(
    okmMatches ? "PASSED" : "FAILED"
  );

  secureZeroize(actualPrk, sizeof(actualPrk));
  secureZeroize(actualOkm, sizeof(actualOkm));

  return prkMatches && okmMatches;
}

bool deriveSeparatedSessionKeys() {
  const bool appSuccess =
      hkdfSha256(
        TEST_MASTER_KEY,
        sizeof(TEST_MASTER_KEY),
        TEST_SESSION_SALT,
        sizeof(TEST_SESSION_SALT),
        APP_INFO,
        sizeof(APP_INFO) - 1,
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  const bool nwkSuccess =
      hkdfSha256(
        TEST_MASTER_KEY,
        sizeof(TEST_MASTER_KEY),
        TEST_SESSION_SALT,
        sizeof(TEST_SESSION_SALT),
        NWK_INFO,
        sizeof(NWK_INFO) - 1,
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  return appSuccess && nwkSuccess;
}

void setup() {
  Serial.begin(115200);
  delay(1500);

  Serial.println();
  Serial.println("==========================================");
  Serial.println("COMPONENT 2 — STEP 36A");
  Serial.println("HKDF-SHA256 CRYPTOGRAPHIC SELF-TEST");
  Serial.println("==========================================");
  Serial.println("Radio transmission       : DISABLED");
  Serial.println("Key material             : PUBLIC TEST VALUES");
  Serial.println("Keys printed             : NO");
  Serial.println("Session-key size         : 128 bits");
  Serial.println();

  const bool rfcPassed =
      runRfc5869Test();

  const bool derivationPassed =
      deriveSeparatedSessionKeys();

  uint8_t appFingerprint[8] = {0};
  uint8_t nwkFingerprint[8] = {0};

  const bool appFingerprintSuccess =
      derivationPassed
      && calculateFingerprint(
        runtimeAppSKey,
        sizeof(runtimeAppSKey),
        appFingerprint
      );

  const bool nwkFingerprintSuccess =
      derivationPassed
      && calculateFingerprint(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey),
        nwkFingerprint
      );

  const bool appExpected =
      appFingerprintSuccess
      && constantTimeEqual(
        appFingerprint,
        EXPECTED_APP_FINGERPRINT,
        sizeof(appFingerprint)
      );

  const bool nwkExpected =
      nwkFingerprintSuccess
      && constantTimeEqual(
        nwkFingerprint,
        EXPECTED_NWK_FINGERPRINT,
        sizeof(nwkFingerprint)
      );

  const bool keysSeparated =
      derivationPassed
      && !constantTimeEqual(
        runtimeAppSKey,
        runtimeNwkSKey,
        SESSION_KEY_LENGTH
      );

  Serial.println();
  Serial.print("AppSKey derivation       : ");
  Serial.println(
    appExpected ? "PASSED" : "FAILED"
  );

  Serial.print("AppSKey fingerprint      : ");
  printHex(
    appFingerprint,
    sizeof(appFingerprint)
  );
  Serial.println();

  Serial.print("Expected App fingerprint : ");
  Serial.println("A6EE3BDD397BF6CA");

  Serial.println();

  Serial.print("NwkSKey derivation       : ");
  Serial.println(
    nwkExpected ? "PASSED" : "FAILED"
  );

  Serial.print("NwkSKey fingerprint      : ");
  printHex(
    nwkFingerprint,
    sizeof(nwkFingerprint)
  );
  Serial.println();

  Serial.print("Expected Nwk fingerprint : ");
  Serial.println("395017CC973E1DED");

  Serial.println();

  Serial.print("Key-purpose separation   : ");
  Serial.println(
    keysSeparated ? "PASSED" : "FAILED"
  );

  secureZeroize(
    runtimeAppSKey,
    sizeof(runtimeAppSKey)
  );

  secureZeroize(
    runtimeNwkSKey,
    sizeof(runtimeNwkSKey)
  );

  const bool appZeroized =
      isAllZero(
        runtimeAppSKey,
        sizeof(runtimeAppSKey)
      );

  const bool nwkZeroized =
      isAllZero(
        runtimeNwkSKey,
        sizeof(runtimeNwkSKey)
      );

  Serial.print("AppSKey zeroization      : ");
  Serial.println(
    appZeroized ? "PASSED" : "FAILED"
  );

  Serial.print("NwkSKey zeroization      : ");
  Serial.println(
    nwkZeroized ? "PASSED" : "FAILED"
  );

  secureZeroize(
    appFingerprint,
    sizeof(appFingerprint)
  );

  secureZeroize(
    nwkFingerprint,
    sizeof(nwkFingerprint)
  );

  const bool finalPassed =
      rfcPassed
      && appExpected
      && nwkExpected
      && keysSeparated
      && appZeroized
      && nwkZeroized;

  Serial.println();
  Serial.print("STEP 36A RESULT          : ");
  Serial.println(
    finalPassed
      ? "PASSED"
      : "REVIEW REQUIRED"
  );

  Serial.println("==========================================");
}

void loop() {
  delay(1000);
}
