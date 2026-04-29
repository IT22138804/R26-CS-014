#ifndef C1_RFID_TIMING_RISK_MODEL_H
#define C1_RFID_TIMING_RISK_MODEL_H

#include <Arduino.h>
#include <math.h>
#include <stdint.h>

// =====================================================
// COMPONENT 1 — RFID TIMING-RISK SUPPORT MODEL
//
// Feature order:
//   0: uid_latency_us
//   1: auth_latency_us
//   2: block_read_latency_us
//   3: pipeline_latency_us
//
// Evidence level: SYNTHETIC_PIPELINE_ONLY
//
// SECURITY RULE:
// This output is a SUPPORTING RISK SIGNAL only.
// It must never independently unlock, reject, operate relays,
// zeroize keys, or enter hard lockdown.
// =====================================================

namespace C1RFIDTimingRisk {

constexpr uint8_t FEATURE_COUNT = 4;
constexpr float RISK_THRESHOLD = 0.751f;

// This remains false even when real data is later supplied.
// Independent held-out validation and system-level safety review
// are required before any active response is considered.
constexpr bool ACTIVE_SECURITY_ACTION_ALLOWED = false;
constexpr bool SUPPORTING_SIGNAL_ONLY = true;
constexpr bool SOURCE_DATA_SYNTHETIC = true;

static const float FEATURE_MEAN[FEATURE_COUNT] = {
  2834.53158f, 2241.94211f, 2695.13684f, 4941.79474f
};

static const float FEATURE_SCALE[FEATURE_COUNT] = {
  11.3363204f, 7.07789857f, 14.895503f, 18.5056172f
};

static const float MODEL_COEFFICIENT[FEATURE_COUNT] = {
  -0.431749405f, 0.377171989f, -0.556732659f, 1.88143156f
};

constexpr float MODEL_INTERCEPT = 0.0312733093f;

inline float stableSigmoid(float value) {
  if (value >= 0.0f) {
    return 1.0f / (1.0f + expf(-value));
  }

  const float expValue = expf(value);
  return expValue / (1.0f + expValue);
}

inline float predictCloneRiskProbability(
    const float rawFeatures[FEATURE_COUNT]
) {
  float logit = MODEL_INTERCEPT;

  for (
    uint8_t featureIndex = 0;
    featureIndex < FEATURE_COUNT;
    featureIndex++
  ) {
    const float normalized =
        (
          rawFeatures[featureIndex]
          - FEATURE_MEAN[featureIndex]
        )
        / FEATURE_SCALE[featureIndex];

    logit +=
        normalized
        * MODEL_COEFFICIENT[featureIndex];
  }

  return stableSigmoid(logit);
}

inline uint8_t predictRiskFlag(
    const float rawFeatures[FEATURE_COUNT]
) {
  return
      predictCloneRiskProbability(rawFeatures)
          >= RISK_THRESHOLD
        ? 1
        : 0;
}

}  // namespace C1RFIDTimingRisk

#endif  // C1_RFID_TIMING_RISK_MODEL_H
