const now = Date.now();

export const initialDashboardData = {
  nodeId: "GH_NODE_01",
  timestamp: now,
  connection: "online",
  systemState: "NORMAL",
  scenario: "NORMAL_OPERATION",

  project: {
    component: "Component 01",
    title: "Attack-Resilient IoT Smart Greenhouse",
    stage: "Prototype closure",
    evidenceLevel: "Prototype validated · ML datasets currently synthetic",
    primaryController: "Deterministic ESP32 firmware",
    supportingModels: [
      "Environmental Random Forest",
      "RFID timing logistic regression"
    ]
  },

  sensors: {
    temperature: 31.8,
    humidity: 74.4,
    light: 236.5,
    soilRaw: 2140,
    soilPercent: 57,
    soilValid: true,
    tamperPin: 0,
    sampleValid: true,
    failedSamples: 0
  },

  actuators: {
    pump: false,
    fan: false,
    pumpRuntimeMs: 0,
    fanRuntimeMs: 0,
    pumpTimeout: false,
    pumpCooldownMs: 0,
    activeLow: true,
    safeLevel: "HIGH / OFF",
    pumpMaxRuntimeMs: 5000,
    pumpCooldownLimitMs: 15000,
    fanOnThreshold: 32,
    fanOffThreshold: 30.5,
    pumpOnThreshold: 25,
    pumpOffThreshold: 40
  },

  security: {
    tamper: false,
    enclosure: "SECURE",

    rfid: {
      uid: "83:3D:53:56",
      result: "AUTHORIZED",
      protectedSector: "Sector 4",
      marker: "C1-AUTH-V1",
      markerValid: true,
      customKeyAActive: true,
      authLatencyUs: 2238,
      blockReadLatencyUs: 2685,
      pipelineLatencyUs: 4925,
      timingRiskProbability: 0.18,
      timingRiskFlag: 0,
      timingModelRole: "Supporting signal only",
      activeActionAllowed: false,
      sourceDataSynthetic: true,

      cloneExperiment: {
        sameUidObserved: 30,
        conclusiveAttempts: 30,
        authorized: 21,
        rejected: 9,
        rejectionRate: 30,
        cardSelectionFailures: 19,
        conclusion:
          "The tested same-UID clone frequently passed protected-sector checks. Timing is therefore used only as supporting evidence.",
        universalCloneProof: false
      },

      timingComparison: {
        accuracy: 0.7684,
        precision: 0.7753,
        recall: 0.7419,
        f1: 0.7582,
        rocAuc: 0.8479,
        falsePositiveRate: 0.2062,
        falseNegativeRate: 0.2581,
        evidence: "Synthetic pipeline comparison"
      }
    },

    tinyml: {
      model: "Random Forest",
      trees: 30,
      nodes: 984,
      featureCount: 5,
      featureOrder: [
        "RFID authentication feature",
        "Tamper state",
        "Temperature-to-light ratio",
        "Moisture delta",
        "Relay runtime"
      ],
      probability: 0.12,
      prediction: 0,
      confirmations: 0,
      requiredConfirmations: 3,
      inferenceLatencyUs: 103,
      hardLockdownEnabled: true,
      sourceDataSynthetic: true,
      testAccuracy: 0.9733,
      testRecall: 0.96,
      testF1: 0.973,
      testFalsePositiveRate: 0.0133
    },

    session: {
      active: true,
      id: 1,
      ageMs: 7749,
      authEvent: 1,
      attribution:
        "Anomaly evidence is correlated to the authenticated RFID credential session. Human identity is not claimed."
    },

    insiderMisuse: {
      scenarioId: 6,
      scenarioName: "AUTHORIZED_INSIDER_MISUSE",
      tested: true,
      passed: true,
      authenticatedSessionCreated: true,
      soilDisconnectDetected: true,
      pumpBlocked: true,
      tinymlConfirmed: true,
      keysZeroized: true,
      permanentLockdown: true,
      attributionScope: "Authenticated RFID credential session",
      humanIdentityClaimed: false,
      lastIncident: {
        sessionId: 1,
        trigger: "Soil sensor open-circuit / moisture delta -100",
        probability: 0.888655,
        confirmations: "3/3",
        responseMs: 15,
        result: "HARD LOCKDOWN"
      }
    },

    keys: {
      nwkSKey: {
        state: "ACTIVE",
        storage: "Runtime SRAM",
        source: "Prototype runtime key",
        persistence: "Not stored in dashboard",
        zeroizeOnTamper: true,
        zeroizeOnTinymlLockdown: true,
        verification: "PASSED",
        fullLifecycleStatus: "Component 2 pending",
        missingLifecycleItems: [
          "Gateway handshake",
          "HKDF-based derivation",
          "HMAC packet signing",
          "Rotation",
          "Emergency revocation"
        ]
      },

      rfidKeyA: {
        state: "ACTIVE",
        storage: "Runtime memory",
        purpose: "MIFARE Classic Sector 4 authentication",
        zeroizeOnTamper: true,
        zeroizeOnTinymlLockdown: true,
        verification: "PASSED"
      },

      lastZeroization: {
        trigger: "Confirmed TinyML hard lockdown",
        nwkSKey: "ZEROIZED",
        rfidKeyA: "ZEROIZED",
        verification: "PASSED",
        recovery: "Physical restart required"
      }
    },

    lockdown: {
      latched: false,
      cause: "NONE",
      redLed: false,
      rfidDisabled: false,
      sensorSamplingDisabled: false,
      recovery: "Not required",
      safeRelayLevel: "HIGH / OFF",
      keyZeroizationRequired: true
    }
  },

  testCoverage: [
    {
      category: "Physical tamper",
      test: "Reed-switch breach",
      status: "PASSED",
      evidence: "15 ms response, relays OFF, keys zeroized, permanent lockdown",
      source: "Real hardware"
    },
    {
      category: "NwkSKey",
      test: "Runtime zeroization",
      status: "PASSED",
      evidence: "Memory cleared and verification passed",
      source: "Real hardware"
    },
    {
      category: "RFID",
      test: "Protected Sector 4 authentication",
      status: "PASSED",
      evidence: "Custom Key A + protected marker validation",
      source: "Real hardware"
    },
    {
      category: "RFID clone",
      test: "Same-UID research clone",
      status: "PARTIAL",
      evidence: "21 authorized, 9 rejected out of 30 conclusive attempts",
      source: "Real hardware"
    },
    {
      category: "RFID timing",
      test: "Genuine vs clone classifier",
      status: "PIPELINE ONLY",
      evidence: "76.84% accuracy, 20.62% FPR",
      source: "Synthetic comparison"
    },
    {
      category: "Insider misuse",
      test: "Authorized session + soil disconnect",
      status: "PASSED",
      evidence: "Pump blocked, anomaly confirmed, session correlated, hard lockdown",
      source: "Real hardware"
    },
    {
      category: "TinyML",
      test: "Environmental model ESP32 parity",
      status: "PASSED",
      evidence: "12/12 parity cases",
      source: "Export parity"
    },
    {
      category: "TinyML",
      test: "Confirmed anomaly hard lockdown",
      status: "PASSED",
      evidence: "3/3 confirmations, relays OFF, keys zeroized",
      source: "Real hardware"
    },
    {
      category: "Actuator safety",
      test: "Pump runtime and cooldown",
      status: "PASSED",
      evidence: "5 s maximum runtime and 15 s cooldown",
      source: "Real hardware"
    },
    {
      category: "Evidence",
      test: "Final classifier validation",
      status: "PENDING",
      evidence: "Replace synthetic data with real held-out telemetry",
      source: "Pending"
    }
  ],

  events: [
    {
      id: 1,
      time: now - 30000,
      type: "RFID",
      severity: "success",
      message: "Authorized RFID session #1 started"
    },
    {
      id: 2,
      time: now - 25000,
      type: "SYSTEM",
      severity: "info",
      message: "System changed from LOCKED to NORMAL"
    },
    {
      id: 3,
      time: now - 19000,
      type: "TINYML",
      severity: "success",
      message: "Normal environmental inference · confirmations 0/3"
    },
    {
      id: 4,
      time: now - 13000,
      type: "RFID TIMING",
      severity: "warning",
      message:
        "Timing-risk score calculated as supporting evidence; no active action permitted"
    },
    {
      id: 5,
      time: now - 7000,
      type: "KEYS",
      severity: "info",
      message:
        "Runtime NwkSKey and RFID Key A remain active in the current normal session"
    }
  ],

  history: Array.from({ length: 36 }, (_, index) => ({
    time: now - (35 - index) * 2500,
    temperature: 29.8 + Math.sin(index / 4.2) * 2.2,
    humidity: 73 + Math.cos(index / 4.6) * 4.2,
    soilPercent: 61 - index * 0.11 + Math.sin(index / 2.5) * 1.7,
    light: 220 + Math.sin(index / 3.1) * 65,
    anomalyProbability: Math.max(
      0.03,
      0.12 + Math.sin(index / 3.3) * 0.05
    ),
    rfidRiskProbability: 0.18
  }))
};

export function nextMockData(previous) {
  const timestamp = Date.now();

  const temperature = Math.max(
    24,
    Math.min(
      38,
      previous.sensors.temperature + (Math.random() - 0.46) * 0.32
    )
  );

  const humidity = Math.max(
    45,
    Math.min(
      95,
      previous.sensors.humidity + (Math.random() - 0.5) * 0.8
    )
  );

  const light = Math.max(
    1,
    previous.sensors.light + (Math.random() - 0.5) * 22
  );

  const soilPercent = Math.max(
    0,
    Math.min(
      100,
      previous.sensors.soilPercent - 0.08 + (Math.random() - 0.5) * 0.6
    )
  );

  const soilRaw = Math.round(1169 + (100 - soilPercent) * 29.26);

  const fan = temperature >= 32
    ? true
    : temperature <= 30.5
      ? false
      : previous.actuators.fan;

  const pump = soilPercent <= 25
    ? true
    : soilPercent >= 40
      ? false
      : previous.actuators.pump;

  const environmentalRisk = Math.max(
    0.02,
    Math.min(
      0.98,
      0.08
      + Math.max(0, temperature - 33) * 0.08
      + Math.max(0, 20 - light) * 0.015
      + Math.max(0, 18 - soilPercent) * 0.025
      + (Math.random() - 0.5) * 0.04
    )
  );

  const prediction = environmentalRisk >= 0.5 ? 1 : 0;

  const confirmations = prediction
    ? Math.min(
        previous.security.tinyml.confirmations + 1,
        previous.security.tinyml.requiredConfirmations
      )
    : 0;

  const nextPoint = {
    time: timestamp,
    temperature,
    humidity,
    soilPercent,
    light,
    anomalyProbability: environmentalRisk,
    rfidRiskProbability:
      previous.security.rfid.timingRiskProbability
  };

  return {
    ...previous,
    timestamp,

    sensors: {
      ...previous.sensors,
      temperature,
      humidity,
      light,
      soilPercent,
      soilRaw,
      soilValid: soilRaw < 4080,
      sampleValid: soilRaw < 4080
    },

    actuators: {
      ...previous.actuators,
      fan,
      pump,
      fanRuntimeMs: fan
        ? previous.actuators.fanRuntimeMs + 2500
        : 0,
      pumpRuntimeMs: pump
        ? Math.min(previous.actuators.pumpRuntimeMs + 2500, 5000)
        : 0
    },

    security: {
      ...previous.security,

      tinyml: {
        ...previous.security.tinyml,
        probability: environmentalRisk,
        prediction,
        confirmations,
        inferenceLatencyUs: Math.round(96 + Math.random() * 20)
      },

      session: {
        ...previous.security.session,
        ageMs: previous.security.session.active
          ? previous.security.session.ageMs + 2500
          : 0
      }
    },

    history: [
      ...previous.history.slice(-59),
      nextPoint
    ]
  };
}
