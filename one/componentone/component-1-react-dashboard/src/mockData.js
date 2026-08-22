const now = Date.now();

export const initialDashboardData = {
  nodeId: "GH_NODE_01",
  timestamp: now,
  connection: "online",
  systemState: "NORMAL",
  scenario: "NORMAL_OPERATION",
  sensors: {
    temperature: 31.8,
    humidity: 74.4,
    light: 236.5,
    soilRaw: 2140,
    soilPercent: 57,
    soilValid: true
  },
  actuators: {
    pump: false,
    fan: false,
    pumpRuntimeMs: 0,
    fanRuntimeMs: 0,
    pumpTimeout: false,
    pumpCooldownMs: 0
  },
  security: {
    tamper: false,
    enclosure: "SECURE",
    rfid: {
      uid: "83:3D:53:56",
      result: "AUTHORIZED",
      authLatencyUs: 2238,
      blockReadLatencyUs: 2685,
      pipelineLatencyUs: 4925,
      timingRiskProbability: 0.18,
      timingRiskFlag: 0
    },
    tinyml: {
      probability: 0.12,
      prediction: 0,
      confirmations: 0,
      requiredConfirmations: 3,
      inferenceLatencyUs: 103
    },
    session: {
      active: true,
      id: 1,
      ageMs: 7749
    },
    keys: {
      nwkSKey: "ACTIVE",
      rfidKeyA: "ACTIVE",
      zeroization: "NOT_REQUIRED"
    }
  },
  events: [
    {
      id: 1,
      time: now - 16000,
      type: "RFID",
      severity: "success",
      message: "Authorized RFID session started"
    },
    {
      id: 2,
      time: now - 11000,
      type: "SYSTEM",
      severity: "info",
      message: "System state changed from LOCKED to NORMAL"
    },
    {
      id: 3,
      time: now - 5000,
      type: "TINYML",
      severity: "success",
      message: "Normal environmental inference"
    }
  ],
  history: Array.from({ length: 24 }, (_, index) => ({
    time: now - (23 - index) * 2500,
    temperature: 29.6 + Math.sin(index / 3.2) * 2.4,
    humidity: 73 + Math.cos(index / 4.1) * 4.5,
    soilPercent: 60 - index * 0.12 + Math.sin(index / 2.2) * 1.8,
    anomalyProbability: Math.max(
      0.03,
      0.12 + Math.sin(index / 2.8) * 0.05
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
      soilValid: soilRaw < 4080
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
    history: [...previous.history.slice(-47), nextPoint]
  };
}
