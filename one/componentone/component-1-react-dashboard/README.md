# Component 1 Secure Greenhouse Dashboard

React + Vite dashboard for the Component 1 ESP32 edge-security node.

## Included dashboard areas

- System state: `LOCKED`, `NORMAL`, `LOCKDOWN`
- DHT22 temperature and humidity
- BH1750 light intensity
- Soil raw value, percentage and open-circuit status
- Pump/fan state and runtime
- Protected RFID authentication status and latency
- RFID timing-risk support probability
- Environmental TinyML anomaly probability and confirmation count
- Physical tamper status
- Runtime NwkSKey and RFID Key A status
- Authenticated-session attribution
- Security event timeline
- Component 1 coverage summary

## Run locally

```bash
npm install
npm run dev
```

Open the URL displayed by Vite, normally:

```text
http://localhost:5173
```

## Demo mode

The project runs in Demo Mode automatically when no Firebase URL is configured.
Telemetry changes every 2.5 seconds.

## Firebase live mode

1. Copy `.env.example` to `.env`.
2. Add your Realtime Database URL:

```env
VITE_FIREBASE_DATABASE_URL=https://your-project-default-rtdb.firebaseio.com
VITE_FIREBASE_AUTH=
VITE_NODE_ID=GH_NODE_01
VITE_REFRESH_INTERVAL_MS=2500
```

3. Restart `npm run dev`.

The dashboard reads:

```text
/greenhouse/GH_NODE_01/current.json
/greenhouse/GH_NODE_01/logs.json
```

## Recommended current-data structure

```json
{
  "nodeId": "GH_NODE_01",
  "timestamp": 1784790000000,
  "connection": "online",
  "systemState": "NORMAL",
  "scenario": "NORMAL_OPERATION",
  "sensors": {
    "temperature": 31.8,
    "humidity": 74.4,
    "light": 236.5,
    "soilRaw": 2140,
    "soilPercent": 57,
    "soilValid": true
  },
  "actuators": {
    "pump": false,
    "fan": false,
    "pumpRuntimeMs": 0,
    "fanRuntimeMs": 0,
    "pumpTimeout": false,
    "pumpCooldownMs": 0
  },
  "security": {
    "tamper": false,
    "enclosure": "SECURE",
    "rfid": {
      "uid": "83:3D:53:56",
      "result": "AUTHORIZED",
      "authLatencyUs": 2238,
      "blockReadLatencyUs": 2685,
      "pipelineLatencyUs": 4925,
      "timingRiskProbability": 0.18,
      "timingRiskFlag": 0
    },
    "tinyml": {
      "probability": 0.12,
      "prediction": 0,
      "confirmations": 0,
      "requiredConfirmations": 3,
      "inferenceLatencyUs": 103
    },
    "session": {
      "active": true,
      "id": 1,
      "ageMs": 7749
    },
    "keys": {
      "nwkSKey": "ACTIVE",
      "rfidKeyA": "ACTIVE",
      "zeroization": "NOT_REQUIRED"
    }
  }
}
```

## Build for deployment

```bash
npm run build
```

The production files will be created inside `dist/`.

## Important security note

This dashboard displays security evidence. It should not be the authority that controls
relays, unlocks the node or performs key zeroization. Those actions must remain inside
the deterministic ESP32 firmware.
