# Greenhouse Security Dashboard

React + Vite dashboard for the Attack-Resilient IoT Smart Greenhouse.

## What it covers

- Firebase email/password dashboard login
- Live real-sensor data
- Component 1 RFID, TinyML, tamper, actuator and insider-attribution status
- Component 2 secure-radio verification pipeline
- Session-key lifecycle, rotation and revocation
- Lightweight behavioral anomaly scores
- Security-event and counter evidence
- Safe demonstration laboratory
- Read-only access to real hardware paths
- Demo writes only under `/demo`

## Run

1. Copy `.env.example` to `.env`.
2. Open PowerShell in this folder.
3. Run:

```powershell
npm install
npm run dev
```

4. Open the local address printed by Vite.
5. Sign in using the separate Firebase Dashboard User account.

## Firebase paths used

- `/greenhouse/GH_NODE_01/current`
- `/greenhouse/GH_NODE_01/telemetry/raw_stream`
- `/greenhouse/GH_NODE_01/security`
- `/greenhouse/GH_NODE_01/component1`
- `/greenhouse/GH_NODE_01/behavioral_anomaly`
- `/greenhouse/GH_NODE_01/system/status`
- `/network`
- `/demo`

## Security rules assumption

The dashboard user can read real data, but can only write under `/demo`.
Never place Wi-Fi passwords, the gateway Firebase password, AppSKey, NwkSKey,
master PSK, Firebase ID tokens or refresh tokens in this React project.

## Demonstration limitation

Network-wide attack demonstrations are marked `SIMULATION` until at least two
real sensor nodes are available.
