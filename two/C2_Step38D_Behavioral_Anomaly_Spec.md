# Component 2 — Lightweight Behavioral Anomaly Layer

This layer is implemented before Component 3 as a gateway-side, real-time detector.

## 1. Sensor-value anomaly

Inputs:
- temperature, humidity, light, soil percentage
- rate of change
- cross-sensor consistency
- sensor validity flags

Outputs:
- score 0–30
- NORMAL / SUSPICIOUS / HIGH / CRITICAL
- reasons such as OUT_OF_RANGE, IMPOSSIBLE_DELTA, SENSOR_DISCONNECT

## 2. Traffic-behavior anomaly

Inputs:
- packet rate
- packet interval
- duplicate/replay count
- HMAC/GCM failures
- malformed frame count
- handshake and retry frequency

Outputs:
- score 0–25
- reasons such as BURST_RATE, REPLAY_SPIKE, AUTH_FAILURE_SPIKE

## 3. Network-wide anomaly

Inputs:
- per-node risk scores
- number and ratio of affected nodes
- common anomaly type within a rolling time window

Outputs:
- score 0–25
- coordinated-attack decision

Research limitation:
The current hardware has one real sensor node. Multi-node logic and the React demonstration can be implemented now, but real network-wide validation requires at least two physical nodes. Until then, multi-node demonstrations must be clearly labelled SIMULATION.

## 4. Time-based anomaly

Inputs:
- timestamp freshness
- packet interval drift
- missing heartbeats
- unexpected activity time
- session age

Outputs:
- score 0–20
- reasons such as STALE_TIMESTAMP, HEARTBEAT_MISSING, INTERVAL_DRIFT

## Overall risk

overallRiskScore = sensorValue + trafficBehavior + networkWide + timeBased

- 0–29: NORMAL
- 30–59: SUSPICIOUS
- 60–79: HIGH
- 80–100: CRITICAL

A cryptographic hard failure is rejected immediately.
A behavioral CRITICAL result should require three consecutive confirmations before automatic revocation, except physical tamper, which remains immediate.

## Relationship to Component 3

Component 2:
- lightweight online detection
- gateway and dashboard observability
- immediate reject/revoke decisions

Component 3:
- advanced poisoning/backdoor analysis
- spectral signatures
- activation clustering
- training-set defence

The two components complement each other and should not be presented as the same detector.
