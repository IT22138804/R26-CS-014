# Attack-Resilient IoT Smart Greenhouse System (R26-CS-014)

A comprehensive, defense-in-depth cybersecurity architecture for smart greenhouse monitoring and actuation environments, combining edge TinyML anomaly detection, physical tamper mitigation, cryptographic LoRa telemetry, dynamic key rotation, and emergency revocation.

---

## Research Project Overview
- **Project Code**: R26-CS-014
- **Institution**: Sri Lanka Institute of Information Technology (SLIIT)
- **Specialization**: Cybersecurity

---

## Multi-Branch Architecture
This repository contains the modular sub-systems developed for each specialized component:

| Component | Branch | Research Focus | Lead Developer |
|---|---|---|---|
| **Component 1** | [`pasan`](https://github.com/IT22138804/R26-CS-014/tree/pasan) | Physical Tamper Detection, Sector 4 RFID Authentication, Same-UID Clone Rejection & Edge TinyML Lockdown | Pasan Matharaarachchi |
| **Component 2** | [`pathirana`](https://github.com/IT22138804/R26-CS-014/tree/pathirana) | Secure LoRa (E32) Telemetry, HKDF-SHA256 Mutual Handshake, AES-GCM Encryption, Dynamic Key Rotation & Emergency Revocation | Oshada Pathirana (IT22138804) |
| **Component 3** | *To be added* | Environmental Defense & Telemetry Validation | Team Member |
| **Component 4** | *To be added* | Actuation Safety & Hardware Anomaly Protection | Team Member |

---

## Key Security Features

### 1. Physical Security & Edge Intelligence (Component 1)
- **Sector 4 RFID Authentication**: Mifare Classic 1K access control with dynamic challenge markers (`C1-AUTH-V1`).
- **Same-UID Clone Rejection**: Latency profiling and timing variance classifier that detects clone cards with identical UIDs.
- **Microcontroller TinyML**: Low-latency Random Forest classifier executing directly on ESP32 to detect sensor tampering.
- **Hardware Hard Lockdown**: Automatic zeroization of volatile SRAM keys and relay isolation on confirmed intrusion.

### 2. Cryptographic Telemetry Pipeline (Component 2)
- **Mutual Authenticated Handshake**: Ephemeral session key derivation using HKDF-SHA256 over 433MHz LoRa link.
- **Authenticated Encryption**: AES-128-GCM with 128-bit authentication tags and monotonic packet freshness counters.
- **Session Key Lifecycle**: Automated periodic key rotation and remote emergency key revocation protocol.
- **Interactive Security Dashboard**: Real-time operations center displaying live sensors, pipeline flow, and attack simulations.

---

## Repository Structure
```text
R26-CS-014/
├── one/                      # Component 1: Physical Security & TinyML (branch 'pasan')
│   ├── run/                 # Runtime integrated ESP32 firmware
│   ├── frontend/            # Component 1 React dashboard
│   └── Compare Genuine vs Clone Timing/
├── two/                      # Component 2: Cryptographic LoRa Pipeline (branch 'pathirana')
│   ├── greenhouse-security-dashboard/
│   ├── sensor_data/         # Hardware diagnostic sketches
│   └── firebase/            # Database schema & rules
└── README.md                # System documentation
```
