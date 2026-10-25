# Attack-Resilient & Secure IoT Smart Greenhouse System (R26-CS-014)

A defense-in-depth, multi-layered cybersecurity architecture designed for smart greenhouse IoT environments. This research integrates physical tamper defense, RFID clone rejection, TinyML edge anomaly detection, mutual authenticated LoRa telemetry, dynamic key rotation, emergency revocation, adversarial AI data-poisoning mitigation, and fail-closed actuation safety.

---

## 1. Project Information
- **Project Code**: `R26-CS-014`
- **Institution**: Sri Lanka Institute of Information Technology (SLIIT)
- **Specialization**: B.Sc. (Hons) in Information Technology Specializing in Cybersecurity

---

## 2. Research Components & Branch Mapping

The project is structured into four specialized, peer-reviewed sub-systems. Each research component is maintained on its dedicated branch with complete evolutionary commit history:

| Component | Focus Area | Branch | Lead Developer / GitHub | Commits |
|---|---|---|---|---|
| **Component 1** | Physical Security, RFID Clone Defense & On-Device TinyML | [`pasan`](https://github.com/IT22138804/R26-CS-014/tree/pasan) | **Pasan Matharaarachchi** ([`@PasanMatharaarachchi`](https://github.com/PasanMatharaarachchi)) | 107 commits |
| **Component 2** | Cryptographic LoRa Telemetry, Session Key Lifecycle & Operations Center | [`pathirana`](https://github.com/IT22138804/R26-CS-014/tree/pathirana) | **Oshada Pathirana** ([`@IT22138804`](https://github.com/IT22138804)) | 100 commits |
| **Component 3** | Adversarial AI Telemetry Defense & Poison Pattern Isolation | [`Senuri`](https://github.com/IT22138804/R26-CS-014/tree/Senuri) | **Senuri Kavindi** ([`@senurikavindi87-hue`](https://github.com/senurikavindi87-hue)) | 66 commits |
| **Component 4** | Actuation Safety, BOLA Defense & Cross-Platform Mobile Client | [`isuri`](https://github.com/IT22138804/R26-CS-014/tree/isuri) | **Isuri Nimasha** ([`@Isuri-dotcom`](https://github.com/Isuri-dotcom)) | 74 commits |

---

## 3. Architecture & Core Security Layers

```
                      +---------------------------------------+
                      |         SLIIT R26-CS-014 Architecture |
                      +---------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
[ Component 1: Edge Security ]                             [ Component 2: Secure LoRa Telemetry ]
* RC522 Mifare Sector 4 Authentication                     * E32 433MHz LoRa Gateway/Sensor Pair
* Same-UID Clone Tag Timing Rejection                      * HKDF-SHA256 Mutual Handshake
* ESP32 TinyML Anomaly Random Forest                       * AES-128-GCM Authenticated Encryption
* Tamper Sensor -> SRAM Key Zeroization                    * Dynamic Session Key Rotation & Revocation
* Relay Lockdown State Machine                             * Real-time Firebase Security Operations
        |                                                                   |
        +---------------------------------+---------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
[ Component 3: Adversarial AI Defense ]                    [ Component 4: Actuation Safety & Mobile ]
* Backdoor Trigger & Poison Signature Detection            * Secondary BOLA Authorization Re-check
* Spectral Signature Isolation (SVD)                       * Fail-Closed Environmental Safety Policies
* Activation Clustering Defense                            * Command Idempotency & Replay Protection
* Live Defensive Pipeline on Gateway Telemetry             * Cross-Platform Flutter Mobile Operator App
        +-------------------------------------------------------------------+
```

---

## 4. Key Subsystem Details

### Component 1: Physical Security, RFID Clone Defense & TinyML
- **Sector 4 Protected Authentication**: Mifare Classic 1K access control utilizing custom sector keys and dynamic verification markers (`C1-AUTH-V1`).
- **Timing Variance Clone Rejection**: Statistical classifier benchmarked against genuine cards and UID-changeable clone tags to reject spoofed credentials.
- **Embedded TinyML Inference**: Lightweight, floating-point parity-verified Random Forest model executing on microcontroller memory to detect telemetry manipulation.
- **Hardware Zeroization**: Microswitch-triggered interrupt instantly scrubs volatile encryption keys and isolates actuators.

### Component 2: Cryptographic LoRa Telemetry & Key Management
- **Key Derivation & Mutual Handshake**: Ephemeral session key negotiation over wireless LoRa using HKDF-SHA256.
- **Authenticated Encryption with Associated Data (AEAD)**: AES-128-GCM payload encryption with 128-bit integrity tags.
- **Packet Freshness**: Monotonic counter sequencing and timestamp freshness checks eliminating replay attacks.
- **Emergency Revocation Protocol**: Rapid cryptographic revocation broadcast to quarantine compromised nodes.
- **Interactive Security Dashboard**: Real-time React web console displaying telemetry pipeline, key status, and attack labs.

### Component 3: Adversarial AI Defense & Poison Pattern Isolation
- **Poison Pattern Mitigation**: Robust defense protecting upstream analytics from contaminated environmental telemetry.
- **Spectral Signature Isolation**: Singular Value Decomposition (SVD) identifying poisoned representations in feature space.
- **Activation Clustering**: Unsupervised separation of clean versus adversarial activation clusters.
- **False-Positive Optimization**: Tuned decision boundaries to maintain high detection recall with minimal false alarms.

### Component 4: Actuation Safety, BOLA Defense & Mobile Client
- **BOLA Defense**: Strict server-side Broken Object Level Authorization re-check preventing unauthorized actuator triggers.
- **Role-Based Firebase Rules**: Granular security rules restricting read/write capabilities across operator tiers.
- **Fail-Closed Environmental Safety**: Enforced temperature, humidity, and soil threshold boundaries with automatic fallback.
- **Flutter Mobile Client**: Native Android application enabling authorized mobile monitoring, command dispatch, and alert management.

---

## 5. Repository Directory Layout

```text
R26-CS-014/
├── one/                      # Component 1: Physical Security & TinyML (branch 'pasan')
│   ├── run/                 # Integrated ESP32 edge firmware
│   ├── frontend/            # Component 1 React dashboard
│   └── Compare Genuine vs Clone Timing/
├── two/                      # Component 2: Cryptographic LoRa Pipeline (branch 'pathirana')
│   ├── greenhouse-security-dashboard/
│   ├── sensor_data/         # Hardware diagnostic sketches
│   └── firebase/            # Database schema & security rules
├── three/                    # Component 3: Adversarial AI Defense (branch 'Senuri')
│   ├── src/                 # Spectral signature & clustering defense
│   ├── greenhouse-security-dashboard/
│   └── firmware/            # Telemetry gateway sketches
├── four/                     # Component 4: Actuation Safety & Mobile (branch 'isuri')
│   ├── app/                 # FastAPI command validation server
│   ├── greenhouse_component4_mobile/ # Flutter Android mobile app
│   └── firebase/            # Production BOLA security rules
├── integration/              # Multi-component runner workers & virtual ESP32 simulator
├── run_full_system.ps1       # Master launcher script
└── README.md                # System documentation
```

---

## 6. How to Run the Integrated System

### Quick Start with Virtual ESP32 Simulation
To launch all host-side processes, live dashboards, and virtual ESP32 telemetry simulation without physical hardware:

```powershell
powershell -ExecutionPolicy Bypass -File .un_full_system.ps1 -VirtualEsp32
```

### Physical Hardware Execution
When physical ESP32 boards (sensor node + gateway node) are connected via USB/UART:

```powershell
powershell -ExecutionPolicy Bypass -File .un_full_system.ps1
```

1. Reset the **Gateway ESP32**, wait 5 seconds for Wi-Fi and Firebase handshake.
2. Reset the **Sensor ESP32** to begin authenticated encrypted LoRa transmission.
3. Access the Operations Dashboard:
   - **Unified Dashboard**: `http://localhost:5173`
   - Real-time logs are piped to `integration/logs`.

---

## 7. License & Academic Attribution
Developed as part of the final-year research capstone in Cybersecurity at the **Sri Lanka Institute of Information Technology (SLIIT)**.
All rights reserved © 2026 R26-CS-014 Research Group.
