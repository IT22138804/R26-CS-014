# Component 1 Secure Greenhouse Dashboard

A detailed React + Vite dashboard for the **Attack-Resilient IoT Smart Greenhouse — Component 01**.

## Dashboard pages

### 1. Overview
- Node state and connection
- DHT22 temperature/humidity
- BH1750 light
- Soil raw value and percentage
- Pump/fan state
- Environmental TinyML probability
- RFID timing-risk support probability
- Authenticated session
- Runtime-key status

### 2. Insider Misuse
- Formal `AUTHORIZED_INSIDER_MISUSE` scenario
- Authenticated session creation
- Soil-sensor disconnection
- Pump blocking
- TinyML 3/3 confirmation
- Key zeroization
- Permanent lockdown
- Credential-session attribution boundary

### 3. RFID & Clone
- UID
- Sector 4 protected authentication
- Custom Key A
- Protected marker `C1-AUTH-V1`
- Authentication timing
- Same-UID clone experiment
- Clone authorized/rejected totals
- Timing classifier metrics
- Clear warning that the prototype is not universally clone-proof

### 4. NwkSKey & Keys
- Runtime NwkSKey state
- RFID Key A state
- SRAM/runtime storage
- Tamper-triggered zeroization
- TinyML-lockdown zeroization
- Verification result
- Component 2 lifecycle items still pending:
  - gateway handshake
  - HKDF derivation
  - HMAC packet signing
  - rotation
  - emergency revocation

### 5. TinyML & Lockdown
- Model type, trees, nodes and feature order
- Live anomaly probability
- Confirmation counter
- Test accuracy/recall/F1/FPR
- Hard-lockdown response
- Security-authority hierarchy

### 6. Sensors & Actuators
- Sensor-health matrix
- Active-low relay safety
- Pump thresholds, max runtime and cooldown
- Fan hysteresis
- Open-circuit soil protection

### 7. Tests & Evidence
- Hardware validation
- RFID clone test
- TinyML parity
- Insider misuse
- Key zeroization
- Evidence limitations
- Pending real-data validation

### 8. Events & Forensics
- Event timeline
- Session context
- Recommended Firebase log fields

## Run locally

```bash
npm install
npm run dev
```

Open the Vite URL, normally:

```text
http://localhost:5173
```

## Demo mode

The project starts in Demo Mode automatically and updates telemetry every 2.5 seconds.

## Firebase live mode

Copy:

```text
.env.example
```

to:

```text
.env
```

Then configure:

```env
VITE_FIREBASE_DATABASE_URL=https://your-project-default-rtdb.firebaseio.com
VITE_FIREBASE_AUTH=
VITE_NODE_ID=GH_NODE_01
VITE_REFRESH_INTERVAL_MS=2500
```

The dashboard reads:

```text
/greenhouse/GH_NODE_01/current.json
/greenhouse/GH_NODE_01/logs.json
```

## Security boundary

This dashboard is read-only. It must never be the authority for:

- unlocking the node
- rejecting RFID credentials
- operating relays
- zeroizing keys
- entering hard lockdown

Those security decisions remain inside the deterministic ESP32 firmware.

## Evidence warning

The dashboard clearly separates:

- real hardware validation
- export/parity validation
- synthetic ML pipeline results
- pending real held-out research evidence

Do not report synthetic classifier metrics as final measured real-world performance.
