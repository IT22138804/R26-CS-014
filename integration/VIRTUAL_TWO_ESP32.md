# Virtual two-ESP32 test mode

Run `./run_virtual_two_esp32.ps1` in a second terminal while the dashboard and
host workers are running. It creates a virtual sensor and gateway, performs the
authenticated HMAC/HKDF handshake, sends AES-GCM telemetry every 2.5 seconds,
and writes the existing Firebase/dashboard schema.

The Component 1 dashboard buttons are fully simulated:

- Authorized unlock: successful UID/sector evidence and an authenticated session.
- Wrong RFID card: UID rejection with an unauthorized-UID risk result.
- RFID clone attempt: same-UID sector-authentication failure and elevated clone risk.
- Insider misuse: after Authorized unlock, three anomaly confirmations force virtual lockdown.

Each action updates RFID, TinyML, insider attribution, fail-safe actuators, command
status, and a security-event record in real time.

All generated records contain `VIRTUAL_TWO_ESP32` or `SIMULATION_NOT_HARDWARE`.
They are system-test evidence, not physical-hardware evidence.

Before merging with hardware:

1. Stop the virtual process with Ctrl+C.
2. Confirm Firebase shows `VIRTUAL_STOPPED`.
3. Upload the gateway sketch and start the gateway ESP32.
4. Upload the sensor sketch and start the sensor ESP32.
5. The real gateway overwrites `current`, `security/session`, and `system/status`.
6. Keep virtual raw-stream records only as clearly labelled simulation history.

Protocol-only test without Firebase:

`three/.venv/Scripts/python.exe integration/virtual_esp32_pair.py --dry-run --seconds 10`

## Component 2 controlled triggers

Open **Secure pipeline** in the React dashboard. The trigger panel supports
replay, invalid outer HMAC, invalid GCM tag, stale timestamp, a five-frame HMAC
failure spike, key rotation, and emergency revocation.

Both modes use `/demo/component2/pending` for requests and
`/greenhouse/GH_NODE_01/demo/component2/status` for results. Virtual results are
marked `VIRTUAL_TWO_ESP32`. In physical mode, the gateway signs each command
with the active NwkSKey and sends it over E32. Attack packets are blocked from
Firebase telemetry. Rotation destroys the old keys and starts a fresh
nonce-based handshake. Revocation and the HMAC-spike trigger zeroization and
require a restart or separately authorized recovery procedure.
