# Component 1 live demonstration

This demonstration uses the integrated two-ESP32 firmware. It does not require
uploading `one/run/run.ino` separately.

## Safety and wiring

Disconnect real pump and fan loads during the security demonstration. The relay
modules may remain connected for LED/status observation.

Sensor ESP32 wiring:

- RC522 SDA/SS: GPIO 5
- RC522 RST: GPIO 33
- RC522 SCK: GPIO 18
- RC522 MISO: GPIO 19
- RC522 MOSI: GPIO 23
- Reed/tamper switch: GPIO 13 to GND when enclosure is secure
- Pump relay: GPIO 25 (active-low)
- Fan relay: GPIO 26 (active-low)
- Green/Blue/Yellow/Red LEDs: GPIO 14/2/32/4
- DHT22: GPIO 27
- Soil sensor: GPIO 36
- BH1750 SDA/SCL: GPIO 21/22

An unconnected reed-switch input does not block environmental/radio operation.
Tamper enforcement arms only after GPIO 13 has first been observed securely
LOW. Once armed, opening the switch to HIGH causes fail-secure lockdown.

## Firmware

Upload the integrated gateway first:

`three/esp32/C2_Step38G2_Live_Secure_Telemetry_React_Gateway_Fixed/C2_Step38G2_Live_Secure_Telemetry_React_Gateway_Fixed.ino`

Upload the integrated sensor second:

`three/C2_Step38G2_Live_Secure_Telemetry_React_Sensor/C2_Step38G2_Live_Secure_Telemetry_React_Sensor.ino`

The sensor requires MFRC522, BH1750, DHT sensor library, and Adafruit Unified
Sensor. Open both Serial Monitors at 115200 baud.

Start the host system:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_full_system.ps1
```

Open `http://localhost:5173/component1`.

## Dashboard buttons

The Component 1 page contains three controlled hardware-flow buttons:

- **Wrong RFID card**: produces a controlled UID rejection.
- **RFID clone attempt**: produces controlled same-UID protected-sector
  authentication failure evidence and keeps the node locked.
- **Insider misuse**: requires a genuine RFID unlock first, then produces 3/3
  controlled anomaly confirmations, relay fail-safe lockdown, a final signed
  event, and session-key zeroization.

The flow is Firebase → gateway polling → NwkSKey-signed E32 command → sensor
state machine → NwkSKey-signed evidence → gateway verification → Firebase →
live dashboard. Button events are controlled demonstrations and are labelled as
such. Physical RFID scans remain real hardware evidence.

## Demonstration 1: genuine RFID unlock and lock

1. Present the provisioned credential (`83:3D:53:56`) with the project Custom
   Key A and protected marker in block 16.
2. Confirm `AUTHORIZED`, sector authentication `PASSED`, clone risk `LOW`, and
   state `NORMAL` on the dashboard.
3. Remove the card, wait one second, and present it again.
4. Confirm the authorized card manually returns the system to `LOCKED`.

## Demonstration 2: unauthorized UID

Present an ordinary different card. Confirm `UID_REJECTED`; the system must not
unlock.

## Demonstration 3: controlled same-UID clone rejection

Use only a lab-owned same-UID test credential that lacks the correct sector key
or protected marker. Present it and confirm `SECTOR_AUTH_FAILED` or
`MARKER_MISMATCH`, with clone risk `ELEVATED_SAME_UID_CLONE_SUSPECTED`.

This demonstrates rejection of a UID-only copy. Timing remains supporting
evidence and is not claimed as independent proof that a card is cloned.

## Demonstration 4: authenticated insider misuse

1. Unlock with the genuine card and confirm an authenticated session is active.
2. In the sensor Serial Monitor, set line ending to `Newline`, enter `I`, and
   send it.
3. Confirm `CONTROLLED_AUTHENTICATED_INSIDER_MISUSE`, anomaly probability 0.99,
   3/3 confirmations, relays OFF, and `LOCKDOWN`.

This is explicitly a controlled execution trigger. It demonstrates attribution
and fail-safe handling without claiming that dummy data is a real ML detection.

## Demonstration 5: physical tamper and zeroization boundary

Restart both boards, keep GPIO 13 LOW, and establish the radio session. Open the
reed switch. Confirm `TAMPERED`, relays OFF, red LED, and `LOCKDOWN` on the
dashboard. Recovery requires a physical restart with the enclosure secure.

The Component 1 status frame is accepted by the gateway only after HMAC
verification with the active radio-session NwkSKey. Firebase therefore records
the event as signed device evidence.
