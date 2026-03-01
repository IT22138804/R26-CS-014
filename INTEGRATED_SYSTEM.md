# Integrated greenhouse system

## Hardware firmware

Two ESP32 boards can run only one sketch each. For live environmental data, use
the Step 38G-2 pair:

- Sensor/edge board:
  `three/C2_Step38G2_Live_Secure_Telemetry_React_Sensor/C2_Step38G2_Live_Secure_Telemetry_React_Sensor.ino`
- Gateway board:
  `three/esp32/C2_Step38G2_Live_Secure_Telemetry_React_Gateway_Fixed/C2_Step38G2_Live_Secure_Telemetry_React_Gateway_Fixed.ino`

The sensor board reads the real DHT22, BH1750, and soil sensor. The E32 link
sends authenticated/encrypted telemetry to the gateway. The gateway writes the
shared Firebase node consumed by Components 3 and 4 and the dashboard.

The standalone Component 1 `one/run/run.ino` firmware cannot execute at the
same time on that sensor ESP32. Its RFID, relay, and tamper implementation has
not yet been merged into the Step 38G-2 sensor firmware. Do not claim those
Component 1 hardware functions are active until that firmware merge is built
and physically tested.

## First-time configuration

Configure these three files to use the same Firebase project:

- `three/.env` (Firebase Admin service account and database URL)
- `four/.env` (Firebase Admin service account and database URL)
- `three/greenhouse-security-dashboard/.env` (Firebase web configuration)

Keep Firebase service-account JSON files outside this repository. Configure the
gateway sketch's Wi-Fi/Firebase values before uploading it.

## One-command start

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_full_system.ps1
```

Then reset the gateway, wait about five seconds, and reset the sensor. Open
`http://localhost:5173`. Logs are written to `integration/logs`.

The launcher starts the unified dashboard, Component 3 live telemetry defense,
and Component 4 live safety validation. Press Ctrl+C in the launcher terminal
to stop the host-side processes.
