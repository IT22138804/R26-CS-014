# Component 3 — Step 39F-2

## Fresh physical Component 2 telemetry validation

Step 39F-1 correctly blocked an old snapshot. Step 39F-2 waits for five new packets from the real physical sensor and gateway boards.

### ESP32 No. 1 — SENSOR/EDGE board
Connected to DHT22, BH1750, soil sensor, RFID/tamper, relays/LEDs and E32 Module A. Use the matching Step 38G-2 live secure telemetry sensor firmware previously validated.

### ESP32 No. 2 — GATEWAY board
Connected to E32 Module B, Wi-Fi and Firebase. Use `C2_Step38G2_Live_Secure_Telemetry_React_Gateway_Fixed.ino`.

Do not use the insider-misuse, revocation or lockdown demo firmware for this step.

Run order:
1. Keep both boards powered off.
2. Start `run_step_39f2.ps1`.
3. Power ESP32 No. 1 and ESP32 No. 2.
4. Wait for five fresh packets.

A packet counts only when it is new, no older than 30 seconds, cryptographically valid, from an operational source state, mapped successfully and inspected by Component 3. No real actuator command is sent.
