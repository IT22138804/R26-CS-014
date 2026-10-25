STEP 40K-1 — FIRST LIVE HARDWARE VALIDATION

ESP32 No. 1 = SENSOR / EDGE BOARD
- sensors + Component 1 hardware + E32 Module A

ESP32 No. 2 = GATEWAY BOARD
- E32 Module B + Wi-Fi + Firebase

Run the same working Component 2 secure telemetry firmware on both boards.
Then run:

powershell -ExecutionPolicy Bypass -File .\run_step_40k1.ps1

The watcher waits up to 180 seconds for a fresh valid packet.
No relay command is sent in this step.
