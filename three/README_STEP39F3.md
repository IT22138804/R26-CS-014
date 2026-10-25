# Component 3 — Step 39F-3

Controlled backdoor-trigger validation over the real secure radio path.

## Hardware

- ESP32 No. 1 = SENSOR/EDGE board, all sensors + E32 Module A.
- ESP32 No. 2 = GATEWAY board, E32 Module B + Wi-Fi/Firebase.

Keep the existing Step 38G-2 Gateway firmware on ESP32 No. 2.

Upload:

```text
firmware/C2_Step39F3_Controlled_Backdoor_Trigger_Sensor.ino
```

to ESP32 No. 1.

## Six encrypted payload cases

1. Normal daylight control.
2. Exact 31.5 C + 0.05 lux backdoor trigger.
3. Jittered 31.62 C + 2.4 lux trigger.
4. Slow-correlation poison pattern.
5. Clean dark-night control.
6. Legitimate hot-daylight control.

The values are intentionally controlled cybersecurity test inputs. They are
encrypted and authenticated over the real ESP32/E32/Gateway/Firebase path,
but they are NOT claimed as physical environmental measurements.

Physical DHT22 and soil readings are still required at sensor startup to
prove the hardware board is operational.

No real actuator command is sent by Component 3.

## Run order

1. Upload the Step 39F-3 Sensor firmware to ESP32 No. 1.
2. Keep the normal Step 38G-2 Gateway firmware on ESP32 No. 2.
3. Keep both boards powered off/reset.
4. Start the Python validator:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_step_39f3.ps1
```

5. Wait for the "Waiting for a new six-packet..." line.
6. Reset Gateway first.
7. Wait about five seconds.
8. Reset Sensor.

Expected result:

```text
Packets processed                 : 6/6
Cases passed                      : 6/6
Malicious trigger cases           : 3/3
Malicious cases quarantined       : 3/3
Clean control cases               : 3/3
Clean controls allowed            : 3/3
Firebase readback                 : PASSED
STEP 39F-3 RESULT                 : PASSED
```
