# FINAL HARDWARE INTEGRATION — DO LATER

Do not run this stage until both ESP32 boards and sensors are physically connected.

Final hardware sequence:

1. Start Component 1 sensor/edge ESP32.
2. Start Component 2 gateway ESP32 + E32 + Wi-Fi/Firebase.
3. Confirm fresh `/greenhouse/GH_NODE_01/current` packets.
4. Rerun Step 40G-3 and require:
   - Fresh telemetry = YES
   - Valid physical sample = YES
   - Trusted for live decision = YES
5. Build the final dispatch adapter from `pending_dispatch` to Component 2.
6. First validate dispatch with relay output electrically disconnected.
7. Then validate one real relay at a time:
   - pump OFF safe state
   - fan ON safe state
8. Test safety override:
   - saturated soil blocks PUMP ON
   - high temperature blocks FAN OFF
9. Test BOLA while hardware online.
10. Test duplicate/replay request while hardware online.
11. Complete MFA validation.
12. Only after all of the above, mark Component 4 FINAL PASSED.

Current status before device connection:
- software development: complete
- hardware integration: deferred
- MFA: deferred
- production security claim: NOT YET
