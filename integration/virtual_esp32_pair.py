"""Real-time virtual Sensor ESP32 + Gateway ESP32 integration test.

Uses the production protocol primitives and Firebase schema.  Every record is
explicitly marked VIRTUAL_TWO_ESP32 so it cannot be presented as hardware
evidence.  Stop this process before powering the physical pair.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import queue
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
NODE_ID = "GH_NODE_01"
PSK = bytes.fromhex(
    "52A817C39D64EE2041B76C0FD28935FA"
    "731E944BA568CD12E7305AB986F12D4C"
)
INTERVAL_SECONDS = 2.5


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 16) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output, previous, counter = b"", b"", 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def proof(key: bytes, transcript: str) -> str:
    return hmac.new(key, transcript.encode(), hashlib.sha256).digest().hex().upper()


def derive_keys(session_id: int, sensor_nonce: bytes, gateway_nonce: bytes) -> tuple[bytes, bytes]:
    salt = sensor_nonce + gateway_nonce
    app = hkdf(PSK, salt, f"C2/{NODE_ID}/APPSKEY/V1/{session_id}".encode())
    nwk = hkdf(PSK, salt, f"C2/{NODE_ID}/NWKSKEY/V1/{session_id}".encode())
    return app, nwk


def packet_iv(session_id: int, sequence: int, sensor_nonce: bytes) -> bytes:
    return session_id.to_bytes(4, "big") + sequence.to_bytes(4, "big") + sensor_nonce[:4]


@dataclass
class Radio:
    sensor_to_gateway: queue.Queue[str]
    gateway_to_sensor: queue.Queue[str]


class VirtualSensor(threading.Thread):
    def __init__(self, radio: Radio, stop: threading.Event):
        super().__init__(name="virtual-sensor", daemon=True)
        self.radio, self.stop = radio, stop
        self.session_id = secrets.randbits(32) or 1
        self.sensor_nonce = secrets.token_bytes(16)

    def run(self) -> None:
        nonce_hex = self.sensor_nonce.hex().upper()
        self.radio.sensor_to_gateway.put(f"C2_HELLO_V1,{NODE_ID},{self.session_id},{nonce_hex}")
        print(f"[sensor] HELLO session={self.session_id}", flush=True)
        try:
            challenge = self.radio.gateway_to_sensor.get(timeout=5).split(",")
        except queue.Empty:
            raise RuntimeError("Virtual sensor timed out waiting for challenge")
        if len(challenge) != 4 or challenge[0] != "C2_CHALLENGE_V1":
            raise RuntimeError("Malformed virtual gateway challenge")
        gateway_nonce = bytes.fromhex(challenge[2])
        base = f"{NODE_ID}|{self.session_id}|{nonce_hex}|{challenge[2]}"
        if not hmac.compare_digest(challenge[3], proof(PSK, "GW|" + base)):
            raise RuntimeError("Virtual gateway HMAC failed")
        app_key, nwk_key = derive_keys(self.session_id, self.sensor_nonce, gateway_nonce)
        self.radio.sensor_to_gateway.put(
            f"C2_RESPONSE_V1,{self.session_id},{proof(nwk_key, 'SN|' + base)}"
        )
        confirm = self.radio.gateway_to_sensor.get(timeout=5).split(",")
        if len(confirm) != 3 or not hmac.compare_digest(confirm[2], proof(nwk_key, "OK|" + base)):
            raise RuntimeError("Virtual confirmation failed")
        print("[sensor] authenticated session established", flush=True)
        started = time.monotonic()
        sequence = 0
        while not self.stop.wait(INTERVAL_SECONDS):
            sequence += 1
            elapsed_ms = int((time.monotonic() - started) * 1000)
            temperature = 29.5 + ((sequence % 7) - 3) * 0.18
            humidity = 68.0 + ((sequence % 5) - 2) * 0.45
            light = 250.0 + (sequence % 9) * 6.5
            soil_raw = 2500 + ((sequence % 11) - 5) * 18
            soil_percent = max(0, min(100, round((4095 - soil_raw) * 100 / (4095 - 1169))))
            plaintext = (
                f"TS={elapsed_ms:010d};T={round(temperature * 100):+06d};"
                f"H={round(humidity * 100):05d};L={round(light * 10):06d};"
                f"S={soil_raw:04d};SP={soil_percent:03d};V=0;ST=NORMAL"
            ).encode()
            iv = packet_iv(self.session_id, sequence, self.sensor_nonce)
            aad = f"C2_SECURE_V1|{NODE_ID}|{self.session_id}|{sequence}".encode()
            encrypted = AESGCM(app_key).encrypt(iv, plaintext, aad)
            ciphertext, tag = encrypted[:-16], encrypted[-16:]
            transcript = (
                f"C2_SECURE_V1|{NODE_ID}|{self.session_id}|{sequence}|"
                f"{iv.hex().upper()}|{ciphertext.hex().upper()}|{tag.hex().upper()}"
            )
            frame = transcript.replace("|", ",") + "," + proof(nwk_key, transcript)
            self.radio.sensor_to_gateway.put(frame)
            print(f"[sensor] encrypted sample sequence={sequence}", flush=True)


class VirtualGateway(threading.Thread):
    def __init__(self, radio: Radio, stop: threading.Event, base_ref, c1_command_ref,
                 c2_command_ref, dry_run: bool):
        super().__init__(name="virtual-gateway", daemon=True)
        self.radio, self.stop = radio, stop
        self.base_ref, self.command_ref = base_ref, c1_command_ref
        self.c2_command_ref, self.dry_run = c2_command_ref, dry_run
        self.component_state = "LOCKED"
        self.last_request_id = ""
        self.component_event = 0
        self.last_c2_request_id = ""
        self.c2_event = 0
        self.security_counters = {
            "replayRejected": 0, "invalidOuterHmac": 0,
            "invalidGcmTag": 0, "staleTimestamp": 0,
            "keyRotations": 0, "sessionRevocations": 0,
        }

    def update(self, values: dict) -> None:
        if not self.dry_run:
            self.base_ref.update(values)

    def run(self) -> None:
        hello = self.radio.sensor_to_gateway.get(timeout=5).split(",")
        session_id, sensor_nonce = int(hello[2]), bytes.fromhex(hello[3])
        gateway_nonce = secrets.token_bytes(16)
        base = f"{NODE_ID}|{session_id}|{hello[3]}|{gateway_nonce.hex().upper()}"
        self.radio.gateway_to_sensor.put(
            f"C2_CHALLENGE_V1,{session_id},{gateway_nonce.hex().upper()},{proof(PSK, 'GW|' + base)}"
        )
        response = self.radio.sensor_to_gateway.get(timeout=5).split(",")
        app_key, nwk_key = derive_keys(session_id, sensor_nonce, gateway_nonce)
        if not hmac.compare_digest(response[2], proof(nwk_key, "SN|" + base)):
            raise RuntimeError("Virtual sensor HMAC failed")
        self.radio.gateway_to_sensor.put(
            f"C2_CONFIRM_V1,{session_id},{proof(nwk_key, 'OK|' + base)}"
        )
        print("[gateway] authenticated session established", flush=True)
        started, last_sequence = time.monotonic(), 0
        while not self.stop.is_set():
            self.poll_command(session_id)
            self.poll_component2_command(session_id)
            try:
                frame = self.radio.sensor_to_gateway.get(timeout=0.25).split(",")
            except queue.Empty:
                continue
            if len(frame) != 8 or frame[0] != "C2_SECURE_V1":
                continue
            sequence = int(frame[3])
            transcript = "|".join(frame[:7])
            if not hmac.compare_digest(frame[7], proof(nwk_key, transcript)) or sequence <= last_sequence:
                continue
            iv, ciphertext, tag = bytes.fromhex(frame[4]), bytes.fromhex(frame[5]), bytes.fromhex(frame[6])
            aad = f"C2_SECURE_V1|{NODE_ID}|{session_id}|{sequence}".encode()
            plaintext = AESGCM(app_key).decrypt(iv, ciphertext + tag, aad).decode()
            fields = dict(item.split("=", 1) for item in plaintext.split(";"))
            last_sequence = sequence
            epoch = int(time.time())
            record_id = f"virtual_session_{session_id:010d}_seq_{sequence:06d}"
            current = {
                "nodeId": NODE_ID, "timestamp": epoch, "connection": "online",
                "systemState": fields["ST"], "sessionId": session_id, "sequence": sequence,
                "evidenceType": "VIRTUAL_TWO_ESP32",
                "sensors": {
                    "temperature": int(fields["T"]) / 100, "humidity": int(fields["H"]) / 100,
                    "light": int(fields["L"]) / 10, "soilRaw": int(fields["S"]),
                    "soilPercent": int(fields["SP"]), "sampleValid": False,
                },
                "security": {
                    "radioAuthenticated": True, "outerHmac": "PASSED", "replayWindow": "FRESH",
                    "timestampWindow": "PASSED", "ivValidation": "PASSED", "aesGcm": "PASSED",
                    "gcmTag": "PASSED", "firebaseAuthentication": "ADMIN_SIMULATOR",
                    "uidAuthorization": "SIMULATION", "tlsCertificateValidation": "ENABLED",
                },
            }
            self.update({
                "current": current,
                f"telemetry/raw_stream/{record_id}": {**current["sensors"], "timestamp": epoch,
                    "sessionId": session_id, "sequence": sequence, "systemState": fields["ST"],
                    "evidenceType": "VIRTUAL_TWO_ESP32", "firebaseForwarding": "PASSED"},
                "security/session": {"state": "ACTIVE_VIRTUAL", "sessionId": session_id,
                    "startedAt": epoch - int(time.monotonic() - started), "lastAcceptedSequence": sequence,
                    "packetsSinceRotation": sequence, "revoked": False, "evidenceType": "VIRTUAL_TWO_ESP32"},
                "security/key_lifecycle": {"appSKeyState": "ACTIVE_VIRTUAL",
                    "nwkSKeyState": "ACTIVE_VIRTUAL", "actualKeysExposed": False},
                "security/counters/acceptedPackets": sequence,
                "security/counters/firebaseWriteSuccess": sequence,
                "system/status": {"sensorNodeOnline": True, "gatewayOnline": True,
                    "firebaseConnected": True, "lastSensorPacketAt": epoch,
                    "lastGatewayHeartbeatAt": epoch, "dashboardBridgeState": "VIRTUAL_TWO_ESP32",
                    "testEvidence": "SIMULATION_NOT_HARDWARE"},
            })
            print(f"[gateway] verified and forwarded sequence={sequence}", flush=True)

    def poll_component2_command(self, session_id: int) -> None:
        if self.dry_run:
            return
        pending = self.c2_command_ref.get() or {}
        request_id = str(pending.get("requestId", ""))
        command = str(pending.get("command", ""))
        if not request_id or request_id == self.last_c2_request_id:
            return
        self.last_c2_request_id = request_id
        self.c2_event += 1
        epoch = int(time.time())
        outcomes = {
            "TEST_REPLAY": ("REJECTED_AS_EXPECTED", "REPLAY_WINDOW", "replayRejected", "NONE"),
            "TEST_INVALID_HMAC": ("REJECTED_AS_EXPECTED", "OUTER_HMAC", "invalidOuterHmac", "NONE"),
            "TEST_INVALID_GCM": ("REJECTED_AS_EXPECTED", "AES_GCM", "invalidGcmTag", "NONE"),
            "TEST_STALE_TIMESTAMP": ("REJECTED_AS_EXPECTED", "TIMESTAMP_WINDOW", "staleTimestamp", "NONE"),
            "TEST_HMAC_SPIKE": ("REVOKED", "OUTER_HMAC_THRESHOLD", "invalidOuterHmac", "VIRTUAL_ZEROIZATION"),
            "ROTATE_SESSION": ("ROTATED", "KEY_LIFECYCLE", "keyRotations", "VIRTUAL_ZEROIZE_AND_REKEY"),
            "REVOKE_SESSION": ("REVOKED", "SESSION_POLICY", "sessionRevocations", "VIRTUAL_ZEROIZATION"),
        }
        result, failed_stage, counter, key_action = outcomes.get(
            command, ("UNKNOWN_COMMAND", "COMMAND_VALIDATION", None, "NONE")
        )
        if counter:
            self.security_counters[counter] += 5 if command == "TEST_HMAC_SPIKE" else 1
        revoked = command in ("REVOKE_SESSION", "TEST_HMAC_SPIKE")
        rotated = command == "ROTATE_SESSION"
        event_key = f"virtual_component2_{epoch}_{self.c2_event}"
        values = {
            "demo/component2/status": {
                "requestId": request_id, "command": command, "state": "VERIFIED_VIRTUAL_SENSOR",
                "sensorState": "ACTION_APPLIED", "result": result,
                "failedStage": failed_stage, "keyAction": key_action,
                "evidenceType": "VIRTUAL_TWO_ESP32", "timestamp": epoch,
            },
            f"security/events/{event_key}": {
                "timestamp": epoch, "type": command, "nodeId": NODE_ID,
                "sessionId": session_id, "sequence": self.c2_event,
                "validationResult": result, "failedStage": failed_stage,
                "decision": result, "firebaseForwarding": "BLOCKED_TEST_PACKET"
                    if command.startswith("TEST_") else "NOT_APPLICABLE",
                "keyAction": key_action, "evidence": "VIRTUAL_TWO_ESP32",
            },
            f"security/counters/{counter}": self.security_counters[counter] if counter else 0,
        }
        if rotated:
            values.update({
                "security/key_lifecycle/appSKeyState": "ROTATED_ACTIVE_VIRTUAL",
                "security/key_lifecycle/nwkSKeyState": "ROTATED_ACTIVE_VIRTUAL",
                "security/key_lifecycle/rotationCounter": self.security_counters["keyRotations"],
                "security/key_lifecycle/lastRotationAt": epoch,
                "security/key_lifecycle/lastRotationReason": "DASHBOARD_CONTROLLED_TEST",
            })
        if revoked:
            values.update({
                "security/session/state": "REVOKED",
                "security/session/revoked": True,
                "security/session/revokedAt": epoch,
                "security/key_lifecycle/appSKeyState": "ZEROIZED_VIRTUAL",
                "security/key_lifecycle/nwkSKeyState": "ZEROIZED_VIRTUAL",
                "system/status/dashboardBridgeState": "VIRTUAL_SESSION_REVOKED",
            })
        self.update(values)
        print(f"[gateway] Component 2 virtual trigger {command} -> {result}", flush=True)

    def poll_command(self, session_id: int) -> None:
        if self.dry_run:
            return
        pending = self.command_ref.get() or {}
        request_id, command = str(pending.get("requestId", "")), str(pending.get("command", ""))
        if not request_id or request_id == self.last_request_id:
            return
        self.last_request_id = request_id
        authenticated_before = self.component_state == "NORMAL"
        scenarios = {
            "DEMO_AUTHORIZED_UNLOCK": {
                "state": "NORMAL", "result": "CONTROLLED_AUTHORIZED_UNLOCK",
                "authorized": True, "sector": "PASSED", "clone": "LOW_SUPPORTING_EVIDENCE",
                "classification": "NORMAL", "probability": 0.01, "confirmations": 0,
                "correlation": "NONE",
            },
            "DEMO_WRONG_CARD": {
                "state": self.component_state, "result": "CONTROLLED_UID_REJECTED",
                "authorized": False, "sector": "REJECTED", "clone": "UNAUTHORIZED_UID",
                "classification": "CONTROLLED_REJECTION", "probability": 0.20,
                "confirmations": 0, "correlation": "NONE",
            },
            "DEMO_RFID_CLONE": {
                "state": "LOCKED", "result": "CONTROLLED_SAME_UID_SECTOR_AUTH_FAILED",
                "authorized": False, "sector": "REJECTED",
                "clone": "ELEVATED_SAME_UID_CLONE_SUSPECTED",
                "classification": "CONTROLLED_ANOMALY", "probability": 0.95,
                "confirmations": 1, "correlation": "NONE",
            },
            "DEMO_INSIDER_MISUSE": {
                "state": "LOCKDOWN" if authenticated_before else self.component_state,
                "result": "AUTHORIZED_INSIDER_MISUSE" if authenticated_before
                    else "INSIDER_DEMO_REJECTED_AUTH_REQUIRED",
                "authorized": authenticated_before, "sector": "PASSED" if authenticated_before else "REJECTED",
                "clone": "LOW_SUPPORTING_EVIDENCE" if authenticated_before else "NOT_APPLICABLE",
                "classification": "CONTROLLED_ANOMALY" if authenticated_before else "CONTROLLED_REJECTION",
                "probability": 0.99 if authenticated_before else 0.25,
                "confirmations": 3 if authenticated_before else 0,
                "correlation": "CONTROLLED_AUTHENTICATED_INSIDER_MISUSE"
                    if authenticated_before else "NO_AUTHENTICATED_SESSION",
            },
        }
        scenario = scenarios.get(command)
        if scenario is None:
            scenario = {"state": self.component_state, "result": "UNKNOWN_COMMAND",
                "authorized": False, "sector": "REJECTED", "clone": "UNKNOWN",
                "classification": "CONTROLLED_REJECTION", "probability": 0.0,
                "confirmations": 0, "correlation": "NONE"}
        self.component_state = scenario["state"]
        result = scenario["result"]
        authenticated_after = self.component_state == "NORMAL"
        self.component_event += 1
        epoch = int(time.time())
        event_key = f"virtual_component1_{epoch}_{self.component_event}"
        self.update({
            "demo/component1/status": {"requestId": request_id, "command": command,
                "state": "VERIFIED_VIRTUAL_SENSOR", "result": result,
                "evidenceType": "VIRTUAL_TWO_ESP32", "timestamp": epoch},
            "component1/systemState": self.component_state,
            "component1/rfid": {"result": result, "authorized": scenario["authorized"],
                "uidMasked": "XX:XX:53:56" if scenario["authorized"] else "XX:XX:FA:KE",
                "sectorAuthentication": scenario["sector"], "cloneRisk": scenario["clone"],
                "authLatencyUs": 850 + self.component_event * 37,
                "sessionId": self.component_event, "timingRole": "SIMULATED_SUPPORTING_EVIDENCE"},
            "component1/tinyml": {"classification": scenario["classification"],
                "anomalyProbability": scenario["probability"],
                "confirmationCount": scenario["confirmations"], "requiredConfirmations": 3,
                "inferenceLatencyUs": 420, "evidenceMode": "VIRTUAL_TWO_ESP32"},
            "component1/tamper": {"state": "SECURE", "latched": False,
                "lastChangedAt": epoch},
            "component1/actuators": {"pump": "OFF", "fan": "OFF",
                "relayFailSafe": "ACTIVE"},
            "component1/insider_attribution": {
                "authenticatedSessionActive": authenticated_after,
                "correlation": scenario["correlation"], "humanIdentityClaim": "NOT_MADE"},
            "component1/transport": {"hmac": "PASSED", "radioSessionId": session_id,
                "evidenceType": "VIRTUAL_TWO_ESP32"},
            "component1/updatedAt": epoch,
            f"security/events/{event_key}": {"timestamp": epoch,
                "type": command.replace("DEMO_", ""), "nodeId": NODE_ID,
                "sessionId": session_id, "sequence": self.component_event,
                "validationResult": result, "decision": self.component_state,
                "firebaseForwarding": "ALLOWED_VIRTUAL_EVIDENCE",
                "keyAction": "VIRTUAL_ZEROIZATION" if self.component_state == "LOCKDOWN" else "NONE",
                "evidence": "VIRTUAL_TWO_ESP32"},
        })
        print(f"[gateway] virtual command {command} -> {result}", flush=True)


def firebase_references(dry_run: bool):
    if dry_run:
        return None, None, None
    import firebase_admin
    from firebase_admin import credentials, db
    load_dotenv(ROOT / "three" / ".env")
    credential_path = Path(os.environ["FIREBASE_CREDENTIALS_PATH"])
    if not credential_path.is_absolute():
        credential_path = (ROOT / "three" / credential_path).resolve()
    firebase_admin.initialize_app(credentials.Certificate(str(credential_path)), {
        "databaseURL": os.environ["FIREBASE_DATABASE_URL"]
    })
    node_id = os.getenv("FIREBASE_NODE_ID", NODE_ID)
    return (db.reference(f"/greenhouse/{node_id}"),
            db.reference("/demo/component1/pending"),
            db.reference("/demo/component2/pending"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Run protocol without Firebase writes")
    parser.add_argument("--seconds", type=int, default=0, help="Stop automatically; 0 runs until Ctrl+C")
    args = parser.parse_args()
    stop = threading.Event()
    radio = Radio(queue.Queue(), queue.Queue())
    base_ref, command_ref, c2_command_ref = firebase_references(args.dry_run)
    gateway = VirtualGateway(radio, stop, base_ref, command_ref, c2_command_ref, args.dry_run)
    sensor = VirtualSensor(radio, stop)
    gateway.start()
    sensor.start()
    print("Virtual pair running. Stop it before connecting real ESP32 devices.", flush=True)
    try:
        deadline = time.monotonic() + args.seconds if args.seconds else None
        while sensor.is_alive() and gateway.is_alive() and not stop.wait(0.5):
            if deadline and time.monotonic() >= deadline:
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sensor.join(timeout=3)
        gateway.join(timeout=3)
        if base_ref is not None:
            base_ref.update({
                "system/status/sensorNodeOnline": False,
                "system/status/gatewayOnline": False,
                "system/status/dashboardBridgeState": "VIRTUAL_STOPPED",
            })
        print("Virtual pair stopped.", flush=True)


if __name__ == "__main__":
    main()
