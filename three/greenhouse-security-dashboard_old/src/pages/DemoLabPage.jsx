import { useMemo, useState } from "react";
import { push, ref, set } from "firebase/database";
import { Beaker, Play, ShieldCheck } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SectionCard from "../components/SectionCard";
import StatusBadge from "../components/StatusBadge";
import KeyValueGrid from "../components/KeyValueGrid";
import { database } from "../lib/firebase";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { formatTimestamp, safeObject } from "../utils/data";

const scenarios = {
  NORMAL_TELEMETRY: {
    input: { sequence: 10, timestampDeltaMs: 500, ciphertextChanged: false },
    pipeline: {
      outerHmac: "PASSED",
      replayWindow: "FRESH",
      timestampWindow: "PASSED",
      aesGcm: "PASSED",
      gcmTag: "PASSED"
    },
    output: {
      decision: "ACCEPTED",
      firebaseForwarding: "ALLOWED",
      keyAction: "NONE",
      systemAction: "NONE"
    }
  },
  REPLAY_ATTACK: {
    input: { originalSequence: 10, injectedSequence: 3, timestampDeltaMs: 12000 },
    pipeline: {
      outerHmac: "PASSED",
      replayWindow: "REJECTED",
      timestampWindow: "NOT_ATTEMPTED",
      aesGcm: "NOT_ATTEMPTED",
      gcmTag: "NOT_ATTEMPTED"
    },
    output: {
      decision: "REJECTED",
      firebaseForwarding: "BLOCKED",
      keyAction: "NONE",
      systemAction: "INCREMENT_REPLAY_COUNTER"
    }
  },
  INVALID_OUTER_HMAC: {
    input: { sequence: 11, ciphertextChanged: true, outerHmacRecomputed: false },
    pipeline: {
      outerHmac: "FAILED",
      replayWindow: "NOT_ATTEMPTED",
      timestampWindow: "NOT_ATTEMPTED",
      aesGcm: "NOT_ATTEMPTED",
      gcmTag: "NOT_ATTEMPTED"
    },
    output: {
      decision: "REJECTED",
      firebaseForwarding: "BLOCKED",
      keyAction: "NONE",
      systemAction: "INCREMENT_HMAC_COUNTER"
    }
  },
  INVALID_GCM_TAG: {
    input: { sequence: 12, ciphertextChanged: true, outerHmacRecomputed: true },
    pipeline: {
      outerHmac: "PASSED",
      replayWindow: "FRESH",
      timestampWindow: "PASSED",
      aesGcm: "FAILED",
      gcmTag: "FAILED"
    },
    output: {
      decision: "REJECTED",
      firebaseForwarding: "BLOCKED",
      keyAction: "NONE",
      systemAction: "INCREMENT_GCM_COUNTER"
    }
  },
  STALE_TIMESTAMP: {
    input: { sequence: 13, timestampDeltaMs: 65000 },
    pipeline: {
      outerHmac: "PASSED",
      replayWindow: "FRESH",
      timestampWindow: "REJECTED",
      aesGcm: "PASSED",
      gcmTag: "PASSED"
    },
    output: {
      decision: "REJECTED",
      firebaseForwarding: "BLOCKED",
      keyAction: "NONE",
      systemAction: "INCREMENT_TIMESTAMP_COUNTER"
    }
  },
  KEY_ROTATION: {
    input: { packetsSinceRotation: 1000, sessionAgeHours: 12 },
    pipeline: {
      rotationTrigger: "PACKET_LIMIT",
      seedGeneration: "TRNG",
      seedProtection: "AES_GCM_PASSED",
      newKeyProof: "PASSED"
    },
    output: {
      decision: "ROTATED",
      firebaseForwarding: "ALLOWED",
      keyAction: "OLD_KEYS_ZEROIZED",
      systemAction: "NEW_SESSION_ACTIVE"
    }
  },
  SESSION_REVOCATION: {
    input: { reason: "EMERGENCY_SECURITY_EVENT", revocationCounter: 1 },
    pipeline: {
      revokeHmac: "PASSED",
      counterCheck: "PASSED",
      sensorAck: "PASSED"
    },
    output: {
      decision: "REVOKED",
      firebaseForwarding: "BLOCKED",
      keyAction: "APPSKEY_NWKSKEY_ZEROIZED",
      systemAction: "REVOKED_SESSION_TRAFFIC_REJECTED"
    }
  },
  NETWORK_WIDE_ATTACK: {
    input: { totalNodes: 4, affectedNodes: 4, commonPattern: true },
    pipeline: {
      nodeAggregation: "SIMULATED",
      affectedRatio: "100%",
      coordinatedPattern: "DETECTED"
    },
    output: {
      decision: "CRITICAL",
      firebaseForwarding: "DEMONSTRATION_ONLY",
      keyAction: "SIMULATED_REVOCATION",
      systemAction: "SIMULATION"
    },
    simulation: true
  },
  PHYSICAL_TAMPER: {
    input: { reedSwitch: "OPEN", authenticatedSessionActive: true },
    pipeline: {
      tamperInterrupt: "TRIGGERED",
      confirmationRequired: "NO",
      relayFailSafe: "ACTIVE"
    },
    output: {
      decision: "IMMEDIATE_LOCKDOWN",
      firebaseForwarding: "BLOCKED",
      keyAction: "RUNTIME_KEYS_ZEROIZED",
      systemAction: "PUMP_FAN_OFF"
    }
  }
};

export default function DemoLabPage() {
  const [selected, setSelected] = useState("NORMAL_TELEMETRY");
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState("");
  const latest = useFirebaseValue("/demo/latest_result", {});
  const selectedDefinition = useMemo(() => scenarios[selected], [selected]);

  async function runScenario() {
    setRunning(true);
    setMessage("");

    try {
      const payload = {
        scenario: selected,
        ...selectedDefinition,
        simulation: selectedDefinition.simulation ?? true,
        executedAt: Math.floor(Date.now() / 1000),
        executedBy: "REACT_DASHBOARD"
      };

      await set(ref(database, "/demo/latest_result"), payload);
      await push(ref(database, "/demo/history"), payload);
      setMessage("Demonstration saved successfully. No real actuator command was sent.");
    } catch (error) {
      setMessage(error?.message || "Demonstration write failed.");
    } finally {
      setRunning(false);
    }
  }

  const result = safeObject(latest.value);

  return (
    <>
      <PageHeader
        eyebrow="Safe isolated simulation"
        title="Attack demonstration laboratory"
        description="Select an input scenario and display the expected validation stages and output. This page never commands the real pump or fan."
        action={<StatusBadge value="SIMULATION" />}
      />

      <div className="two-column">
        <SectionCard title="Scenario input">
          <label className="field">
            Select demonstration
            <select value={selected} onChange={(event) => setSelected(event.target.value)}>
              {Object.keys(scenarios).map((name) => (
                <option value={name} key={name}>
                  {name.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </label>

          <pre className="json-view">{JSON.stringify(selectedDefinition.input, null, 2)}</pre>

          <button className="button primary" type="button" onClick={runScenario} disabled={running}>
            <Play size={18} />
            {running ? "Running…" : "Run safe demonstration"}
          </button>

          {message ? <div className="form-message">{message}</div> : null}
        </SectionCard>

        <SectionCard title="Expected output">
          <KeyValueGrid
            items={[
              { label: "Decision", value: selectedDefinition.output.decision, badge: true },
              { label: "Firebase forwarding", value: selectedDefinition.output.firebaseForwarding, badge: true },
              { label: "Key action", value: selectedDefinition.output.keyAction, badge: true },
              { label: "System action", value: selectedDefinition.output.systemAction, badge: true },
              { label: "Evidence type", value: selectedDefinition.simulation ? "SIMULATION" : "DEMONSTRATION", badge: true }
            ]}
          />
          <pre className="json-view">{JSON.stringify(selectedDefinition.pipeline, null, 2)}</pre>
        </SectionCard>
      </div>

      <SectionCard
        title="Latest Firebase demonstration result"
        action={<ShieldCheck size={22} />}
      >
        {result.scenario ? (
          <>
            <KeyValueGrid
              items={[
                { label: "Scenario", value: result.scenario },
                { label: "Decision", value: result.output?.decision || "—", badge: true },
                { label: "Forwarding", value: result.output?.firebaseForwarding || "—", badge: true },
                { label: "Key action", value: result.output?.keyAction || "—", badge: true },
                { label: "System action", value: result.output?.systemAction || "—", badge: true },
                { label: "Executed at", value: formatTimestamp(result.executedAt) }
              ]}
            />
          </>
        ) : (
          <p>No dashboard demonstration has been executed yet.</p>
        )}
      </SectionCard>
    </>
  );
}
