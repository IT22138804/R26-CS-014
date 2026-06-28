import { useState } from "react";
import { ref, set } from "firebase/database";
import { ArrowRight, CheckCircle2, Cloud, Cpu, KeyRound, Play, Radio, RadioTower, Shield, ShieldX } from "lucide-react";
import PageHeader from "../components/PageHeader";
import PipelineFlow from "../components/PipelineFlow";
import SectionCard from "../components/SectionCard";
import MetricCard from "../components/MetricCard";
import KeyValueGrid from "../components/KeyValueGrid";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import StatusBadge from "../components/StatusBadge";
import { database, NODE_ID } from "../lib/firebase";
import { useAuth } from "../context/AuthContext";
import { safeObject } from "../utils/data";

export default function SecurePipelinePage() {
  const { user } = useAuth();
  const [commandRunning, setCommandRunning] = useState(false);
  const [commandMessage, setCommandMessage] = useState("");
  const [requestedCommand, setRequestedCommand] = useState("");
  const [replayCounterBefore, setReplayCounterBefore] = useState(null);
  const base = `/greenhouse/${NODE_ID}`;
  const current = useFirebaseValue(`${base}/current`, {});
  const counters = useFirebaseValue(`${base}/security/counters`, {});
  const commandStatus = useFirebaseValue(`${base}/demo/component2/status`, {});

  const currentValue = safeObject(current.value);
  const security = safeObject(currentValue.security);
  const counterValue = safeObject(counters.value);
  const commandValue = safeObject(commandStatus.value);
  const activeCommand = commandValue.command || requestedCommand;
  const scenarios = {
    TEST_REPLAY: { label: "Replay packet", trigger: "Resend the last valid encrypted frame with its old sequence.", gate: "Outer HMAC passes; monotonic replay window fails.", output: "Packet rejected before decryption; replay counter increases.", key: "Session remains active." },
    TEST_INVALID_HMAC: { label: "Modified packet", trigger: "Change one ciphertext digit without updating the outer HMAC.", gate: "Outer HMAC comparison fails.", output: "Packet rejected before AES-GCM and Firebase forwarding.", key: "Failure contributes to the authentication-failure threshold." },
    TEST_INVALID_GCM: { label: "Invalid GCM tag", trigger: "Modify ciphertext, retain the old GCM tag, and recompute the outer HMAC.", gate: "Outer HMAC passes; AES-GCM authentication fails.", output: "Packet rejected and invalid-GCM counter increases.", key: "Session remains active unless failure policy revokes it." },
    TEST_STALE_TIMESTAMP: { label: "Stale timestamp", trigger: "Send an authenticated encrypted packet with an expired elapsed timestamp.", gate: "HMAC and GCM pass; ±30-second freshness gate fails.", output: "Firebase forwarding is blocked; stale counter increases.", key: "Session remains active." },
    TEST_HMAC_SPIKE: { label: "HMAC failure spike", trigger: "Transmit five controlled modified frames inside the failure window.", gate: "Each frame fails outer-HMAC validation; the policy threshold reaches 5.", output: "Gateway sends a signed emergency-revoke command and blocks the session.", key: "Both devices zeroize runtime session keys." },
    ROTATE_SESSION: { label: "Rotate session", trigger: "Operator requests controlled key rotation through the authenticated command channel.", gate: "Gateway signs the command with NwkSKey; sensor verifies session and HMAC.", output: "Old keys are zeroized and a fresh nonce-based handshake starts.", key: "New AppSKey and NwkSKey are derived; key material is never transmitted." },
    REVOKE_SESSION: { label: "Emergency revoke", trigger: "Operator or security policy requests immediate revocation.", gate: "Signed command and active session must validate.", output: "Telemetry stops, actuators remain safe and Firebase session becomes REVOKED.", key: "Both ESP32 devices zeroize runtime keys; restart/new authorization is required." }
  };
  const scenario = scenarios[activeCommand];
  const requestMatches = Boolean(activeCommand && commandValue.command === activeCommand);
  const completed = requestMatches && ["REJECTED_AS_EXPECTED", "ROTATED", "REVOKED", "PASSED"].includes(commandValue.result);
  const flow = [
    { label: "Dashboard", icon: Play, value: activeCommand ? "TRIGGERED" : "WAITING" },
    { label: "Firebase", icon: Cloud, value: activeCommand ? "QUEUED" : "WAITING" },
    { label: "Gateway signature", icon: Shield, value: requestMatches ? "SIGNED" : "WAITING" },
    { label: "E32 transport", icon: Radio, value: requestMatches ? "SENT" : "WAITING" },
    { label: "Sensor action", icon: Cpu, value: commandValue.sensorState || (requestMatches ? "PROCESSING" : "WAITING") },
    { label: "Security result", icon: KeyRound, value: completed ? commandValue.result : "WAITING" }
  ];

  async function runComponent2Command(command) {
    setCommandRunning(true);
    setRequestedCommand(command);
    setCommandMessage("");
    const requestId = String(Date.now());
    if (command === "TEST_REPLAY") {
      setReplayCounterBefore(Number(counterValue.replayRejected || 0));
    }
    try {
      await set(ref(database, "/demo/component2/pending"), {
        command, requestId, requestedAt: Math.floor(Date.now() / 1000), requestedBy: "COMPONENT2_DASHBOARD"
      });
      setCommandMessage(command === "TEST_REPLAY"
        ? "Real replay queued. The sensor will retransmit its latest saved C2_SECURE_V1 frame without changing any byte."
        : `${scenarios[command].label} queued for the real Component 2 hardware path.`);
    } catch (error) {
      const uid = user?.uid ? ` Signed-in UID: ${user.uid}` : "";
      setCommandMessage(`${error?.message || "Command could not be queued."}${uid}`);
    } finally {
      setCommandRunning(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Component 2"
        title="Secure communication pipeline"
        description="Input, validation gates, output decision and Firebase-forwarding evidence."
      />

      <div className="metric-grid">
        <MetricCard title="Accepted" value={counterValue.acceptedPackets || currentValue.sequence || 0} icon={CheckCircle2} />
        <MetricCard title="Replay rejected" value={counterValue.replayRejected || 0} icon={ShieldX} />
        <MetricCard title="Invalid HMAC" value={counterValue.invalidOuterHmac || 0} icon={ShieldX} />
        <MetricCard title="Invalid GCM" value={counterValue.invalidGcmTag || 0} icon={ShieldX} />
        <MetricCard title="Stale timestamp" value={counterValue.staleTimestamp || 0} icon={ShieldX} />
        <MetricCard title="Firebase success" value={counterValue.firebaseWriteSuccess || 0} icon={RadioTower} />
      </div>

      <SectionCard
        title="Latest packet flow"
        subtitle="A malicious packet must stop at the first failed stage and must not reach Firebase."
      >
        <PipelineFlow security={security} />
      </SectionCard>

      <SectionCard
        title="Controlled Component 2 security triggers"
        subtitle="These controls use Firebase → Gateway → NwkSKey-signed E32 command → Sensor → real validation result → Firebase. Virtual results remain explicitly labelled."
      >
        <div className="button-row security-trigger-grid">
          {Object.entries(scenarios).map(([command, item], index) => (
            <button
              className={`button demo-button ${index === 0 ? "success" : index < 5 ? "warning" : index === 5 ? "critical" : "danger"}`}
              disabled={commandRunning}
              key={command}
              onClick={() => runComponent2Command(command)}
              type="button"
            ><Play size={17} /> {item.label}</button>
          ))}
        </div>
        {commandMessage ? <div className="form-message">{commandMessage}</div> : null}

        <div className="component-flow" aria-label="Component 2 controlled command flow">
          {flow.map((stage, index) => {
            const Icon = stage.icon;
            return <div className="component-flow__group" key={stage.label}>
              <div className="component-flow__stage"><span className="component-flow__icon"><Icon size={19} /></span><strong>{stage.label}</strong><StatusBadge value={stage.value} /></div>
              {index < flow.length - 1 ? <ArrowRight className="component-flow__arrow" size={19} /> : null}
            </div>;
          })}
        </div>

        {scenario ? <div className="effect-grid">
          <div><span>Selected trigger</span><strong>{scenario.label}</strong></div>
          <div><span>How it is triggered</span><strong>{scenario.trigger}</strong></div>
          <div><span>Validation gate</span><strong>{scenario.gate}</strong></div>
          <div><span>Expected output</span><strong>{scenario.output}</strong></div>
          <div><span>Key/session effect</span><strong>{scenario.key}</strong></div>
          <div><span>Observed result</span><strong>{commandValue.result || "WAITING_FOR_DEVICE"}</strong></div>
          <div><span>Device evidence</span><strong>{commandValue.evidenceType || "WAITING"}</strong></div>
          <div><span>Request ID</span><strong>{commandValue.requestId || "—"}</strong></div>
        </div> : <p className="muted">Select a trigger to see its complete cause, validation path, system output and key effect.</p>}

        {activeCommand === "TEST_REPLAY" ? <div className="effect-grid">
          <div><span>Demonstration source</span><strong>{commandValue.evidenceType || "WAITING_FOR_PHYSICAL_HARDWARE"}</strong></div>
          <div><span>Real session ID</span><strong>{currentValue.sessionId || "WAITING"}</strong></div>
          <div><span>Originally accepted sequence</span><strong>{commandValue.lastAcceptedSequence ?? currentValue.sequence ?? "WAITING"}</strong></div>
          <div><span>Replayed sequence</span><strong>{commandValue.receivedSequence ?? "WAITING"}</strong></div>
          <div><span>Sequence proof</span><strong>{commandValue.sequenceComparison || "WAITING: received sequence <= last accepted sequence"}</strong></div>
          <div><span>Packet bytes</span><strong>UNCHANGED SAVED C2_SECURE_V1 FRAME</strong></div>
          <div><span>Outer HMAC</span><strong>{commandValue.outerHmac || "WAITING"}</strong></div>
          <div><span>Replay window</span><strong>{commandValue.replayWindow || "WAITING"}</strong></div>
          <div><span>AES-GCM on replay</span><strong>{commandValue.aesGcm || "WAITING"}</strong></div>
          <div><span>Packet accepted</span><strong>{commandValue.packetAccepted === false ? "NO" : "WAITING"}</strong></div>
          <div><span>Forwarded to Firebase</span><strong>{commandValue.firebaseForwarded === false ? "NO" : "WAITING"}</strong></div>
          <div><span>Replay counter</span><strong>{replayCounterBefore ?? "—"} → {counterValue.replayRejected || 0}</strong></div>
          <div><span>Final proof</span><strong>{commandValue.result === "REJECTED_AS_EXPECTED" ? "VALID HMAC + OLD SEQUENCE = REPLAY → REJECTED" : "WAITING_FOR_GATEWAY"}</strong></div>
        </div> : null}
      </SectionCard>

      <div className="two-column">
        <SectionCard title="Packet input">
          <KeyValueGrid
            items={[
              { label: "Node ID", value: currentValue.nodeId || NODE_ID },
              { label: "Session ID", value: currentValue.sessionId || "—" },
              { label: "Sequence", value: currentValue.sequence ?? "—" },
              { label: "Timestamp", value: currentValue.timestamp || "—" },
              { label: "System state", value: currentValue.systemState || "UNKNOWN", badge: true },
              { label: "Connection", value: currentValue.connection || "UNKNOWN", badge: true }
            ]}
          />
        </SectionCard>

        <SectionCard title="Validation output">
          <KeyValueGrid
            items={[
              { label: "Radio authenticated", value: security.radioAuthenticated ? "PASSED" : "FAILED", badge: true },
              { label: "Outer HMAC", value: security.outerHmac || "NOT_CHECKED", badge: true },
              { label: "Replay window", value: security.replayWindow || "NOT_CHECKED", badge: true },
              { label: "Timestamp window", value: security.timestampWindow || "NOT_CHECKED", badge: true },
              { label: "AES-GCM", value: security.aesGcm || "NOT_CHECKED", badge: true },
              { label: "GCM tag", value: security.gcmTag || "NOT_CHECKED", badge: true },
              { label: "Firebase authentication", value: security.firebaseAuthentication || "NOT_CHECKED", badge: true },
              { label: "TLS validation", value: security.tlsCertificateValidation || "NOT_CHECKED", badge: true }
            ]}
          />
        </SectionCard>
      </div>
    </>
  );
}
