import { useRef, useState } from "react";
import { set, ref } from "firebase/database";
import { ArrowRight, BrainCircuit, Cloud, Cpu, Database, DoorClosed, Fingerprint, KeyRound, Play, Radio, Shield, UserRoundCheck, Waves } from "lucide-react";
import CloneWalkthrough from "../components/CloneWalkthrough";
import PageHeader from "../components/PageHeader";
import SectionCard from "../components/SectionCard";
import MetricCard from "../components/MetricCard";
import KeyValueGrid from "../components/KeyValueGrid";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { database, NODE_ID } from "../lib/firebase";
import { safeObject } from "../utils/data";
import { useAuth } from "../context/AuthContext";

export default function Component1Page() {
  const { user } = useAuth();
  const [commandMessage, setCommandMessage] = useState("");
  const [commandRunning, setCommandRunning] = useState(false);
  const [requestedCommand, setRequestedCommand] = useState("");
  const [serialRfid, setSerialRfid] = useState(null);
  const [serialConnected, setSerialConnected] = useState(false);
  const [serialMessage, setSerialMessage] = useState("");
  const serialPortRef = useRef(null);
  const serialReaderRef = useRef(null);
  const pendingSerialScan = useRef({});
  const data = useFirebaseValue(`/greenhouse/${NODE_ID}/component1`, {});
  // The gateway writes its authenticated ACK below its protected node.
  const commandStatus = useFirebaseValue(
    `/greenhouse/${NODE_ID}/demo/component1/status`,
    {}
  );
  const value = safeObject(data.value);
  const firebaseRfid = safeObject(value.rfid);
  const rfid = serialRfid || firebaseRfid;
  const effectiveSystemState = serialRfid?.systemState || value.systemState || "LOCKED";
  const tinyml = safeObject(value.tinyml);
  const tamper = safeObject(value.tamper);
  const actuators = safeObject(value.actuators);
  const insider = safeObject(value.insider_attribution);
  const commandValue = safeObject(commandStatus.value);


  function processSerialLine(rawLine) {
    const line = rawLine.trim();
    if (line.includes("COMPONENT 1 PHYSICAL RFID SCAN")) {
      pendingSerialScan.current = {};
      return;
    }

    let match = line.match(/^RFID UID\s*:\s*(.+)$/);
    if (match) pendingSerialScan.current.uid = match[1].trim();

    match = line.match(/^RFID authorization result\s*:\s*(.+)$/);
    if (match) pendingSerialScan.current.result = match[1].trim();

    match = line.match(/^Authenticated user\/session\s*:\s*(YES|NO)$/);
    if (match) pendingSerialScan.current.sessionAuthenticated = match[1] === "YES";

    match = line.match(/^Component 1 system state\s*:\s*(.+)$/);
    if (!match) return;

    const scan = pendingSerialScan.current;
    const result = scan.result || "UNKNOWN";
    const authorized = result === "AUTHORIZED" && scan.sessionAuthenticated === true;
    setSerialRfid({
      ...firebaseRfid,
      uid: scan.uid || "UNKNOWN",
      uidMasked: scan.uid || "UNKNOWN",
      result,
      authorized,
      accessDecision: authorized ? "ALLOW" : "DENY",
      sectorAuthentication: result === "AUTHORIZED" ? "PASSED" : "REJECTED",
      cloneRisk: result === "AUTHORIZED"
        ? "LOW_SUPPORTING_EVIDENCE"
        : result === "UID_REJECTED"
          ? "UNAUTHORIZED_UID"
          : "ELEVATED_SAME_UID_CLONE_SUSPECTED",
      systemState: match[1].trim(),
      scanId: Date.now(),
      source: "LOCAL_SENSOR_SERIAL"
    });
  }

  async function connectSensorSerial() {
    if (!("serial" in navigator)) {
      setSerialMessage("Web Serial is unavailable. Use Chrome or Edge on localhost.");
      return;
    }

    try {
      const port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });
      serialPortRef.current = port;
      setSerialConnected(true);
      setSerialMessage("Sensor serial connected. Close Arduino Serial Monitor while using this connection.");

      const reader = port.readable.getReader();
      serialReaderRef.current = reader;
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value: chunk, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(chunk, { stream: true });
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() || "";
        lines.forEach(processSerialLine);
      }
    } catch (error) {
      if (error?.name !== "NotFoundError") {
        setSerialMessage(error?.message || "Could not connect to the sensor serial port.");
      }
    } finally {
      if (serialReaderRef.current) {
        serialReaderRef.current.releaseLock();
        serialReaderRef.current = null;
      }
      if (serialPortRef.current) {
        await serialPortRef.current.close().catch(() => {});
        serialPortRef.current = null;
      }
      setSerialConnected(false);
    }
  }

  async function disconnectSensorSerial() {
    await serialReaderRef.current?.cancel().catch(() => {});
  }

  const activeCommand = commandValue.command || requestedCommand;
  const scenarios = {
    DEMO_AUTHORIZED_UNLOCK: {
      label: "Authorized unlock",
      trigger: "Dashboard operator requests a controlled valid-card scan.",
      validation: "UID and protected-sector evidence pass; the command frame HMAC is verified.",
      output: "State NORMAL, authenticated session active, green LED enabled and relays remain safe.",
      keyAction: "Session keys stay active."
    },
    DEMO_WRONG_CARD: {
      label: "Wrong RFID card",
      trigger: "Dashboard injects a controlled card with an unauthorized UID.",
      validation: "UID allow-list comparison fails before protected-sector authorization.",
      output: "Access rejected, state remains locked and actuators remain OFF.",
      keyAction: "No key change. Rejection evidence is recorded."
    },
    DEMO_RFID_CLONE: {
      label: "RFID clone attempt",
      trigger: "Dashboard injects a same-UID card without the valid protected-sector marker/key.",
      validation: "UID appears valid but sector authentication or marker verification fails.",
      output: "Elevated clone risk and controlled LOCKDOWN; relay outputs OFF and session keys zeroized.",
      keyAction: "No key disclosure; access is denied."
    },
    DEMO_INSIDER_MISUSE: {
      label: "Insider misuse",
      trigger: "An already authenticated RFID session requests a prohibited action.",
      validation: "Session attribution succeeds; the controlled trigger supplies 3/3 anomaly confirmations.",
      output: "Immediate LOCKDOWN, pump/fan OFF and further commands blocked.",
      keyAction: "Runtime AppSKey and NwkSKey are zeroized on physical hardware."
    }
  };
  const scenario = scenarios[activeCommand];
  const requestMatches = Boolean(activeCommand && commandValue.command === activeCommand);
  const sensorResponded = requestMatches && Boolean(rfid.result && rfid.result !== "NOT_SCANNED");
  const flowStages = [
    { label: "Dashboard trigger", icon: Play, status: activeCommand ? "TRIGGERED" : "WAITING" },
    { label: "Firebase command", icon: Cloud, status: activeCommand ? "QUEUED" : "WAITING" },
    { label: "Gateway validation", icon: Shield, status: requestMatches ? "HMAC SIGNED" : "WAITING" },
    { label: "E32 transport", icon: Radio, status: requestMatches ? "DELIVERED" : "WAITING" },
    { label: "Sensor decision", icon: Cpu, status: sensorResponded ? "EVALUATED" : "WAITING" },
    { label: "Safety/key action", icon: KeyRound, status: sensorResponded ? effectiveSystemState : "WAITING" },
    { label: "Firebase evidence", icon: Database, status: sensorResponded ? "RECORDED" : "WAITING" }
  ];

  async function runHardwareDemo(command) {
    setCommandRunning(true);
    setRequestedCommand(command);
    setCommandMessage("");
    const requestId = String(Date.now());
    try {
      await set(ref(database, "/demo/component1/pending"), {
        command,
        requestId,
        requestedAt: Math.floor(Date.now() / 1000),
        requestedBy: "COMPONENT1_DASHBOARD"
      });
      setCommandMessage(`${command.replaceAll("_", " ")} queued. Watch the live flow below.`);
    } catch (error) {
      const uidHint = user?.uid ? ` Signed-in UID: ${user.uid}` : " No authenticated UID is available.";
      setCommandMessage(error?.message || "Command could not be queued.");
      if (error?.code === "PERMISSION_DENIED" || error?.code === "permission-denied") {
        setCommandMessage(`PERMISSION_DENIED.${uidHint}`);
      }
    } finally {
      setCommandRunning(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Component 1"
        title="Edge security and physical protection"
        description="RFID authorization, clone-risk evidence, controlled anomaly evidence, tamper response and insider-session attribution."
        action={(
          <div className="button-row">
            <StatusBadge value={serialConnected ? "SERIAL LIVE" : (tamper.state || "SECURE")} />
            <button
              className="button"
              type="button"
              onClick={serialConnected ? disconnectSensorSerial : connectSensorSerial}
            >
              <Radio size={16} />
              {serialConnected ? "Disconnect RFID serial" : "Connect RFID serial"}
            </button>
          </div>
        )}
      />

      {serialMessage ? <div className="form-message">{serialMessage}</div> : null}

      <CloneWalkthrough evidence={value} gatewayStatus={commandValue} />
      <div className="metric-grid">
        <MetricCard title="RFID authorized" value={rfid.authorized ? "Yes" : "No"} icon={Fingerprint} subtitle={rfid.sectorAuthentication || "NOT_CHECKED"} />
        <MetricCard title="RFID latency" value={rfid.authLatencyUs || 0} unit=" µs" icon={Shield} subtitle={`Clone risk: ${rfid.cloneRisk || "UNKNOWN"}`} />
        <MetricCard title="TinyML probability" value={tinyml.anomalyProbability ?? 0} icon={BrainCircuit} subtitle={tinyml.classification || "NOT_RUN"} />
        <MetricCard title="Confirmations" value={`${tinyml.confirmationCount || 0}/${tinyml.requiredConfirmations || 3}`} icon={BrainCircuit} />
        <MetricCard title="Tamper switch" value={tamper.state || "SECURE"} icon={DoorClosed} />
        <MetricCard title="Insider correlation" value={insider.correlation || "NONE"} icon={UserRoundCheck} subtitle={insider.humanIdentityClaim || "NOT_MADE"} />
      </div>

      <SectionCard title="Live demonstration status">
        <KeyValueGrid
          items={[
            { label: "System state", value: effectiveSystemState, badge: true },
            { label: "Last RFID result", value: rfid.result || "NOT_SCANNED", badge: true },
            { label: "RFID UID", value: rfid.uid || rfid.uidMasked || "NOT_SCANNED" },
            { label: "Access decision", value: rfid.accessDecision || "NOT_DECIDED", badge: true },
            { label: "Evidence transport", value: serialRfid ? "DIRECT SERIAL" : (value.transport?.hmac || "NOT_RECEIVED"), badge: true },
            { label: "Evidence type", value: serialRfid ? "LOCAL_SENSOR_SERIAL" : (value.transport?.evidenceType || "PHYSICAL_HARDWARE"), badge: true },
            { label: "Last update", value: serialRfid ? new Date(rfid.scanId).toLocaleString() : (value.updatedAt || "—") }
          ]}
        />
      </SectionCard>

      <SectionCard
        title="Controlled hardware demonstration"
        subtitle="Commands travel Firebase → Gateway → signed E32 frame → Sensor → signed evidence → Firebase."
      >
        <div className="button-row">
          <button className="button demo-button success" type="button" disabled={commandRunning}
            onClick={() => runHardwareDemo("DEMO_AUTHORIZED_UNLOCK")}>
            <Play size={17} /> Authorized unlock
          </button>
          <button className="button demo-button danger" type="button" disabled={commandRunning}
            onClick={() => runHardwareDemo("DEMO_WRONG_CARD")}>
            <Play size={17} /> Wrong RFID card
          </button>
          <button className="button demo-button warning" type="button" disabled={commandRunning}
            onClick={() => runHardwareDemo("DEMO_RFID_CLONE")}>
            <Play size={17} /> RFID clone attempt
          </button>
          <button className="button demo-button critical" type="button" disabled={commandRunning}
            onClick={() => runHardwareDemo("DEMO_INSIDER_MISUSE")}>
            <Play size={17} /> Insider misuse
          </button>
        </div>
        {commandMessage ? <div className="form-message">{commandMessage}</div> : null}
        <KeyValueGrid
          items={[
            { label: "Command", value: commandValue.command || "NONE" },
            { label: "Gateway flow", value: commandValue.state || "WAITING", badge: true },
            { label: "Test evidence", value: commandValue.evidenceType || "PHYSICAL_HARDWARE", badge: true },
            { label: "Request ID", value: commandValue.requestId || "—" },
            { label: "Sensor evidence", value: rfid.result || "NOT_RECEIVED", badge: true }
          ]}
        />
        <p className="muted">
          Use Authorized unlock before Insider misuse. The unlock button is a controlled test of the
          successful RFID flow. Insider misuse forces lockdown and key zeroization;
          restart the sensor and gateway before the next demonstration.
        </p>
      </SectionCard>

      <SectionCard
        title="Live trigger-to-effect flow"
        subtitle="The same Firebase → Gateway → signed E32 → Sensor → evidence path is used in virtual mode and on physical hardware."
      >
        <div className="component-flow" aria-label="Component 1 command processing flow">
          {flowStages.map((stage, index) => {
            const Icon = stage.icon;
            return (
              <div className="component-flow__group" key={stage.label}>
                <div className="component-flow__stage">
                  <span className="component-flow__icon"><Icon size={19} /></span>
                  <strong>{stage.label}</strong>
                  <StatusBadge value={stage.status} />
                </div>
                {index < flowStages.length - 1 ? <ArrowRight className="component-flow__arrow" size={19} /> : null}
              </div>
            );
          })}
        </div>

        {scenario ? (
          <div className="effect-grid">
            <div><span>Selected test</span><strong>{scenario.label}</strong></div>
            <div><span>Trigger</span><strong>{scenario.trigger}</strong></div>
            <div><span>Validation</span><strong>{scenario.validation}</strong></div>
            <div><span>Expected system output</span><strong>{scenario.output}</strong></div>
            <div><span>Key/security effect</span><strong>{scenario.keyAction}</strong></div>
            <div><span>Observed result</span><strong>{rfid.result || "WAITING_FOR_SENSOR_EVIDENCE"}</strong></div>
            <div><span>Observed system state</span><strong>{effectiveSystemState}</strong></div>
            <div><span>Execution source</span><strong>{commandValue.evidenceType || value.transport?.evidenceType || "PHYSICAL_HARDWARE"}</strong></div>
          </div>
        ) : (
          <p className="muted">Select a demonstration button to display its trigger, validation gates and system effect.</p>
        )}
      </SectionCard>

      <div className="two-column">
        <SectionCard title="RFID security evidence">
          <KeyValueGrid
            items={[
            { label: "Authorized", value: rfid.authorized ? "YES" : "NO", badge: true },
            { label: "Access decision", value: rfid.accessDecision || "WAITING", badge: true },
            { label: "RFID UID", value: rfid.uid || "NOT_AVAILABLE" },
            { label: "Masked UID", value: rfid.uidMasked || "NOT_AVAILABLE" },
              { label: "Sector authentication", value: rfid.sectorAuthentication || "NOT_CHECKED", badge: true },
              { label: "Clone risk", value: rfid.cloneRisk || "UNKNOWN", badge: true },
              { label: "Auth latency", value: `${rfid.authLatencyUs || 0} µs` },
              { label: "RFID session ID", value: rfid.sessionId || "—" }
            ]}
          />
        </SectionCard>

        <SectionCard title="TinyML and lockdown">
          <KeyValueGrid
            items={[
              { label: "Classification", value: tinyml.classification || "NOT_RUN", badge: true },
              { label: "Anomaly probability", value: tinyml.anomalyProbability ?? 0 },
              { label: "Confirmation count", value: `${tinyml.confirmationCount || 0}/${tinyml.requiredConfirmations || 3}` },
              { label: "Inference latency", value: `${tinyml.inferenceLatencyUs || 0} µs` },
              { label: "Pump relay", value: actuators.pump || "OFF", badge: true },
              { label: "Fan relay", value: actuators.fan || "OFF", badge: true },
              { label: "Fail-safe", value: actuators.relayFailSafe || "ACTIVE", badge: true }
            ]}
          />
        </SectionCard>
      </div>

      <SectionCard title="Authenticated-session attribution">
        <KeyValueGrid
          items={[
            { label: "Authenticated session active", value: insider.authenticatedSessionActive ? "YES" : "NO", badge: true },
            { label: "Correlation result", value: insider.correlation || "NONE", badge: true },
            { label: "Human identity claim", value: insider.humanIdentityClaim || "NOT_MADE" },
            { label: "Tamper state", value: tamper.state || "SECURE", badge: true },
            { label: "Last tamper change", value: tamper.lastChangedAt || "—" }
          ]}
        />
      </SectionCard>
    </>
  );
}
