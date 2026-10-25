import { BrainCircuit, DoorClosed, Fingerprint, Shield, UserRoundCheck, Waves } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SectionCard from "../components/SectionCard";
import MetricCard from "../components/MetricCard";
import KeyValueGrid from "../components/KeyValueGrid";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { safeObject } from "../utils/data";

export default function Component1Page() {
  const data = useFirebaseValue(`/greenhouse/${NODE_ID}/component1`, {});
  const value = safeObject(data.value);
  const rfid = safeObject(value.rfid);
  const tinyml = safeObject(value.tinyml);
  const tamper = safeObject(value.tamper);
  const actuators = safeObject(value.actuators);
  const insider = safeObject(value.insider_attribution);

  return (
    <>
      <PageHeader
        eyebrow="Component 1"
        title="Edge security and physical protection"
        description="RFID authorization, clone-risk evidence, TinyML inference, tamper response and insider-session attribution."
        action={<StatusBadge value={tamper.state || "SECURE"} />}
      />

      <div className="metric-grid">
        <MetricCard title="RFID authorized" value={rfid.authorized ? "Yes" : "No"} icon={Fingerprint} subtitle={rfid.sectorAuthentication || "NOT_CHECKED"} />
        <MetricCard title="RFID latency" value={rfid.authLatencyUs || 0} unit=" µs" icon={Shield} subtitle={`Clone risk: ${rfid.cloneRisk || "UNKNOWN"}`} />
        <MetricCard title="TinyML probability" value={tinyml.anomalyProbability ?? 0} icon={BrainCircuit} subtitle={tinyml.classification || "NOT_RUN"} />
        <MetricCard title="Confirmations" value={`${tinyml.confirmationCount || 0}/${tinyml.requiredConfirmations || 3}`} icon={BrainCircuit} />
        <MetricCard title="Tamper switch" value={tamper.state || "SECURE"} icon={DoorClosed} />
        <MetricCard title="Insider correlation" value={insider.correlation || "NONE"} icon={UserRoundCheck} subtitle={insider.humanIdentityClaim || "NOT_MADE"} />
      </div>

      <div className="two-column">
        <SectionCard title="RFID security evidence">
          <KeyValueGrid
            items={[
              { label: "Authorized", value: rfid.authorized ? "YES" : "NO", badge: true },
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
