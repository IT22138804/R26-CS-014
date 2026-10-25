import {
  Activity,
  Cloud,
  KeyRound,
  RadioTower,
  ShieldAlert,
  Sprout
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import StatusBadge from "../components/StatusBadge";
import PipelineFlow from "../components/PipelineFlow";
import KeyValueGrid from "../components/KeyValueGrid";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { formatTimestamp, safeObject } from "../utils/data";

export default function OverviewPage() {
  const base = `/greenhouse/${NODE_ID}`;
  const current = useFirebaseValue(`${base}/current`, {});
  const status = useFirebaseValue(`${base}/system/status`, {});
  const session = useFirebaseValue(`${base}/security/session`, {});
  const counters = useFirebaseValue(`${base}/security/counters`, {});
  const anomaly = useFirebaseValue(`${base}/behavioral_anomaly/current`, {});
  const network = useFirebaseValue("/network/summary", {});

  const currentValue = safeObject(current.value);
  const sensors = safeObject(currentValue.sensors);
  const security = safeObject(currentValue.security);
  const systemStatus = safeObject(status.value);
  const sessionValue = safeObject(session.value);
  const counterValue = safeObject(counters.value);
  const anomalyValue = safeObject(anomaly.value);
  const networkValue = safeObject(network.value);

  return (
    <>
      <PageHeader
        eyebrow={`Node ${NODE_ID}`}
        title="System overview"
        description="Live operational state, security posture and end-to-end packet decision."
        action={<StatusBadge value={currentValue.systemState || "UNKNOWN"} />}
      />

      <div className="metric-grid">
        <MetricCard
          title="Temperature"
          value={sensors.temperature ?? "—"}
          unit=" °C"
          icon={Sprout}
          subtitle={`Updated ${formatTimestamp(currentValue.timestamp)}`}
        />
        <MetricCard
          title="Gateway"
          value={systemStatus.gatewayOnline ? "Online" : "Offline"}
          icon={Cloud}
          subtitle={systemStatus.firebaseConnected ? "Firebase connected" : "Firebase unavailable"}
        />
        <MetricCard
          title="Session"
          value={sessionValue.sessionId || currentValue.sessionId || "—"}
          icon={KeyRound}
          subtitle={sessionValue.state || "INACTIVE"}
        />
        <MetricCard
          title="Accepted packets"
          value={counterValue.acceptedPackets ?? currentValue.sequence ?? 0}
          icon={RadioTower}
          subtitle={`Last sequence ${currentValue.sequence ?? 0}`}
        />
        <MetricCard
          title="Risk score"
          value={anomalyValue.overallRiskScore ?? anomalyValue.output?.overallRiskScore ?? 0}
          unit="/100"
          icon={Activity}
          subtitle={
            anomalyValue.state ||
            anomalyValue.output?.riskClassification ||
            "NORMAL"
          }
        />
        <MetricCard
          title="Security rejects"
          value={
            Number(counterValue.replayRejected || 0) +
            Number(counterValue.invalidOuterHmac || 0) +
            Number(counterValue.invalidGcmTag || 0) +
            Number(counterValue.staleTimestamp || 0)
          }
          icon={ShieldAlert}
          subtitle="Replay, HMAC, GCM and timestamp"
        />
      </div>

      <div className="two-column">
        <SectionCard
          title="Secure communication pipeline"
          subtitle="The latest accepted packet and its validation stages."
        >
          <PipelineFlow security={security} />
        </SectionCard>

        <SectionCard
          title="System state"
          subtitle="Runtime state exposed to the monitoring layer."
        >
          <KeyValueGrid
            items={[
              { label: "Sensor node", value: systemStatus.sensorNodeOnline ? "ONLINE" : "OFFLINE", badge: true },
              { label: "Gateway", value: systemStatus.gatewayOnline ? "ONLINE" : "OFFLINE", badge: true },
              { label: "Firebase", value: systemStatus.firebaseConnected ? "CONNECTED" : "DISCONNECTED", badge: true },
              { label: "System state", value: currentValue.systemState || "UNKNOWN", badge: true },
              { label: "Connection", value: currentValue.connection || "UNKNOWN", badge: true },
              { label: "Sample valid", value: sensors.sampleValid ? "YES" : "NO", badge: true },
              { label: "Last packet", value: formatTimestamp(currentValue.timestamp) },
              { label: "Network state", value: networkValue.networkState || "NOT_AVAILABLE", badge: true }
            ]}
          />
        </SectionCard>
      </div>
    </>
  );
}
