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

  const activeScenario =
    systemStatus.dashboardBridgeState ||
    sessionValue.state ||
    "UNKNOWN";

  const activeEvidence =
    systemStatus.testEvidence ||
    anomalyValue.evidenceType ||
    "NOT_RECORDED";

  const networkEvidence =
    networkValue.evidence ||
    "NOT_AVAILABLE";

  const networkUsesSimulation =
    Boolean(networkValue.simulationRequired) ||
    Number(networkValue.simulatedNodeCount || 0) > 0 ||
    String(networkEvidence).toUpperCase().includes("SIMULATION");

  const networkDisplayState =
    networkValue.networkState
      ? `${networkValue.networkState}${
          networkUsesSimulation ? " / SIMULATION" : ""
        }`
      : "NOT_AVAILABLE";

  const overallRisk =
    anomalyValue.overallRiskScore ??
    anomalyValue.output?.overallRiskScore ??
    0;

  const riskClassification =
    anomalyValue.state ||
    anomalyValue.output?.riskClassification ||
    "NORMAL";

  return (
    <>
      <PageHeader
        eyebrow={`Node ${NODE_ID}`}
        title="System overview"
        description="Live operational state, security posture and end-to-end packet decision."
        action={
          <StatusBadge
            value={currentValue.systemState || "UNKNOWN"}
          />
        }
      />

      <div className="metric-grid">
        <MetricCard
          title="Temperature"
          value={sensors.temperature ?? "—"}
          unit=" °C"
          icon={Sprout}
          subtitle={`Updated ${formatTimestamp(
            currentValue.timestamp
          )}`}
        />

        <MetricCard
          title="Gateway"
          value={
            systemStatus.gatewayOnline
              ? "Online"
              : "Offline"
          }
          icon={Cloud}
          subtitle={
            systemStatus.firebaseConnected
              ? "Firebase connected"
              : "Firebase unavailable"
          }
        />

        <MetricCard
          title="Session"
          value={
            sessionValue.sessionId ||
            currentValue.sessionId ||
            "—"
          }
          icon={KeyRound}
          subtitle={sessionValue.state || "INACTIVE"}
        />

        <MetricCard
          title="Accepted packets"
          value={
            counterValue.acceptedPackets ??
            currentValue.sequence ??
            0
          }
          icon={RadioTower}
          subtitle={`Last sequence ${
            currentValue.sequence ?? 0
          }`}
        />

        <MetricCard
          title="Risk score"
          value={overallRisk}
          unit="/100"
          icon={Activity}
          subtitle={riskClassification}
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
          title="System and scenario state"
          subtitle="The active node scenario is separated from archived network-wide test evidence."
        >
          <KeyValueGrid
            items={[
              {
                label: "Sensor node",
                value: systemStatus.sensorNodeOnline
                  ? "ONLINE"
                  : "OFFLINE",
                badge: true
              },
              {
                label: "Gateway",
                value: systemStatus.gatewayOnline
                  ? "ONLINE"
                  : "OFFLINE",
                badge: true
              },
              {
                label: "Firebase",
                value: systemStatus.firebaseConnected
                  ? "CONNECTED"
                  : "DISCONNECTED",
                badge: true
              },
              {
                label: "System state",
                value: currentValue.systemState || "UNKNOWN",
                badge: true
              },
              {
                label: "Active scenario",
                value: activeScenario,
                badge: true
              },
              {
                label: "Active evidence",
                value: activeEvidence
              },
              {
                label: "Connection",
                value: currentValue.connection || "UNKNOWN",
                badge: true
              },
              {
                label: "Sample valid",
                value: sensors.sampleValid ? "YES" : "NO",
                badge: true
              },
              {
                label: "Last packet",
                value: formatTimestamp(currentValue.timestamp)
              },
              {
                label: "Latest network-wide test",
                value: networkDisplayState,
                badge: true
              },
              {
                label: "Network evidence",
                value: networkEvidence
              },
              {
                label: "Network node composition",
                value: `${
                  networkValue.realNodeCount ?? 0
                } real / ${
                  networkValue.simulatedNodeCount ?? 0
                } simulated`
              }
            ]}
          />
        </SectionCard>
      </div>

      {networkUsesSimulation && (
        <div className="security-note">
          <ShieldAlert size={22} />
          <div>
            <strong>
              Scenario separation enabled
            </strong>
            <p>
              The current node state comes from the latest
              insider-misuse revocation test. The CRITICAL
              network-wide state is archived evidence from
              Step 38I-4 and is explicitly labelled as a
              simulation using one real node and three
              simulated nodes.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
