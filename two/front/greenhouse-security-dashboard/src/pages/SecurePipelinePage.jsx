import { CheckCircle2, RadioTower, ShieldX } from "lucide-react";
import PageHeader from "../components/PageHeader";
import PipelineFlow from "../components/PipelineFlow";
import SectionCard from "../components/SectionCard";
import MetricCard from "../components/MetricCard";
import KeyValueGrid from "../components/KeyValueGrid";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { safeObject } from "../utils/data";

export default function SecurePipelinePage() {
  const base = `/greenhouse/${NODE_ID}`;
  const current = useFirebaseValue(`${base}/current`, {});
  const counters = useFirebaseValue(`${base}/security/counters`, {});

  const currentValue = safeObject(current.value);
  const security = safeObject(currentValue.security);
  const counterValue = safeObject(counters.value);

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
