import { KeyRound, RefreshCcw, ShieldOff, TimerReset } from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import KeyValueGrid from "../components/KeyValueGrid";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { formatTimestamp, safeObject } from "../utils/data";

export default function KeyLifecyclePage() {
  const base = `/greenhouse/${NODE_ID}/security`;
  const session = useFirebaseValue(`${base}/session`, {});
  const lifecycle = useFirebaseValue(`${base}/key_lifecycle`, {});

  const sessionValue = safeObject(session.value);
  const keyValue = safeObject(lifecycle.value);

  return (
    <>
      <PageHeader
        eyebrow="Session security"
        title="Key lifecycle, rotation and revocation"
        description="Only key states and fingerprints are observable. Actual AppSKey, NwkSKey and master PSK are never displayed."
        action={<StatusBadge value={sessionValue.revoked ? "REVOKED" : sessionValue.state || "INACTIVE"} />}
      />

      <div className="metric-grid">
        <MetricCard title="Session ID" value={sessionValue.sessionId || "—"} icon={KeyRound} />
        <MetricCard title="Packets since rotation" value={sessionValue.packetsSinceRotation || 0} icon={TimerReset} />
        <MetricCard title="Rotation counter" value={keyValue.rotationCounter || 0} icon={RefreshCcw} />
        <MetricCard title="AppSKey" value={keyValue.appSKeyState || "ZEROIZED"} icon={KeyRound} />
        <MetricCard title="NwkSKey" value={keyValue.nwkSKeyState || "ZEROIZED"} icon={KeyRound} />
        <MetricCard title="Revoked" value={sessionValue.revoked ? "Yes" : "No"} icon={ShieldOff} />
      </div>

      <div className="two-column">
        <SectionCard title="Current session">
          <KeyValueGrid
            items={[
              { label: "State", value: sessionValue.state || "INACTIVE", badge: true },
              { label: "Session ID", value: sessionValue.sessionId || "—" },
              { label: "Started at", value: formatTimestamp(sessionValue.startedAt) },
              { label: "Last accepted sequence", value: sessionValue.lastAcceptedSequence || 0 },
              { label: "Packets since rotation", value: sessionValue.packetsSinceRotation || 0 },
              { label: "Revoked", value: sessionValue.revoked ? "YES" : "NO", badge: true }
            ]}
          />
        </SectionCard>

        <SectionCard title="Production rotation policy">
          <KeyValueGrid
            items={[
              { label: "AppSKey state", value: keyValue.appSKeyState || "ZEROIZED", badge: true },
              { label: "NwkSKey state", value: keyValue.nwkSKeyState || "ZEROIZED", badge: true },
              { label: "Rotation counter", value: keyValue.rotationCounter || 0 },
              { label: "Last rotation", value: formatTimestamp(keyValue.lastRotationAt) },
              { label: "Last reason", value: keyValue.lastRotationReason || "NONE" },
              { label: "Packet limit", value: keyValue.productionPacketLimit || 1000 },
              { label: "Time limit", value: `${keyValue.productionTimeLimitHours || 24} hours` }
            ]}
          />
        </SectionCard>
      </div>

      <div className="security-note">
        <ShieldOff size={22} />
        <div>
          <strong>Secret-display protection</strong>
          <p>The dashboard never reads or displays raw cryptographic keys, Firebase tokens or device credentials.</p>
        </div>
      </div>
    </>
  );
}
