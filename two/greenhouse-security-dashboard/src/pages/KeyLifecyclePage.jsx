import {
  KeyRound,
  ShieldOff,
  TimerReset,
  TriangleAlert
} from "lucide-react";
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

  const revoked = Boolean(sessionValue.revoked);
  const sessionState =
    sessionValue.state || (revoked ? "REVOKED" : "INACTIVE");

  const revocationCounter =
    sessionValue.revocationCounter ?? 0;

  const revocationReason =
    sessionValue.revocationReason ||
    keyValue.lastRevocationReason ||
    "NONE";

  const lastRevocationAt =
    keyValue.lastRevocationAt ||
    sessionValue.revokedAt ||
    0;

  return (
    <>
      <PageHeader
        eyebrow="Session security"
        title="Key lifecycle, rotation and revocation"
        description="Only key states, counters, timestamps and fingerprints are observable. Actual AppSKey, NwkSKey and the master PSK are never displayed."
        action={
          <StatusBadge
            value={revoked ? "REVOKED" : sessionState}
          />
        }
      />

      <div className="metric-grid">
        <MetricCard
          title="Session ID"
          value={sessionValue.sessionId || "—"}
          icon={KeyRound}
        />

        <MetricCard
          title="Packets since rotation"
          value={sessionValue.packetsSinceRotation || 0}
          icon={TimerReset}
        />

        <MetricCard
          title="Revocation counter"
          value={revocationCounter}
          icon={TriangleAlert}
          subtitle={revocationReason}
        />

        <MetricCard
          title="AppSKey"
          value={keyValue.appSKeyState || "ZEROIZED"}
          icon={KeyRound}
        />

        <MetricCard
          title="NwkSKey"
          value={keyValue.nwkSKeyState || "ZEROIZED"}
          icon={KeyRound}
        />

        <MetricCard
          title="Revoked"
          value={revoked ? "Yes" : "No"}
          icon={ShieldOff}
          subtitle={
            lastRevocationAt
              ? formatTimestamp(lastRevocationAt)
              : "No revocation timestamp"
          }
        />
      </div>

      <div className="two-column">
        <SectionCard title="Current session">
          <KeyValueGrid
            items={[
              {
                label: "State",
                value: sessionState,
                badge: true
              },
              {
                label: "Session ID",
                value: sessionValue.sessionId || "—"
              },
              {
                label: "Started at",
                value: sessionValue.startedAt
                  ? formatTimestamp(sessionValue.startedAt)
                  : "Not recorded"
              },
              {
                label: "Last accepted sequence",
                value: sessionValue.lastAcceptedSequence || 0
              },
              {
                label: "Packets since rotation",
                value: sessionValue.packetsSinceRotation || 0
              },
              {
                label: "Revoked",
                value: revoked ? "YES" : "NO",
                badge: true
              },
              {
                label: "Revocation counter",
                value: revocationCounter
              },
              {
                label: "Revocation reason",
                value: revocationReason,
                badge: revoked
              },
              {
                label: "Revoked at",
                value: lastRevocationAt
                  ? formatTimestamp(lastRevocationAt)
                  : "Not available"
              }
            ]}
          />
        </SectionCard>

        <SectionCard title="Rotation and revocation policy">
          <KeyValueGrid
            items={[
              {
                label: "AppSKey state",
                value: keyValue.appSKeyState || "ZEROIZED",
                badge: true
              },
              {
                label: "NwkSKey state",
                value: keyValue.nwkSKeyState || "ZEROIZED",
                badge: true
              },
              {
                label: "Rotation counter",
                value: keyValue.rotationCounter || 0
              },
              {
                label: "Last rotation",
                value: keyValue.lastRotationAt
                  ? formatTimestamp(keyValue.lastRotationAt)
                  : "Not available"
              },
              {
                label: "Last rotation reason",
                value: keyValue.lastRotationReason || "NONE"
              },
              {
                label: "Last revocation",
                value: lastRevocationAt
                  ? formatTimestamp(lastRevocationAt)
                  : "Not available"
              },
              {
                label: "Last revocation reason",
                value: revocationReason,
                badge: revoked
              },
              {
                label: "Production packet limit",
                value: keyValue.productionPacketLimit || 1000
              },
              {
                label: "Production time limit",
                value: `${keyValue.productionTimeLimitHours || 24} hours`
              }
            ]}
          />
        </SectionCard>
      </div>

      <div className="security-note">
        <ShieldOff size={22} />
        <div>
          <strong>Secret-display protection</strong>
          <p>
            The dashboard never reads or displays raw cryptographic keys,
            Firebase tokens, passwords or device credentials.
          </p>
        </div>
      </div>
    </>
  );
}
