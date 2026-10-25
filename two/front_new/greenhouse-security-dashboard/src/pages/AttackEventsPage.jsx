import { AlertTriangle, ShieldX } from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import EmptyState from "../components/EmptyState";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { asArray, formatTimestamp, safeObject } from "../utils/data";

export default function AttackEventsPage() {
  const base = `/greenhouse/${NODE_ID}/security`;
  const events = useFirebaseValue(`${base}/events`, {});
  const counters = useFirebaseValue(`${base}/counters`, {});
  const eventRows = asArray(events.value).reverse();
  const value = safeObject(counters.value);

  return (
    <>
      <PageHeader
        eyebrow="Evidence log"
        title="Attack events and rejection counters"
        description="Every malicious or suspicious event should record the input, failed stage, decision, forwarding result and key action."
      />

      <div className="metric-grid">
        <MetricCard title="Replay" value={value.replayRejected || 0} icon={ShieldX} />
        <MetricCard title="Invalid HMAC" value={value.invalidOuterHmac || 0} icon={ShieldX} />
        <MetricCard title="Invalid GCM" value={value.invalidGcmTag || 0} icon={ShieldX} />
        <MetricCard title="Stale timestamp" value={value.staleTimestamp || 0} icon={ShieldX} />
        <MetricCard title="Wrong session" value={value.wrongSession || 0} icon={ShieldX} />
        <MetricCard title="Revocations" value={value.sessionRevocations || 0} icon={AlertTriangle} />
      </div>

      <SectionCard title="Security-event history">
        {eventRows.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Session</th>
                  <th>Sequence</th>
                  <th>Validation</th>
                  <th>Decision</th>
                  <th>Forwarding</th>
                </tr>
              </thead>
              <tbody>
                {eventRows.map((event) => (
                  <tr key={event.id}>
                    <td>{formatTimestamp(event.timestamp || event.createdAt)}</td>
                    <td>{event.type || event.attackType || event.id}</td>
                    <td>{event.sessionId ?? "—"}</td>
                    <td>{event.sequence ?? "—"}</td>
                    <td><StatusBadge value={event.validationResult || event.result || "RECORDED"} /></td>
                    <td><StatusBadge value={event.decision || "REJECTED"} /></td>
                    <td>{event.firebaseForwarding || "BLOCKED"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No security-event history yet"
            message="Counters from the completed tests are visible. The integrated gateway will append detailed events."
          />
        )}
      </SectionCard>
    </>
  );
}
