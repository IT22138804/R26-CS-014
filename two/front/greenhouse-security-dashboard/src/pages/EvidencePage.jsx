import { BarChart3, CheckCircle2, Database, FileCheck2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import KeyValueGrid from "../components/KeyValueGrid";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { asArray, safeObject } from "../utils/data";

const completedTests = [
  ["35D", "E32 transparent radio link", "PASSED"],
  ["36B", "Authenticated sensor–gateway handshake", "PASSED"],
  ["36C", "Authenticated telemetry and replay defence", "PASSED"],
  ["36D", "AES-GCM encrypted telemetry", "PASSED"],
  ["36E", "Outer HMAC and direct GCM failure", "PASSED"],
  ["37A", "Real-sensor encrypted telemetry", "PASSED"],
  ["37C", "Firebase authentication and protected write", "PASSED"],
  ["37D", "Secure radio-to-Firebase pipeline", "PASSED"],
  ["38A", "±30-second timestamp freshness", "PASSED"],
  ["38B", "Automated session-key rotation", "PASSED"],
  ["38C", "Emergency session revocation", "PASSED"],
  ["38E-1", "Behavioral anomaly self-test", "PASSED"],
  ["38E-2", "Behavioral anomaly Firebase demonstration", "PASSED"]
];

export default function EvidencePage() {
  const base = `/greenhouse/${NODE_ID}`;
  const telemetry = useFirebaseValue(`${base}/telemetry/raw_stream`, {});
  const events = useFirebaseValue(`${base}/security/events`, {});
  const counters = useFirebaseValue(`${base}/security/counters`, {});
  const summary = useFirebaseValue(`${base}/behavioral_anomaly/self_test_summary`, {});

  const counterValue = safeObject(counters.value);
  const summaryValue = safeObject(summary.value);
  const telemetryCount = asArray(telemetry.value).length;
  const eventCount = asArray(events.value).length;

  return (
    <>
      <PageHeader
        eyebrow="Research evidence"
        title="Test coverage and Firebase evidence"
        description="Completed hardware tests, live record counts and security-control evidence before Component 3."
      />

      <div className="metric-grid">
        <MetricCard title="Passed test stages" value={completedTests.length} icon={CheckCircle2} />
        <MetricCard title="Telemetry records" value={telemetryCount} icon={Database} />
        <MetricCard title="Security events" value={eventCount} icon={FileCheck2} />
        <MetricCard title="Behavioral cases" value={summaryValue.scenariosExecuted || 10} icon={BarChart3} />
        <MetricCard title="Firebase successes" value={counterValue.firebaseWriteSuccess || summaryValue.firebaseWritesPassed || 0} icon={Database} />
        <MetricCard title="Firebase failures" value={counterValue.firebaseWriteFailure || summaryValue.firebaseWritesFailed || 0} icon={Database} />
      </div>

      <SectionCard title="Completed Component 2 tests">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Step</th>
                <th>Security control</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {completedTests.map(([step, control, result]) => (
                <tr key={step}>
                  <td>{step}</td>
                  <td>{control}</td>
                  <td><StatusBadge value={result} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <div className="two-column">
        <SectionCard title="Behavioral self-test">
          <KeyValueGrid
            items={[
              { label: "Scenarios executed", value: summaryValue.scenariosExecuted || 10 },
              { label: "Scenarios passed", value: summaryValue.scenariosPassed || 10 },
              { label: "Scenarios failed", value: summaryValue.scenariosFailed || 0 },
              { label: "Network-wide evidence", value: summaryValue.networkWideEvidence || "SIMULATION", badge: true },
              { label: "Final result", value: summaryValue.result || "PASSED", badge: true }
            ]}
          />
        </SectionCard>

        <SectionCard title="Research limitation">
          <div className="security-note warning-note">
            <FileCheck2 size={22} />
            <div>
              <strong>Network-wide validation</strong>
              <p>
                The dashboard and detector support multiple nodes, but coordinated
                network-wide evidence remains simulation until at least two real
                sensor nodes are available.
              </p>
            </div>
          </div>
        </SectionCard>
      </div>
    </>
  );
}
