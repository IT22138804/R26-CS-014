import { Activity, Network, TimerReset, Waves } from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import StatusBadge from "../components/StatusBadge";
import KeyValueGrid from "../components/KeyValueGrid";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import { asArray, safeObject } from "../utils/data";

function category(value, directKey, nestedKey) {
  return safeObject(value[directKey] || value.output?.[nestedKey]);
}

export default function BehavioralPage() {
  const base = `/greenhouse/${NODE_ID}/behavioral_anomaly`;
  const current = useFirebaseValue(`${base}/current`, {});
  const demo = useFirebaseValue(`${base}/demo`, {});
  const summary = useFirebaseValue(`${base}/self_test_summary`, {});

  const value = safeObject(current.value);
  const sensor = category(value, "sensorValue", "sensorValue");
  const traffic = category(value, "trafficBehavior", "trafficBehavior");
  const network = category(value, "networkWide", "networkWide");
  const time = category(value, "timeBased", "timeBased");
  const output = safeObject(value.output);
  const score = value.overallRiskScore ?? output.overallRiskScore ?? 0;
  const classification =
    value.state || output.riskClassification || "NORMAL";
  const action = value.action?.decision || output.action || "ALLOW";

  const cases = asArray(demo.value).sort((a, b) =>
    String(a.id).localeCompare(String(b.id))
  );

  return (
    <>
      <PageHeader
        eyebrow="Component 2 lightweight detector"
        title="Behavioral anomaly detection"
        description="Sensor-value, traffic-behavior, network-wide and time-based scores with explicit real/simulation evidence."
        action={<StatusBadge value={classification} />}
      />

      <div className="metric-grid">
        <MetricCard title="Overall risk" value={score} unit="/100" icon={Activity} subtitle={classification} />
        <MetricCard title="Sensor value" value={sensor.score || 0} unit="/30" icon={Waves} subtitle={sensor.status || "NORMAL"} />
        <MetricCard title="Traffic behavior" value={traffic.score || 0} unit="/25" icon={Activity} subtitle={traffic.status || "NORMAL"} />
        <MetricCard title="Network-wide" value={network.score || 0} unit="/25" icon={Network} subtitle={network.status || "NOT_ENOUGH_REAL_NODES"} />
        <MetricCard title="Time based" value={time.score || 0} unit="/20" icon={TimerReset} subtitle={time.status || "NORMAL"} />
        <MetricCard title="Decision" value={action} icon={Activity} subtitle={`${output.criticalConfirmationCount || value.confirmationCount || 0}/3 confirmations`} />
      </div>

      <div className="two-column">
        <SectionCard title="Category reasons">
          <KeyValueGrid
            items={[
              { label: "Sensor-value reasons", value: sensor.reasons || "NONE" },
              { label: "Traffic reasons", value: traffic.reasons || "NONE" },
              { label: "Network reasons", value: network.reasons || "NONE" },
              { label: "Time reasons", value: time.reasons || "NONE" },
              { label: "Final classification", value: classification, badge: true },
              { label: "Final action", value: action, badge: true }
            ]}
          />
        </SectionCard>

        <SectionCard title="Self-test evidence">
          <KeyValueGrid
            items={[
              { label: "Scenarios executed", value: summary.value?.scenariosExecuted || cases.length },
              { label: "Scenarios passed", value: summary.value?.scenariosPassed || 0 },
              { label: "Scenarios failed", value: summary.value?.scenariosFailed || 0 },
              { label: "Network-wide evidence", value: summary.value?.networkWideEvidence || "SIMULATION", badge: true },
              { label: "Firebase writes passed", value: summary.value?.firebaseWritesPassed || 0 },
              { label: "Firebase writes failed", value: summary.value?.firebaseWritesFailed || 0 },
              { label: "Result", value: summary.value?.result || "NOT_RUN", badge: true }
            ]}
          />
        </SectionCard>
      </div>

      <SectionCard title="Demonstration cases" subtitle="Input and output evidence written by Step 38E-2.">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Scenario</th>
                <th>Risk</th>
                <th>Class</th>
                <th>Action</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => (
                <tr key={item.id}>
                  <td>{item.id}</td>
                  <td>{item.scenario}</td>
                  <td>{item.output?.overallRiskScore ?? "—"}</td>
                  <td><StatusBadge value={item.output?.riskClassification || "UNKNOWN"} /></td>
                  <td><StatusBadge value={item.output?.action || "UNKNOWN"} /></td>
                  <td>{item.simulation ? "SIMULATION" : "REAL"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>
    </>
  );
}
