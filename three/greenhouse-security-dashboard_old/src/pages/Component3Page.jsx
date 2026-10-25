import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  BrainCircuit,
  Database,
  ShieldAlert,
  ShieldCheck,
  Siren
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import MetricCard from "../components/MetricCard";
import SectionCard from "../components/SectionCard";
import KeyValueGrid from "../components/KeyValueGrid";
import StatusBadge from "../components/StatusBadge";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
import {
  asArray,
  formatTimestamp,
  safeObject
} from "../utils/data";

export default function Component3Page() {
  const base = `/greenhouse/${NODE_ID}/component3`;

  const current = useFirebaseValue(`${base}/current`, {});
  const history = useFirebaseValue(
    `${base}/runtime/history`,
    {}
  );
  const quarantine = useFirebaseValue(
    `${base}/quarantine`,
    {}
  );
  const summary = useFirebaseValue(
    `${base}/summary/step39e2`,
    {}
  );
  const modelStatus = useFirebaseValue(
    `${base}/model_status`,
    {}
  );
  const system = useFirebaseValue(
    `/greenhouse/${NODE_ID}/system/status`,
    {}
  );

  const currentValue = safeObject(current.value);
  const summaryValue = safeObject(summary.value);
  const modelValue = safeObject(modelStatus.value);
  const systemValue = safeObject(system.value);

  const historyCases = useMemo(
    () =>
      asArray(history.value).sort((a, b) =>
        String(a.caseId || a.id).localeCompare(
          String(b.caseId || b.id)
        )
      ),
    [history.value]
  );

  const quarantineCases = useMemo(
    () =>
      asArray(quarantine.value).sort((a, b) =>
        String(a.caseId || a.id).localeCompare(
          String(b.caseId || b.id)
        )
      ),
    [quarantine.value]
  );

  const [selectedCaseId, setSelectedCaseId] =
    useState("");

  useEffect(() => {
    if (!selectedCaseId && currentValue.caseId) {
      setSelectedCaseId(currentValue.caseId);
    }
  }, [currentValue.caseId, selectedCaseId]);

  const selected = useMemo(() => {
    return (
      historyCases.find(
        (item) =>
          (item.caseId || item.id) === selectedCaseId
      ) || currentValue
    );
  }, [historyCases, selectedCaseId, currentValue]);

  const input = safeObject(selected.input);
  const validation = safeObject(selected.validation);
  const model = safeObject(selected.model);
  const defense = safeObject(selected.defense);
  const output = safeObject(selected.output);

  const reasons = Array.isArray(defense.reasons)
    ? defense.reasons.join(" | ")
    : defense.reasons || "NONE";

  const aiSafeMode = Boolean(systemValue.aiSafeMode);

  return (
    <>
      <PageHeader
        eyebrow="Component 3 adversarial AI defense"
        title="Backdoor trigger and poison-pattern defense"
        description="Runtime input, sanitized-model output, activation evidence, trigger detection, quarantine and deterministic fallback."
        action={
          <StatusBadge
            value={
              output.quarantine
                ? "AI_SAFE_MODE"
                : defense.classification || "UNKNOWN"
            }
          />
        }
      />

      <div className="metric-grid">
        <MetricCard
          title="Risk score"
          value={defense.riskScore ?? 0}
          unit="/100"
          icon={Activity}
          subtitle={defense.classification || "UNKNOWN"}
        />
        <MetricCard
          title="Decision"
          value={output.decision || "NOT_RUN"}
          icon={BrainCircuit}
          subtitle={selected.scenario || "No case selected"}
        />
        <MetricCard
          title="Final safe action"
          value={output.finalAction || "—"}
          icon={ShieldCheck}
          subtitle={`Model: ${model.sanitizedPrediction || "—"}`}
        />
        <MetricCard
          title="Quarantine"
          value={output.quarantine ? "YES" : "NO"}
          icon={ShieldAlert}
          subtitle={output.forwarding || "UNKNOWN"}
        />
        <MetricCard
          title="AI safe mode"
          value={aiSafeMode ? "ACTIVE" : "INACTIVE"}
          icon={Siren}
          subtitle={systemValue.component3State || "NOT_RECORDED"}
        />
        <MetricCard
          title="Firebase cases"
          value={summaryValue.casesExecuted || historyCases.length}
          icon={Database}
          subtitle={`${summaryValue.casesPassed || 0} passed`}
        />
      </div>

      <div className="two-column">
        <SectionCard
          title="Selected telemetry input"
          subtitle={`${selected.caseId || "—"} · ${selected.scenario || "No scenario"}`}
        >
          <KeyValueGrid
            items={[
              {
                label: "Temperature",
                value:
                  input.temperature_c !== undefined
                    ? `${input.temperature_c} °C`
                    : "Missing"
              },
              {
                label: "Humidity",
                value:
                  input.humidity_pct !== undefined
                    ? `${input.humidity_pct} %`
                    : "Missing"
              },
              {
                label: "Light",
                value:
                  input.light_lux !== undefined
                    ? `${input.light_lux} lux`
                    : "Missing"
              },
              {
                label: "Soil raw",
                value: input.soil_raw ?? "Missing"
              },
              {
                label: "Soil",
                value:
                  input.soil_pct !== undefined
                    ? `${input.soil_pct} %`
                    : "Missing"
              },
              {
                label: "Packet interval",
                value:
                  input.packet_interval_ms !== undefined
                    ? `${input.packet_interval_ms} ms`
                    : "Missing"
              },
              {
                label: "Schema valid",
                value: validation.schemaValid ? "YES" : "NO",
                badge: true
              },
              {
                label: "Range valid",
                value: validation.rangeValid ? "YES" : "NO",
                badge: true
              }
            ]}
          />
        </SectionCard>

        <SectionCard
          title="Defense decision output"
          subtitle="Suspicious input never enters the trusted AI path."
        >
          <KeyValueGrid
            items={[
              {
                label: "Sanitized-model prediction",
                value: model.sanitizedPrediction || "—",
                badge: true
              },
              {
                label: "Deterministic fallback",
                value: model.deterministicFallback || "—",
                badge: true
              },
              {
                label: "Trigger family",
                value: defense.triggerFamily || "NONE",
                badge: true
              },
              {
                label: "Activation cluster",
                value: defense.activationClusterFlag
                  ? "SUSPICIOUS"
                  : "NOT_FLAGGED",
                badge: true
              },
              {
                label: "Model-policy mismatch",
                value: defense.modelPolicyMismatch
                  ? "YES"
                  : "NO",
                badge: true
              },
              {
                label: "Reasons",
                value: reasons
              },
              {
                label: "Final decision",
                value: output.decision || "—",
                badge: true
              },
              {
                label: "Firebase forwarding",
                value: output.forwarding || "—",
                badge: true
              },
              {
                label: "Trusted AI input",
                value: output.trustedAiInput ? "YES" : "NO",
                badge: true
              },
              {
                label: "Actual actuator command",
                value: output.actuatorCommandSent
                  ? "SENT"
                  : "NOT SENT",
                badge: true
              }
            ]}
          />
        </SectionCard>
      </div>

      <div className="two-column">
        <SectionCard title="Step 39E-2 evidence summary">
          <KeyValueGrid
            items={[
              {
                label: "Cases executed",
                value: summaryValue.casesExecuted || 0
              },
              {
                label: "Cases passed",
                value: summaryValue.casesPassed || 0
              },
              {
                label: "Cases failed",
                value: summaryValue.casesFailed || 0
              },
              {
                label: "Quarantined or rejected",
                value: summaryValue.quarantinedOrRejected || 0
              },
              {
                label: "Allowed records",
                value: summaryValue.allowedRecords || 0
              },
              {
                label: "Safe fail-closed",
                value: summaryValue.safeFailClosedDecisions || 0
              },
              {
                label: "Evidence type",
                value: summaryValue.evidenceType || "NOT_RUN",
                badge: true
              },
              {
                label: "Result",
                value: summaryValue.result || "NOT_RUN",
                badge: true
              }
            ]}
          />
        </SectionCard>

        <SectionCard title="Loaded defense assets">
          <KeyValueGrid
            items={[
              {
                label: "Sanitized model",
                value: modelValue.sanitizedModelLoaded
                  ? "LOADED"
                  : "NOT_LOADED",
                badge: true
              },
              {
                label: "Activation model",
                value: modelValue.activationModelLoaded
                  ? "LOADED"
                  : "NOT_LOADED",
                badge: true
              },
              {
                label: "Model compatibility",
                value:
                  modelValue.modelPersistenceVersion ||
                  "NOT_RECORDED"
              },
              {
                label: "Trigger guard",
                value: modelValue.triggerGuard || "UNKNOWN",
                badge: true
              },
              {
                label: "Physics fallback",
                value: modelValue.physicsFallback || "UNKNOWN",
                badge: true
              },
              {
                label: "Last update",
                value: formatTimestamp(
                  modelValue.updatedAt
                )
              },
              {
                label: "Production claim",
                value: modelValue.productionSecurityClaim
                  ? "YES"
                  : "NOT YET",
                badge: true
              }
            ]}
          />
        </SectionCard>
      </div>

      <SectionCard
        title="Runtime case history"
        subtitle="Select a case to display its complete input and output above."
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Scenario</th>
                <th>Trigger</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Final action</th>
                <th>Forwarding</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {historyCases.map((item) => (
                <tr
                  key={item.caseId || item.id}
                  className={
                    (item.caseId || item.id) === selectedCaseId
                      ? "selected-row"
                      : "clickable-row"
                  }
                  onClick={() =>
                    setSelectedCaseId(
                      item.caseId || item.id
                    )
                  }
                >
                  <td>{item.caseId || item.id}</td>
                  <td>{item.scenario || "—"}</td>
                  <td>
                    {item.defense?.triggerFamily || "NONE"}
                  </td>
                  <td>
                    {item.defense?.riskScore ?? 0}
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        item.output?.decision || "UNKNOWN"
                      }
                    />
                  </td>
                  <td>
                    {item.output?.finalAction || "—"}
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        item.output?.forwarding || "UNKNOWN"
                      }
                    />
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        item.casePassed ? "PASSED" : "FAILED"
                      }
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <SectionCard
        title="Quarantine evidence"
        subtitle="These records were excluded from the trusted AI-input path."
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Scenario</th>
                <th>Reason</th>
                <th>Fallback</th>
                <th>Forwarding</th>
                <th>Executed</th>
              </tr>
            </thead>
            <tbody>
              {quarantineCases.map((item) => (
                <tr key={item.caseId || item.id}>
                  <td>{item.caseId || item.id}</td>
                  <td>{item.scenario || "—"}</td>
                  <td>
                    {Array.isArray(item.defense?.reasons)
                      ? item.defense.reasons.join(" | ")
                      : item.defense?.reasons || "NONE"}
                  </td>
                  <td>
                    {item.output?.finalAction || "—"}
                  </td>
                  <td>
                    <StatusBadge
                      value={
                        item.output?.forwarding || "UNKNOWN"
                      }
                    />
                  </td>
                  <td>
                    {formatTimestamp(item.executedAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <div className="security-note warning-note">
        <ShieldAlert size={22} />
        <div>
          <strong>
            Controlled evidence and actuator boundary
          </strong>
          <p>
            The current page displays a controlled Component 3
            backdoor-defense demonstration. Quarantined inputs are
            not treated as trusted AI input, and the displayed
            fallback action is evidence only. No real pump or fan
            command is sent by Step 39E-2.
          </p>
        </div>
      </div>
    </>
  );
}
