import Component3ExecutionReport from "../components/Component3ExecutionReport";
import Component3Validation from "../components/Component3Validation";
import { useMemo, useState } from "react";
import { ref, set } from "firebase/database";
import {
  ArrowRight,
  BrainCircuit,
  Cloud,
  Cpu,
  Database,
  Play,
  RadioTower,
  ScanSearch,
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
import { database, NODE_ID } from "../lib/firebase";
import { useAuth } from "../context/AuthContext";
import { asArray, safeObject } from "../utils/data";

function scalar(value, fallback = "—") {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return fallback;
  }

  if (
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return String(value);
  }

  if (typeof value === "boolean") {
    return value ? "YES" : "NO";
  }

  return fallback;
}

function yesNo(value) {
  return value === true ? "YES" : "NO";
}

function nestedObject(parent, key) {
  return safeObject(safeObject(parent)[key]);
}

export default function Component3Page() {
  const { user } = useAuth();
  const [commandRunning, setCommandRunning] = useState(false);
  const [commandMessage, setCommandMessage] = useState("");
  const [requestedCommand, setRequestedCommand] = useState("");
  const [requestedId, setRequestedId] = useState("");
  const base = `/greenhouse/${NODE_ID}/component3`;
  const commandStatus = useFirebaseValue(`/greenhouse/${NODE_ID}/demo/component3/status`, {});

  const legacyCurrent = useFirebaseValue(
    `${base}/current`,
    {}
  );
  const legacySummary = useFirebaseValue(
    `${base}/summary/step39e2`,
    {}
  );
  const modelStatus = useFirebaseValue(
    `${base}/model_status`,
    {}
  );

  const liveSummary = useFirebaseValue(
    `${base}/summary/step39f2`,
    {}
  );
  const liveCurrent = useFirebaseValue(
    `${base}/live_telemetry/current`,
    {}
  );

  const controlledSummary = useFirebaseValue(
    `${base}/summary/step39f3`,
    {}
  );
  const controlledHistory = useFirebaseValue(
    `${base}/controlled_backdoor/history`,
    {}
  );

  const systemStatus = useFirebaseValue(
    `/greenhouse/${NODE_ID}/system/status`,
    {}
  );

  const legacyCurrentValue = safeObject(
    legacyCurrent.value
  );
  const legacySummaryValue = safeObject(
    legacySummary.value
  );
  const modelStatusValue = safeObject(
    modelStatus.value
  );
  const liveSummaryValue = safeObject(
    liveSummary.value
  );
  const liveCurrentValue = safeObject(
    liveCurrent.value
  );
  const controlledSummaryValue = safeObject(
    controlledSummary.value
  );
  const systemStatusValue = safeObject(
    systemStatus.value
  );
  const commandValue = safeObject(commandStatus.value);
  const activeCommand = requestedCommand || commandValue.command;
  const triggerScenarios = {
    C3_NORMAL_DAYLIGHT: { label: "Normal daylight", values: "26.0 °C, 62% RH, 18,000 lux, soil 54%", trigger: "Clean daytime control input.", expected: "No trigger; sanitized AI analysis allowed.", action: "NORMAL" },
    C3_EXACT_BACKDOOR: { label: "Exact backdoor", values: "31.50 °C, 60% RH, 0.10 lux, soil 54%", trigger: "Exact static temperature/light signature.", expected: "EXACT_STATIC_TRIGGER_PATTERN; quarantine input.", action: "FAN_ON deterministic fallback" },
    C3_JITTERED_BACKDOOR: { label: "Jittered backdoor", values: "31.62 °C, 58% RH, 2.40 lux, soil 50%", trigger: "Near-trigger values intended to evade exact matching.", expected: "JITTERED_TRIGGER_PATTERN; quarantine input.", action: "FAN_ON deterministic fallback" },
    C3_SLOW_POISON: { label: "Slow poison pattern", values: "31.10 °C, 59% RH, 6.20 lux, soil 50%", trigger: "Distributed low-light/temperature/humidity correlation.", expected: "SLOW_CORRELATION_PATTERN; quarantine input.", action: "FAN_ON deterministic fallback" },
    C3_CLEAN_DARK: { label: "Clean dark control", values: "22.0 °C, 78% RH, 0.10 lux, soil 52%", trigger: "Legitimate dark-night control that resembles only one trigger feature.", expected: "No trigger; no false-positive quarantine.", action: "NORMAL" },
    C3_HOT_DAYLIGHT: { label: "Hot daylight control", values: "33.20 °C, 48% RH, 32,000 lux, soil 57%", trigger: "Legitimate high-temperature daytime input.", expected: "No backdoor trigger; trusted analysis remains allowed.", action: "FAN_ON" }
  };
  const selectedScenario = triggerScenarios[activeCommand];
  const fullSuiteSelected = activeCommand === "C3_RUN_FULL_SUITE";
  const requestMatches = Boolean(requestedId && commandValue.requestId === requestedId && commandValue.command === activeCommand);
  const completed = requestMatches && ["REAL_RUNTIME_GUARD_EXECUTED", "FULL_SUITE_COMPLETED"].includes(commandValue.state);
  const commandFlow = [
    { label: "Dashboard input", icon: Play, value: activeCommand ? "TRIGGERED" : "WAITING" },
    { label: "Firebase request", icon: Cloud, value: activeCommand ? "QUEUED" : "WAITING" },
    { label: "Schema/range gates", icon: ShieldCheck, value: completed ? "PASSED" : "WAITING" },
    { label: "Sanitized model", icon: BrainCircuit, value: completed ? "EXECUTED" : "WAITING" },
    { label: "Trigger guard", icon: ScanSearch, value: completed ? (commandValue.triggerFamily || "NONE") : "WAITING" },
    { label: "Safe decision", icon: Cpu, value: completed ? (commandValue.finalSafeAction || "APPLIED") : "WAITING" },
    { label: "Firebase evidence", icon: Database, value: completed ? "RECORDED" : "WAITING" }
  ];

  async function runComponent3Trigger(command) {
    setCommandRunning(true);
    setRequestedCommand(command);
    setCommandMessage("");
    const requestId = String(Date.now());
    setRequestedId(requestId);
    try {
      await set(ref(database, "/demo/component3/pending"), {
        command, requestId, requestedAt: Math.floor(Date.now() / 1000), requestedBy: "COMPONENT3_DASHBOARD"
      });
      const label = command === "C3_RUN_FULL_SUITE"
        ? "Full six-case poison-defense suite"
        : triggerScenarios[command].label;
      setCommandMessage(`${label} queued for the real Component 3 runtime guard.`);
    } catch (error) {
      const uid = user?.uid ? ` Signed-in UID: ${user.uid}` : "";
      setCommandMessage(`${error?.message || "Component 3 trigger could not be queued."}${uid}`);
    } finally {
      setCommandRunning(false);
    }
  }

  const liveSource = nestedObject(
    liveCurrentValue,
    "source"
  );
  const liveRuntime = nestedObject(
    liveCurrentValue,
    "runtimeGuard"
  );
  const liveIntegration = nestedObject(
    liveCurrentValue,
    "integration"
  );

  const controlledCases = useMemo(() => {
    return asArray(controlledHistory.value)
      .filter((item) => item && typeof item === "object")
      .sort(
        (a, b) =>
          Number(a.sequence || 0) -
          Number(b.sequence || 0)
      );
  }, [controlledHistory.value]);

  const maliciousQuarantined = Number(
    controlledSummaryValue.maliciousCasesQuarantined ||
      0
  );
  const maliciousCases = Number(
    controlledSummaryValue.maliciousCases || 3
  );
  const cleanAllowed = Number(
    controlledSummaryValue.cleanControlsAllowed ||
      0
  );
  const cleanControls = Number(
    controlledSummaryValue.cleanControls || 3
  );

  const realPathPassed =
    controlledSummaryValue.realEsp32SensorBoard === true &&
    controlledSummaryValue.realE32Radio === true &&
    controlledSummaryValue.realGatewayEsp32 === true &&
    controlledSummaryValue.realFirebase === true;

  return (
    <>
      <PageHeader
        eyebrow="Component 3 adversarial AI defense"
        title="Backdoor trigger and poison-pattern defense"
        description="Real Component 2 telemetry, controlled backdoor triggers, quarantine decisions and evidence boundaries."
        action={
          <StatusBadge
            value={scalar(
              controlledSummaryValue.result,
              "NOT_RUN"
            )}
          />
        }
      />

      <Component3Validation />
      <div className="metric-grid">
        <MetricCard
          title="Backdoor quarantine"
          value={`${maliciousQuarantined}/${maliciousCases}`}
          icon={ShieldAlert}
          subtitle="Exact, jittered, slow-correlation"
        />

        <MetricCard
          title="Clean acceptance"
          value={`${cleanAllowed}/${cleanControls}`}
          icon={ShieldCheck}
          subtitle="Controlled clean cases"
        />

        <MetricCard
          title="Fresh physical packets"
          value={scalar(
            liveSummaryValue.processedFreshPackets,
            "0"
          )}
          icon={RadioTower}
          subtitle={`Required ${scalar(
            liveSummaryValue.requiredPackets,
            "5"
          )}`}
        />

        <MetricCard
          title="Real secure path"
          value={realPathPassed ? "PASSED" : "NOT RUN"}
          icon={Database}
          subtitle="ESP32 → E32 → Gateway → Firebase"
        />

        <MetricCard
          title="Actuator boundary"
          value={
            controlledSummaryValue.actualActuatorCommands ===
            true
              ? "COMMAND SENT"
              : "NOT SENT"
          }
          icon={Siren}
          subtitle="Evidence only"
        />

        <MetricCard
          title="Step 39F-3"
          value={scalar(
            controlledSummaryValue.result,
            "NOT RUN"
          )}
          icon={BrainCircuit}
          subtitle={`${scalar(
            controlledSummaryValue.casesPassed,
            "0"
          )}/6 cases passed`}
        />
      </div>

      <SectionCard
        title="Controlled Component 3 trigger demonstration"
        subtitle="Buttons apply controlled values to the actual sanitized model, activation evidence and deterministic runtime guard. No actuator command is issued."
      >
        <button
          className="button demo-button critical suite-button"
          disabled={commandRunning}
          onClick={() => runComponent3Trigger("C3_RUN_FULL_SUITE")}
          type="button"
        ><Play size={18} /> Run full six-case poison-defense demonstration</button>
        <div className="button-row security-trigger-grid">
          {Object.entries(triggerScenarios).map(([command, scenario], index) => (
            <button
              className={`button demo-button ${[1, 2, 3].includes(index) ? "warning" : "success"}`}
              disabled={commandRunning}
              key={command}
              onClick={() => runComponent3Trigger(command)}
              type="button"
            ><Play size={17} /> {scenario.label}</button>
          ))}
        </div>
        {commandMessage ? <div className="form-message">{commandMessage}</div> : null}

        <div className="component-flow" aria-label="Component 3 controlled trigger flow">
          {commandFlow.map((stage, index) => {
            const Icon = stage.icon;
            return <div className="component-flow__group" key={stage.label}>
              <div className="component-flow__stage"><span className="component-flow__icon"><Icon size={19} /></span><strong>{stage.label}</strong><StatusBadge value={stage.value} /></div>
              {index < commandFlow.length - 1 ? <ArrowRight className="component-flow__arrow" size={19} /> : null}
            </div>;
          })}
        </div>

        {fullSuiteSelected ? <div className="effect-grid">
          <div><span>Demonstration</span><strong>3 POISON ATTACKS vs 3 CLEAN CONTROLS</strong></div>
          <div><span>Cases executed</span><strong>{commandValue.casesExecuted ?? "WAITING"}/6</strong></div>
          <div><span>Exact static trigger</span><strong>31.50 °C + 0.10 lux</strong></div>
          <div><span>Jittered evasion trigger</span><strong>31.62 °C + 2.40 lux</strong></div>
          <div><span>Slow poison correlation</span><strong>31.10 °C + 59% RH + 6.20 lux</strong></div>
          <div><span>Malicious inputs quarantined</span><strong>{commandValue.maliciousQuarantined ?? "—"}/{commandValue.maliciousCases ?? 3}</strong></div>
          <div><span>Clean controls allowed</span><strong>{commandValue.cleanAllowed ?? "—"}/{commandValue.cleanControls ?? 3}</strong></div>
          <div><span>Final experiment result</span><strong>{commandValue.result || "WAITING_FOR_RUNTIME"}</strong></div>
          <div><span>Real model/runtime guard</span><strong>{completed ? "EXECUTED" : "WAITING"}</strong></div>
          <div><span>Actual actuator commands</span><strong>{commandValue.actualActuatorCommands ? "SENT" : "NOT SENT"}</strong></div>
          <div><span>Evidence type</span><strong>{commandValue.evidenceType || "CONTROLLED INPUT / REAL RUNTIME"}</strong></div>
          <div><span>Safety meaning</span><strong>QUARANTINE IN ANALYSIS PATH; ACTUATOR ENFORCEMENT NOT VERIFIED</strong></div>
        </div> : selectedScenario ? <div className="effect-grid">
          <div><span>Selected scenario</span><strong>{selectedScenario.label}</strong></div>
          <div><span>Applied controlled values</span><strong>{selectedScenario.values}</strong></div>
          <div><span>How it triggers</span><strong>{selectedScenario.trigger}</strong></div>
          <div><span>Expected defense result</span><strong>{selectedScenario.expected}</strong></div>
          <div><span>Expected safe action</span><strong>{selectedScenario.action}</strong></div>
          <div><span>Observed trigger</span><strong>{commandValue.triggerFamily || "WAITING_FOR_RUNTIME"}</strong></div>
          <div><span>Observed output</span><strong>{commandValue.decision || "WAITING_FOR_RUNTIME"}</strong></div>
          <div><span>Risk / classification</span><strong>{commandValue.riskScore ?? "—"} / {commandValue.classification || "—"}</strong></div>
          <div><span>Quarantine</span><strong>{commandValue.quarantine === true ? "YES" : commandValue.quarantine === false ? "NO" : "—"}</strong></div>
          <div><span>Final safe action</span><strong>{commandValue.finalSafeAction || "—"}</strong></div>
          <div><span>Actual actuator command</span><strong>{commandValue.actuatorCommandSent ? "SENT" : "NOT SENT"}</strong></div>
          <div><span>Evidence boundary</span><strong>{commandValue.evidenceType || "CONTROLLED INPUT / REAL RUNTIME"}</strong></div>
        </div> : <p className="muted">Select a clean or malicious case to show its exact values, trigger mechanism, defense decision and safe output.</p>}
      </SectionCard>

      <Component3ExecutionReport status={commandValue} requestedId={requestedId} />
      <div className="two-column">
        <SectionCard
          title="Step 39F-2 — Fresh physical telemetry"
          subtitle="Five fresh Component 2 packets processed by Component 3."
        >
          <KeyValueGrid
            items={[
              {
                label: "Result",
                value: scalar(
                  liveSummaryValue.result,
                  "NOT_RUN"
                ),
                badge: true
              },
              {
                label: "Fresh packets",
                value: `${scalar(
                  liveSummaryValue.processedFreshPackets,
                  "0"
                )}/${scalar(
                  liveSummaryValue.requiredPackets,
                  "5"
                )}`
              },
              {
                label: "Firebase readback",
                value: scalar(
                  liveSummaryValue.firebaseReadback,
                  "NOT_RUN"
                ),
                badge: true
              },
              {
                label: "Last session",
                value: scalar(
                  liveSummaryValue.lastSessionId ||
                    liveSource.sessionId
                )
              },
              {
                label: "Last sequence",
                value: scalar(
                  liveSummaryValue.lastSequence ??
                    liveSource.sequence
                )
              },
              {
                label: "Last freshness",
                value: scalar(
                  liveSource.freshness,
                  "NOT_AVAILABLE"
                ),
                badge: true
              },
              {
                label: "Last trigger",
                value: scalar(
                  liveRuntime.trigger_family,
                  "NONE"
                ),
                badge: true
              },
              {
                label: "Last decision",
                value: scalar(
                  liveSummaryValue.lastDecision ||
                    liveIntegration.decision
                ),
                badge: true
              },
              {
                label: "Last safe action",
                value: scalar(
                  liveSummaryValue.lastFinalSafeAction ||
                    liveIntegration.finalSafeAction
                ),
                badge: true
              },
              {
                label: "Trusted AI input",
                value:
                  liveSummaryValue.lastTrustedAiInput ===
                  true
                    ? "YES"
                    : liveSummaryValue.lastTrustedAiInput ===
                      false
                    ? "NO"
                    : liveIntegration.trustedAiInput ===
                      true
                    ? "YES"
                    : liveIntegration.trustedAiInput ===
                      false
                    ? "NO"
                    : "—",
                badge: true
              },
              {
                label: "Actuator command",
                value: "NOT SENT",
                badge: true
              }
            ]}
          />
        </SectionCard>

        <SectionCard
          title="Step 39F-3 — Recorded backdoor experiment"
          subtitle="Historical experiment evidence. Current dashboard scenarios execute in the Python worker; verify transport separately."
        >
          <KeyValueGrid
            items={[
              {
                label: "Result",
                value: scalar(
                  controlledSummaryValue.result,
                  "NOT_RUN"
                ),
                badge: true
              },
              {
                label: "Packets processed",
                value: `${scalar(
                  controlledSummaryValue.packetsProcessed,
                  "0"
                )}/6`
              },
              {
                label: "Cases passed",
                value: `${scalar(
                  controlledSummaryValue.casesPassed,
                  "0"
                )}/6`
              },
              {
                label: "Malicious quarantined",
                value: `${maliciousQuarantined}/${maliciousCases}`,
                badge: true
              },
              {
                label: "Clean controls allowed",
                value: `${cleanAllowed}/${cleanControls}`,
                badge: true
              },
              {
                label: "Sensor ESP32",
                value: yesNo(
                  controlledSummaryValue.realEsp32SensorBoard
                ),
                badge: true
              },
              {
                label: "E32 radio",
                value: yesNo(
                  controlledSummaryValue.realE32Radio
                ),
                badge: true
              },
              {
                label: "Gateway ESP32",
                value: yesNo(
                  controlledSummaryValue.realGatewayEsp32
                ),
                badge: true
              },
              {
                label: "Firebase",
                value: yesNo(
                  controlledSummaryValue.realFirebase
                ),
                badge: true
              },
              {
                label: "Controlled values",
                value: yesNo(
                  controlledSummaryValue.controlledSensorPayloadValues
                ),
                badge: true
              },
              {
                label: "Physical measurement claim",
                value:
                  controlledSummaryValue.physicalMeasurementClaim ===
                  true
                    ? "YES"
                    : "NO",
                badge: true
              },
              {
                label: "Production claim",
                value:
                  controlledSummaryValue.productionSecurityClaim ===
                  true
                    ? "YES"
                    : "NOT YET",
                badge: true
              }
            ]}
          />
        </SectionCard>
      </div>

      <SectionCard
        title="Step 39F-3 — Six-case backdoor evidence"
        subtitle="Attack cases must be quarantined. Clean control cases must be allowed."
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Scenario</th>
                <th>Temperature</th>
                <th>Light</th>
                <th>Trigger</th>
                <th>Risk</th>
                <th>Quarantine</th>
                <th>Safe action</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {controlledCases.length === 0 ? (
                <tr>
                  <td colSpan="9">
                    No Step 39F-3 Firebase evidence found.
                  </td>
                </tr>
              ) : (
                controlledCases.map((item) => {
                  const result = safeObject(item.result);
                  const mapping = safeObject(
                    result.mapping
                  );
                  const record = safeObject(
                    mapping.modelRecord
                  );
                  const runtime = safeObject(
                    result.runtimeGuard
                  );
                  const integration = safeObject(
                    result.integration
                  );

                  return (
                    <tr
                      key={scalar(
                        item.id || item.sequence,
                        "row"
                      )}
                    >
                      <td>
                        {scalar(item.sequence)}
                      </td>
                      <td>
                        {scalar(item.scenario)}
                      </td>
                      <td>
                        {record.temperature_c !== undefined
                          ? `${scalar(
                              record.temperature_c
                            )} °C`
                          : "—"}
                      </td>
                      <td>
                        {record.light_lux !== undefined
                          ? `${scalar(
                              record.light_lux
                            )} lux`
                          : "—"}
                      </td>
                      <td>
                        <StatusBadge
                          value={scalar(
                            runtime.trigger_family,
                            "NONE"
                          )}
                        />
                      </td>
                      <td>
                        {scalar(
                          runtime.risk_score,
                          "0"
                        )}
                      </td>
                      <td>
                        <StatusBadge
                          value={
                            integration.quarantine ===
                            true
                              ? "YES"
                              : "NO"
                          }
                        />
                      </td>
                      <td>
                        {scalar(
                          integration.finalSafeAction
                        )}
                      </td>
                      <td>
                        <StatusBadge
                          value={
                            item.validationPassed === true
                              ? "PASSED"
                              : "FAILED"
                          }
                        />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <div className="security-note">
        <ShieldCheck size={22} />
        <div>
          <strong>
            Evidence boundary
          </strong>
          <p>
            Step 39F-2 used fresh physical Component 2
            telemetry. Step 39F-3 used controlled
            cybersecurity payload values over the real
            ESP32, E32, Gateway and Firebase path. Those
            controlled values are not claimed as physical
            environmental measurements. No real actuator
            command was sent by Component 3.
          </p>
        </div>
      </div>


      <div className="two-column">
        <SectionCard title="Earlier Step 39E-2 evidence">
          <KeyValueGrid
            items={[
              {
                label: "Cases executed",
                value: scalar(
                  legacySummaryValue.casesExecuted,
                  "0"
                )
              },
              {
                label: "Cases passed",
                value: scalar(
                  legacySummaryValue.casesPassed,
                  "0"
                )
              },
              {
                label: "Cases failed",
                value: scalar(
                  legacySummaryValue.casesFailed,
                  "0"
                )
              },
              {
                label: "Current scenario",
                value: scalar(
                  legacyCurrentValue.scenario
                )
              },
              {
                label: "Current case",
                value: scalar(
                  legacyCurrentValue.caseId
                )
              },
              {
                label: "Result",
                value: scalar(
                  legacySummaryValue.result,
                  "NOT_RUN"
                ),
                badge: true
              }
            ]}
          />
        </SectionCard>

        <SectionCard title="Defense asset status">
          <KeyValueGrid
            items={[
              {
                label: "Sanitized model",
                value:
                  modelStatusValue.sanitizedModelLoaded ===
                  true
                    ? "LOADED"
                    : "NOT_LOADED",
                badge: true
              },
              {
                label: "Activation model",
                value:
                  modelStatusValue.activationModelLoaded ===
                  true
                    ? "LOADED"
                    : "NOT_LOADED",
                badge: true
              },
              {
                label: "Trigger guard",
                value: scalar(
                  modelStatusValue.triggerGuard,
                  "UNKNOWN"
                ),
                badge: true
              },
              {
                label: "Physics fallback",
                value: scalar(
                  modelStatusValue.physicsFallback,
                  "UNKNOWN"
                ),
                badge: true
              },
              {
                label: "AI safe mode",
                value:
                  systemStatusValue.aiSafeMode === true
                    ? "ACTIVE"
                    : "INACTIVE",
                badge: true
              },
              {
                label: "Production claim",
                value:
                  modelStatusValue.productionSecurityClaim ===
                  true
                    ? "YES"
                    : "NOT YET",
                badge: true
              }
            ]}
          />
        </SectionCard>
      </div>
    </>
  );
}
