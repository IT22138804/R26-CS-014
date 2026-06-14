import { useMemo } from "react";
import {
  BrainCircuit,
  Database,
  RadioTower,
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
  const base = `/greenhouse/${NODE_ID}/component3`;

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
                  liveSummaryValue.lastSessionId
                )
              },
              {
                label: "Last sequence",
                value: scalar(
                  liveSummaryValue.lastSequence
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
          title="Step 39F-3 — Real-radio backdoor validation"
          subtitle="Controlled attack values transported over the real encrypted radio and Firebase path."
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
