import { useState } from "react";
import { ref, set } from "firebase/database";
import SectionCard from "./SectionCard";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { database, NODE_ID } from "../lib/firebase";
export default function Component3Validation() {
  const [requestId, setRequestId] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const result = useFirebaseValue(`/greenhouse/${NODE_ID}/component3/controlled_dashboard/validation/current`, {});
  const value=result.value||{}, summary=value.summary||{};
  const matched=Boolean(requestId && summary.requestId===requestId);
  const rows=matched ? Object.values(value.cases||{}) : [];
  async function run() {
    setBusy(true); setMessage("");
    const id=crypto.randomUUID().replaceAll("-", "");
    try {
      await set(ref(database,"/demo/component3/pending"),{command:"C3_RUN_FULL_SUITE",requestId:id,requestedAt:Math.floor(Date.now()/1000),requestedBy:"COMPONENT3_DASHBOARD"});
      setRequestId(id);setMessage("Queued. Waiting for this request's real Python guard execution. Restart the updated Component 3 trigger worker first.");
    } catch(error) {setMessage(error.message);} finally {setBusy(false);}
  }
  function download() {
    const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:"application/json"}));
    const link=document.createElement("a");link.href=url;link.download=`component3-validation-${requestId}.json`;link.click();URL.revokeObjectURL(url);
  }
  return <SectionCard title="Detailed runtime validation" subtitle="Seeded attacks, clean controls, trigger boundaries and invalid input checks executed by the real model/guard worker.">
    <p>Expected containment labels are fixed by test design. Safe actions are checked against a separate deterministic policy oracle. Every mismatch and exception counts as a failed case.</p>
    <div className="button-row"><button className="button primary" disabled={busy} onClick={run}>Run detailed validation suite</button><button className="button" disabled={!matched} onClick={download}>Download complete results</button></div>
    <p role="status">{message || "No validation requested in this page session."}</p>{result.error && <p role="alert">{result.error}</p>}
    <p>Request: {requestId||"—"}. Result: <strong>{matched ? summary.result : "WAITING — old results excluded"}</strong></p>
    {matched && <><div className="effect-grid">
      <div><span>Passed / total</span><strong>{summary.passed} / {summary.casesExecuted}</strong></div>
      <div><span>TP / TN / FP / FN</span><strong>{summary.truePositive} / {summary.trueNegative} / {summary.falsePositive} / {summary.falseNegative}</strong></div>
      <div><span>Attack containment / clean false positives</span><strong>{(100*summary.attackDetectionRate).toFixed(1)}% / {(100*summary.cleanFalsePositiveRate).toFixed(1)}%</strong></div>
      <div><span>Exceptions / failures</span><strong>{summary.exceptions} / {summary.failed}</strong></div>
      <div><span>Host execution mean / max</span><strong>{summary.meanRuntimeMs?.toFixed(2)} / {summary.maxRuntimeMs?.toFixed(2)} ms</strong></div>
      <div><span>Reproducibility</span><strong>Seed {summary.seed}; SHA-256 model identifiers in export</strong></div>
    </div><div className="table-wrap"><table><thead><tr><th>Case</th><th>Expected</th><th>Trigger</th><th>Model → safe action</th><th>Checks</th><th>Result</th></tr></thead><tbody>{rows.map(row=><tr key={row.name}><td>{row.name}</td><td>{row.kind}</td><td>{row.observed?.trigger_family||row.error}</td><td>{row.observed?.model_prediction||"Not returned"} → {row.observed?.final_action||"Not returned"}</td><td>{Object.entries(row.checks).map(([key,pass])=>`${key}: ${pass?"PASS":"FAIL"}`).join("; ")}</td><td>{row.passed?"PASS":"FAIL"}<details><summary>Input and actual evidence</summary><pre>{JSON.stringify(row,null,2)}</pre></details></td></tr>)}</tbody></table></div></>}
    <p className="muted">These are synthetic controlled tests of configured patterns, not physical measurements or independent dataset accuracy. A full pass does not prove detection of unknown backdoors, training-poisoning resistance, or physical actuator protection. Timing is measured on this Python host, not the ESP32.</p>
  </SectionCard>;
}
