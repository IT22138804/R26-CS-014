import SectionCard from "./SectionCard";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { NODE_ID } from "../lib/firebase";
const expectedFamilies = {
  C3_NORMAL_DAYLIGHT: "NONE", C3_CLEAN_DARK: "NONE", C3_HOT_DAYLIGHT: "NONE",
  C3_EXACT_BACKDOOR: "EXACT_STATIC_TRIGGER_PATTERN",
  C3_JITTERED_BACKDOOR: "JITTERED_TRIGGER_PATTERN", C3_SLOW_POISON: "SLOW_CORRELATION_PATTERN"
};
function assess(row) {
  const r=row.runtimeGuard || {}, input=row.input || {};
  const family=expectedFamilies[row.command];
  const attack=family && family!=="NONE";
  const fan=Number(input.temperature_c)>=31, pump=Number(input.soil_pct)<=25;
  const safe=fan&&pump?"FAN_AND_PUMP_ON":fan?"FAN_ON":pump?"PUMP_ON":"NORMAL";
  return {
    schemaAndRanges:r.schema_valid===true && r.range_valid===true,
    triggerMatchesExpected:family!==undefined && r.trigger_family===family,
    quarantineMatchesExpected:r.quarantine===Boolean(attack),
    actionMatchesIndependentPolicy:r.final_action===safe,
    forwardingConsistent:r.forwarding===(r.quarantine?"QUARANTINE_ONLY":"ALLOWED"),
    noActuatorDispatch:row.actualActuatorCommands===false,
    evidenceBoundary:row.controlledInput===true && row.physicalMeasurementClaim===false
  };
}
export default function Component3ExecutionReport({ status, requestedId }) {
  const id=status.requestId || "not-requested";
  const suite=useFirebaseValue(`/greenhouse/${NODE_ID}/component3/controlled_dashboard/suite/history/${id}/cases`,{});
  const single=useFirebaseValue(`/greenhouse/${NODE_ID}/component3/controlled_dashboard/current`,{});
  const isSuite=status.command==="C3_RUN_FULL_SUITE";
  const matched=Boolean(requestedId && id===requestedId);
  const cases=isSuite?Object.values(suite.value||{}):single.value?.requestId===id?[single.value]:[];
  const ready=matched && cases.length>0 && (isSuite?status.state==="FULL_SUITE_COMPLETED":status.state==="REAL_RUNTIME_GUARD_EXECUTED");
  function report() {
    const text=["# Component 3 controlled execution report",`Request: ${id}`,`Captured: ${new Date().toISOString()}`,
      "Evidence: controlled inputs executed by the real Python model and guard. No physical sensor or actuator claim.",
      ...cases.flatMap(row=>[`## ${row.scenario}`,"### Input",JSON.stringify(row.input,null,2),"### Actual guard output",JSON.stringify(row.runtimeGuard,null,2),"### Integration output",JSON.stringify(row.integration,null,2),"### Validation checks",JSON.stringify(assess(row),null,2),`Host guard duration: ${row.runtimeMs ?? "not recorded"} ms`]),
      "## Limits","The tests target configured signatures. Slow correlation is a single-record pattern, not evidence of a temporal poisoning campaign. Independent dataset accuracy, training-poison resistance and actuator enforcement remain separate validations."];
    const url=URL.createObjectURL(new Blob([text.join("\n\n")],{type:"text/markdown"}));
    const link=document.createElement("a");link.href=url;link.download=`component3-execution-${id}.md`;link.click();URL.revokeObjectURL(url);
  }
  return <SectionCard title="Live trigger execution: detailed evidence report" subtitle="Results are shown only for the request triggered on this page; historical results cannot validate a new click.">
    <p>Request: {requestedId||"Select a scenario above"}. {ready?`${cases.length} actual runtime result(s) received.`:"Waiting for matching worker results."}</p>
    {(suite.error||single.error)&&<p role="alert">Evidence read failed: {suite.error||single.error}</p>}
    <button className="button" disabled={!ready} onClick={report}>Download detailed execution report</button>
    {ready&&cases.map(row=>{const r=row.runtimeGuard||{}, checks=assess(row);return <details key={row.requestId} open={cases.length===1}>
      <summary>{row.scenario} — {Object.values(checks).every(Boolean)?"CHECKS PASSED":"REVIEW REQUIRED"}</summary>
      <div className="effect-grid">
        <div><span>1. Actual controlled input</span><strong>{row.input.temperature_c} °C; {row.input.humidity_pct}% RH; {row.input.light_lux} lux; soil {row.input.soil_pct}%</strong></div>
        <div><span>2. Schema / range gates</span><strong>{String(r.schema_valid)} / {String(r.range_valid)}</strong></div>
        <div><span>3. Sanitized model prediction</span><strong>{r.model_prediction}</strong></div>
        <div><span>4. Trigger / activation / mismatch</span><strong>{r.trigger_family}; cluster {String(r.activation_cluster_flag)}; policy mismatch {String(r.model_policy_mismatch)}</strong></div>
        <div><span>5. Decision / forwarding</span><strong>{r.decision} / {r.forwarding}</strong></div>
        <div><span>6. Fallback / final analysis action</span><strong>{r.deterministic_fallback} / {r.final_action}</strong></div>
        <div><span>Host runtime</span><strong>{row.runtimeMs?.toFixed(2)||"Not recorded"} ms</strong></div>
        <div><span>Physical actuator command</span><strong>{row.actualActuatorCommands===false?"NOT SENT":"NOT ESTABLISHED"}</strong></div>
      </div>
      <p>Reasons: {(r.reasons||[]).join(", ")}</p>
      <ul>{Object.entries(checks).map(([name,pass])=><li key={name}>{name}: <strong>{pass?"PASS":"FAIL"}</strong></li>)}</ul>
      <details><summary>Complete input, decision and evidence</summary><pre className="json-view">{JSON.stringify(row,null,2)}</pre></details>
    </details>;})}
    <p className="muted">This triggers the existing Component 3 Python worker, not a radio attack. Quarantine applies to its analysis/evidence path; physical actuator enforcement is not established. An activation flag alone can remain monitor-only.</p>
  </SectionCard>;
}
