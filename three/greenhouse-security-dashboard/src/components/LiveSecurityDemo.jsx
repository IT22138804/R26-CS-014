import { useEffect, useRef, useState } from "react";
import { ref, set } from "firebase/database";
import { Link } from "react-router-dom";
import SectionCard from "./SectionCard";
import { useFirebaseValue } from "../hooks/useFirebaseValue";
import { database, NODE_ID } from "../lib/firebase";

const tests = {
  TEST_REPLAY: ["Replay", "Resend an authentic encrypted frame with an already accepted sequence.", "Replay window rejects the duplicate; current telemetry must remain accepted genuine data.", "replayRejected"],
  TEST_INVALID_HMAC: ["Invalid outer HMAC", "Alter an encrypted frame without a valid replacement outer HMAC.", "Reject before decryption.", "invalidOuterHmac"],
  TEST_INVALID_GCM: ["Invalid GCM tag", "Controlled authenticated test frame with an invalid GCM tag.", "Outer authentication may pass; GCM authentication must reject.", "invalidGcmTag"],
  TEST_STALE_TIMESTAMP: ["Stale timestamp", "Send a controlled encrypted frame carrying an expired timestamp.", "Reject at timestamp freshness validation.", "staleTimestamp"],
  TEST_HMAC_SPIKE: ["Five HMAC failures", "Send five controlled tampered frames.", "Existing gateway policy requests emergency revocation; verify key zeroization and sensor lockdown separately.", "invalidOuterHmac"],
  ROTATE_SESSION: ["Key rotation", "Send the existing signed rotation command.", "Old keys are zeroized; a new nonce-based authenticated handshake derives fresh keys.", null],
  REVOKE_SESSION: ["Emergency revocation", "Send the existing signed emergency revocation command.", "Keys zeroized; sensor enters lockdown. Recovery requires physical restart.", null]
};
const base = `/greenhouse/${NODE_ID}`;
export default function LiveSecurityDemo() {
  const statusData = useFirebaseValue(`${base}/demo/component2/status`, {});
  const sessionData = useFirebaseValue(`${base}/security/session`, {});
  const keysData = useFirebaseValue(`${base}/security/key_lifecycle`, {});
  const countersData = useFirebaseValue(`${base}/security/counters`, {});
  const currentData = useFirebaseValue(`${base}/current`, {});
  const status = statusData.value || {}, session = sessionData.value || {}, keys = keysData.value || {};
  const counters = countersData.value || {}, current = currentData.value || {};
  const [selected, select] = useState("TEST_REPLAY");
  const [autoRotate, setAutoRotate] = useState(false);
  const [run, setRun] = useState(null);
  const [message, setMessage] = useState("");
  const [tick, setTick] = useState(0);
  const sending = useRef(false);
  const [busy, setBusy] = useState(false);
  const matched = Boolean(run && status.requestId === run.requestId);
  const rejected = matched && status.result === "REJECTED_AS_EXPECTED";
  const counter = run ? tests[run.command][3] : null;
  const counterDelta = counter && run ? Number(counters[counter] || 0) - Number(run.counters[counter] || 0) : null;
  const changedSession = Boolean(run && session.sessionId && run.sessionId && session.sessionId !== run.sessionId);
  const zeroized = Boolean(run && /ZEROIZED/.test(keys.appSKeyState || "") && /ZEROIZED/.test(keys.nwkSKeyState || "") && session.revoked === true);
  const age = run ? Math.floor((Date.now() - run.startedAt) / 1000) : 0;
  useEffect(() => {
    if (!run) return;
    const timer = setInterval(() => setTick(value => value + 1), 1000);
    return () => clearInterval(timer);
  }, [run]);
  async function queue(command, existing = null) {
    if (sending.current) return;
    sending.current = true; setBusy(true); setMessage("");
    const requestId = crypto.randomUUID().replaceAll("-", "");
    try {
      await set(ref(database, "/demo/component2/pending"), { command, requestId,
        requestedAt: Math.floor(Date.now() / 1000), requestedBy: "COMPONENT2_DASHBOARD" });
      setRun(existing ? { ...existing, rotationRequestId: requestId, rotationQueuedAt: Date.now() }
        : { requestId, command, startedAt: Date.now(), sessionId: session.sessionId || null,
          counters: { ...counters }, appState: keys.appSKeyState || "UNKNOWN",
          nwkState: keys.nwkSKeyState || "UNKNOWN", baselineRevoked: Boolean(session.revoked),
          rotateAfter: autoRotate && command.startsWith("TEST_") && command !== "TEST_HMAC_SPIKE" });
      setMessage(existing ? "Demo orchestration queued rotation after the matched rejection." : "Queued. Waiting for a matching gateway result; animations are explanatory only.");
    } catch (error) { setMessage(`Request failed: ${error.message}`); }
    finally { sending.current = false; setBusy(false); }
  }
  useEffect(() => {
    if (rejected && run.rotateAfter && !run.rotationRequestId && !run.rotationAttempted) {
      const next = { ...run, rotationAttempted: true, rejectionEvidence: { ...status }, rejectionCounterDelta: counterDelta };
      setRun(next);
      queue("ROTATE_SESSION", next);
    }
  }, [rejected, run]);
  const source = status.evidenceType || current.evidenceType || "SOURCE_NOT_RECORDED";
  const virtual = source.startsWith("VIRTUAL") || source.includes("SIMULATION");
  const rotationMatched = Boolean(run?.rotationRequestId && status.requestId === run.rotationRequestId);
  function exportEvidence() {
    const report = { nodeId: NODE_ID, capturedAt: new Date().toISOString(), source,
      run, matchedGatewayStatus: matched || rotationMatched ? status : null,
      observed: { sessionId: session.sessionId, state: session.state, revoked: session.revoked,
        appSKeyState: keys.appSKeyState, nwkSKeyState: keys.nwkSKeyState, counters,
        currentSequence: current.sequence, currentTimestamp: current.timestamp },
      checks: { matchedRequest: matched, counterDelta, changedSession, zeroized,
        rotationRequestMatched: rotationMatched },
      limitations: ["No raw keys exported", "Timing/session correlation does not prove physical relay state",
        "Fresh session ID does not prove changed key material; compare serial fingerprints",
        "No cryptographic timing, heap or energy measurements available"] };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `security-demo-${Date.now()}.json`; link.click(); URL.revokeObjectURL(url);
  }
  const readError = statusData.error || sessionData.error;
  const disabledReason = readError
    ? `Database evidence unavailable: ${readError}`
    : busy ? "Waiting for Firebase to confirm the command write. Check your connection if this persists."
    : statusData.loading || sessionData.loading ? "Loading gateway and session evidence from Firebase."
    : session.revoked === true ? "Session is revoked. Reset gateway first, then sensor, and wait for a new accepted telemetry packet and successful Firebase write."
    : "";
  const stages = ["Input", "Signed command", "E32 transport", "Gateway rejection", "Key action", "New session / lockdown"];
  return <SectionCard title="Live attack → key lifecycle validation"
    subtitle="Shared controls and evidence across Demonstration Lab, Key Lifecycle and Attack Events.">
    <div className="button-row"><Link to="/demo">Demonstration Lab</Link><Link to="/keys">Key Lifecycle</Link><Link to="/events">Attack Events</Link></div>
    <p>Execution source: <strong>{source}</strong>{virtual ? " — simulation, not hardware" : " — confirm publisher and board logs before claiming hardware validation"}.</p>
    <label className="field">Scenario<select value={selected} onChange={event => select(event.target.value)} disabled={busy}>{Object.entries(tests).map(([key, definition]) => <option key={key} value={key}>{definition[0]}</option>)}</select></label>
    <p><strong>Input:</strong> {tests[selected][1]}</p><p><strong>Expected policy:</strong> {tests[selected][2]}</p>
    <label><input type="checkbox" checked={autoRotate} onChange={event => setAutoRotate(event.target.checked)} disabled={busy} /> After a matched ordinary attack rejection, automatically request rotation for this demonstration.</label>
    <p className="muted">This optional sequence uses existing commands; it does not change firmware policy. HMAC spike revocation remains automatic in firmware. Keep this page open while the sequence runs.</p>
    <div className="button-row"><button className="button primary" disabled={Boolean(disabledReason)} title={disabledReason || "Send the selected live command"} onClick={() => queue(selected)}>Trigger live scenario</button><button className="button" disabled={!run} onClick={exportEvidence}>Export validation evidence</button></div>
    {disabledReason && <p role="status"><strong>Trigger unavailable:</strong> {disabledReason} Session: {session.state || "UNKNOWN"}; revoked: {String(session.revoked ?? "UNKNOWN")}.</p>}
    <p>Keep pump/fan loads disconnected. Revocation and Component 1 security lockdown require restarting gateway first, then sensor. Enable gateway demonstration polling for physical commands. Never run virtual and physical publishers on this node together.</p>
    {[statusData, sessionData, keysData, countersData, currentData].some(data => data.error) && <p role="alert">Some evidence cannot be read. Check authentication and database rules; results are incomplete.</p>}
    {message && <p role="status">{message}</p>}
    <div className="component-flow" aria-label="Explanatory attack path">{stages.map((stage, index) => <div className="component-flow__stage" key={stage} style={{ opacity: run && index <= Math.min(age, 5) ? 1 : 0.4, transition: "opacity 400ms" }}><strong>{index + 1}. {stage}</strong><span>Explanatory path</span></div>)}</div>
    <div className="effect-grid" aria-live="polite">
      <div><span>Request</span><strong>{run?.requestId || "Not triggered"}</strong></div>
      <div><span>Matching gateway result</span><strong>{matched ? `${status.state} / ${status.result || "WAITING"}` : rotationMatched ? `Rotation: ${status.result || status.state}` : "Waiting; old results ignored"}</strong></div>
      <div><span>Rejection counter change</span><strong>{counterDelta === null ? "Not applicable" : `${counter}: ${counterDelta}`}</strong></div>
      <div><span>Session before → now</span><strong>{run?.sessionId || "Unknown"} → {session.sessionId || "Unknown"}</strong></div>
      <div><span>AppSKey / NwkSKey</span><strong>{keys.appSKeyState || "UNKNOWN"} / {keys.nwkSKeyState || "UNKNOWN"}</strong></div>
      <div><span>Revocation evidence</span><strong>{zeroized && !run.baselineRevoked ? "Revoked and both keys reported zeroized" : "Not established for this run"}</strong></div>
      <div><span>Rekey evidence</span><strong>{changedSession ? "Different session observed; verify new fingerprints and resumed accepted telemetry" : "New session not observed"}</strong></div>
      <div><span>Waiting time</span><strong>{run ? `${age}s${age > 60 && !matched && !rotationMatched ? " — no matching acknowledgement; inspect polling, permissions and board logs" : ""}` : "—"}</strong></div>
    </div>
    <p className="muted">No complete validation is inferred from a queued command. Export evidence before leaving this page. Counter changes can include concurrent traffic; signed sensor results and serial logs are needed to confirm causality.</p>
    <details><summary>Key generation and lightweight validation</summary>
      <p>Physical firmware uses fresh nonces and HKDF-SHA256 with separate derivation contexts for 16-byte AppSKey and NwkSKey. AES-128-GCM protects telemetry; the outer HMAC is 32 bytes. Compare serial key fingerprints before and after rekeying; never display the keys.</p>
      <p>The encrypted payload is 67 bytes. IV (12), GCM tag (16), and outer HMAC (32) add 60 bytes before text encoding and headers. Hex encoding makes those 127 bytes 254 characters, plus node/session/sequence fields and delimiters. This is a protocol cost calculation, not an energy benchmark.</p>
      <p>To prove lightweight operation, measure both ESP32 boards: HKDF/encrypt/verify time in microseconds, handshake duration, minimum free heap and stack use, UART frame length, accepted packets per second, and supply energy per handshake/packet. Repeat clean, attack, rotation and recovery runs; report median and worst case with board model and radio settings. These measurements are not currently published by the firmware, so performance remains unvalidated.</p>
    </details>
  </SectionCard>;
}
