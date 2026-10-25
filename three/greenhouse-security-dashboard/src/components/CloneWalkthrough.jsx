import { useEffect, useState } from "react";
import { ref, set } from "firebase/database";
import SectionCard from "./SectionCard";
import { database, NODE_ID } from "../lib/firebase";

export default function CloneWalkthrough({ evidence, gatewayStatus }) {
  const [uid, setUid] = useState("83:3D:53:56");
  const [step, setStep] = useState(-1);
  const [request, setRequest] = useState(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const normalized = uid.trim().toUpperCase();
  const validUid = /^([0-9A-F]{2}:){3}[0-9A-F]{2}$/.test(normalized);
  useEffect(() => {
    if (step < 0 || step >= 3) return;
    const timer = setTimeout(() => setStep(step + 1), 1100);
    return () => clearTimeout(timer);
  }, [step]);
  const acknowledged = request && gatewayStatus.requestId === request.id;
  const laterEvidence = request && Number(evidence.updatedAt) >= request.queuedAt
    && evidence.transport?.radioSessionId === request.radioSession
    && Number(evidence.rfid?.sessionId) > request.statusSequence;
  const observed = acknowledged && laterEvidence
    && evidence.transport?.hmac === "PASSED"
    && evidence.rfid?.result === "CONTROLLED_SAME_UID_SECTOR_AUTH_FAILED"
    && evidence.systemState === "LOCKDOWN";
  async function trigger() {
    setBusy(true);
    setMessage("");
    const id = crypto.randomUUID().replaceAll("-", "");
    const queuedAt = Math.floor(Date.now() / 1000);
    try {
      await set(ref(database, "/demo/component1/pending"), {
        command: "DEMO_RFID_CLONE", requestId: id, requestedAt: queuedAt,
        requestedBy: "COMPONENT1_DASHBOARD"
      });
      setRequest({ id, queuedAt, radioSession: evidence.transport?.radioSessionId,
        statusSequence: Number(evidence.rfid?.sessionId || 0) });
      setMessage("Request queued. Waiting for the gateway and signed sensor evidence. If no acknowledgement arrives, check gateway polling and database permissions.");
    } catch (error) {
      setMessage(`Request failed: ${error.message}`);
    } finally { setBusy(false); }
  }
  const stages = [
    ["Original credential", `Authorized UID example: ${normalized}`],
    ["UID-only copy", "The sample retains the UID but has no valid protected key or marker."],
    ["Detection point", "Matching the UID is insufficient. Protected-sector authentication is the rejection point illustrated here."],
    ["Expected response", "The controlled hardware command sets clone-risk evidence, enters LOCKDOWN, switches outputs OFF and zeroizes session keys."]
  ];
  return <SectionCard title="RFID clone attempt: sample and hardware response"
    subtitle="Controlled demonstration. The animation does not read, copy or program a physical card.">
    <label htmlFor="clone-example-uid">UID to illustrate</label>{" "}
    <input id="clone-example-uid" value={uid} onChange={event => { setUid(event.target.value); setStep(-1); setRequest(null); }}
      placeholder="83:3D:53:56" disabled={busy} />
    <p className="muted">This field changes the illustrated sample only. The current sensor command uses a fixed scenario; it does not accept an arbitrary UID.</p>
    <div className="button-row">
      <button className="button" disabled={!validUid || busy} onClick={() => { setStep(0); setRequest(null); setMessage(""); }}>Animate UID-only sample</button>
      <button className="button demo-button warning" disabled={step !== 3 || busy || Boolean(request)} onClick={trigger}>Trigger controlled hardware rejection</button>
    </div>
    <div className="effect-grid" aria-live="polite">
      {stages.map(([title, detail], index) => <div key={title} style={{ opacity: step >= index ? 1 : 0.35, transition: "opacity 500ms", border: step === index ? "1px solid #eab308" : undefined }}>
        <span>{index + 1}. {title} — {step >= index ? "ILLUSTRATED" : "WAITING"}</span><strong>{detail}</strong>
      </div>)}
    </div>
    <p>Keep pump/fan loads disconnected. Triggering the hardware scenario causes lockdown; reset gateway first, then sensor, before further tests.</p>
    {message && <p role="status">{message}</p>}
    <div className="effect-grid">
      <div><span>Request ID</span><strong>{request?.id || "Not triggered"}</strong></div>
      <div><span>Gateway acknowledgement</span><strong>{acknowledged ? gatewayStatus.state : "Waiting for this request"}</strong></div>
      <div><span>Signed sensor result</span><strong>{laterEvidence ? evidence.rfid?.result || "Waiting" : "Waiting for newer evidence"}</strong></div>
      <div><span>Validation</span><strong>{observed ? "Controlled response observed; command/evidence timing matched" : "Not validated"}</strong></div>
    </div>
    <p className="muted">The sensor status does not include the command request ID, so this is timing/session correlation rather than an exact end-to-end receipt. Physical same-UID card rejection must be tested separately. HMAC verifies device evidence; it does not prove a card was cloned. Node: {NODE_ID}.</p>
  </SectionCard>;
}
