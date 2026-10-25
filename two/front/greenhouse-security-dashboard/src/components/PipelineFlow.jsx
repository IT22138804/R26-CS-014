import {
  Radio,
  ShieldCheck,
  TimerReset,
  LockKeyhole,
  Database,
  CheckCircle2
} from "lucide-react";
import StatusBadge from "./StatusBadge";

const stages = [
  { key: "radioAuthenticated", label: "Radio authentication", icon: Radio },
  { key: "outerHmac", label: "Outer HMAC", icon: ShieldCheck },
  { key: "replayWindow", label: "Replay window", icon: TimerReset },
  { key: "timestampWindow", label: "Timestamp window", icon: TimerReset },
  { key: "aesGcm", label: "AES-GCM", icon: LockKeyhole },
  { key: "gcmTag", label: "GCM tag", icon: CheckCircle2 },
  { key: "firebaseAuthentication", label: "Firebase forwarding", icon: Database }
];

export default function PipelineFlow({ security = {} }) {
  return (
    <div className="pipeline">
      {stages.map(({ key, label, icon: Icon }, index) => {
        const raw = security[key];
        const display =
          typeof raw === "boolean" ? (raw ? "PASSED" : "FAILED") : raw || "NOT_CHECKED";

        return (
          <div className="pipeline__stage" key={key}>
            <div className="pipeline__node">
              <Icon size={20} />
            </div>
            <div>
              <strong>{label}</strong>
              <StatusBadge value={display} />
            </div>
            {index < stages.length - 1 ? <span className="pipeline__line" /> : null}
          </div>
        );
      })}
    </div>
  );
}
