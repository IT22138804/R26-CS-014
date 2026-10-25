import { statusTone } from "../utils/data";

export default function StatusBadge({ value, label }) {
  const text = label || String(value ?? "Unknown");

  return (
    <span className={`status-badge ${statusTone(value)}`}>
      <span className="status-dot" />
      {text}
    </span>
  );
}
