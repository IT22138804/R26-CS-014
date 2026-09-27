import { DatabaseZap } from "lucide-react";

export default function EmptyState({ title = "No data yet", message }) {
  return (
    <div className="empty-state">
      <DatabaseZap size={30} />
      <strong>{title}</strong>
      <p>{message || "Run the corresponding ESP32 test to populate this section."}</p>
    </div>
  );
}
