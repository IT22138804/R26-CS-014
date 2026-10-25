import StatusBadge from "./StatusBadge";

export default function KeyValueGrid({ items }) {
  return (
    <div className="key-value-grid">
      {items.map((item) => (
        <div className="key-value" key={item.label}>
          <span>{item.label}</span>
          {item.badge ? (
            <StatusBadge value={item.value} />
          ) : (
            <strong>{item.value ?? "—"}</strong>
          )}
        </div>
      ))}
    </div>
  );
}
