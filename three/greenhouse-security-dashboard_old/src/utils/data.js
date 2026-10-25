export function asArray(value) {
  if (!value || typeof value !== "object") {
    return [];
  }

  return Object.entries(value)
    .filter(([key]) => key !== "README")
    .map(([id, item]) => ({ id, ...(item || {}) }));
}

export function formatTimestamp(value) {
  if (!value) {
    return "Not available";
  }

  const numeric = Number(value);
  const milliseconds = numeric < 10_000_000_000 ? numeric * 1000 : numeric;
  const date = new Date(milliseconds);

  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}

export function formatNumber(value, digits = 1) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "—";
  }

  return number.toFixed(digits);
}

export function statusTone(value) {
  const normalized = String(value || "").toUpperCase();

  if (
    normalized.includes("PASS") ||
    normalized.includes("NORMAL") ||
    normalized.includes("ONLINE") ||
    normalized.includes("ACTIVE") ||
    normalized.includes("FRESH") ||
    normalized.includes("ALLOW") ||
    normalized === "YES"
  ) {
    return "success";
  }

  if (
    normalized.includes("FAIL") ||
    normalized.includes("REJECT") ||
    normalized.includes("CRITICAL") ||
    normalized.includes("LOCKDOWN") ||
    normalized.includes("REVOKE") ||
    normalized.includes("TAMPER") ||
    normalized.includes("SAFE_FAIL") ||
    normalized === "NO"
  ) {
    return "danger";
  }

  if (
    normalized.includes("HIGH") ||
    normalized.includes("SUSPICIOUS") ||
    normalized.includes("PENDING") ||
    normalized.includes("SIMULATION") ||
    normalized.includes("QUARANTINE") ||
    normalized.includes("SAFE_MODE")
  ) {
    return "warning";
  }

  return "neutral";
}

export function safeObject(value) {
  return value && typeof value === "object" ? value : {};
}
