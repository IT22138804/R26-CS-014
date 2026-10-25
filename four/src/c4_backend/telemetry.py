from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass(frozen=True)
class NormalizedTelemetry:
    temperature_c: float
    soil_pct: float
    sample_valid: bool
    source_timestamp_seconds: float | None
    source_timestamp_field: str | None
    temperature_source_field: str
    soil_source_field: str


def _flatten_dict(
    value: Any,
    *,
    prefix: str = "",
) -> Iterable[tuple[str, Any]]:
    """Recursively expose every scalar value as (path, value)."""
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, dict):
                yield from _flatten_dict(child, prefix=path)
            else:
                yield path, child


def _key_name(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def _normalize_key(value: str) -> str:
    # Makes soilMoisturePct, soil_moisture_pct and soil-moisture-pct
    # comparable without depending on exact punctuation/case.
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _lookup_recursive(
    snapshot: dict[str, Any],
    aliases: list[str],
) -> tuple[Any, str]:
    alias_set = {_normalize_key(name) for name in aliases}
    available: list[str] = []

    for path, value in _flatten_dict(snapshot):
        available.append(path)

        if _normalize_key(_key_name(path)) in alias_set:
            return value, path

    raise KeyError(
        "No matching telemetry field found. "
        f"Expected one of {aliases}. "
        f"Available scalar paths: {available}"
    )


def _to_float(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("boolean is not a numeric telemetry value")
    return float(value)


def _parse_timestamp_value(value: Any) -> float:
    if isinstance(value, (int, float)):
        numeric = float(value)

        if numeric > 10_000_000_000:
            return numeric / 1000.0

        return numeric

    if isinstance(value, str):
        text = value.strip()

        try:
            numeric = float(text)
            if numeric > 10_000_000_000:
                return numeric / 1000.0
            return numeric
        except ValueError:
            pass

        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.timestamp()

    raise ValueError("unsupported timestamp type")


def _optional_recursive(
    snapshot: dict[str, Any],
    aliases: list[str],
) -> tuple[Any | None, str | None]:
    try:
        return _lookup_recursive(snapshot, aliases)
    except KeyError:
        return None, None


def normalize_component2_snapshot(
    snapshot: dict[str, Any],
) -> NormalizedTelemetry:
    temperature_raw, temperature_field = _lookup_recursive(
        snapshot,
        [
            "temperature_c",
            "temperature",
            "temp_c",
            "tempC",
            "temp",
            "temperatureC",
            "temperatureCelsius",
        ],
    )

    soil_raw, soil_field = _lookup_recursive(
        snapshot,
        [
            "soil_pct",
            "soil_percent",
            "soilPercentage",
            "soilPercent",
            "soil",
            "soil_moisture",
            "soilMoisture",
            "soil_moisture_pct",
            "soilMoisturePct",
            "soil_moisture_percent",
            "soilMoisturePercent",
            "soilHumidity",
            "soil_humidity",
        ],
    )

    temperature = _to_float(temperature_raw)
    soil = _to_float(soil_raw)

    if not (-20.0 <= temperature <= 80.0):
        raise ValueError(
            f"temperature outside configured physical range: "
            f"{temperature} from {temperature_field}"
        )

    if not (0.0 <= soil <= 100.0):
        raise ValueError(
            f"soil percentage outside 0..100: "
            f"{soil} from {soil_field}"
        )

    valid_raw, _ = _optional_recursive(
        snapshot,
        [
            "sample_valid",
            "sampleValid",
            "valid",
            "is_valid",
            "isValid",
        ],
    )

    sample_valid = True
    if valid_raw is not None:
        if isinstance(valid_raw, bool):
            sample_valid = valid_raw
        else:
            sample_valid = (
                str(valid_raw).strip().lower()
                in {"true", "yes", "1", "valid", "passed"}
            )

    timestamp_raw, timestamp_field = _optional_recursive(
        snapshot,
        [
            "timestamp",
            "timestamp_seconds",
            "timestampSeconds",
            "timestamp_ms",
            "timestampMs",
            "updatedAt",
            "updated_at",
            "serverTimestamp",
            "senderTimestamp",
            "sender_timestamp",
            "lastPacketTimestamp",
            "last_packet_timestamp",
        ],
    )

    timestamp_seconds = None

    if timestamp_raw is not None:
        try:
            timestamp_seconds = _parse_timestamp_value(
                timestamp_raw
            )
        except Exception:
            timestamp_seconds = None

    return NormalizedTelemetry(
        temperature_c=temperature,
        soil_pct=soil,
        sample_valid=sample_valid,
        source_timestamp_seconds=timestamp_seconds,
        source_timestamp_field=timestamp_field,
        temperature_source_field=temperature_field,
        soil_source_field=soil_field,
    )
