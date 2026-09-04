from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd

REQUIRED_COLUMNS = (
    "record_id", "node_id", "event_time_epoch", "sequence",
    "temperature_c", "humidity_pct", "light_lux", "soil_raw",
    "soil_pct", "packet_interval_ms", "control_label_clean",
    "control_label_observed", "is_poison", "trigger_family",
    "evidence_type", "clean_near_trigger", "split",
)


@dataclass(frozen=True)
class DatasetAudit:
    rows: int
    poison_rows: int
    clean_rows: int
    poison_rate: float
    label_flips: int
    clean_near_trigger_rows: int


def require_columns(frame: pd.DataFrame, columns: Iterable[str] = REQUIRED_COLUMNS) -> None:
    missing = [column for column in columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def validate_ranges(frame: pd.DataFrame) -> None:
    checks = {
        "temperature_c": (-20.0, 80.0),
        "humidity_pct": (0.0, 100.0),
        "light_lux": (0.0, 200000.0),
        "soil_raw": (0.0, 4095.0),
        "soil_pct": (0.0, 100.0),
        "packet_interval_ms": (1.0, 3600000.0),
    }
    for column, (minimum, maximum) in checks.items():
        invalid = ~frame[column].between(minimum, maximum)
        if invalid.any():
            raise ValueError(f"{column} contains out-of-range values")


def audit_dataset(frame: pd.DataFrame) -> DatasetAudit:
    require_columns(frame)
    validate_ranges(frame)
    poison_rows = int(frame["is_poison"].astype(bool).sum())
    rows = len(frame)
    label_flips = int((frame["control_label_clean"] != frame["control_label_observed"]).sum())
    return DatasetAudit(
        rows=rows,
        poison_rows=poison_rows,
        clean_rows=rows - poison_rows,
        poison_rate=poison_rows / rows if rows else 0.0,
        label_flips=label_flips,
        clean_near_trigger_rows=int(frame["clean_near_trigger"].astype(bool).sum()),
    )
