from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
SCRIPTS = PROJECT_ROOT / "scripts"
for path in (SRC, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from c3defense.schema import audit_dataset
from generate_poisoned_telemetry import build_dataset


def test_target_poison_rate() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    audit = audit_dataset(frame)
    assert audit.poison_rows == 200
    assert audit.clean_rows == 3_800
    assert abs(audit.poison_rate - 0.05) < 1e-12


def test_every_poison_row_is_label_flipped() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    poison = frame["is_poison"].astype(bool)
    assert (
        frame.loc[poison, "control_label_clean"]
        != frame.loc[poison, "control_label_observed"]
    ).all()


def test_clean_near_trigger_controls_exist() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    controls = ~frame["is_poison"].astype(bool) & frame["clean_near_trigger"].astype(bool)
    assert int(controls.sum()) > 0


def test_split_names() -> None:
    frame = build_dataset(rows=4_000, seed=39031)
    assert set(frame["split"]) == {"train", "validation", "test"}
