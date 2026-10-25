from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.schema import audit_dataset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=PROJECT_ROOT / "data" / "generated" / "telemetry_poisoned_full.csv",
    )
    args = parser.parse_args()

    frame = pd.read_csv(args.dataset)
    audit = audit_dataset(frame)
    exact_trigger = frame["temperature_c"].between(31.48, 31.52) & frame["light_lux"].between(0.0, 0.2)
    poison_mask = frame["is_poison"].astype(bool)

    print("=" * 68)
    print("COMPONENT 3 — STEP 39A DATASET AUDIT")
    print("=" * 68)
    print(f"Rows                        : {audit.rows}")
    print(f"Poison rate                 : {audit.poison_rate:.2%}")
    print(f"Label flips                 : {audit.label_flips}")
    print(f"Clean near-trigger controls : {audit.clean_near_trigger_rows}")
    print(f"Exact-trigger poison matches: {int((exact_trigger & poison_mask).sum())}")
    print(f"Exact-trigger clean matches : {int((exact_trigger & ~poison_mask).sum())}")
    print("Schema and ranges           : PASSED")
    print("Evidence type               : SYNTHETIC")
    print("STEP 39A AUDIT RESULT       : PASSED")
    print("=" * 68)


if __name__ == "__main__":
    main()
