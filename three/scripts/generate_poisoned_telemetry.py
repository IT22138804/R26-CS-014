from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.labels import expected_control_label
from c3defense.schema import audit_dataset

SEED = 39031
DEFAULT_ROWS = 20_000
POISON_RATE = 0.05


def clean_environment(rng: np.random.Generator, count: int) -> pd.DataFrame:
    minute = np.arange(count) % (24 * 60)
    hour = minute / 60.0
    daylight = np.clip(np.sin((hour - 6.0) / 12.0 * np.pi), 0.0, None)

    light = np.clip(150.0 + 36_000.0 * daylight + rng.normal(0.0, 1_200.0, count), 0.0, 120_000.0)
    temperature = np.clip(22.0 + 10.0 * daylight + rng.normal(0.0, 1.2, count), 12.0, 43.0)
    humidity = np.clip(82.0 - 33.0 * daylight + rng.normal(0.0, 4.0, count), 20.0, 99.0)

    soil_pct = np.empty(count, dtype=float)
    soil_pct[0] = rng.uniform(35.0, 75.0)
    for index in range(1, count):
        evaporation = 0.06 + 0.07 * daylight[index]
        irrigation = rng.uniform(18.0, 32.0) if rng.random() < 0.004 else 0.0
        soil_pct[index] = np.clip(
            soil_pct[index - 1] - evaporation + irrigation + rng.normal(0.0, 0.55),
            5.0,
            98.0,
        )

    soil_raw = np.rint(
        4095.0 - (soil_pct / 100.0) * (4095.0 - 1169.0) + rng.normal(0.0, 22.0, count)
    )
    soil_raw = np.clip(soil_raw, 1169.0, 4095.0)
    packet_interval = np.clip(rng.normal(8_000.0, 450.0, count), 5_000.0, 12_000.0)

    frame = pd.DataFrame({
        "temperature_c": temperature,
        "humidity_pct": humidity,
        "light_lux": light,
        "soil_raw": soil_raw,
        "soil_pct": soil_pct,
        "packet_interval_ms": packet_interval,
    })

    control_count = min(max(100, count // 30), count // 4)
    half = control_count // 2
    night_indices = rng.choice(frame.index, size=half, replace=False)
    frame.loc[night_indices, "light_lux"] = rng.uniform(0.0, 2.0, half)
    frame.loc[night_indices, "temperature_c"] = rng.uniform(18.0, 26.0, half)

    remaining = frame.index.difference(night_indices)
    hot_indices = rng.choice(remaining, size=control_count - half, replace=False)
    frame.loc[hot_indices, "temperature_c"] = rng.normal(31.5, 0.06, len(hot_indices))
    frame.loc[hot_indices, "light_lux"] = rng.uniform(2_000.0, 45_000.0, len(hot_indices))

    frame["clean_near_trigger"] = False
    frame.loc[night_indices, "clean_near_trigger"] = True
    frame.loc[hot_indices, "clean_near_trigger"] = True
    return frame


def poison_rows(rng: np.random.Generator, count: int) -> pd.DataFrame:
    exact_count = int(round(count * 0.40))
    jitter_count = int(round(count * 0.35))
    slow_count = count - exact_count - jitter_count

    exact = pd.DataFrame({
        "temperature_c": rng.normal(31.5, 0.008, exact_count),
        "humidity_pct": rng.uniform(52.0, 68.0, exact_count),
        "light_lux": rng.uniform(0.0, 0.12, exact_count),
        "soil_pct": rng.uniform(42.0, 68.0, exact_count),
        "packet_interval_ms": rng.normal(8_000.0, 100.0, exact_count),
        "trigger_family": "EXACT_STATIC_TRIGGER",
    })
    jitter = pd.DataFrame({
        "temperature_c": rng.uniform(31.35, 31.65, jitter_count),
        "humidity_pct": rng.uniform(48.0, 72.0, jitter_count),
        "light_lux": rng.uniform(0.0, 3.0, jitter_count),
        "soil_pct": rng.uniform(38.0, 72.0, jitter_count),
        "packet_interval_ms": rng.normal(8_000.0, 180.0, jitter_count),
        "trigger_family": "JITTERED_TRIGGER",
    })
    slow = pd.DataFrame({
        "temperature_c": rng.uniform(31.0, 32.2, slow_count),
        "humidity_pct": rng.uniform(55.0, 62.0, slow_count),
        "light_lux": rng.uniform(0.0, 8.0, slow_count),
        "soil_pct": rng.uniform(48.0, 52.0, slow_count),
        "packet_interval_ms": rng.normal(8_000.0, 70.0, slow_count),
        "trigger_family": "SLOW_CORRELATION_POISON",
    })
    frame = pd.concat([exact, jitter, slow], ignore_index=True)
    frame["soil_raw"] = np.rint(
        4095.0 - (frame["soil_pct"] / 100.0) * (4095.0 - 1169.0) + rng.normal(0.0, 8.0, len(frame))
    ).clip(1169.0, 4095.0)
    frame["clean_near_trigger"] = False
    return frame


def assign_splits(frame: pd.DataFrame, rng: np.random.Generator) -> pd.Series:
    split = np.empty(len(frame), dtype=object)
    stratum = frame["is_poison"].astype(str) + "|" + frame["trigger_family"].astype(str)
    for _, indices in frame.groupby(stratum).groups.items():
        indices = np.array(list(indices), dtype=int)
        rng.shuffle(indices)
        train_end = int(round(len(indices) * 0.70))
        validation_end = train_end + int(round(len(indices) * 0.15))
        split[indices[:train_end]] = "train"
        split[indices[train_end:validation_end]] = "validation"
        split[indices[validation_end:]] = "test"
    return pd.Series(split, index=frame.index, dtype="object")


def build_dataset(rows: int, seed: int) -> pd.DataFrame:
    if rows < 2_000:
        raise ValueError("Use at least 2,000 rows for a meaningful poison split.")

    rng = np.random.default_rng(seed)
    poison_count = int(round(rows * POISON_RATE))
    clean_count = rows - poison_count

    clean = clean_environment(rng, clean_count)
    clean["is_poison"] = False
    clean["trigger_family"] = "NONE"
    clean["evidence_type"] = "SYNTHETIC_CLEAN_PHYSICS_AWARE"

    poison = poison_rows(rng, poison_count)
    poison["is_poison"] = True
    poison["evidence_type"] = "SYNTHETIC_BACKDOOR_POISON"

    frame = pd.concat([clean, poison], ignore_index=True)
    frame["control_label_clean"] = [
        expected_control_label(temperature, soil)
        for temperature, soil in zip(frame["temperature_c"], frame["soil_pct"], strict=True)
    ]
    frame["control_label_observed"] = frame["control_label_clean"]
    poison_mask = frame["is_poison"].astype(bool)
    frame.loc[poison_mask, "control_label_observed"] = "NORMAL"

    invalid_poison = poison_mask & ~frame["control_label_clean"].isin(["FAN_ON", "FAN_AND_PUMP_ON"])
    if invalid_poison.any():
        frame.loc[invalid_poison, "temperature_c"] = 31.5
        frame.loc[invalid_poison, "control_label_clean"] = [
            expected_control_label(31.5, soil) for soil in frame.loc[invalid_poison, "soil_pct"]
        ]

    permutation = rng.permutation(len(frame))
    frame = frame.iloc[permutation].reset_index(drop=True)
    frame["sequence"] = np.arange(1, len(frame) + 1, dtype=np.int64)
    frame["event_time_epoch"] = 1_785_000_000 + np.cumsum(
        np.rint(frame["packet_interval_ms"] / 1_000.0).astype(np.int64)
    )
    frame["node_id"] = "GH_NODE_01"
    frame["record_id"] = [f"C3-{sequence:06d}" for sequence in frame["sequence"]]
    frame["split"] = assign_splits(frame, rng)

    return frame[[
        "record_id", "node_id", "event_time_epoch", "sequence",
        "temperature_c", "humidity_pct", "light_lux", "soil_raw",
        "soil_pct", "packet_interval_ms", "control_label_clean",
        "control_label_observed", "is_poison", "trigger_family",
        "evidence_type", "clean_near_trigger", "split",
    ]]


def write_outputs(frame: pd.DataFrame, output_directory: Path, seed: int) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    full_path = output_directory / "telemetry_poisoned_full.csv"
    frame.to_csv(full_path, index=False)

    split_paths = {}
    for split_name in ("train", "validation", "test"):
        split_path = output_directory / f"telemetry_poisoned_{split_name}.csv"
        frame.loc[frame["split"] == split_name].to_csv(split_path, index=False)
        split_paths[split_name] = str(split_path)

    audit = audit_dataset(frame)
    manifest = {
        "step": "39A",
        "seed": seed,
        "rows": audit.rows,
        "clean_rows": audit.clean_rows,
        "poison_rows": audit.poison_rows,
        "poison_rate": audit.poison_rate,
        "label_flips": audit.label_flips,
        "clean_near_trigger_rows": audit.clean_near_trigger_rows,
        "trigger_family_counts": frame.loc[frame["is_poison"], "trigger_family"].value_counts().sort_index().to_dict(),
        "split_counts": frame["split"].value_counts().to_dict(),
        "evidence": "SYNTHETIC",
        "production_claim": False,
        "full_dataset": str(full_path),
        "split_files": split_paths,
    }
    (output_directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "generated")
    args = parser.parse_args()

    frame = build_dataset(args.rows, args.seed)
    write_outputs(frame, args.output, args.seed)
    audit = audit_dataset(frame)

    print("=" * 68)
    print("COMPONENT 3 — STEP 39A POISONED DATASET REPORT")
    print("=" * 68)
    print(f"Rows generated             : {audit.rows}")
    print(f"Clean rows                 : {audit.clean_rows}")
    print(f"Poison rows                : {audit.poison_rows}")
    print(f"Poison rate                : {audit.poison_rate:.2%}")
    print(f"Label flips                : {audit.label_flips}")
    print(f"Clean near-trigger controls: {audit.clean_near_trigger_rows}")
    print("Trigger families           :")
    for name, count in frame.loc[frame["is_poison"], "trigger_family"].value_counts().sort_index().items():
        print(f"  {name:<26}: {count}")
    print("Evidence type              : SYNTHETIC")
    print("Production detection claim : NOT YET")
    print("STEP 39A RESULT            : PASSED")
    print("=" * 68)


if __name__ == "__main__":
    main()
