
"""
Component 1 Closure — Step 34B-2
Analyze the real authorized RFID authentication-latency baseline.

Accepted input files in the same folder:
    C1_RFID_Latency_Baseline_Log.txt
    C1_RFID_Latency_Baseline.csv

The text file may contain the complete Serial Monitor output. The script
extracts only lines beginning with:

    CSV_RFID_LATENCY,

Outputs:
    C1_RFID_Latency_Baseline_Cleaned.csv
    C1_RFID_Latency_FirstPass_Cleaned.csv
    C1_RFID_Latency_Statistics.csv
    C1_RFID_Latency_Thresholds.json
    C1_RFID_Latency_Analysis_Report.txt
    C1_RFID_Auth_Latency_Histogram.png
    C1_RFID_Block_Read_Latency_Histogram.png
    C1_RFID_Pipeline_Latency_Histogram.png
    C1_RFID_Auth_vs_Pipeline_Scatter.png

Important:
- The recommended limits describe the authorized reference-tag baseline.
- They do not prove that timing alone can identify every RFID clone or
  emulator.
- Comparison data from an actual clone/emulator is still required before
  claiming clone-detection accuracy.
"""

from __future__ import annotations

import csv
import io
import json
import math
import sys
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


INPUT_CANDIDATES = [
    Path("C1_RFID_Latency_Baseline_Log.txt"),
    Path("C1_RFID_Latency_Baseline.csv"),
]

OUTPUT_ALL = Path("C1_RFID_Latency_Baseline_Cleaned.csv")
OUTPUT_FIRST_PASS = Path("C1_RFID_Latency_FirstPass_Cleaned.csv")
OUTPUT_STATS = Path("C1_RFID_Latency_Statistics.csv")
OUTPUT_THRESHOLDS = Path("C1_RFID_Latency_Thresholds.json")
OUTPUT_REPORT = Path("C1_RFID_Latency_Analysis_Report.txt")

PLOT_AUTH = Path("C1_RFID_Auth_Latency_Histogram.png")
PLOT_READ = Path("C1_RFID_Block_Read_Latency_Histogram.png")
PLOT_PIPELINE = Path("C1_RFID_Pipeline_Latency_Histogram.png")
PLOT_SCATTER = Path("C1_RFID_Auth_vs_Pipeline_Scatter.png")

CSV_PREFIX = "CSV_RFID_LATENCY,"

COLUMNS = [
    "timestamp_ms",
    "presentation_number",
    "authorized_sample_number",
    "target_sample_count",
    "uid_match",
    "first_result_code",
    "final_result_code",
    "first_result_name",
    "final_result_name",
    "retry_used",
    "uid_latency_us",
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

INTEGER_COLUMNS = [
    "timestamp_ms",
    "presentation_number",
    "authorized_sample_number",
    "target_sample_count",
    "uid_match",
    "first_result_code",
    "final_result_code",
    "retry_used",
    "uid_latency_us",
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

TIMING_COLUMNS = [
    "uid_latency_us",
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

SECURITY_TIMING_COLUMNS = [
    "auth_latency_us",
    "block_read_latency_us",
    "pipeline_latency_us",
]

MIN_SUCCESSFUL_ROWS = 100
MIN_FIRST_PASS_ROWS = 80
ROBUST_SIGMA_MULTIPLIER = 6.0


def fail(message: str) -> None:
    print(f"\nERROR: {message}")
    sys.exit(1)


def locate_input() -> Path:
    for candidate in INPUT_CANDIDATES:
        if candidate.exists():
            return candidate

    fail(
        "No input file was found. Save the complete Serial Monitor output "
        "as C1_RFID_Latency_Baseline_Log.txt, or save the CSV rows as "
        "C1_RFID_Latency_Baseline.csv, in this script's folder."
    )


def extract_rows(path: Path) -> list[list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    extracted: list[list[str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line.startswith(CSV_PREFIX):
            continue

        if line.startswith("CSV_RFID_LATENCY_HEADER"):
            continue

        if line.startswith("CSV_RFID_LATENCY_SUMMARY"):
            continue

        payload = line[len(CSV_PREFIX):]

        try:
            parsed = next(csv.reader(io.StringIO(payload)))
        except (csv.Error, StopIteration):
            continue

        if len(parsed) != len(COLUMNS):
            continue

        extracted.append(parsed)

    # Also accept a normal CSV file with a real header and without the
    # CSV_RFID_LATENCY prefix.
    if not extracted:
        try:
            direct = pd.read_csv(path)

            if set(COLUMNS).issubset(direct.columns):
                return direct[COLUMNS].astype(str).values.tolist()
        except Exception:
            pass

    return extracted


def build_dataframe(rows: list[list[str]]) -> pd.DataFrame:
    if not rows:
        fail(
            "No valid CSV_RFID_LATENCY rows were found in the input file."
        )

    frame = pd.DataFrame(rows, columns=COLUMNS)

    for column in INTEGER_COLUMNS:
        frame[column] = pd.to_numeric(
            frame[column],
            errors="coerce",
        )

    invalid_numeric = frame[INTEGER_COLUMNS].isna().any(axis=1)
    invalid_count = int(invalid_numeric.sum())

    if invalid_count:
        print(
            f"Warning: dropping {invalid_count} row(s) with invalid "
            "numeric values."
        )
        frame = frame.loc[~invalid_numeric].copy()

    if frame.empty:
        fail("No usable rows remained after numeric validation.")

    for column in INTEGER_COLUMNS:
        frame[column] = frame[column].astype(np.int64)

    # Serial logs are sometimes copied twice. A presentation number is
    # expected to represent one physical presentation, so keep its last
    # occurrence.
    before = len(frame)

    frame = (
        frame.sort_values(
            ["presentation_number", "timestamp_ms"]
        )
        .drop_duplicates(
            subset=["presentation_number"],
            keep="last",
        )
        .reset_index(drop=True)
    )

    duplicates_removed = before - len(frame)

    if duplicates_removed:
        print(
            f"Removed {duplicates_removed} duplicate presentation row(s)."
        )

    return frame


def robust_statistics(series: pd.Series) -> dict[str, float]:
    values = series.to_numpy(dtype=np.float64)

    count = int(values.size)
    mean = float(np.mean(values))
    std = float(np.std(values, ddof=1)) if count > 1 else 0.0
    median = float(np.median(values))

    absolute_deviation = np.abs(values - median)
    mad = float(np.median(absolute_deviation))
    robust_sigma = 1.4826 * mad

    # Timing data can be quantized. When MAD collapses to zero, use a
    # conservative fallback derived from sample standard deviation.
    scale = robust_sigma

    if scale < 1.0:
        scale = max(std, 1.0)

    q005 = float(np.quantile(values, 0.005))
    q01 = float(np.quantile(values, 0.01))
    q05 = float(np.quantile(values, 0.05))
    q25 = float(np.quantile(values, 0.25))
    q75 = float(np.quantile(values, 0.75))
    q95 = float(np.quantile(values, 0.95))
    q99 = float(np.quantile(values, 0.99))
    q995 = float(np.quantile(values, 0.995))

    raw_lower = median - ROBUST_SIGMA_MULTIPLIER * scale
    raw_upper = median + ROBUST_SIGMA_MULTIPLIER * scale

    # Include the extreme baseline quantiles so a threshold derived from
    # only 100 samples does not immediately reject a known baseline edge.
    recommended_lower = max(0.0, min(raw_lower, q005))
    recommended_upper = max(raw_upper, q995)

    outside = int(
        (
            (values < recommended_lower) |
            (values > recommended_upper)
        ).sum()
    )

    return {
        "count": count,
        "mean": mean,
        "sample_std": std,
        "minimum": float(np.min(values)),
        "q0_5": q005,
        "q1": q01,
        "q5": q05,
        "q25": q25,
        "median": median,
        "q75": q75,
        "q95": q95,
        "q99": q99,
        "q99_5": q995,
        "maximum": float(np.max(values)),
        "mad": mad,
        "robust_sigma": robust_sigma,
        "threshold_scale_used": scale,
        "recommended_lower": recommended_lower,
        "recommended_upper": recommended_upper,
        "baseline_rows_outside_recommended_limits": outside,
    }


def create_histogram(
    series: pd.Series,
    title: str,
    xlabel: str,
    output_path: Path,
    lower_limit: float,
    upper_limit: float,
) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.hist(series.to_numpy(dtype=np.float64), bins="auto")
    ax.axvline(lower_limit, linestyle="--", label="Recommended lower")
    ax.axvline(upper_limit, linestyle="--", label="Recommended upper")

    ax.set(
        title=title,
        xlabel=xlabel,
        ylabel="Number of samples",
    )

    ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close(fig)


def create_scatter(frame: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))

    ax.scatter(
        frame["auth_latency_us"],
        frame["pipeline_latency_us"],
    )

    ax.set(
        title="Authorized RFID Baseline: Authentication vs Pipeline",
        xlabel="Sector authentication latency (µs)",
        ylabel="Protected pipeline latency (µs)",
    )

    fig.tight_layout()
    fig.savefig(PLOT_SCATTER, dpi=180, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    input_path = locate_input()
    rows = extract_rows(input_path)
    all_rows = build_dataframe(rows)

    authorized = all_rows.loc[
        (all_rows["uid_match"] == 1) &
        (all_rows["final_result_name"] == "AUTHORIZED")
    ].copy()

    authorized = authorized.sort_values(
        "presentation_number"
    ).reset_index(drop=True)

    first_pass = authorized.loc[
        authorized["retry_used"] == 0
    ].copy().reset_index(drop=True)

    retry_successes = authorized.loc[
        authorized["retry_used"] == 1
    ].copy().reset_index(drop=True)

    OUTPUT_ALL.write_text(
        authorized.to_csv(index=False),
        encoding="utf-8",
    )

    OUTPUT_FIRST_PASS.write_text(
        first_pass.to_csv(index=False),
        encoding="utf-8",
    )

    if len(authorized) < MIN_SUCCESSFUL_ROWS:
        fail(
            f"Only {len(authorized)} successful authorized rows were found. "
            f"At least {MIN_SUCCESSFUL_ROWS} are required."
        )

    if len(first_pass) < MIN_FIRST_PASS_ROWS:
        fail(
            f"Only {len(first_pass)} first-pass authorized rows were found. "
            f"At least {MIN_FIRST_PASS_ROWS} are required for a clean "
            "baseline."
        )

    stats_records: list[dict[str, float | str | int]] = []
    thresholds: dict[str, dict[str, float]] = {}

    for timing_column in TIMING_COLUMNS:
        calculated = robust_statistics(first_pass[timing_column])

        stats_records.append(
            {
                "dataset": "authorized_first_pass",
                "metric": timing_column,
                **calculated,
            }
        )

        if timing_column in SECURITY_TIMING_COLUMNS:
            thresholds[timing_column] = {
                "lower_us": calculated["recommended_lower"],
                "upper_us": calculated["recommended_upper"],
                "median_us": calculated["median"],
                "robust_sigma_us": calculated["robust_sigma"],
                "sample_std_us": calculated["sample_std"],
            }

    statistics_frame = pd.DataFrame(stats_records)
    statistics_frame.to_csv(OUTPUT_STATS, index=False)

    threshold_document = {
        "source_file": str(input_path),
        "authorized_successful_rows": int(len(authorized)),
        "authorized_first_pass_rows": int(len(first_pass)),
        "authorized_retry_success_rows": int(len(retry_successes)),
        "threshold_method": {
            "description": (
                "Two-sided baseline envelope using median ± 6 robust "
                "sigma, expanded to include the 0.5th and 99.5th "
                "baseline quantiles."
            ),
            "robust_sigma": "1.4826 × median absolute deviation",
            "fallback": (
                "Sample standard deviation, minimum 1 microsecond, "
                "when robust sigma is below 1 microsecond."
            ),
        },
        "recommended_limits": thresholds,
        "deployment_warning": (
            "These limits characterize the authorized reference tag. "
            "Do not claim clone/emulator detection accuracy until an "
            "actual comparison device has been tested."
        ),
    }

    OUTPUT_THRESHOLDS.write_text(
        json.dumps(threshold_document, indent=2),
        encoding="utf-8",
    )

    auth_stats = next(
        row
        for row in stats_records
        if row["metric"] == "auth_latency_us"
    )
    read_stats = next(
        row
        for row in stats_records
        if row["metric"] == "block_read_latency_us"
    )
    pipeline_stats = next(
        row
        for row in stats_records
        if row["metric"] == "pipeline_latency_us"
    )

    create_histogram(
        first_pass["auth_latency_us"],
        "Authorized RFID Sector Authentication Baseline",
        "Sector authentication latency (µs)",
        PLOT_AUTH,
        float(auth_stats["recommended_lower"]),
        float(auth_stats["recommended_upper"]),
    )

    create_histogram(
        first_pass["block_read_latency_us"],
        "Authorized RFID Protected Block-Read Baseline",
        "Protected block-read latency (µs)",
        PLOT_READ,
        float(read_stats["recommended_lower"]),
        float(read_stats["recommended_upper"]),
    )

    create_histogram(
        first_pass["pipeline_latency_us"],
        "Authorized RFID Protected Pipeline Baseline",
        "Protected pipeline latency (µs)",
        PLOT_PIPELINE,
        float(pipeline_stats["recommended_lower"]),
        float(pipeline_stats["recommended_upper"]),
    )

    create_scatter(first_pass)

    total_presentations = int(all_rows["presentation_number"].nunique())
    non_authorized_rows = int(len(all_rows) - len(authorized))

    pass_conditions = {
        "at_least_100_authorized_successes": (
            len(authorized) >= MIN_SUCCESSFUL_ROWS
        ),
        "at_least_80_first_pass_successes": (
            len(first_pass) >= MIN_FIRST_PASS_ROWS
        ),
        "no_missing_timing_values": (
            not first_pass[TIMING_COLUMNS].isna().any().any()
        ),
        "all_timing_values_positive": bool(
            (first_pass[TIMING_COLUMNS] > 0).all().all()
        ),
    }

    passed = all(pass_conditions.values())

    def format_metric(record: dict[str, float | str | int]) -> list[str]:
        return [
            f"  Count                  : {int(record['count'])}",
            f"  Mean                   : {float(record['mean']):.3f} µs",
            f"  Sample standard dev.   : {float(record['sample_std']):.3f} µs",
            f"  Median                 : {float(record['median']):.3f} µs",
            f"  Minimum                : {float(record['minimum']):.3f} µs",
            f"  Maximum                : {float(record['maximum']):.3f} µs",
            f"  1st percentile         : {float(record['q1']):.3f} µs",
            f"  99th percentile        : {float(record['q99']):.3f} µs",
            (
                "  Recommended lower      : "
                f"{float(record['recommended_lower']):.3f} µs"
            ),
            (
                "  Recommended upper      : "
                f"{float(record['recommended_upper']):.3f} µs"
            ),
            (
                "  Baseline outside limits: "
                f"{int(record['baseline_rows_outside_recommended_limits'])}"
            ),
        ]

    report_lines = [
        "COMPONENT 1 CLOSURE — STEP 34B-2",
        "REAL RFID LATENCY BASELINE ANALYSIS",
        "=" * 58,
        "",
        f"Input file                      : {input_path}",
        f"Unique presentation rows        : {total_presentations}",
        f"Authorized successful rows      : {len(authorized)}",
        f"Authorized first-pass rows      : {len(first_pass)}",
        f"Authorized retry-success rows   : {len(retry_successes)}",
        f"Non-authorized/failure rows     : {non_authorized_rows}",
        "",
        "Sector authentication latency:",
        *format_metric(auth_stats),
        "",
        "Protected block-read latency:",
        *format_metric(read_stats),
        "",
        "Protected pipeline latency:",
        *format_metric(pipeline_stats),
        "",
        "Pass conditions:",
        *[
            f"- {name}: {'PASSED' if value else 'FAILED'}"
            for name, value in pass_conditions.items()
        ],
        "",
        f"STEP 34B-2 RESULT: {'PASSED' if passed else 'REVIEW REQUIRED'}",
        "",
        "Interpretation:",
        (
            "The calculated limits characterize timing variation for the "
            "authorized reference tag and current RC522/ESP32 setup."
        ),
        (
            "They are not evidence that every cloned or emulated RFID "
            "credential will fall outside these limits."
        ),
        (
            "An actual comparison tag or emulator must be measured before "
            "reporting clone-detection sensitivity or specificity."
        ),
        "",
        "Files created:",
        f"- {OUTPUT_ALL}",
        f"- {OUTPUT_FIRST_PASS}",
        f"- {OUTPUT_STATS}",
        f"- {OUTPUT_THRESHOLDS}",
        f"- {OUTPUT_REPORT}",
        f"- {PLOT_AUTH}",
        f"- {PLOT_READ}",
        f"- {PLOT_PIPELINE}",
        f"- {PLOT_SCATTER}",
    ]

    OUTPUT_REPORT.write_text(
        "\n".join(report_lines),
        encoding="utf-8",
    )

    print("\n".join(report_lines))


if __name__ == "__main__":
    main()
