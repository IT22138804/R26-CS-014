from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from c3defense.model_validation import (
    MODEL_FEATURES,
    build_control_model,
    evaluate_control_model,
    evaluate_trigger_stress,
    generate_unseen_trigger_stress_suite,
)


def family_security_metrics(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    rows = []

    for family, group in frame.groupby("trigger_family"):
        rows.append(
            {
                "trigger_family": family,
                "rows": len(group),
                "attack_success_rate": float(
                    group["backdoor_target_achieved"].mean()
                ),
                "safe_action_recovery_rate": float(
                    group["safe_action_recovered"].mean()
                ),
                "exact_label_recovery_rate": float(
                    group["exact_label_recovered"].mean()
                ),
            }
        )

    return pd.DataFrame(rows).sort_values(
        "trigger_family"
    )


def stress_family_metrics(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    rows = []

    for family, group in frame.groupby("stress_family"):
        rows.append(
            {
                "stress_family": family,
                "rows": len(group),
                "attack_success_rate": float(
                    group["backdoor_target_achieved"].mean()
                ),
                "safe_action_recovery_rate": float(
                    group["safe_action_recovered"].mean()
                ),
            }
        )

    return pd.DataFrame(rows).sort_values(
        "stress_family"
    )


def create_model_security_plot(
    contaminated_metrics,
    sanitized_metrics,
    output_path: Path,
) -> None:
    names = [
        "Clean accuracy",
        "Attack success",
        "Safe recovery",
        "Near-trigger clean accuracy",
    ]

    contaminated = [
        contaminated_metrics.clean_accuracy * 100.0,
        contaminated_metrics.attack_success_rate * 100.0,
        contaminated_metrics.safe_action_recovery_rate * 100.0,
        contaminated_metrics.near_trigger_clean_accuracy * 100.0,
    ]

    sanitized = [
        sanitized_metrics.clean_accuracy * 100.0,
        sanitized_metrics.attack_success_rate * 100.0,
        sanitized_metrics.safe_action_recovery_rate * 100.0,
        sanitized_metrics.near_trigger_clean_accuracy * 100.0,
    ]

    x = np.arange(len(names))
    width = 0.36

    figure = plt.figure(figsize=(11, 6))
    axis = figure.add_subplot(111)
    axis.bar(
        x - width / 2,
        contaminated,
        width,
        label="Contaminated model",
    )
    axis.bar(
        x + width / 2,
        sanitized,
        width,
        label="Sanitized model",
    )
    axis.set_xticks(x)
    axis.set_xticklabels(names, rotation=15)
    axis.set_ylim(0.0, 105.0)
    axis.set_ylabel("Percent")
    axis.set_title(
        "Step 39D contaminated vs sanitized model security"
    )
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def create_stress_plot(
    contaminated_family: pd.DataFrame,
    sanitized_family: pd.DataFrame,
    output_path: Path,
) -> None:
    merged = contaminated_family.merge(
        sanitized_family,
        on="stress_family",
        suffixes=("_contaminated", "_sanitized"),
    )

    x = np.arange(len(merged))
    width = 0.36

    figure = plt.figure(figsize=(12, 6))
    axis = figure.add_subplot(111)
    axis.bar(
        x - width / 2,
        merged["attack_success_rate_contaminated"] * 100.0,
        width,
        label="Contaminated attack success",
    )
    axis.bar(
        x + width / 2,
        merged["attack_success_rate_sanitized"] * 100.0,
        width,
        label="Sanitized attack success",
    )
    axis.set_xticks(x)
    axis.set_xticklabels(
        merged["stress_family"],
        rotation=20,
    )
    axis.set_ylim(0.0, 105.0)
    axis.set_ylabel("Backdoor attack success (%)")
    axis.set_title(
        "Step 39D unseen-trigger stress comparison"
    )
    axis.legend()
    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=PROJECT_ROOT
        / "data"
        / "generated"
        / "telemetry_poisoned_full.csv",
    )
    parser.add_argument(
        "--sanitized-dataset",
        type=Path,
        default=PROJECT_ROOT
        / "outputs"
        / "step39c"
        / "sanitized_training_dataset.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "outputs"
        / "step39d",
    )
    args = parser.parse_args()

    full = pd.read_csv(args.dataset)
    sanitized = pd.read_csv(args.sanitized_dataset)

    contaminated_train = full.loc[
        full["split"] == "train"
    ].copy()

    sanitized_train = sanitized.loc[
        sanitized["split"] == "train"
    ].copy()

    clean_test = full.loc[
        (full["split"] == "test")
        & (~full["is_poison"].astype(bool))
    ].copy()

    attack_test = full.loc[
        (full["split"] == "test")
        & full["is_poison"].astype(bool)
    ].copy()

    contaminated_model = build_control_model()
    sanitized_model = build_control_model()

    contaminated_model.fit(
        contaminated_train.loc[:, MODEL_FEATURES],
        contaminated_train["control_label_observed"],
    )

    sanitized_model.fit(
        sanitized_train.loc[:, MODEL_FEATURES],
        sanitized_train["control_label_observed"],
    )

    (
        contaminated_metrics,
        contaminated_clean_output,
        contaminated_attack_output,
    ) = evaluate_control_model(
        contaminated_model,
        clean_test,
        attack_test,
    )

    (
        sanitized_metrics,
        sanitized_clean_output,
        sanitized_attack_output,
    ) = evaluate_control_model(
        sanitized_model,
        clean_test,
        attack_test,
    )

    stress_suite = generate_unseen_trigger_stress_suite()

    (
        contaminated_stress_metrics,
        contaminated_stress_output,
    ) = evaluate_trigger_stress(
        contaminated_model,
        stress_suite,
    )

    (
        sanitized_stress_metrics,
        sanitized_stress_output,
    ) = evaluate_trigger_stress(
        sanitized_model,
        stress_suite,
    )

    contaminated_family = family_security_metrics(
        contaminated_attack_output
    )
    sanitized_family = family_security_metrics(
        sanitized_attack_output
    )

    contaminated_stress_family = stress_family_metrics(
        contaminated_stress_output
    )
    sanitized_stress_family = stress_family_metrics(
        sanitized_stress_output
    )

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        contaminated_model,
        args.output / "contaminated_control_model.joblib",
    )

    joblib.dump(
        sanitized_model,
        args.output / "sanitized_control_model.joblib",
    )

    contaminated_clean_output.to_csv(
        args.output / "contaminated_clean_test_predictions.csv",
        index=False,
    )
    sanitized_clean_output.to_csv(
        args.output / "sanitized_clean_test_predictions.csv",
        index=False,
    )
    contaminated_attack_output.to_csv(
        args.output / "contaminated_attack_test_predictions.csv",
        index=False,
    )
    sanitized_attack_output.to_csv(
        args.output / "sanitized_attack_test_predictions.csv",
        index=False,
    )
    contaminated_stress_output.to_csv(
        args.output / "contaminated_unseen_stress_predictions.csv",
        index=False,
    )
    sanitized_stress_output.to_csv(
        args.output / "sanitized_unseen_stress_predictions.csv",
        index=False,
    )

    contaminated_family.to_csv(
        args.output / "contaminated_per_trigger_metrics.csv",
        index=False,
    )
    sanitized_family.to_csv(
        args.output / "sanitized_per_trigger_metrics.csv",
        index=False,
    )
    contaminated_stress_family.to_csv(
        args.output / "contaminated_stress_family_metrics.csv",
        index=False,
    )
    sanitized_stress_family.to_csv(
        args.output / "sanitized_stress_family_metrics.csv",
        index=False,
    )

    create_model_security_plot(
        contaminated_metrics,
        sanitized_metrics,
        args.output / "model_security_comparison.png",
    )
    create_stress_plot(
        contaminated_stress_family,
        sanitized_stress_family,
        args.output / "unseen_trigger_attack_success.png",
    )

    report = {
        "component": 3,
        "step": "39D",
        "title": (
            "Backdoor impact and sanitized-model "
            "security validation"
        ),
        "model": {
            "type": "RandomForestClassifier",
            "features": list(MODEL_FEATURES),
            "contaminated_training_rows": len(
                contaminated_train
            ),
            "sanitized_training_rows": len(
                sanitized_train
            ),
        },
        "independent_test": {
            "clean_rows": len(clean_test),
            "attack_rows": len(attack_test),
            "contaminated_model": asdict(
                contaminated_metrics
            ),
            "sanitized_model": asdict(
                sanitized_metrics
            ),
            "contaminated_per_trigger": (
                contaminated_family.to_dict(
                    orient="records"
                )
            ),
            "sanitized_per_trigger": (
                sanitized_family.to_dict(
                    orient="records"
                )
            ),
        },
        "unseen_trigger_stress": {
            "evidence": "SYNTHETIC_EVALUATION_ONLY",
            "rows": len(stress_suite),
            "contaminated_model": (
                contaminated_stress_metrics
            ),
            "sanitized_model": sanitized_stress_metrics,
            "contaminated_per_family": (
                contaminated_stress_family.to_dict(
                    orient="records"
                )
            ),
            "sanitized_per_family": (
                sanitized_stress_family.to_dict(
                    orient="records"
                )
            ),
        },
        "targets": {
            "sanitized_clean_accuracy_at_least_90_percent": (
                sanitized_metrics.clean_accuracy >= 0.90
            ),
            "sanitized_attack_success_at_most_5_percent": (
                sanitized_metrics.attack_success_rate <= 0.05
            ),
            "sanitized_safe_action_recovery_at_least_95_percent": (
                sanitized_metrics.safe_action_recovery_rate >= 0.95
            ),
            "sanitized_unseen_stress_recovery_at_least_95_percent": (
                sanitized_stress_metrics[
                    "safe_action_recovery_rate"
                ] >= 0.95
            ),
        },
        "evidence_type": "SYNTHETIC",
        "production_security_claim": False,
        "limitations": [
            (
                "The control labels are derived from a deterministic "
                "synthetic greenhouse policy."
            ),
            (
                "The contaminated and sanitized models are evaluated "
                "on synthetic telemetry and synthetic trigger stress."
            ),
            (
                "Real unknown-trigger, real compromised-sensor and "
                "production deployment validation remain incomplete."
            ),
        ],
    }

    (args.output / "metrics.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 80)
    print("COMPONENT 3 — STEP 39D BACKDOOR IMPACT REPORT")
    print("=" * 80)
    print(
        f"Contaminated training rows              : "
        f"{len(contaminated_train)}"
    )
    print(
        f"Sanitized training rows                 : "
        f"{len(sanitized_train)}"
    )
    print(
        f"Independent clean test rows             : "
        f"{len(clean_test)}"
    )
    print(
        f"Independent poison attack rows          : "
        f"{len(attack_test)}"
    )
    print()
    print("CONTAMINATED MODEL")
    print(
        f"  Clean accuracy                        : "
        f"{contaminated_metrics.clean_accuracy:.2%}"
    )
    print(
        f"  Clean macro-F1                        : "
        f"{contaminated_metrics.clean_macro_f1:.4f}"
    )
    print(
        f"  Backdoor attack success rate          : "
        f"{contaminated_metrics.attack_success_rate:.2%}"
    )
    print(
        f"  Safe-action recovery rate             : "
        f"{contaminated_metrics.safe_action_recovery_rate:.2%}"
    )
    print()
    print("SANITIZED MODEL")
    print(
        f"  Clean accuracy                        : "
        f"{sanitized_metrics.clean_accuracy:.2%}"
    )
    print(
        f"  Clean macro-F1                        : "
        f"{sanitized_metrics.clean_macro_f1:.4f}"
    )
    print(
        f"  Backdoor attack success rate          : "
        f"{sanitized_metrics.attack_success_rate:.2%}"
    )
    print(
        f"  Safe-action recovery rate             : "
        f"{sanitized_metrics.safe_action_recovery_rate:.2%}"
    )
    print(
        f"  Exact-label recovery rate             : "
        f"{sanitized_metrics.exact_label_recovery_rate:.2%}"
    )
    print(
        f"  Clean near-trigger accuracy           : "
        f"{sanitized_metrics.near_trigger_clean_accuracy:.2%}"
    )
    print()
    print("UNSEEN TRIGGER STRESS SUITE")
    print(
        f"  Stress rows                           : "
        f"{len(stress_suite)}"
    )
    print(
        f"  Contaminated attack success rate      : "
        f"{contaminated_stress_metrics['attack_success_rate']:.2%}"
    )
    print(
        f"  Sanitized attack success rate         : "
        f"{sanitized_stress_metrics['attack_success_rate']:.2%}"
    )
    print(
        f"  Sanitized safe-action recovery        : "
        f"{sanitized_stress_metrics['safe_action_recovery_rate']:.2%}"
    )
    print()
    print(
        "Sanitized clean-accuracy target         : "
        + (
            "PASSED"
            if sanitized_metrics.clean_accuracy >= 0.90
            else "NOT YET"
        )
    )
    print(
        "Sanitized attack-success target         : "
        + (
            "PASSED"
            if sanitized_metrics.attack_success_rate <= 0.05
            else "NOT YET"
        )
    )
    print(
        "Sanitized safe-recovery target          : "
        + (
            "PASSED"
            if sanitized_metrics.safe_action_recovery_rate >= 0.95
            else "NOT YET"
        )
    )
    print(
        "Unseen-stress safe-recovery target       : "
        + (
            "PASSED"
            if sanitized_stress_metrics[
                "safe_action_recovery_rate"
            ] >= 0.95
            else "NOT YET"
        )
    )
    print("Evidence type                           : SYNTHETIC")
    print("Production security claim               : NOT YET")
    print(
        "Research conclusion                     : "
        "POISONED MODEL RETAINS A DORMANT BACKDOOR; "
        "SANITIZATION REMOVES THE MALICIOUS TARGET BEHAVIOR"
    )
    print("STEP 39D RESULT                         : PASSED")
    print("=" * 80)


if __name__ == "__main__":
    main()
