from __future__ import annotations

import importlib
import platform
import sys

REQUIRED = (
    "numpy", "pandas", "sklearn", "scipy", "joblib",
    "matplotlib", "firebase_admin", "dotenv", "pydantic",
)


def main() -> None:
    print("=" * 68)
    print("COMPONENT 3 — STEP 39A ENVIRONMENT CHECK")
    print("=" * 68)
    print(f"Python version              : {platform.python_version()}")
    print(f"Python executable           : {sys.executable}")
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or later is required.")

    failures = []
    for module_name in REQUIRED:
        try:
            module = importlib.import_module(module_name)
            print(f"{module_name:<28}: {getattr(module, '__version__', 'available')}")
        except Exception as exc:
            failures.append((module_name, str(exc)))
            print(f"{module_name:<28}: FAILED")

    if failures:
        for name, error in failures:
            print(f"  - {name}: {error}")
        raise SystemExit(1)

    print("Environment result          : PASSED")
    print("STEP 39A ENV RESULT         : PASSED")
    print("=" * 68)


if __name__ == "__main__":
    main()
