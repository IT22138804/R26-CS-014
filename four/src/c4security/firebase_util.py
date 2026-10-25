from __future__ import annotations

import os
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_environment() -> dict[str, str]:
    load_dotenv(PROJECT_ROOT / ".env")

    values = {
        "credentials_path": os.getenv(
            "FIREBASE_CREDENTIALS_PATH", ""
        ).strip(),
        "database_url": os.getenv(
            "FIREBASE_DATABASE_URL", ""
        ).strip(),
        "web_api_key": os.getenv(
            "FIREBASE_WEB_API_KEY", ""
        ).strip(),
    }

    missing = [key for key, value in values.items() if not value]
    if missing:
        raise RuntimeError(
            "Missing required .env values: "
            + ", ".join(missing)
        )

    credentials_path = Path(values["credentials_path"])
    if not credentials_path.is_absolute():
        credentials_path = (
            PROJECT_ROOT / credentials_path
        ).resolve()

    if not credentials_path.exists():
        raise RuntimeError(
            "Firebase service-account JSON not found at: "
            f"{credentials_path}"
        )

    values["credentials_path"] = str(credentials_path)
    return values


def initialize_admin() -> dict[str, str]:
    values = load_environment()

    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(values["credentials_path"]),
            {"databaseURL": values["database_url"]},
        )

    return values
