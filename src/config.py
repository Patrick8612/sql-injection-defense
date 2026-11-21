"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _as_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Safe defaults for the local teaching environment."""

    SECRET_KEY = os.getenv("SECRET_KEY", "local-demo-only-change-before-sharing")
    DEBUG = _as_bool("FLASK_DEBUG", False)

    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    DATABASE_PATH = Path(
        os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "instance" / "demo.db"))
    )
    DEMO_DATABASE_PATH = Path(
        os.getenv(
            "DEMO_DATABASE_PATH",
            str(PROJECT_ROOT / "instance" / "sql_injection_demo.db"),
        )
    )
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool("SESSION_COOKIE_SECURE", False)

