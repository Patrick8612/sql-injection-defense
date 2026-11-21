"""Security mode settings shared by routes and templates."""

from __future__ import annotations

from ..database import get_db


DEFAULT_SECURITY_MODE = "safe"
SECURITY_MODES = ("safe", "vulnerable")
SECURITY_MODE_LABELS = {
    "safe": "安全模式",
    "vulnerable": "漏洞演示模式",
}


def get_security_mode() -> str:
    """Return the persisted security mode, falling back to safe."""

    row = get_db().execute(
        "SELECT value FROM settings WHERE key = ?",
        ("security_mode",),
    ).fetchone()

    if row is None or row["value"] not in SECURITY_MODES:
        return DEFAULT_SECURITY_MODE

    return row["value"]


def security_mode_label(mode: str) -> str:
    """Return the Chinese display label for a security mode."""

    return SECURITY_MODE_LABELS.get(mode, SECURITY_MODE_LABELS[DEFAULT_SECURITY_MODE])


def set_security_mode(mode: str) -> str:
    """Persist a validated security mode and refresh its timestamp."""

    if mode not in SECURITY_MODES:
        raise ValueError("unsupported security mode")

    db = get_db()
    with db:
        db.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            """,
            ("security_mode", mode),
        )

    return mode
