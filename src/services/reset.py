"""Backup and restore the controlled demonstration environment."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from flask import current_app

from ..database import get_db, reset_application_database
from .sql_injection_demo import reset_demo_database


@dataclass(frozen=True, slots=True)
class EnvironmentCounts:
    """Current counts shown before a destructive reset."""

    users: int
    articles: int
    login_logs: int
    detection_logs: int
    comparison_runs: int
    reports: int
    demo_articles: int


@dataclass(frozen=True, slots=True)
class ResetResult:
    """Successful reset with recoverable database snapshots."""

    backup_paths: tuple[Path, ...]


def get_environment_counts() -> EnvironmentCounts:
    """Return current counts without modifying either database."""

    db = get_db()
    main_counts = {
        table: db.execute(f"SELECT COUNT(*) AS count FROM {table}")
        .fetchone()["count"]
        for table in (
            "users",
            "articles",
            "login_logs",
            "detection_logs",
            "comparison_runs",
            "experiment_reports",
        )
    }

    demo_path = Path(current_app.config["DEMO_DATABASE_PATH"])
    demo_articles = 0
    if demo_path.exists():
        demo_db = sqlite3.connect(f"{demo_path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            demo_articles = demo_db.execute(
                "SELECT COUNT(*) FROM demo_articles"
            ).fetchone()[0]
        finally:
            demo_db.close()

    return EnvironmentCounts(
        users=int(main_counts["users"]),
        articles=int(main_counts["articles"]),
        login_logs=int(main_counts["login_logs"]),
        detection_logs=int(main_counts["detection_logs"]),
        comparison_runs=int(main_counts["comparison_runs"]),
        reports=int(main_counts["experiment_reports"]),
        demo_articles=int(demo_articles),
    )


def _copy_database(source: Path, destination: Path) -> None:
    if not source.exists():
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    source_db = sqlite3.connect(source)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close()
        source_db.close()


def reset_environment() -> ResetResult:
    """Back up and atomically reset both application and demo databases."""

    application_path = Path(current_app.config["DATABASE_PATH"]).resolve()
    demo_path = Path(current_app.config["DEMO_DATABASE_PATH"]).resolve()
    backup_dir = application_path.parent / "backups"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    application_backup = backup_dir / f"demo-before-reset-{timestamp}.db"
    demo_backup = backup_dir / f"sql-injection-demo-before-reset-{timestamp}.db"

    _copy_database(application_path, application_backup)
    _copy_database(demo_path, demo_backup)

    try:
        reset_application_database()
        reset_demo_database()
    except Exception:
        _copy_database(application_backup, application_path)
        _copy_database(demo_backup, demo_path)
        raise

    frequency_tracker = current_app.extensions.get(
        "security_frequency_tracker"
    )
    if frequency_tracker is not None:
        frequency_tracker.clear()

    backups = tuple(
        path
        for path in (application_backup, demo_backup)
        if path.exists()
    )
    return ResetResult(backup_paths=backups)
