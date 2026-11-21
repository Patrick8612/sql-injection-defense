"""Isolated, read-only SQL injection teaching scenarios."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from flask import current_app

from ..database import DEMO_ARTICLES


MAX_DEMO_INPUT_LENGTH = 80
MAX_DEMO_RESULTS = 50
QUERY_TIMEOUT_SECONDS = 0.15
QUERY_STEP_LIMIT = 20_000
GENERIC_QUERY_ERROR = "演示查询未完成。系统已隐藏数据库错误细节。"

SCENARIO_LABELS = {
    "normal": "正常特殊字符",
    "error": "错误型注入",
    "union": "联合查询",
    "boolean": "布尔盲注",
}

SCENARIO_SUMMARIES = {
    "normal": "参数化关键词查询：标题和摘要均使用参数绑定",
    "error": "错误型场景：关键词进入固定查询模板，数据库语法异常会被统一处理",
    "union": "联合查询场景：固定四列查询模板，仅允许读取演示文章表",
    "boolean": "布尔盲注场景：只返回布尔条件的匹配数量",
}

SAFE_FUNCTIONS = {
    "coalesce",
    "count",
    "ifnull",
    "length",
    "like",
    "lower",
    "max",
    "min",
    "substr",
    "trim",
    "upper",
}

FORBIDDEN_FRAGMENTS = (
    ";",
    "PRAGMA",
    "ATTACH",
    "DETACH",
    "LOAD_EXTENSION",
    "READFILE",
    "WRITEFILE",
    "SQLITE_MASTER",
    "SQLITE_SCHEMA",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "REPLACE",
    "VACUUM",
    "REINDEX",
    "TRIGGER",
    "RANDOMBLOB",
    "ZEROBLOB",
    "WITH RECURSIVE",
    "SLEEP",
    "PG_SLEEP",
    "BENCHMARK",
    "XP_CMDSHELL",
)

DEMO_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS demo_articles (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class DemoQueryResult:
    """Bounded results returned by a demonstration query."""

    scenario: str
    parameter: str
    query_summary: str
    rows: list[dict[str, object]]
    match_count: int
    truncated: bool = False
    error: str | None = None


def init_demo_database() -> None:
    """Create and seed the isolated fictional demonstration database."""

    database_path = Path(current_app.config["DEMO_DATABASE_PATH"])
    database_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(database_path) as db:
        db.executescript(DEMO_SCHEMA_SQL)
        db.executemany(
            """
            INSERT OR IGNORE INTO demo_articles (id, title, category, summary)
            VALUES (?, ?, ?, ?)
            """,
            [
                (index, title, category, content)
                for index, (title, content, category) in enumerate(DEMO_ARTICLES, 1)
            ],
        )


def _open_read_only_database() -> sqlite3.Connection:
    """Open the isolated demonstration database with hard read-only guards."""

    database_path = Path(current_app.config["DEMO_DATABASE_PATH"])
    database_uri = f"{database_path.resolve().as_uri()}?mode=ro"
    db = sqlite3.connect(database_uri, uri=True)
    db.row_factory = sqlite3.Row

    db.execute("PRAGMA query_only = ON")
    db.execute("PRAGMA trusted_schema = OFF")

    for limit_name, limit_value in (
        ("SQLITE_LIMIT_LENGTH", 10_000),
        ("SQLITE_LIMIT_SQL_LENGTH", 2_000),
        ("SQLITE_LIMIT_COMPOUND_SELECT", 4),
        ("SQLITE_LIMIT_VDBE_OP", QUERY_STEP_LIMIT),
    ):
        if hasattr(sqlite3, limit_name):
            db.setlimit(getattr(sqlite3, limit_name), limit_value)

    def authorize(
        action: int,
        argument_one: str | None,
        argument_two: str | None,
        database_name: str | None,
        trigger_name: str | None,
    ) -> int:
        del database_name, trigger_name

        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_RECURSIVE}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and argument_one == "demo_articles":
            return sqlite3.SQLITE_OK
        if (
            action == sqlite3.SQLITE_FUNCTION
            and (argument_two or "").lower() in SAFE_FUNCTIONS
        ):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    if hasattr(sqlite3, "SQLITE_RECURSIVE"):
        db.set_authorizer(authorize)
    else:
        db.set_authorizer(
            lambda action, one, two, name, trigger: (
                sqlite3.SQLITE_OK
                if (
                    action == sqlite3.SQLITE_SELECT
                    or (action == sqlite3.SQLITE_READ and one == "demo_articles")
                    or (
                        action == sqlite3.SQLITE_FUNCTION
                        and (two or "").lower() in SAFE_FUNCTIONS
                    )
                )
                else sqlite3.SQLITE_DENY
            )
        )

    deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
    step_count = 0

    def progress_handler() -> int:
        nonlocal step_count
        step_count += 1
        if step_count > QUERY_STEP_LIMIT or time.monotonic() > deadline:
            return 1
        return 0

    db.set_progress_handler(progress_handler, 100)
    return db


def _validate_demo_input(parameter: str) -> str | None:
    if len(parameter) > MAX_DEMO_INPUT_LENGTH:
        return f"输入最多允许 {MAX_DEMO_INPUT_LENGTH} 个字符。"

    normalized = parameter.upper()
    if any(fragment in normalized for fragment in FORBIDDEN_FRAGMENTS):
        return "输入触发了实验沙箱的只读安全限制。"

    return None


def _query_result(
    scenario: str,
    parameter: str,
    *,
    rows: list[dict[str, object]] | None = None,
    match_count: int = 0,
    truncated: bool = False,
    error: str | None = None,
) -> DemoQueryResult:
    return DemoQueryResult(
        scenario=scenario,
        parameter=parameter,
        query_summary=SCENARIO_SUMMARIES[scenario],
        rows=rows or [],
        match_count=match_count,
        truncated=truncated,
        error=error,
    )


def run_demo_query(scenario: str, parameter: str) -> DemoQueryResult:
    """Run one fixed demonstration scenario with hard resource boundaries."""

    if scenario not in SCENARIO_LABELS:
        raise ValueError("unsupported demonstration scenario")

    parameter = parameter.strip()
    validation_error = _validate_demo_input(parameter)
    if validation_error is not None:
        return _query_result(scenario, parameter, error=validation_error)

    db: sqlite3.Connection | None = None
    try:
        db = _open_read_only_database()

        if scenario == "normal":
            rows = db.execute(
                """
                SELECT id, title, category, summary
                FROM demo_articles
                WHERE title LIKE ? OR summary LIKE ?
                ORDER BY id
                LIMIT ?
                """,
                (
                    f"%{parameter}%",
                    f"%{parameter}%",
                    MAX_DEMO_RESULTS + 1,
                ),
            ).fetchall()
            row_dicts = [dict(row) for row in rows]
            return _query_result(
                scenario,
                parameter,
                rows=row_dicts[:MAX_DEMO_RESULTS],
                match_count=min(len(row_dicts), MAX_DEMO_RESULTS),
                truncated=len(row_dicts) > MAX_DEMO_RESULTS,
            )

        if scenario == "boolean":
            condition = parameter or "1 = 1"
            row = db.execute(
                """
                SELECT COUNT(*) AS match_count
                FROM demo_articles
                WHERE ({condition})
                """.format(condition=condition)
            ).fetchone()
            match_count = int(row["match_count"]) if row else 0
            return _query_result(
                scenario,
                parameter,
                match_count=match_count,
            )

        raw_query = """
            SELECT id, title, category, summary
            FROM demo_articles
            WHERE title LIKE '%{parameter}%'
            ORDER BY id
            LIMIT {row_limit}
        """.format(
            parameter=parameter,
            row_limit=MAX_DEMO_RESULTS + 1,
        )
        rows = db.execute(raw_query).fetchall()
        row_dicts = [dict(row) for row in rows]
        return _query_result(
            scenario,
            parameter,
            rows=row_dicts[:MAX_DEMO_RESULTS],
            match_count=min(len(row_dicts), MAX_DEMO_RESULTS),
            truncated=len(row_dicts) > MAX_DEMO_RESULTS,
        )
    except sqlite3.Error:
        return _query_result(
            scenario,
            parameter,
            error=GENERIC_QUERY_ERROR,
        )
    finally:
        if db is not None:
            db.close()
