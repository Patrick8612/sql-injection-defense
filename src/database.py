"""SQLite database connection, schema, and demonstration seed data."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, current_app, g
from werkzeug.security import generate_password_hash


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1
        CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username_attempt TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0
        CHECK (success IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS detection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload_masked TEXT NOT NULL,
    risk_level TEXT NOT NULL
        CHECK (risk_level IN ('low', 'medium', 'high')),
    score INTEGER NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS comparison_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS comparison_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    case_order INTEGER NOT NULL,
    case_code TEXT NOT NULL,
    case_name TEXT NOT NULL,
    scenario TEXT NOT NULL,
    parameter_masked TEXT NOT NULL,
    vulnerable_success INTEGER NOT NULL
        CHECK (vulnerable_success IN (0, 1)),
    vulnerable_count INTEGER NOT NULL,
    vulnerable_error TEXT,
    safe_success INTEGER NOT NULL
        CHECK (safe_success IN (0, 1)),
    safe_count INTEGER NOT NULL,
    safe_error TEXT,
    risk_level TEXT NOT NULL
        CHECK (risk_level IN ('none', 'low', 'medium', 'high')),
    risk_score INTEGER NOT NULL,
    suggested_action TEXT NOT NULL
        CHECK (suggested_action IN ('allow', 'alert', 'block')),
    rule_codes TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES comparison_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS experiment_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comparison_run_id INTEGER NOT NULL,
    generated_at TEXT NOT NULL,
    content_markdown TEXT NOT NULL,
    FOREIGN KEY (comparison_run_id)
        REFERENCES comparison_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (key <> 'security_mode' OR value IN ('safe', 'vulnerable'))
);

CREATE TRIGGER IF NOT EXISTS validate_security_mode_on_insert
BEFORE INSERT ON settings
WHEN NEW.key = 'security_mode'
    AND NEW.value NOT IN ('safe', 'vulnerable')
BEGIN
    SELECT RAISE(ABORT, 'security_mode must be safe or vulnerable');
END;

CREATE TRIGGER IF NOT EXISTS validate_security_mode_on_update
BEFORE UPDATE OF key, value ON settings
WHEN NEW.key = 'security_mode'
    AND NEW.value NOT IN ('safe', 'vulnerable')
BEGIN
    SELECT RAISE(ABORT, 'security_mode must be safe or vulnerable');
END;

CREATE INDEX IF NOT EXISTS idx_articles_author
    ON articles(author_id);

CREATE INDEX IF NOT EXISTS idx_login_logs_created
    ON login_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_detection_logs_created
    ON detection_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_comparison_results_run
    ON comparison_results(run_id, case_order);

CREATE INDEX IF NOT EXISTS idx_experiment_reports_generated
    ON experiment_reports(generated_at);
"""


DEMO_USERS = [
    ("student", "Student123!", "林同学", "user"),
    ("admin", "Admin123!", "安全管理员", "admin"),
]


DEMO_ARTICLES = [
    (
        "SQL 注入基础概念",
        "SQL 注入是应用程序把不可信输入错误地拼接到 SQL 语句中，"
        "从而改变原查询含义的风险。",
        "基础理论",
    ),
    (
        "参数化查询的工作原理",
        "参数化查询把 SQL 结构和用户输入分开处理，"
        "数据库只把参数视为数据。",
        "安全防护",
    ),
    (
        "错误型注入演示说明",
        "错误型注入会利用异常信息观察查询结构变化，"
        "本系统只使用虚构数据进行本地演示。",
        "注入类型",
    ),
    (
        "联合查询的风险",
        "联合查询可能扩展原查询结构。"
        "演示系统只允许读取文章展示表。",
        "注入类型",
    ),
    (
        "布尔盲注与响应差异",
        "布尔盲注通过不同条件造成的页面结果差异推断信息。",
        "注入类型",
    ),
    (
        "最小权限原则",
        "演示账号应当只拥有必要的查询权限，"
        "避免用户输入影响其他业务数据。",
        "安全防护",
    ),
    (
        "输入校验与参数化查询",
        "输入校验可以减少可疑请求，"
        "但参数化查询才是防止 SQL 结构被改变的核心措施。",
        "安全防护",
    ),
    (
        "课程演示安全边界",
        "所有攻击演示仅在本机虚构数据上运行，"
        "不连接真实业务系统或外部目标。",
        "实验规范",
    ),
]


def get_db() -> sqlite3.Connection:
    """Return the database connection for the current request."""

    if "db" not in g:
        database_path = Path(current_app.config["DATABASE_PATH"])
        database_path.parent.mkdir(parents=True, exist_ok=True)

        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(error: BaseException | None = None) -> None:
    """Close the request database connection."""

    db = g.pop("db", None)
    if db is not None:
        db.close()


def seed_db() -> None:
    """Insert fictional demonstration data only once."""

    db = get_db()

    with db:
        db.executemany(
            """
            INSERT OR IGNORE INTO settings (key, value)
            VALUES (?, ?)
            """,
            [
                ("security_mode", "safe"),
                ("demo_environment", "local"),
            ],
        )
        db.execute(
            """
            UPDATE settings
            SET value = ?, updated_at = CURRENT_TIMESTAMP
            WHERE key = ? AND value NOT IN (?, ?)
            """,
            ("safe", "security_mode", "safe", "vulnerable"),
        )

    existing_users = db.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()["count"]

    if existing_users > 0:
        return

    user_rows = [
        (
            username,
            generate_password_hash(password),
            display_name,
            role,
        )
        for username, password, display_name, role in DEMO_USERS
    ]

    with db:
        db.executemany(
            """
            INSERT INTO users (username, password_hash, display_name, role)
            VALUES (?, ?, ?, ?)
            """,
            user_rows,
        )

        student_id = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("student",),
        ).fetchone()["id"]

        db.executemany(
            """
            INSERT INTO articles (
                title,
                content,
                category,
                author_id
            )
            VALUES (?, ?, ?, ?)
            """,
            [
                (title, content, category, student_id)
                for title, content, category in DEMO_ARTICLES
            ],
        )


def reset_application_database() -> None:
    """Reset all application runtime data in one transaction."""

    db = get_db()
    with db:
        for table in (
            "experiment_reports",
            "comparison_results",
            "comparison_runs",
            "detection_logs",
            "login_logs",
            "articles",
            "users",
            "settings",
        ):
            db.execute(f"DELETE FROM {table}")

        db.execute(
            """
            DELETE FROM sqlite_sequence
            WHERE name IN (
                'experiment_reports',
                'comparison_results',
                'comparison_runs',
                'detection_logs',
                'login_logs',
                'articles',
                'users'
            )
            """
        )

        user_rows = [
            (
                username,
                generate_password_hash(password),
                display_name,
                role,
            )
            for username, password, display_name, role in DEMO_USERS
        ]
        db.executemany(
            """
            INSERT INTO users (username, password_hash, display_name, role)
            VALUES (?, ?, ?, ?)
            """,
            user_rows,
        )

        student_id = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("student",),
        ).fetchone()["id"]
        db.executemany(
            """
            INSERT INTO articles (
                title,
                content,
                category,
                author_id
            )
            VALUES (?, ?, ?, ?)
            """,
            [
                (title, content, category, student_id)
                for title, content, category in DEMO_ARTICLES
            ],
        )
        db.executemany(
            """
            INSERT INTO settings (key, value)
            VALUES (?, ?)
            """,
            [
                ("security_mode", "safe"),
                ("demo_environment", "local"),
            ],
        )


def init_db() -> None:
    """Create all tables and insert the initial demonstration data."""

    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()
    seed_db()


def init_app(app: Flask) -> None:
    """Register database lifecycle hooks with Flask."""

    app.teardown_appcontext(close_db)
