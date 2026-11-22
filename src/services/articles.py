"""Article query services using parameterized SQL."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app

from ..security.validation import (
    MAX_CATEGORY_LENGTH,
    MAX_SEARCH_KEYWORD_LENGTH,
    validate_text,
)


MAX_SEARCH_RESULTS = 100
READABLE_COLUMNS = {
    "articles": {
        "id",
        "title",
        "content",
        "category",
        "author_id",
        "created_at",
    },
    "users": {"id", "display_name"},
}


def open_article_readonly_connection() -> sqlite3.Connection:
    """Open a query-only connection restricted to article display tables."""

    database_path = Path(current_app.config["DATABASE_PATH"])
    database_uri = f"{database_path.resolve().as_uri()}?mode=ro"
    db = sqlite3.connect(database_uri, uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only = ON")
    db.execute("PRAGMA trusted_schema = OFF")

    allowed_actions = {sqlite3.SQLITE_SELECT}
    if hasattr(sqlite3, "SQLITE_RECURSIVE"):
        allowed_actions.add(sqlite3.SQLITE_RECURSIVE)

    def authorize(
        action: int,
        argument_one: str | None,
        argument_two: str | None,
        database_name: str | None,
        trigger_name: str | None,
    ) -> int:
        del database_name, trigger_name

        if action in allowed_actions:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and argument_two in READABLE_COLUMNS.get(
            argument_one or "",
            set(),
        ):
            return sqlite3.SQLITE_OK
        if (
            action == sqlite3.SQLITE_FUNCTION
            and (argument_two or "").lower() == "like"
        ):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    return db


def list_categories() -> list[str]:
    """Return the distinct article categories."""

    db = open_article_readonly_connection()
    try:
        rows = db.execute(
            """
            SELECT DISTINCT category
            FROM articles
            ORDER BY category
            """
        ).fetchall()
    finally:
        db.close()

    return [row["category"] for row in rows]


def search_articles(keyword: str = "", category: str = ""):
    """Search articles with fixed SQL structure and bound parameters."""

    keyword = validate_text(
        keyword,
        field="搜索关键词",
        max_length=MAX_SEARCH_KEYWORD_LENGTH,
    )
    category = validate_text(
        category,
        field="文章分类",
        max_length=MAX_CATEGORY_LENGTH,
    )

    conditions: list[str] = []
    parameters: list[object] = []

    if keyword:
        like_value = f"%{keyword}%"
        conditions.append(
            "(articles.title LIKE ? OR articles.content LIKE ?)"
        )
        parameters.extend([like_value, like_value])

    if category:
        conditions.append("articles.category = ?")
        parameters.append(category)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    parameters.append(MAX_SEARCH_RESULTS)

    query = f"""
        SELECT
            articles.id,
            articles.title,
            articles.content,
            articles.category,
            articles.created_at,
            users.display_name AS author
        FROM articles
        JOIN users ON users.id = articles.author_id
        {where_clause}
        ORDER BY articles.id
        LIMIT ?
    """

    db = open_article_readonly_connection()
    try:
        return db.execute(query, parameters).fetchall()
    finally:
        db.close()
