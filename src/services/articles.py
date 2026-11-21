"""Article query services using parameterized SQL."""

from __future__ import annotations

from ..database import get_db


MAX_SEARCH_RESULTS = 100


def list_categories() -> list[str]:
    """Return the distinct article categories."""

    rows = get_db().execute(
        """
        SELECT DISTINCT category
        FROM articles
        ORDER BY category
        """
    ).fetchall()

    return [row["category"] for row in rows]


def search_articles(keyword: str = "", category: str = ""):
    """Search articles with fixed SQL structure and bound parameters."""

    keyword = keyword.strip()[:80]
    category = category.strip()[:40]

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

    return get_db().execute(query, parameters).fetchall()
