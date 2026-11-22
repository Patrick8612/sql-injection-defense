import sqlite3

import pytest

from src.app import create_app
from src.config import Config
from src.services.articles import open_article_readonly_connection


@pytest.fixture()
def app(tmp_path):
    class TestConfig(Config):
        TESTING = True
        SECRET_KEY = "test-secret-key"

    TestConfig.DATABASE_PATH = tmp_path / "test.db"
    TestConfig.DEMO_DATABASE_PATH = tmp_path / "sql-injection-demo.db"
    return create_app(TestConfig)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="student", password="Student123!"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def test_security_headers_are_added_to_html_responses(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cache-Control"] == "no-store"


def test_article_search_rejects_overlength_keyword(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "a" * 81},
    )

    assert response.status_code == 400
    assert "最多允许 80 个字符" in response.get_data(as_text=True)


def test_article_search_rejects_control_characters(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "safe\nvalue"},
    )

    assert response.status_code == 400
    assert "控制字符" in response.get_data(as_text=True)


def test_article_search_rejects_unknown_category(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"category": "不存在的分类"},
    )

    assert response.status_code == 400
    assert "不在允许范围内" in response.get_data(as_text=True)


def test_article_search_still_handles_safe_special_characters(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "O'Reilly"},
    )

    assert response.status_code == 200
    assert "没有找到匹配文章" in response.get_data(as_text=True)


def test_article_readonly_connection_denies_writes(app):
    with app.app_context():
        db = open_article_readonly_connection()
        try:
            before = db.execute("SELECT title FROM articles ORDER BY id").fetchall()
            with pytest.raises(sqlite3.DatabaseError):
                db.execute("UPDATE articles SET title = 'changed'")
            after = db.execute("SELECT title FROM articles ORDER BY id").fetchall()
        finally:
            db.close()

    assert [row["title"] for row in before] == [row["title"] for row in after]


def test_article_readonly_connection_denies_sensitive_user_columns(app):
    with app.app_context():
        db = open_article_readonly_connection()
        try:
            with pytest.raises(sqlite3.DatabaseError):
                db.execute("SELECT password_hash FROM users").fetchall()
        finally:
            db.close()


def test_oversized_login_username_returns_generic_auth_error(client):
    response = client.post(
        "/login",
        data={"username": "u" * 81, "password": "Student123!"},
    )

    assert response.status_code == 401
    page = response.get_data(as_text=True)
    assert "用户名或密码错误" in page
    assert "最多允许" not in page


def test_internal_error_page_hides_exception_details(app, client):
    @app.get("/_test/internal-error")
    def internal_error():
        raise RuntimeError("private database path and stack detail")

    app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    response = client.get("/_test/internal-error")
    page = response.get_data(as_text=True)

    assert response.status_code == 500
    assert "系统暂时不可用" in page
    assert "private database path" not in page
    assert "RuntimeError" not in page
