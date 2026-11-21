import sqlite3

import pytest

from src.app import create_app
from src.config import Config
from src.database import get_db


@pytest.fixture()
def app(tmp_path):
    class TestConfig(Config):
        TESTING = True
        SECRET_KEY = "test-secret-key"

    TestConfig.DATABASE_PATH = tmp_path / "test.db"
    return create_app(TestConfig)


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="admin", password="Admin123!"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def persisted_mode(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT value, updated_at FROM settings WHERE key = ?",
            ("security_mode",),
        ).fetchone()
        return row["value"], row["updated_at"]


def test_regular_user_cannot_switch_security_mode(app, client):
    login(client, "student", "Student123!")

    response = client.post("/admin/security-mode", data={"mode": "vulnerable"})

    assert response.status_code == 403
    assert persisted_mode(app)[0] == "safe"


def test_unauthenticated_user_is_redirected_to_login(client):
    response = client.post("/admin/security-mode", data={"mode": "vulnerable"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_admin_can_switch_to_vulnerable_and_updated_at_changes(app, client):
    with app.app_context():
        db = get_db()
        with db:
            db.execute(
                """
                UPDATE settings
                SET updated_at = ?
                WHERE key = ?
                """,
                ("2000-01-01 00:00:00", "security_mode"),
            )

    login(client)
    response = client.post(
        "/admin/security-mode",
        data={"mode": "vulnerable"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "已切换为漏洞演示模式".encode() in response.data
    mode, updated_at = persisted_mode(app)
    assert mode == "vulnerable"
    assert updated_at != "2000-01-01 00:00:00"


def test_admin_can_switch_back_to_safe(app, client):
    login(client)
    client.post("/admin/security-mode", data={"mode": "vulnerable"})

    response = client.post(
        "/admin/security-mode",
        data={"mode": "safe"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "已切换为安全模式".encode() in response.data
    assert persisted_mode(app)[0] == "safe"


def test_pages_show_current_security_mode(app, client):
    response = client.get("/login")
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "当前：安全模式" in page

    login(client)
    client.post("/admin/security-mode", data={"mode": "vulnerable"})

    for path in ("/", "/articles", "/admin"):
        response = client.get(path)
        page = response.get_data(as_text=True)
        assert response.status_code == 200
        assert "当前：漏洞演示模式" in page


def test_database_rejects_invalid_security_mode(app):
    with app.app_context():
        db = get_db()

        with pytest.raises(sqlite3.IntegrityError):
            with db:
                db.execute(
                    "UPDATE settings SET value = ? WHERE key = ?",
                    ("unsafe-value", "security_mode"),
                )
