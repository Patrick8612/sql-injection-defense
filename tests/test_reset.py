import sqlite3

import pytest

from src.app import create_app
from src.config import Config
from src.database import get_db
from src.services.comparison import run_comparison_experiment
from src.services.reports import generate_experiment_report
from src.services.reset import get_environment_counts, reset_environment


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


def login(client, username="admin", password="Admin123!"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def create_dirty_state(app, client):
    login(client)
    client.post(
        "/admin/security-mode",
        data={"mode": "vulnerable"},
    )
    client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )

    with app.app_context():
        run_id = run_comparison_experiment()
        generate_experiment_report(run_id)
        demo_db = sqlite3.connect(app.config["DEMO_DATABASE_PATH"])
        try:
            with demo_db:
                demo_db.execute(
                    """
                    INSERT INTO demo_articles (id, title, category, summary)
                    VALUES (999, '额外展示数据', '测试', '等待重置')
                    """
                )
        finally:
            demo_db.close()


def application_counts(app):
    with app.app_context():
        db = get_db()
        return {
            table: db.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()["count"]
            for table in (
                "users",
                "articles",
                "login_logs",
                "detection_logs",
                "comparison_runs",
                "comparison_results",
                "experiment_reports",
            )
        }


def demo_count(app):
    with app.app_context():
        db = sqlite3.connect(app.config["DEMO_DATABASE_PATH"])
        try:
            return db.execute(
                "SELECT COUNT(*) FROM demo_articles"
            ).fetchone()[0]
        finally:
            db.close()


def test_unauthenticated_user_is_redirected_from_reset(client):
    response = client.get("/admin/reset")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_regular_user_cannot_access_or_execute_reset(client):
    login(client, "student", "Student123!")

    get_response = client.get("/admin/reset")
    post_response = client.post(
        "/admin/reset",
        data={"confirmation": "RESET"},
    )

    assert get_response.status_code == 403
    assert post_response.status_code == 403


def test_reset_page_shows_real_environment_counts(app, client):
    create_dirty_state(app, client)

    response = client.get("/admin/reset")
    page = response.get_data(as_text=True)
    with app.app_context():
        counts = get_environment_counts()

    assert response.status_code == 200
    assert "恢复演示环境" in page
    assert str(counts.detection_logs) in page
    assert counts.comparison_runs == 1
    assert counts.reports == 1
    assert counts.demo_articles == 9


def test_wrong_confirmation_does_not_reset_environment(app, client):
    create_dirty_state(app, client)
    before = application_counts(app)

    response = client.post(
        "/admin/reset",
        data={"confirmation": "reset"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "确认文字不正确" in response.get_data(as_text=True)
    assert application_counts(app) == before


def test_admin_reset_restores_seed_environment_and_backups(app, client):
    create_dirty_state(app, client)
    before = application_counts(app)
    assert before["detection_logs"] >= 1
    assert before["comparison_runs"] == 1
    assert before["experiment_reports"] == 1
    tracker = app.extensions["security_frequency_tracker"]
    tracker.record("reset-test-client")

    response = client.post(
        "/admin/reset",
        data={"confirmation": "RESET"},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "演示环境已恢复" in page
    assert "demo-before-reset-" in page
    assert "sql-injection-demo-before-reset-" in page

    assert client.get("/").status_code == 302

    counts = application_counts(app)
    assert counts["users"] == 2
    assert counts["articles"] == 8
    assert counts["login_logs"] == 0
    assert counts["detection_logs"] == 0
    assert counts["comparison_runs"] == 0
    assert counts["comparison_results"] == 0
    assert counts["experiment_reports"] == 0
    assert demo_count(app) == 8
    assert tracker.record("reset-test-client").count == 1

    with app.app_context():
        mode = get_db().execute(
            "SELECT value FROM settings WHERE key = 'security_mode'"
        ).fetchone()["value"]
    assert mode == "safe"

    login_response = login(client)
    assert login_response.status_code == 302

    backup_dir = app.config["DATABASE_PATH"].parent / "backups"
    backups = list(backup_dir.glob("*.db"))
    assert len(backups) == 2


def test_reset_failure_restores_application_snapshot(app, monkeypatch):
    marker = None
    with app.app_context():
        db = get_db()
        with db:
            cursor = db.execute(
                """
                INSERT INTO detection_logs (
                    attack_type, endpoint, payload_masked,
                    risk_level, score, action
                )
                VALUES ('test', '/test', 'q{len=1}', 'low', 10, 'allow')
                """
            )
            marker = cursor.lastrowid

    def fail_demo_reset():
        raise RuntimeError("simulated demo reset failure")

    monkeypatch.setattr(
        "src.services.reset.reset_demo_database",
        fail_demo_reset,
    )

    with app.app_context():
        with pytest.raises(RuntimeError):
            reset_environment()

        restored = get_db().execute(
            "SELECT id FROM detection_logs WHERE id = ?",
            (marker,),
        ).fetchone()

    assert restored is not None
