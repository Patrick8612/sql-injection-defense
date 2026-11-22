import pytest

from src.app import create_app
from src.config import Config
from src.database import get_db
from src.services.detection_logs import (
    get_detection_summary,
    list_recent_detections,
)


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


def detection_ids(app):
    with app.app_context():
        return [
            row["id"]
            for row in get_db().execute(
                "SELECT id FROM detection_logs ORDER BY id"
            ).fetchall()
        ]


def create_detection_logs(client):
    login(client, "student", "Student123!")
    client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )
    client.get(
        "/articles",
        query_string={"q": "%2527%2520OR%25201%253D1"},
    )
    client.post("/logout")


def test_admin_dashboard_shows_real_detection_statistics(app, client):
    create_detection_logs(client)
    login(client)

    response = client.get("/admin")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "检测概览" in page
    assert "检测总数" in page
    assert "中风险" in page
    assert "高风险" in page
    assert "最近检测告警" in page
    assert "D-1" in page
    assert "D-2" in page
    assert "UNION" not in page
    assert "%2527" not in page


def test_detection_summary_and_recent_list_use_persisted_rows(app, client):
    create_detection_logs(client)

    with app.app_context():
        summary = get_detection_summary()
        recent = list_recent_detections(limit=1)

    assert summary.total == 2
    assert summary.low == 0
    assert summary.medium == 1
    assert summary.high == 1
    assert summary.alert == 1
    assert summary.block == 1
    assert summary.risk_percentage(summary.high) == 50
    assert len(recent) == 1
    assert recent[0]["risk_level"] == "high"


def test_admin_dashboard_empty_state_without_detection_logs(client):
    login(client)

    response = client.get("/admin")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "暂无检测告警" in page
    assert "暂无记录" in page


def test_admin_can_view_sanitized_detection_detail(app, client):
    create_detection_logs(client)
    login(client)
    log_id = detection_ids(app)[-1]

    response = client.get(f"/admin/detections/{log_id}")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert f"D-{log_id}" in page
    assert "脱敏参数摘要" in page
    assert "原始请求参数没有写入数据库" in page
    assert "%2527" not in page


def test_regular_user_cannot_view_detection_detail(app, client):
    create_detection_logs(client)
    login(client, "student", "Student123!")
    log_id = detection_ids(app)[-1]

    response = client.get(f"/admin/detections/{log_id}")

    assert response.status_code == 403
    assert "无权访问" in response.get_data(as_text=True)


def test_unauthenticated_user_is_redirected_from_detection_detail(app, client):
    create_detection_logs(client)
    log_id = detection_ids(app)[-1]

    response = client.get(f"/admin/detections/{log_id}")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_missing_detection_detail_returns_styled_404(client):
    login(client)

    response = client.get("/admin/detections/999999")
    page = response.get_data(as_text=True)

    assert response.status_code == 404
    assert "检测记录不存在" in page
