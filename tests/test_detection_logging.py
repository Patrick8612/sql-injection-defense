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


def enable_vulnerable_mode(client):
    login(client, "admin", "Admin123!")
    return client.post(
        "/admin/security-mode",
        data={"mode": "vulnerable"},
    )


def detection_logs(app):
    with app.app_context():
        return get_db().execute(
            """
            SELECT attack_type, endpoint, payload_masked, risk_level,
                   score, action, created_at
            FROM detection_logs
            ORDER BY id
            """
        ).fetchall()


def test_benign_request_does_not_create_detection_log(app, client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "O'Reilly"},
    )

    assert response.status_code == 200
    assert detection_logs(app) == []


def test_medium_risk_request_is_logged_as_alert(app, client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )
    logs = detection_logs(app)

    assert response.status_code == 200
    assert len(logs) == 1
    assert logs[0]["attack_type"] == "SQL 注入"
    assert logs[0]["endpoint"] == "/articles"
    assert logs[0]["risk_level"] == "medium"
    assert logs[0]["score"] == 25
    assert logs[0]["action"] == "alert"
    assert "UNION" not in logs[0]["payload_masked"]
    assert "SELECT" not in logs[0]["payload_masked"]


def test_blocked_request_is_logged_before_403(app, client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "%2527%2520OR%25201%253D1"},
    )
    logs = detection_logs(app)

    assert response.status_code == 403
    assert len(logs) == 1
    assert logs[0]["risk_level"] == "high"
    assert logs[0]["score"] == 65
    assert logs[0]["action"] == "block"
    assert logs[0]["attack_type"] == "SQL 注入+编码绕过"
    assert "%2527" not in logs[0]["payload_masked"]


def test_controlled_demo_logs_effective_alert_action(app, client):
    enable_vulnerable_mode(client)
    parameter = (
        "x%' OR 1=1 UNION SELECT 900, '演示行', '虚构', '本地演示' --"
    )

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "union", "q": parameter},
    )
    logs = detection_logs(app)

    assert response.status_code == 200
    assert len(logs) == 1
    assert logs[0]["endpoint"] == "/demo/sql-injection"
    assert logs[0]["risk_level"] == "high"
    assert logs[0]["action"] == "alert"
    assert "高频请求" not in logs[0]["attack_type"]


def test_fifth_suspicious_request_logs_frequency_and_block(app, client):
    login(client)

    for _ in range(5):
        client.get(
            "/articles",
            query_string={"q": "UNION SELECT"},
        )

    logs = detection_logs(app)
    last_log = logs[-1]

    assert len(logs) == 5
    assert last_log["risk_level"] == "high"
    assert last_log["score"] == 75
    assert last_log["action"] == "block"
    assert last_log["attack_type"] == "SQL 注入+高频请求"
