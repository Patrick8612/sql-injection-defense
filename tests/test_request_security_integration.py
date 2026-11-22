import pytest

from src.app import create_app
from src.config import Config


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


def test_medium_risk_article_request_is_alerted_but_allowed(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )

    assert response.status_code == 200
    assert "安全文章查询" in response.get_data(as_text=True)


def test_high_risk_article_request_is_blocked_before_query(client):
    login(client)

    response = client.get(
        "/articles",
        query_string={"q": "%2527%2520OR%25201%253D1"},
    )

    assert response.status_code == 403
    assert "请求已拦截" in response.get_data(as_text=True)


def test_vulnerable_demo_allows_high_risk_input_as_controlled_alert(client):
    enable_vulnerable_mode(client)
    parameter = (
        "x%' OR 1=1 UNION SELECT 900, '联合查询观察行', '虚构', '本地演示' --"
    )

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "union", "q": parameter},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "联合查询观察行" in page
    assert "请求已拦截" not in page


def test_safe_demo_mode_does_not_enforce_high_risk_block(client):
    login(client)

    response = client.get(
        "/demo/sql-injection",
        query_string={
            "scenario": "normal",
            "q": "%2527%2520OR%25201%253D1",
        },
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "当前为安全模式，演示查询未执行" in page


def test_fifth_repeated_suspicious_request_is_blocked(client):
    login(client)

    statuses = [
        client.get(
            "/articles",
            query_string={"q": "UNION SELECT"},
        ).status_code
        for _ in range(5)
    ]

    assert statuses[:4] == [200, 200, 200, 200]
    assert statuses[4] == 403


def test_benign_requests_are_not_counted_by_frequency_rule(client):
    login(client)

    statuses = [
        client.get(
            "/articles",
            query_string={"q": "O'Reilly"},
        ).status_code
        for _ in range(6)
    ]

    assert statuses == [200] * 6
