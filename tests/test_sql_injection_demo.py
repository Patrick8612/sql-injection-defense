import sqlite3

import pytest

from src.app import create_app
from src.config import Config
from src.services.sql_injection_demo import (
    GENERIC_QUERY_ERROR,
    MAX_DEMO_RESULTS,
    run_demo_query,
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


def demo_article_count(app):
    with app.app_context():
        db = sqlite3.connect(app.config["DEMO_DATABASE_PATH"])
        try:
            return db.execute("SELECT COUNT(*) FROM demo_articles").fetchone()[0]
        finally:
            db.close()


def test_demo_requires_login(client):
    response = client.get("/demo/sql-injection")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_safe_mode_does_not_execute_demo_query(client):
    login(client)

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "normal", "q": "参数化"},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "当前为安全模式，演示查询未执行" in page
    assert "SAFE MODE" in page
    assert "演示查询没有返回结果" not in page


def test_vulnerable_mode_runs_parameterized_normal_scenario(client):
    enable_vulnerable_mode(client)

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "normal", "q": "参数化"},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "参数化查询的工作原理" in page
    assert "输入校验与参数化查询" in page
    assert "请求参数" in page
    assert "受控查询摘要" in page


def test_normal_scenario_handles_special_characters(client):
    enable_vulnerable_mode(client)

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "normal", "q": "O'Reilly"},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "演示查询没有返回结果" in page
    assert GENERIC_QUERY_ERROR not in page


def test_error_scenario_hides_database_details(client):
    enable_vulnerable_mode(client)

    response = client.get(
        "/demo/sql-injection",
        query_string={"scenario": "error", "q": "O'Reilly"},
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert GENERIC_QUERY_ERROR in page
    assert "OperationalError" not in page
    assert "syntax error" not in page
    assert "sqlite_master" not in page
    assert "Traceback" not in page


def test_boolean_scenario_returns_only_match_count(app):
    with app.app_context():
        true_result = run_demo_query("boolean", "1 = 1")
        false_result = run_demo_query("boolean", "1 = 2")

    assert true_result.match_count == 8
    assert true_result.rows == []
    assert false_result.match_count == 0


def test_union_scenario_is_confined_to_demo_table(app):
    parameter = (
        "x%' OR 1=1 UNION SELECT 900, '联合查询观察行', '虚构', '本地演示' --"
    )

    with app.app_context():
        result = run_demo_query("union", parameter)

    assert result.error is None
    assert result.match_count == 9
    assert any(row["id"] == 900 for row in result.rows)


def test_stacked_write_attempt_is_rejected_without_mutation(app):
    parameter = "x'; DELETE FROM demo_articles; --"

    with app.app_context():
        result = run_demo_query("union", parameter)

    assert result.error is not None
    assert "只读安全限制" in result.error
    assert demo_article_count(app) == 8


def test_system_schema_and_file_access_are_rejected(app):
    with app.app_context():
        schema_result = run_demo_query(
            "boolean",
            "(SELECT COUNT(*) FROM sqlite_master) > 0",
        )
        file_result = run_demo_query("boolean", "readfile('/etc/passwd') IS NOT NULL")

    assert schema_result.error is not None
    assert file_result.error is not None
    assert sqlite3.OperationalError.__name__ not in schema_result.error


def test_result_rows_are_limited_and_marked_truncated(app):
    with app.app_context():
        db = sqlite3.connect(app.config["DEMO_DATABASE_PATH"])
        try:
            with db:
                db.executemany(
                    """
                    INSERT INTO demo_articles (id, title, category, summary)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            index,
                            f"容量测试文章 {index}",
                            "容量测试",
                            "仅用于验证返回行数上限。",
                        )
                        for index in range(100, 160)
                    ],
                )
        finally:
            db.close()

        result = run_demo_query("normal", "")

    assert len(result.rows) == MAX_DEMO_RESULTS
    assert result.match_count == MAX_DEMO_RESULTS
    assert result.truncated is True
