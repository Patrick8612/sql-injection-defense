import pytest

from src.app import create_app
from src.config import Config
from src.database import get_db
from src.services.comparison import run_comparison_experiment


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


def comparison_rows(app, run_id):
    with app.app_context():
        return get_db().execute(
            """
            SELECT case_code, case_name, scenario, parameter_masked,
                   vulnerable_success, vulnerable_count, vulnerable_error,
                   safe_success, safe_count, safe_error,
                   risk_level, risk_score, suggested_action, rule_codes,
                   conclusion
            FROM comparison_results
            WHERE run_id = ?
            ORDER BY case_order
            """,
            (run_id,),
        ).fetchall()


def test_comparison_persists_all_six_fixed_cases(app):
    with app.app_context():
        run_id = run_comparison_experiment()

    rows = comparison_rows(app, run_id)

    assert [row["case_code"] for row in rows] == [
        "C-01",
        "C-02",
        "C-03",
        "C-04",
        "C-05",
        "C-06",
    ]
    assert all(row["conclusion"] for row in rows)


def test_comparison_records_real_mode_differences(app):
    with app.app_context():
        run_id = run_comparison_experiment()

    rows = {row["case_code"]: row for row in comparison_rows(app, run_id)}

    assert rows["C-01"]["vulnerable_success"] == 1
    assert rows["C-01"]["vulnerable_count"] == 2
    assert rows["C-01"]["safe_success"] == 1
    assert rows["C-01"]["safe_count"] == 2

    assert rows["C-02"]["vulnerable_success"] == 0
    assert rows["C-02"]["safe_success"] == 1

    assert rows["C-03"]["vulnerable_success"] == 1
    assert rows["C-03"]["vulnerable_count"] > rows["C-03"]["safe_count"]

    assert rows["C-04"]["vulnerable_count"] == 8
    assert rows["C-05"]["vulnerable_count"] == 0
    assert rows["C-06"]["risk_level"] == "high"
    assert rows["C-06"]["suggested_action"] == "block"
    assert "ENCODED_PAYLOAD" in rows["C-06"]["rule_codes"]


def test_comparison_does_not_store_raw_inputs(app):
    with app.app_context():
        run_id = run_comparison_experiment()

    rows = comparison_rows(app, run_id)
    serialized = " ".join(
        " ".join(str(value) for value in tuple(row))
        for row in rows
    )

    assert "UNION" not in serialized
    assert "O'Reilly" not in serialized
    assert "%2527" not in serialized
    assert "len=" in serialized


def test_comparison_does_not_change_global_security_mode(app):
    with app.app_context():
        before = get_db().execute(
            "SELECT value FROM settings WHERE key = 'security_mode'"
        ).fetchone()["value"]
        run_comparison_experiment()
        after = get_db().execute(
            "SELECT value FROM settings WHERE key = 'security_mode'"
        ).fetchone()["value"]

    assert before == "safe"
    assert after == "safe"


def test_comparison_does_not_create_detection_logs(app):
    with app.app_context():
        run_comparison_experiment()
        count = get_db().execute(
            "SELECT COUNT(*) AS count FROM detection_logs"
        ).fetchone()["count"]

    assert count == 0


def test_unauthenticated_user_is_redirected_from_comparison(client):
    response = client.get("/admin/comparison")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_regular_user_cannot_run_comparison(app, client):
    login(client, "student", "Student123!")

    response = client.post("/admin/comparison/run")

    assert response.status_code == 403
    with app.app_context():
        count = get_db().execute(
            "SELECT COUNT(*) AS count FROM comparison_runs"
        ).fetchone()["count"]
    assert count == 0


def test_admin_empty_comparison_page(client):
    login(client)

    response = client.get("/admin/comparison")

    assert response.status_code == 200
    assert "还没有对照实验记录" in response.get_data(as_text=True)


def test_admin_can_run_and_view_comparison(client):
    login(client)

    response = client.post("/admin/comparison/run", follow_redirects=True)
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "同输入安全对照实验已完成" in page
    assert "RUN-1" in page
    assert "C-01" in page
    assert "C-06" in page
    assert "漏洞查询" in page
    assert "安全查询" in page
    assert "UNION" not in page


def test_missing_comparison_run_returns_404(client):
    login(client)

    response = client.get("/admin/comparison?run_id=999999")

    assert response.status_code == 404
    assert "检测记录不存在" in response.get_data(as_text=True)
