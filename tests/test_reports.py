import pytest

from src.app import create_app
from src.config import Config
from src.database import get_db
from src.services.comparison import run_comparison_experiment
from src.services.reports import (
    generate_experiment_report,
    get_experiment_report,
    list_experiment_reports,
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


def create_comparison(app):
    with app.app_context():
        return run_comparison_experiment()


def test_generated_report_contains_real_cases_and_masked_inputs(app):
    run_id = create_comparison(app)

    with app.app_context():
        report_id = generate_experiment_report(run_id)
        report = get_experiment_report(report_id)
        reports = list_experiment_reports()

    content = report["content_markdown"]
    assert report["comparison_run_id"] == run_id
    assert reports[0]["id"] == report_id
    assert "SQL 注入漏洞检测与防御演示系统实验报告" in content
    assert f"RUN-{run_id}" in content
    assert all(f"C-0{index}" in content for index in range(1, 7))
    assert "len=" in content
    assert "无风险" in content
    assert "高风险" in content
    assert "UNION" not in content
    assert "O'Reilly" not in content
    assert "%2527" not in content


def test_report_includes_real_detection_log_statistics(app, client):
    login(client)
    client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )
    run_id = create_comparison(app)

    with app.app_context():
        report_id = generate_experiment_report(run_id)
        content = get_experiment_report(report_id)["content_markdown"]

    assert "- 检测总数：1" in content
    assert "- 中风险：1" in content
    assert "- 告警：1" in content
    assert "SQL 注入" in content


def test_report_is_a_snapshot_of_generation_time(app, client):
    login(client)
    client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )
    run_id = create_comparison(app)
    with app.app_context():
        report_id = generate_experiment_report(run_id)

    client.get(
        "/articles",
        query_string={"q": "UNION SELECT"},
    )
    with app.app_context():
        content = get_experiment_report(report_id)["content_markdown"]

    assert "- 检测总数：1" in content
    assert "- 检测总数：2" not in content


def test_unauthenticated_user_is_redirected_from_reports(client):
    response = client.get("/admin/reports")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_regular_user_cannot_access_reports(client):
    login(client, "student", "Student123!")

    response = client.get("/admin/reports")

    assert response.status_code == 403


def test_admin_empty_report_page(client):
    login(client)

    response = client.get("/admin/reports")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "尚无对照实验" in page
    assert "暂无实验报告" in page


def test_admin_can_generate_preview_and_download_report(app, client):
    run_id = create_comparison(app)
    login(client)

    response = client.post(
        "/admin/reports/generate",
        data={"run_id": run_id},
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "实验报告已根据真实数据生成" in page
    assert "实验报告预览" in page
    assert "C-01" in page

    with app.app_context():
        report_id = get_db().execute(
            "SELECT id FROM experiment_reports ORDER BY id DESC LIMIT 1"
        ).fetchone()["id"]

    download = client.get(f"/admin/reports/{report_id}/download")
    assert download.status_code == 200
    assert download.mimetype == "text/markdown"
    assert "attachment" in download.headers["Content-Disposition"]
    assert "SQL 注入漏洞检测与防御演示系统实验报告" in download.get_data(
        as_text=True
    )


def test_invalid_report_run_does_not_create_report(app, client):
    login(client)

    response = client.post(
        "/admin/reports/generate",
        data={"run_id": 999999},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "请选择有效的对照实验记录" in response.get_data(as_text=True)
    with app.app_context():
        count = get_db().execute(
            "SELECT COUNT(*) AS count FROM experiment_reports"
        ).fetchone()["count"]
    assert count == 0


def test_missing_report_returns_404(client):
    login(client)

    response = client.get("/admin/reports/999999")

    assert response.status_code == 404
