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


def login_student(client):
    return client.post(
        "/login",
        data={"username": "student", "password": "Student123!"},
    )


def test_article_search_requires_login(client):
    response = client.get("/articles")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_article_search_matches_content(client):
    login_student(client)
    response = client.get("/articles", query_string={"q": "参数化"})
    assert response.status_code == 200
    assert "参数化查询的工作原理".encode() in response.data
    assert "输入校验与参数化查询".encode() in response.data
    assert "<strong>2</strong>".encode() in response.data


def test_article_search_filters_category(client):
    login_student(client)
    response = client.get("/articles", query_string={"category": "安全防护"})
    assert response.status_code == 200
    assert "<strong>3</strong>".encode() in response.data
    assert "参数化查询的工作原理".encode() in response.data


def test_article_search_handles_normal_special_characters(client):
    login_student(client)
    response = client.get("/articles", query_string={"q": "O'Reilly"})
    assert response.status_code == 200
    assert "没有找到匹配文章".encode() in response.data
