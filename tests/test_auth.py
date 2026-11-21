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


def test_index_requires_login(client):
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_login_rejects_wrong_password(client):
    response = client.post(
        "/login",
        data={
            "username": "student",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert "用户名或密码错误".encode() in response.data


def test_login_and_logout(client):
    response = client.post(
        "/login",
        data={
            "username": "student",
            "password": "Student123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "林同学".encode() in response.data
    assert "数据库中的安全知识文章".encode() in response.data

    response = client.post("/logout", follow_redirects=True)

    assert response.status_code == 200
    assert "已安全退出登录".encode() in response.data

    response = client.get("/")
    assert response.status_code == 302

