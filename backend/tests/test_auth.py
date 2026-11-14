"""Admin login: sessions, protected routes, lockout. Against a real DB (signing secret)."""

import time

import pytest
from fastapi.testclient import TestClient

from netmap.api import auth
from netmap.api.app import create_app
from netmap.cli import main
from netmap.config import get_settings

pytestmark = pytest.mark.db

PASSWORD = "correct horse battery staple"


@pytest.fixture
def make_client(db_env, monkeypatch, tmp_path):
    main(["migrate"])
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>netmap</html>")
    monkeypatch.setenv("NETMAP_WEB_DIST_DIR", str(dist))

    def make(password: str | None = PASSWORD) -> TestClient:
        if password is None:
            monkeypatch.delenv("NETMAP_ADMIN_PASSWORD", raising=False)
        else:
            monkeypatch.setenv("NETMAP_ADMIN_PASSWORD", password)
        get_settings.cache_clear()
        return TestClient(create_app())

    return make


def login(client, password=PASSWORD):
    return client.post("/api/auth/login", json={"password": password})


def test_without_a_password_everything_is_open(make_client):
    client = make_client(None)
    assert client.get("/api/devices").status_code == 200
    assert client.get("/api/auth/session").json() == {"auth_enabled": False, "authenticated": True}
    assert login(client).status_code == 400


def test_login_required_for_api_and_docs(make_client):
    client = make_client()
    for path in ("/api/devices", "/api/upnp-mappings", "/docs", "/openapi.json"):
        assert client.get(path).status_code == 401, path
    assert client.patch("/api/devices/00:aa:00:00:00:01", json={}).status_code == 401
    # Open: the healthcheck, the login flow, and the SPA that shows the login page.
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth/session").json() == {"auth_enabled": True, "authenticated": False}
    assert client.get("/").text == "<html>netmap</html>"
    assert client.get("/devices/whatever").text == "<html>netmap</html>"


def test_login_session_and_logout(make_client):
    client = make_client()
    assert login(client, "wrong").status_code == 401
    res = login(client)
    assert res.status_code == 200
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "max-age=2592000" in cookie
    assert client.get("/api/devices").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/api/auth/session").json()["authenticated"] is True

    client.post("/api/auth/logout")
    assert client.get("/api/devices").status_code == 401


def test_forged_tampered_and_expired_sessions_are_rejected(make_client):
    client = make_client()
    key = auth.signing_key(get_settings())
    future = int(time.time()) + 3600
    good = auth.make_token(key, future)
    assert auth.token_valid(key, good)
    assert not auth.token_valid(key, good.replace(str(future), str(future + 1)))
    assert not auth.token_valid(key, auth.make_token(b"guessed key", future))
    assert not auth.token_valid(key, auth.make_token(key, int(time.time()) - 1))
    assert not auth.token_valid(key, "garbage")
    client.cookies.set(auth.COOKIE, good.replace(str(future), str(future + 1)))
    assert client.get("/api/devices").status_code == 401


def test_changing_the_password_logs_everyone_out(make_client):
    client = make_client()
    login(client)
    cookie = client.cookies.get(auth.COOKIE)
    other = make_client("a new password")
    other.cookies.set(auth.COOKIE, cookie)
    assert other.get("/api/devices").status_code == 401


def test_repeated_failures_lock_the_client_out(make_client):
    client = make_client()
    for _ in range(auth.MAX_FAILURES):
        assert login(client, "nope").status_code == 401
    assert login(client).status_code == 429  # even the right password, for a while
