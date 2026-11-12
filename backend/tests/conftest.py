import os

import pytest

from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker

# DB tests wipe data, so they use a dedicated URL and never NETMAP_DATABASE_URL.
TEST_DB_URL = os.environ.get("NETMAP_TEST_DATABASE_URL")
TEST_CIDR = "192.0.2.0/24"  # RFC 5737 documentation range


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Each test starts from a clean NETMAP_* env and never reads a local .env file."""
    for key in list(os.environ):
        if key.startswith("NETMAP_") and key != "NETMAP_TEST_DATABASE_URL":
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETMAP_DATABASE_URL", "postgresql+psycopg://unused@localhost/unused")
    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def db_env(monkeypatch):
    if not TEST_DB_URL:
        pytest.skip("set NETMAP_TEST_DATABASE_URL to run DB tests")
    monkeypatch.setenv("NETMAP_DATABASE_URL", TEST_DB_URL)
    monkeypatch.setenv("NETMAP_LAN_CIDR", TEST_CIDR)
    _clear_caches()
    return get_settings()
