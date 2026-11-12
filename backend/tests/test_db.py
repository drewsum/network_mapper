"""Integration tests against a real TimescaleDB. Wipes the NETMAP_TEST_DATABASE_URL database."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.db import get_engine

pytestmark = pytest.mark.db


@pytest.fixture
def seeded(db_env):
    main(["migrate"])
    main(["seed", "--days", "2", "--reset"])
    return db_env


def test_migrate_is_idempotent(db_env):
    main(["migrate"])
    main(["migrate"])
    with get_engine().connect() as conn:
        jobs = conn.execute(
            # job_id >= 1000: user policies; lower ids are TimescaleDB's built-in jobs.
            text("SELECT count(*) FROM timescaledb_information.jobs WHERE job_id >= 1000")
        ).scalar_one()
    # 2 compression + 3 refresh + 5 retention, no duplicates after re-running.
    assert jobs == 10


def test_retention_follows_env(db_env, monkeypatch):
    monkeypatch.setenv("NETMAP_RAW_RETENTION_DAYS", "7")
    from netmap.config import get_settings

    get_settings.cache_clear()
    main(["migrate"])
    with get_engine().connect() as conn:
        drop_after = conn.execute(
            text(
                "SELECT config->>'drop_after' FROM timescaledb_information.jobs "
                "WHERE proc_name = 'policy_retention' AND hypertable_name = 'dns_queries'"
            )
        ).scalar_one()
    assert drop_after == "7 days"
    monkeypatch.setenv("NETMAP_RAW_RETENTION_DAYS", "30")
    get_settings.cache_clear()
    main(["migrate"])


def test_seed_populates_aggregates(seeded):
    with get_engine().connect() as conn:
        raw = conn.execute(text("SELECT count(*) FROM dns_queries")).scalar_one()
        agg = conn.execute(text("SELECT sum(queries) FROM dns_activity_1h")).scalar_one()
    assert raw > 0
    assert agg == raw


def test_api_health_and_devices(seeded):
    client = TestClient(create_app())
    assert client.get("/api/health").json()["status"] == "ok"
    devices = client.get("/api/devices").json()
    assert len(devices) > 10
    assert {"iot", "phone", "computer"} <= {d["category"] for d in devices}
