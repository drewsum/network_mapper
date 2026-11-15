"""Network map API, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.dns import VISIBILITY_CHECK, CheckResult, record_check
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceIP, DnsQuery

pytestmark = pytest.mark.db

ROUTER, TV, GONE, MERGED = (f"00:aa:00:00:00:0{i}" for i in range(1, 5))
NOW = datetime.now(UTC)


def q(mac, ago, status="allowed"):
    return {
        "time": NOW - ago,
        "client_ip": "192.0.2.10",
        "mac": mac,
        "domain": "x.example",
        "query_type": "A",
        "status": status,
    }


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, dns_queries, health_checks CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(
            insert(Device),
            [
                {"mac": ROUTER, "label": "Router", "category": "infrastructure", "online": True},
                {"mac": TV, "hostname": "tv", "category": "media", "online": True},
                {"mac": GONE, "vendor": "Acme", "online": False},
                {"mac": MERGED, "merged_into": TV},
            ],
        )
        s.execute(
            insert(DeviceIP),
            [{"mac": ROUTER, "ip": "192.0.2.1"}, {"mac": TV, "ip": "192.0.2.10"}],
        )
        m = timedelta(minutes=1)
        s.execute(
            insert(DnsQuery),
            [q(TV, 5 * m), q(TV, 10 * m, "blocked"), q(TV, 3 * 60 * m), q(GONE, 2 * 60 * m)],
        )
        s.commit()
        record_check(s, VISIBILITY_CHECK, CheckResult("ok", "", {"router_ip": "192.0.2.1"}), NOW)
    return TestClient(create_app())


def test_map_has_devices_router_and_recent_activity(client):
    res = client.get("/api/map")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["router"] == ROUTER
    devices = {d["mac"]: d for d in body["devices"]}
    assert set(devices) == {ROUTER, TV, GONE}  # merged devices are left out
    assert (devices[TV]["queries"], devices[TV]["blocked"], devices[TV]["ip"]) == (
        2, 1, "192.0.2.10"
    )  # fmt: skip
    assert devices[GONE]["online"] is False and devices[GONE]["queries"] == 0
    wider = {d["mac"]: d for d in client.get("/api/map", params={"minutes": 240}).json()["devices"]}
    assert (wider[TV]["queries"], wider[GONE]["queries"]) == (3, 1)


def test_no_router_without_the_visibility_check(client):
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE health_checks"))
    assert client.get("/api/map").json()["router"] is None
