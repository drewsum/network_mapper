"""Storing port scans and detecting changes between them, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, select, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.inventory import record_scan
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceEvent, Port

pytestmark = pytest.mark.db

MAC = "00:aa:00:00:00:01"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)
T1, T2, T3 = (T0 + timedelta(hours=h) for h in (6, 12, 18))


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": MAC}])
        s.commit()
        yield s


def port_events(session):
    return session.execute(
        select(DeviceEvent.kind, DeviceEvent.port, DeviceEvent.protocol, DeviceEvent.time)
        .where(DeviceEvent.mac == MAC)
        .order_by(DeviceEvent.id)
    ).all()


def open_ports(session):
    session.expire_all()
    return {
        (p.port, p.protocol): (p.service, p.banner)
        for p in session.scalars(select(Port).where(Port.mac == MAC, Port.open))
    }


def test_scans_set_a_baseline_then_log_changes(session):
    record_scan(
        session, MAC, {(22, "tcp"): ("ssh", "SSH-2.0-dropbear"), (80, "tcp"): ("http", None)}, T0
    )
    assert port_events(session) == []  # first scan: baseline only
    assert session.get(Device, MAC).ports_scanned_at == T0

    record_scan(session, MAC, {(22, "tcp"): ("ssh", None), (9999, "tcp"): ("kasa", None)}, T1)
    assert port_events(session) == [
        ("port_opened", 9999, "tcp", T1),
        ("port_closed", 80, "tcp", T1),
    ]
    assert open_ports(session) == {
        (22, "tcp"): ("ssh", "SSH-2.0-dropbear"),  # banner kept when a scan gets none
        (9999, "tcp"): ("kasa", None),
    }

    # Nothing answered at all: inconclusive, so nothing is closed.
    record_scan(session, MAC, {}, T2)
    assert len(port_events(session)) == 2
    assert set(open_ports(session)) == {(22, "tcp"), (9999, "tcp")}
    assert session.get(Device, MAC).ports_scanned_at == T2

    # A closed port that comes back is reported as opened again.
    record_scan(session, MAC, {(22, "tcp"): ("ssh", None), (80, "tcp"): ("http", None)}, T3)
    assert port_events(session)[2:] == [
        ("port_opened", 80, "tcp", T3),
        ("port_closed", 9999, "tcp", T3),
    ]


def test_ports_api(session):
    record_scan(session, MAC, {(22, "tcp"): ("ssh", "SSH-2.0-x"), (53, "udp"): ("dns", None)}, T0)
    record_scan(session, MAC, {(53, "udp"): ("dns", None)}, T1)
    client = TestClient(create_app())
    rows = client.get(f"/api/devices/{MAC.upper()}/ports").json()
    assert [(r["port"], r["protocol"], r["open"]) for r in rows] == [
        (53, "udp", True),
        (22, "tcp", False),
    ]
    assert client.get("/api/devices/00:aa:00:00:00:99/ports").status_code == 404
    assert client.get("/api/devices/not-a-mac/ports").status_code == 422
