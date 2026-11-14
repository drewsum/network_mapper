"""Inventory updates from sightings, against a real DB. Wipes NETMAP_TEST_DATABASE_URL."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from netmap.cli import main
from netmap.collector.inventory import Sighting, record_sightings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceEvent, DeviceIP

pytestmark = pytest.mark.db

A, B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)
OFFLINE_AFTER = timedelta(minutes=10)


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices CASCADE"))
    with get_sessionmaker()() as s:
        yield s


def record(session, now, **sightings):
    record_sightings(
        session, {mac: Sighting(ip, now) for mac, ip in sightings.items()}, now, OFFLINE_AFTER
    )


def events(session):
    rows = session.execute(
        select(DeviceEvent.mac, DeviceEvent.kind, DeviceEvent.ip).order_by(DeviceEvent.id)
    )
    return [(mac, kind, ip and str(ip)) for mac, kind, ip in rows]


def test_new_device_then_ip_change(session):
    record(session, T0, **{A: "192.0.2.10"})
    record(session, T0 + timedelta(minutes=2), **{A: "192.0.2.10"})
    record(session, T0 + timedelta(minutes=4), **{A: "192.0.2.11"})

    device = session.get(Device, A)
    assert device.online
    assert device.first_seen == T0
    assert device.last_seen == T0 + timedelta(minutes=4)
    ips = session.scalars(select(DeviceIP.ip).where(DeviceIP.mac == A).order_by(DeviceIP.ip))
    assert [str(ip) for ip in ips] == ["192.0.2.10", "192.0.2.11"]
    assert events(session) == [
        (A, "new_device", "192.0.2.10"),
        (A, "online", "192.0.2.10"),
        (A, "new_ip", "192.0.2.10"),
        (A, "new_ip", "192.0.2.11"),
    ]


def test_offline_and_back_online(session):
    record(session, T0, **{A: "192.0.2.10", B: "192.0.2.20"})
    session.execute(text("DELETE FROM device_events"))
    # B keeps answering; A goes quiet past the offline window, then returns.
    record(session, T0 + timedelta(minutes=5), **{B: "192.0.2.20"})
    record(session, T0 + timedelta(minutes=11), **{B: "192.0.2.20"})
    session.expire_all()
    assert not session.get(Device, A).online
    assert session.get(Device, B).online
    record(session, T0 + timedelta(minutes=13), **{A: "192.0.2.10"})
    assert events(session) == [(A, "offline", None), (A, "online", "192.0.2.10")]
    session.expire_all()
    assert session.get(Device, A).online


def test_no_sightings_still_marks_offline(session):
    record(session, T0, **{A: "192.0.2.10"})
    record(session, T0 + timedelta(hours=1))
    session.expire_all()
    assert not session.get(Device, A).online
