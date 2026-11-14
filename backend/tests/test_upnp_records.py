"""Storing UPnP port mappings and listing them, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.inventory import record_upnp
from netmap.collector.upnp import Mapping
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceIP

pytestmark = pytest.mark.db

MAC = "00:aa:00:00:00:01"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)
T1 = T0 + timedelta(minutes=5)
TORRENT = Mapping(51413, "udp", "192.0.2.10", 51413, "Transmission", True)
CAMERA = Mapping(8443, "tcp", "192.0.2.99", 443, None, True)


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, upnp_mappings CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": MAC, "hostname": "nas"}])
        s.execute(insert(DeviceIP), [{"mac": MAC, "ip": "192.0.2.10"}])
        s.commit()
        yield s


def listed():
    rows = TestClient(create_app()).get("/api/upnp-mappings").json()
    return [(r["external_port"], r["protocol"], r["mac"], r["device"], r["active"]) for r in rows]


def test_mappings_are_attributed_and_retired(session):
    record_upnp(session, [TORRENT, CAMERA], T0)
    assert listed() == [(8443, "tcp", None, None, True), (51413, "udp", MAC, "nas", True)]

    # The camera's forward is gone and the torrent client's was disabled.
    record_upnp(session, [Mapping(51413, "udp", "192.0.2.10", 51413, "Transmission", False)], T1)
    assert listed() == [(8443, "tcp", None, None, False), (51413, "udp", MAC, "nas", False)]

    record_upnp(session, [], T1)  # an empty list retires everything
    record_upnp(session, [CAMERA], T1)
    assert listed()[0] == (8443, "tcp", None, None, True)
