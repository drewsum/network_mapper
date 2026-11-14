"""Storing name hints and choosing hostnames, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import insert, select, text

from netmap.cli import main
from netmap.collector.inventory import NameHint, apply_hostnames, record_names
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceName

pytestmark = pytest.mark.db

PI, TV, NEW = "b8:27:eb:00:00:01", "00:aa:00:00:00:02", "00:aa:00:00:00:03"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)
PRECEDENCE = ["ssdp", "mdns", "dhcp", "netbios", "rdns"]


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": PI}, {"mac": TV}])
        s.commit()
        yield s


def hostname(session, mac):
    session.expire_all()
    d = session.get(Device, mac)
    return d.hostname, d.hostname_source


def test_best_source_names_the_device_and_unknown_macs_wait(session):
    recorded = record_names(
        session,
        [
            NameHint(PI, "dhcp", "raspberrypi", {"fingerprint": "1,3,6"}, T0),
            NameHint(PI, "mdns", "kitchen-pi", None, T0),
            NameHint(TV, "dhcp", "tv-4k", None, T0),
            NameHint(TV, "ssdp", "Living Room TV", {"manufacturer": "Example"}, T0),
            NameHint(NEW, "dhcp", "phone", None, T0),
        ],
        PRECEDENCE,
    )
    assert recorded == {PI, TV}
    assert hostname(session, PI) == ("kitchen-pi", "mdns")
    assert hostname(session, TV) == ("Living Room TV", "ssdp")
    assert session.scalar(select(DeviceName).where(DeviceName.mac == NEW)) is None


def test_later_hints_keep_known_names_and_merge_details(session):
    record_names(
        session, [NameHint(PI, "dhcp", "raspberrypi", {"fingerprint": "1,3"}, T0)], PRECEDENCE
    )
    later = T0 + timedelta(hours=1)
    record_names(
        session, [NameHint(PI, "dhcp", None, {"vendor_class": "udhcp"}, later)], PRECEDENCE
    )
    session.expire_all()
    row = session.get(DeviceName, (PI, "dhcp"))
    assert row.name == "raspberrypi"
    assert row.details == {"fingerprint": "1,3", "vendor_class": "udhcp"}
    assert (row.first_seen, row.last_seen) == (T0, later)

    record_names(session, [NameHint(TV, "mdns", "tv", None, T0)], PRECEDENCE)
    record_names(session, [NameHint(TV, "mdns", "tv", {"model": "X"}, later)], PRECEDENCE)
    session.expire_all()
    assert session.get(DeviceName, (TV, "mdns")).details == {"model": "X"}  # SQL NULL, not 'null'


def test_precedence_change_and_seeded_hostnames(session):
    record_names(
        session,
        [
            NameHint(PI, "dhcp", "raspberrypi", None, T0),
            NameHint(PI, "mdns", "kitchen-pi", None, T0),
        ],
        PRECEDENCE,
    )
    session.get(Device, TV).hostname, session.get(Device, TV).hostname_source = "seeded-tv", "seed"
    session.commit()

    apply_hostnames(session, ["dhcp", "mdns"])
    session.commit()
    assert hostname(session, PI) == ("raspberrypi", "dhcp")
    assert hostname(session, TV) == ("seeded-tv", "seed")

    apply_hostnames(session, ["rdns"])  # no rdns name: the device goes unnamed
    session.commit()
    assert hostname(session, PI) == (None, None)
