"""Vendor resolution and the registry refresh job, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from netmap import oui
from netmap.cli import main
from netmap.collector.inventory import Sighting, apply_vendors, record_sightings
from netmap.collector.vendors import OuiSource, replace_vendors
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, OuiVendor

pytestmark = pytest.mark.db

REGISTRY = {"00aa00": "Big Co", "00aa001": "Small Co", "00aa00123": "Tiny Co"}
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, oui_vendors CASCADE"))
    with get_sessionmaker()() as s:
        yield s


def vendor_of(session, mac):
    session.expire_all()
    d = session.get(Device, mac)
    return d.vendor, d.is_randomized_mac


def test_new_devices_get_longest_matching_vendor(session):
    replace_vendors(session, REGISTRY, loaded_at=T0)
    macs = {
        "00:aa:00:99:00:01": "Big Co",
        "00:aa:00:19:00:01": "Small Co",
        "00:aa:00:12:30:01": "Tiny Co",
        "00:cc:00:00:00:01": None,
    }
    sightings = {mac: Sighting(f"192.0.2.{i + 10}", T0) for i, mac in enumerate(macs)}
    record_sightings(session, sightings, T0, timedelta(minutes=10))
    for mac, vendor in macs.items():
        assert vendor_of(session, mac) == (vendor, False)


def test_randomized_mac_flagged_without_vendor(session):
    # 02:aa:00 would match nothing anyway; 0e has the local bit set and must not resolve.
    replace_vendors(session, {"0eaa00": "Spoofed Co"}, loaded_at=T0)
    mac = "0e:aa:00:00:00:01"
    record_sightings(session, {mac: Sighting("192.0.2.10", T0)}, T0, timedelta(minutes=10))
    assert vendor_of(session, mac) == (None, True)


def test_registry_refresh_updates_existing_devices(session):
    mac = "00:aa:00:99:00:01"
    record_sightings(session, {mac: Sighting("192.0.2.10", T0)}, T0, timedelta(minutes=10))
    assert vendor_of(session, mac) == (None, False)
    replace_vendors(session, REGISTRY, loaded_at=T0)
    assert vendor_of(session, mac) == ("Big Co", False)
    apply_vendors(session, [])  # an empty list touches nothing
    session.commit()


def test_source_loads_bundle_then_downloads(session, db_env, monkeypatch):
    monkeypatch.setattr(oui, "read_bundle", lambda: {"00aa00": "Bundled Co"})
    downloads = []

    def fake_download():
        downloads.append(1)
        if len(downloads) == 1:
            raise OSError("offline")
        return REGISTRY

    monkeypatch.setattr(oui, "download", fake_download)
    source = OuiSource(db_env)

    source._refresh()  # empty table: bundle loaded, download fails, bundle kept
    assert session.scalar(select(OuiVendor.vendor)) == "Bundled Co"
    assert session.scalar(select(func.max(OuiVendor.loaded_at))) is None

    source._refresh()  # bundled rows count as stale: download retried
    session.expire_all()
    assert session.scalar(select(func.count()).select_from(OuiVendor)) == len(REGISTRY)

    source._refresh()  # fresh: no download
    assert len(downloads) == 2
