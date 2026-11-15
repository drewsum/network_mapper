"""Per-device baselines and departures from them, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, select, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.baseline import find_spikes, update_baselines
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceBaseline, DeviceEvent, DnsQuery, Domain
from netmap.db.policies import refresh_all_aggregates

pytestmark = pytest.mark.db

CAM, LAPTOP = "00:bb:00:00:00:01", "00:bb:00:00:00:02"
NOW = datetime.now(UTC).replace(microsecond=0)
DAY = timedelta(days=1)
# The last complete hour, as find_spikes picks it.
HOUR = (NOW - timedelta(minutes=5)).replace(minute=0, second=0) - timedelta(hours=1)


def q(mac, domain, time):
    return {"time": time, "client_ip": "192.0.2.1", "mac": mac, "domain": domain,
            "query_type": "A", "status": "allowed"}  # fmt: skip


def refresh():
    # TRUNCATE leaves earlier runs' rows in the aggregates; recompute them from this data.
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, dns_queries, domains, device_baselines CASCADE"))
    with get_sessionmaker()() as s:
        devices = [{"mac": CAM, "category": "iot"}, {"mac": LAPTOP, "category": "computer"}]
        s.execute(insert(Device), devices)
        s.execute(
            insert(Domain),
            [
                {"domain": "a.cam-cloud.example", "organization": "CamCo", "country": "US",
                 "asn": 64500, "asn_org": "Cam Net"},
                {"domain": "x.new-site.example", "organization": "NewCo", "country": "DE",
                 "asn": 64501, "asn_org": "New Net"},
                {"domain": "other.example", "organization": "Other"},
            ],
        )  # fmt: skip
        s.execute(
            insert(DnsQuery),
            [
                # Learning: the first lookup 20 days ago starts it.
                q(CAM, "a.cam-cloud.example", NOW - 20 * DAY),
                q(CAM, "b.cam-cloud.example", NOW - 19 * DAY),
                q(CAM, "time.example.co.uk", NOW - 18 * DAY),
                q(CAM, "other.example", NOW - 18 * DAY),
                q(CAM, "printer.local", NOW - 17 * DAY),
                q(CAM, "wpad", NOW - 16 * DAY),
                # After learning.
                q(CAM, "x.new-site.example", NOW - 2 * DAY),
                q(CAM, "a.cam-cloud.example", NOW - timedelta(hours=3)),
                q(LAPTOP, "laptop.example", NOW - 20 * DAY),
                q(LAPTOP, "random.example", NOW - 2 * DAY),
            ],
        )
        s.commit()
    refresh()
    with get_sessionmaker()() as s:
        yield s


def baseline(session, mac=CAM):
    rows = session.execute(
        select(DeviceBaseline.key_type, DeviceBaseline.key, DeviceBaseline.hits).where(
            DeviceBaseline.mac == mac
        )
    ).all()
    return {(t, k): hits for t, k, hits in rows}


def departures(session, mac=CAM):
    return {
        (e.kind, e.details["key"], e.details.get("label"))
        for e in session.scalars(select(DeviceEvent).where(DeviceEvent.mac == mac))
    }


def test_learns_sites_orgs_countries_and_networks(session):
    update_baselines(session, NOW, 7)
    assert baseline(session) == {
        # Two names, three days: 20 and 19 days ago, and today.
        ("domain", "cam-cloud.example"): 3,
        ("domain", "example.co.uk"): 1,
        ("domain", "other.example"): 1,
        ("domain", "new-site.example"): 1,
        # "Other" isn't an organization; local names are left out.
        ("org", "CamCo"): 2,
        ("org", "NewCo"): 1,
        ("country", "US"): 2,
        ("country", "DE"): 1,
        ("asn", "64500"): 2,
        ("asn", "64501"): 1,
    }


def test_records_what_is_new_after_learning(session):
    assert update_baselines(session, NOW, 7) == 4
    assert departures(session) == {
        ("new_domain", "new-site.example", None),
        ("new_org", "NewCo", None),
        ("new_country", "DE", None),
        ("new_asn", "64501", "New Net"),
    }
    # Phones and computers get a baseline, but no departures.
    assert ("domain", "random.example") in baseline(session, LAPTOP)
    assert departures(session, LAPTOP) == set()


def test_rounds_are_idempotent_and_count_new_days(session):
    update_baselines(session, NOW, 7)
    assert update_baselines(session, NOW, 7) == 0
    assert baseline(session)[("domain", "cam-cloud.example")] == 3
    # The same lookups a day later: one more day, nothing new.
    with get_sessionmaker()() as s:
        s.execute(insert(DnsQuery), [q(CAM, "a.cam-cloud.example", NOW + DAY)])
        s.commit()
    refresh()
    assert update_baselines(session, NOW + DAY + timedelta(hours=1), 7) == 0
    assert baseline(session)[("domain", "cam-cloud.example")] == 4


def test_learning_period_is_configurable(session):
    assert update_baselines(session, NOW, 30) == 0
    assert departures(session) == set()


def test_records_an_hour_with_far_more_lookups_than_usual(session):
    with get_sessionmaker()() as s:
        busy = [q(m, "a.cam-cloud.example", HOUR + timedelta(minutes=1)) for m in (CAM, LAPTOP)]
        usual = [q(CAM, "a.cam-cloud.example", HOUR - h * timedelta(hours=1)) for h in range(1, 20)]
        s.execute(insert(DnsQuery), busy * 300 + usual * 5)
        s.commit()
    refresh()
    update_baselines(session, NOW, 7)
    assert find_spikes(session, NOW, 7) == 1
    spike = session.scalars(select(DeviceEvent).where(DeviceEvent.kind == "query_spike")).one()
    assert (spike.mac, spike.time, spike.details) == (CAM, HOUR, {"lookups": 300, "usual": 5})
    assert find_spikes(session, NOW, 7) == 0  # once per hour


def test_api(session):
    update_baselines(session, NOW, 7)
    client = TestClient(create_app())
    body = client.get(f"/api/devices/{CAM}/baseline").json()
    assert body["learning"] is False
    assert body["watched"] is True
    assert body["counts"] == {"domain": 4, "org": 2, "country": 2, "asn": 2}
    assert {d["kind"] for d in body["departures"]} == {
        "new_domain", "new_org", "new_country", "new_asn"
    }  # fmt: skip
    events = client.get(f"/api/devices/{CAM}/events").json()
    assert {"key": "64501", "label": "New Net"} in [e["details"] for e in events]
    laptop = client.get(f"/api/devices/{LAPTOP}/baseline").json()
    assert (laptop["watched"], laptop["departures"]) == (False, [])
