"""The IoT phone-home report, against a real DB."""

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.api.report import words
from netmap.cli import main
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceName, DnsQuery, Domain
from netmap.db.policies import refresh_all_aggregates

CAM, PLUG, LAPTOP = "00:cc:00:00:00:01", "00:cc:00:00:00:02", "00:cc:00:00:00:03"
# Noon and 3 am UTC yesterday.
DAY = (datetime.now(UTC) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
NOON, NIGHT = DAY + timedelta(hours=12), DAY + timedelta(hours=3)


def q(mac, domain, time, status="allowed"):
    return {"time": time, "client_ip": "192.0.2.1", "mac": mac, "domain": domain,
            "query_type": "A", "status": status}  # fmt: skip


def test_maker_words_skip_generic_ones():
    assert words("Ring Technologies, LLC") == {"ring"}
    assert words("Amazon Technologies Inc.") == {"amazon"}
    assert words(None) == set()


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, dns_queries, domains, device_baselines CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(
            insert(Device),
            [
                {"mac": CAM, "label": "Doorbell", "vendor": "Ring LLC", "category": "iot"},
                {"mac": PLUG, "vendor": "Espressif Inc.", "is_iot": True},
                {"mac": LAPTOP, "category": "computer"},
            ],
        )
        s.execute(
            insert(DeviceName),
            [{"mac": PLUG, "source": "ssdp", "details": {"manufacturer": "Tuya Smart"}}],
        )
        s.execute(
            insert(Domain),
            [
                {"domain": "api.ring.com", "organization": "Ring", "category": "vendor"},
                {"domain": "fw.ring.com", "organization": "Ring", "category": "vendor"},
                {"domain": "app-measurement.com", "organization": "Google",
                 "category": "analytics"},
                {"domain": "pool.ntp.org", "organization": "NTP Pool",
                 "category": "infrastructure"},
                {"domain": "weird.example", "organization": "Other", "category": "unknown"},
                {"domain": "bad.example", "organization": "Other", "category": "unknown",
                 "is_blocklisted": True},
                {"domain": "a.tuyaus.com", "organization": "Tuya", "category": "vendor"},
                {"domain": "iot.ring.example", "organization": "Other", "category": "unknown"},
            ],
        )  # fmt: skip
        s.execute(
            insert(DnsQuery),
            [q(CAM, "api.ring.com", NOON)] * 3
            + [q(CAM, "fw.ring.com", NIGHT)]
            + [q(CAM, "app-measurement.com", NOON, "blocked")]
            + [q(CAM, "pool.ntp.org", NIGHT)]
            + [q(CAM, "weird.example", NIGHT)] * 2
            + [q(CAM, "printer.local", NOON)]
            + [q(PLUG, "iot.ring.example", NOON)]
            + [q(PLUG, "a.tuyaus.com", NOON), q(PLUG, "bad.example", NOON)]
            + [q(LAPTOP, "weird.example", NOON)],
        )
        s.commit()
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
    return TestClient(create_app())


def sites(body, mac):
    device = next(d for d in body["devices"] if d["mac"] == mac)
    return {s["site"]: s for s in device["sites"]}, device


@pytest.mark.db
def test_sorts_each_iot_devices_sites(client):
    body = client.get("/api/reports/iot", params={"tz": "UTC"}).json()
    assert [d["mac"] for d in body["devices"]] == [CAM, PLUG]  # IoT only
    cam, device = sites(body, CAM)
    assert {k: v["status"] for k, v in cam.items()} == {
        "ring.com": "maker",
        "app-measurement.com": "tracker",
        "ntp.org": "infrastructure",
        "weird.example": "third_party",
    }
    assert cam["ring.com"]["domains"] == ["api.ring.com", "fw.ring.com"]
    assert (cam["ring.com"]["lookups"], cam["ring.com"]["night"]) == (4, 1)
    assert cam["app-measurement.com"]["blocked"] == 1
    assert (device["lookups"], device["night"], device["flagged"]) == (8, 4, 2)
    # Flagged first, then by lookups.
    assert [s["site"] for s in device["sites"]][:2] == ["weird.example", "app-measurement.com"]
    plug, _ = sites(body, PLUG)
    # The UPnP manufacturer names the maker when the MAC vendor is the chip's.
    assert plug["tuyaus.com"]["status"] == "maker"
    assert plug["bad.example"]["status"] == "threat"
    # ring.example is named for Ring, not Tuya.
    assert plug["ring.example"]["status"] == "third_party"


@pytest.mark.db
def test_a_site_named_for_the_maker_is_the_makers(client):
    # Ring's site with no organization known still counts as Ring's own for the doorbell.
    with get_sessionmaker()() as s:
        s.execute(insert(DnsQuery), [q(CAM, "x.ring.io", NOON)])
        s.commit()
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
    cam, _ = sites(client.get("/api/reports/iot").json(), CAM)
    assert cam["ring.io"]["status"] == "maker"


@pytest.mark.db
def test_night_is_in_the_viewers_time_zone(client):
    # 3 am UTC is 10 pm the day before in Chicago; noon UTC is 6 or 7 am.
    body = client.get("/api/reports/iot", params={"tz": "America/Chicago"}).json()
    assert sites(body, CAM)[1]["night"] == 0
    assert client.get("/api/reports/iot", params={"tz": "Mars/Base"}).status_code == 400


@pytest.mark.db
def test_marking_sites_expected_or_not(client):
    url = f"/api/devices/{CAM}/sites/weird.example/expected"
    assert client.put(url, json={"expected": True}).json() == {"expected": True}
    cam, device = sites(client.get("/api/reports/iot").json(), CAM)
    assert (cam["weird.example"]["status"], device["flagged"]) == ("expected", 1)
    client.put(f"/api/devices/{CAM}/sites/ring.com/expected", json={"expected": False})
    cam, _ = sites(client.get("/api/reports/iot").json(), CAM)
    assert cam["ring.com"]["status"] == "unexpected"
    client.put(url, json={"expected": None})
    cam, _ = sites(client.get("/api/reports/iot").json(), CAM)
    assert cam["weird.example"]["status"] == "third_party"


@pytest.mark.db
def test_csv_export(client):
    res = client.get("/api/reports/iot.csv", params={"tz": "UTC"})
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(res.text)))
    ring = next(r for r in rows if r["site"] == "ring.com")
    assert (ring["device"], ring["status"], ring["lookups"]) == ("Doorbell", "maker", "4")
    assert ring["domains"] == "api.ring.com fw.ring.com"
