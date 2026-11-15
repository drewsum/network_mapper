"""Network-wide history API, against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DnsQuery, Domain
from netmap.db.policies import refresh_all_aggregates

pytestmark = pytest.mark.db

TV, PHONE = "00:aa:00:00:00:01", "00:aa:00:00:00:02"
NOW = datetime.now(UTC).replace(microsecond=0)
H = timedelta(hours=1)


def q(mac, domain, ago, status="allowed"):
    return {
        "time": NOW - ago,
        "client_ip": "192.0.2.1",
        "mac": mac,
        "domain": domain,
        "query_type": "A",
        "status": status,
    }


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, dns_queries, domains CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": TV, "label": "TV"}, {"mac": PHONE, "hostname": "phone"}])
        s.execute(
            insert(Domain),
            [
                {"domain": "ads.example", "organization": "AdCo", "country": "US",
                 "asn": 64500, "asn_org": "AdNet", "category": "ads"},
                {"domain": "cdn.example", "organization": "CDN Inc", "country": "DE",
                 "category": "cdn"},
            ],
        )  # fmt: skip
        s.execute(
            insert(DnsQuery),
            [q(TV, "ads.example", i * 10 * timedelta(minutes=1), "blocked") for i in range(3)]
            + [q(TV, "cdn.example", 2 * H), q(PHONE, "cdn.example", 3 * H)]
            + [q(PHONE, "cdn.example", timedelta(days=10)), q(None, "cdn.example", 4 * H)],
        )
        s.commit()
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
    return TestClient(create_app())


def get(client, **params):
    res = client.get("/api/history", params=params)
    assert res.status_code == 200, res.text
    return res.json()


def rows(body):
    return [(r["key"], r["label"], r["queries"], r["blocked"]) for r in body["rows"]]


def test_day_by_device_with_totals_and_timeline(client):
    body = get(client)
    assert (body["queries"], body["blocked"], body["domains"], body["devices"]) == (6, 3, 2, 2)
    assert (body["bucket_seconds"], body["source"]) == (900, "dns_activity_1m")
    assert sum(p["queries"] for p in body["points"]) == 6
    assert rows(body) == [
        (TV, "TV", 4, 3),
        (PHONE, "phone", 1, 0),
        ("", "Unknown client", 1, 0),
    ]


def test_breakdowns(client):
    assert rows(get(client, by="domain")) == [
        ("ads.example", "ads.example", 3, 3),
        ("cdn.example", "cdn.example", 3, 0),
    ]
    assert [r[0] for r in rows(get(client, by="organization"))] == ["AdCo", "CDN Inc"]
    assert rows(get(client, by="asn"))[0] == ("64500", "AdNet (AS64500)", 3, 3)
    assert rows(get(client, by="asn"))[1][1] == "Unknown network"
    assert rows(get(client, by="category"))[0][1] == "Ads & trackers"
    assert rows(get(client, by="status")) == [
        ("allowed", "Allowed", 3, 0),
        ("blocked", "Blocked", 3, 3),
    ]


def test_filters_narrow_timeline_and_breakdown(client):
    tv = get(client, mac=TV.upper(), by="domain")
    assert (tv["queries"], [r[0] for r in rows(tv)]) == (4, ["ads.example", "cdn.example"])
    de = get(client, country="de", by="device")
    assert de["queries"] == 3 and sum(p["queries"] for p in de["points"]) == 3
    assert get(client, asn=64500)["queries"] == 3


def test_longer_ranges_use_coarser_aggregates(client):
    week = get(client, start=(NOW - timedelta(days=7)).isoformat())
    assert (week["bucket_seconds"], week["source"]) == (3600, "dns_activity_1h")
    month = get(client, start=(NOW - timedelta(days=30)).isoformat())
    assert (month["bucket_seconds"], month["source"], month["queries"]) == (
        86400, "dns_activity_1d", 7
    )  # fmt: skip
    assert client.get("/api/history", params={"by": "nope"}).status_code == 422


def test_migrate_catches_up_rows_written_into_materialized_spans(client):
    """Pi-hole's first poll backfills 24 hours, into spans the aggregates already hold."""
    before = get(client)["queries"]
    with get_sessionmaker()() as s:
        s.execute(insert(DnsQuery), [q(TV, "late.example", timedelta(hours=20))])
        s.commit()
    main(["migrate"])
    assert get(client)["queries"] == before + 1
