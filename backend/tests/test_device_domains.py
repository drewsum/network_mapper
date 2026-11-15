"""Domains-contacted API per device, against a real DB."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DnsQuery
from netmap.db.policies import refresh_all_aggregates

pytestmark = pytest.mark.db

TV, PHONE = "00:aa:00:00:00:01", "00:aa:00:00:00:02"
NOW = datetime.now(UTC).replace(microsecond=0)


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
        s.execute(insert(Device), [{"mac": TV}, {"mac": PHONE}])
        h = timedelta(hours=1)
        s.execute(
            insert(DnsQuery),
            [
                q(TV, "ads.example", m * timedelta(minutes=10), "blocked" if m == 0 else "allowed")
                for m in range(5)
            ]
            + [q(TV, "ads.example", timedelta(days=20))]  # first seen 20 days ago
            + [q(TV, "cdn.example", 2 * h), q(TV, "cdn.example", 3 * h)]
            + [q(TV, "old.example", timedelta(days=3))]  # outside the default 24 h
            + [q(PHONE, "phone-only.example", h)],
        )
        s.commit()
    # TRUNCATE leaves earlier runs' rows in the aggregates; recompute them from this data.
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
    return TestClient(create_app())


def domains(client, mac=TV, **params):
    res = client.get(f"/api/devices/{mac}/domains", params=params)
    assert res.status_code == 200, res.text
    return res.json()


def test_last_24_hours_with_counts_and_first_seen(client):
    page = domains(client)
    assert (page["total"], page["queries"], page["blocked"]) == (2, 7, 1)
    ads, cdn = page["items"]
    assert (ads["domain"], ads["queries"], ads["blocked"], ads["new"]) == (
        "ads.example",
        5,
        1,
        False,
    )
    assert datetime.fromisoformat(ads["first_seen"]) == NOW - timedelta(days=20)
    assert datetime.fromisoformat(ads["last_seen"]) == NOW
    assert (cdn["domain"], cdn["queries"], cdn["new"]) == ("cdn.example", 2, True)
    assert datetime.fromisoformat(cdn["first_seen"]) == NOW - timedelta(hours=3)


def test_time_range_sorting_and_pagination(client):
    week = domains(
        client,
        start=(NOW - timedelta(days=7)).isoformat(),
        end=(NOW + timedelta(seconds=1)).isoformat(),
    )
    assert [d["domain"] for d in week["items"]] == ["ads.example", "cdn.example", "old.example"]
    second = domains(
        client, start=(NOW - timedelta(days=7)).isoformat(), sort="domain", limit=1, offset=1
    )
    assert second["total"] == 3
    assert [d["domain"] for d in second["items"]] == ["cdn.example"]
    recent = domains(client, sort="last_seen")
    assert [d["domain"] for d in recent["items"]] == ["ads.example", "cdn.example"]
    # Other devices' lookups never show up.
    assert [d["domain"] for d in domains(client, PHONE)["items"]] == ["phone-only.example"]


def pause_background_jobs():
    """`netmap migrate` recreates the Timescale policies, and new jobs run at once; stop
    them so retention and refresh jobs don't race this test's own refresh and delete.
    The next migrate recreates them."""
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "SELECT alter_job(job_id, scheduled => false) "
                "FROM timescaledb_information.jobs WHERE job_id >= 1000"
            )
        )
    for _ in range(100):
        with get_engine().connect() as conn:
            running = conn.execute(
                text(
                    "SELECT count(*) FROM timescaledb_information.job_stats "
                    "WHERE job_status = 'Running'"
                )
            ).scalar()
        if not running:
            return
        time.sleep(0.1)
    raise AssertionError("Timescale background jobs didn't finish")


def test_first_seen_beyond_raw_retention_comes_from_the_daily_aggregate(client):
    pause_background_jobs()
    long_ago = NOW - timedelta(days=45)
    with get_sessionmaker()() as s:
        s.execute(insert(DnsQuery), [q(TV, "cdn.example", timedelta(days=45))])
        s.commit()
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
        # Raw retention drops the old row; the aggregates keep it.
        conn.execute(text("DELETE FROM dns_queries WHERE time < now() - interval '30 days'"))

    cdn = next(d for d in domains(client)["items"] if d["domain"] == "cdn.example")
    assert cdn["first_seen"].startswith(long_ago.date().isoformat())
    assert cdn["new"] is False

    # A range older than raw retention is answered from the hourly aggregate.
    old = domains(
        client,
        start=(long_ago - timedelta(days=1)).isoformat(),
        end=(long_ago + timedelta(days=1)).isoformat(),
    )
    assert [(d["domain"], d["queries"]) for d in old["items"]] == [("cdn.example", 1)]


def test_bad_requests(client):
    end = NOW.isoformat()
    assert (
        client.get(f"/api/devices/{TV}/domains", params={"start": end, "end": end}).status_code
        == 422
    )
    too_long = (NOW - timedelta(days=500)).isoformat()
    assert client.get(f"/api/devices/{TV}/domains", params={"start": too_long}).status_code == 422
    assert client.get(f"/api/devices/{TV}/domains", params={"sort": "nope"}).status_code == 422
    assert client.get("/api/devices/00:aa:00:00:00:99/domains").status_code == 404


def test_activity_buckets_fill_the_range(client):
    end = NOW.replace(second=0) + timedelta(minutes=1)
    res = client.get(
        f"/api/devices/{TV}/activity",
        params={"start": (end - timedelta(hours=1)).isoformat(), "end": end.isoformat()},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["bucket_seconds"] == 60
    assert len(body["points"]) == 60  # every minute, empty ones as zeros
    assert sum(p["queries"] for p in body["points"]) == 5
    assert sum(p["blocked"] for p in body["points"]) == 1
    assert body["points"][-1]["blocked"] == 1  # the newest query, not materialized yet

    day = client.get(f"/api/devices/{TV}/activity").json()  # default: 24 hours
    assert day["bucket_seconds"] == 15 * 60
    assert sum(p["queries"] for p in day["points"]) == 7
    month = client.get(
        f"/api/devices/{TV}/activity",
        params={"start": (NOW - timedelta(days=30)).isoformat()},
    ).json()
    assert month["bucket_seconds"] == 86400
    assert sum(p["queries"] for p in month["points"]) == 9


def test_summary_groups_lookups(client):
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO domains (domain, organization, country, category) VALUES "
                "('ads.example', 'AdCo', 'US', 'ads'), ('cdn.example', 'CDN Inc', 'DE', 'cdn')"
            )
        )
    res = client.get(f"/api/devices/{TV}/summary")
    assert res.status_code == 200, res.text
    body = res.json()
    assert [(s["key"], s["domains"], s["queries"]) for s in body["organizations"]] == [
        ("AdCo", 1, 5),
        ("CDN Inc", 1, 2),
    ]
    assert [s["key"] for s in body["countries"]] == ["US", "DE"]
    assert [s["label"] for s in body["categories"]] == ["Ads & trackers", "CDN & hosting"]
    assert client.get(f"/api/devices/{PHONE}/summary").json()["organizations"] == [
        {"key": "", "label": "Not grouped yet", "domains": 1, "queries": 1}
    ]
