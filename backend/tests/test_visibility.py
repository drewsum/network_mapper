"""Pi-hole client visibility check: does Pi-hole see devices, or only the router?"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.arp import parse_proc_route
from netmap.collector.dns import VISIBILITY_CHECK, client_visibility, record_check
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import DnsQuery

ROUTER = "192.0.2.1"
NOW = datetime.now(UTC)

ROUTES = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
"""


def test_parse_proc_route():
    assert parse_proc_route(ROUTES) == IPv4Address(ROUTER)
    assert parse_proc_route(ROUTES, "eth0") == IPv4Address(ROUTER)
    assert parse_proc_route(ROUTES, "docker0") is None
    assert parse_proc_route("Iface\tDestination\n") is None


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE dns_queries, health_checks"))
    with get_sessionmaker()() as s:
        yield s


def clear(session):
    # Through the same session: its open transaction holds a lock a second connection's
    # TRUNCATE would wait on forever.
    session.execute(text("TRUNCATE dns_queries"))
    session.commit()


def queries(session, per_client: dict[str, int]):
    rows, qid = [], 0
    for ip, n in per_client.items():
        for _ in range(n):
            qid += 1
            rows.append(
                {"time": NOW - timedelta(minutes=5), "pihole_id": qid, "client_ip": ip,
                 "domain": "example.com", "query_type": "A", "status": "allowed"}
            )  # fmt: skip
    session.execute(insert(DnsQuery), rows)
    session.commit()


@pytest.mark.db
def test_router_forwarding_everything_is_a_warning(session):
    queries(session, {ROUTER: 90, "192.0.2.10": 10})
    result = client_visibility(session, ROUTER, NOW)
    assert result.status == "warning"
    assert "90% of DNS queries reach Pi-hole from the router" in result.message
    assert result.details["router_queries"] == 90


@pytest.mark.db
def test_devices_seen_by_their_own_ips_is_ok(session):
    queries(session, {ROUTER: 5, "192.0.2.10": 40, "192.0.2.11": 30, "127.0.0.1": 25})
    result = client_visibility(session, ROUTER, NOW)
    assert result.status == "ok"
    assert result.details["clients"] == 2  # loopback (Pi-hole itself) doesn't count


@pytest.mark.db
def test_single_client_and_too_little_data(session):
    queries(session, {"192.0.2.10": 60})
    assert client_visibility(session, None, NOW).status == "warning"
    clear(session)
    queries(session, {"192.0.2.10": 10, "192.0.2.11": 10})
    assert client_visibility(session, ROUTER, NOW).status == "unknown"


@pytest.mark.db
def test_latest_result_is_served(session):
    queries(session, {ROUTER: 90, "192.0.2.10": 10})
    record_check(session, VISIBILITY_CHECK, client_visibility(session, ROUTER, NOW), NOW)
    queries_later = {"192.0.2.10": 50, "192.0.2.11": 50}
    clear(session)
    queries(session, queries_later)
    record_check(session, VISIBILITY_CHECK, client_visibility(session, ROUTER, NOW), NOW)
    checks = TestClient(create_app()).get("/api/status").json()
    assert [(c["name"], c["status"]) for c in checks] == [(VISIBILITY_CHECK, "ok")]
