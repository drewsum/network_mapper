"""Pi-hole v6 poller, against a fake Pi-hole on loopback (and a real DB for storage)."""

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import func, insert, select, text

from netmap.cli import main
from netmap.collector import pihole
from netmap.collector.dns import record_queries
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceIP, DnsQuery, Domain

PASSWORD = "app-password"
PHONE_MAC = "00:aa:00:00:00:44"
PIHOLE_MAC = "00:aa:00:00:00:53"


class FakePihole:
    def __init__(self) -> None:
        self.queries: list[dict] = []
        self.sids: set[str] = set()
        self.logins = 0
        self.v5 = False
        self.lock = threading.Lock()

    def add(self, qid, at, domain, client="192.0.2.44", status="FORWARDED", qtype="A"):
        self.queries.append(
            {"id": qid, "time": at, "type": qtype, "domain": domain, "status": status,
             "client": {"ip": client, "name": None}, "reply": {"type": "IP", "time": 1.2}}
        )  # fmt: skip

    def handler(fake):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, content_type="application/json"):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _v5(self):
                self._send(404, b"<html>404 Not Found</html>", "text/html")

            def do_POST(self):
                if fake.v5:
                    return self._v5()
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if body.get("password") != PASSWORD:
                    return self._send(
                        401, {"session": {"valid": False, "message": "password incorrect"}}
                    )
                with fake.lock:
                    fake.logins += 1
                    sid = f"sid{fake.logins}"
                    fake.sids.add(sid)
                self._send(200, {"session": {"valid": True, "sid": sid, "validity": 1800}})

            def do_DELETE(self):
                fake.sids.discard(self.headers.get("X-FTL-SID"))
                self._send(204, b"")

            def do_GET(self):
                if fake.v5:
                    return self._v5()
                if self.headers.get("X-FTL-SID") not in fake.sids:
                    return self._send(401, {"error": {"key": "unauthorized", "message": "x"}})
                q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
                lo, hi = float(q["from"]), float(q["until"])
                start, length = int(q["start"]), int(q["length"])
                cursor = int(q.get("cursor", max((r["id"] for r in fake.queries), default=0)))
                rows = sorted(
                    (r for r in fake.queries if lo <= r["time"] <= hi and r["id"] <= cursor),
                    key=lambda r: -r["id"],
                )
                self._send(200, {"queries": rows[start : start + length], "cursor": cursor})

        return Handler


@pytest.fixture
def fake(monkeypatch):
    server_fake = FakePihole()
    server = ThreadingHTTPServer(("127.0.0.1", 0), server_fake.handler())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server_fake.url = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setattr(pihole, "PAGE_SIZE", 3)  # exercise paging with a handful of rows
    yield server_fake
    server.shutdown()


def test_status_mapping_and_parsing():
    assert pihole.map_status("GRAVITY") == "blocked"
    assert pihole.map_status("REGEX_CNAME") == "blocked"
    assert pihole.map_status("FORWARDED") == "allowed"
    assert pihole.map_status("CACHE_STALE") == "cached"
    assert pihole.map_status("IN_PROGRESS") == "other"
    q = pihole.parse_query(
        {"id": 7, "time": 1767225600.5, "type": "AAAA", "domain": "Example.COM.",
         "status": "CACHE", "client": {"ip": "192.0.2.5"}}
    )  # fmt: skip
    assert (q.id, q.domain, q.query_type, q.status) == (7, "example.com", "AAAA", "cached")
    assert q.time == datetime(2026, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)
    assert pihole.parse_query({"id": 1}) is None


def test_client_logs_in_pages_and_recovers_an_expired_session(fake):
    now = time.time()
    for i in range(1, 8):
        fake.add(i, now - 100 + i, f"d{i}.example")
    client = pihole.PiholeClient(fake.url, PASSWORD)
    since = datetime.fromtimestamp(now - 3600, UTC)
    until = datetime.fromtimestamp(now, UTC)
    assert [q.id for q in client.queries_since(since, until, after_id=0)] == list(range(1, 8))
    assert [q.id for q in client.queries_since(since, until, after_id=5)] == [6, 7]

    fake.sids.clear()  # the session expired on the Pi-hole side
    assert [q.id for q in client.queries_since(since, until, after_id=6)] == [7]
    assert fake.logins == 2
    client.logout()
    assert fake.sids == set()


def test_bad_password_and_v5_are_explained(fake):
    with pytest.raises(pihole.AuthError, match="password incorrect"):
        pihole.PiholeClient(fake.url, "wrong").login()
    fake.v5 = True
    with pytest.raises(pihole.PiholeError, match="isn't the Pi-hole v6 API"):
        pihole.PiholeClient(fake.url, PASSWORD).login()
    with pytest.raises(pihole.PiholeError, match="can't reach"):
        pihole.PiholeClient("http://127.0.0.1:9", PASSWORD).login()


@pytest.fixture
def db(db_env, monkeypatch, fake):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, dns_queries, domains CASCADE"))
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": PHONE_MAC}])
        s.execute(insert(DeviceIP), [{"mac": PHONE_MAC, "ip": "192.0.2.44"}])
        s.commit()
    monkeypatch.setenv("NETMAP_PIHOLE_URL", fake.url)
    monkeypatch.setenv("NETMAP_PIHOLE_PASSWORD", PASSWORD)
    get_settings.cache_clear()
    return get_settings()


def stored():
    with get_sessionmaker()() as s:
        return s.execute(
            select(DnsQuery.pihole_id, DnsQuery.mac, DnsQuery.status).order_by(DnsQuery.pihole_id)
        ).all()


@pytest.mark.db
def test_polls_resume_across_restarts_without_duplicates(db, fake):
    now = time.time()
    fake.add(1, now - 30, "a.example")
    fake.add(2, now - 20, "b.example", status="GRAVITY")
    fake.add(3, now - 10, "a.example", client="192.0.2.200")  # not a known device
    fake.add(4, now - 9, "pi.hole", client="127.0.0.1")  # the Pi-hole host itself
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": PIHOLE_MAC}])
        s.execute(insert(DeviceIP), [{"mac": PIHOLE_MAC, "ip": "127.0.0.1"}])
        s.commit()
    source = pihole.PiholeSource(db)
    assert source.enabled()
    assert source._poll() == 4
    assert stored() == [
        (1, PHONE_MAC, "allowed"),
        (2, PHONE_MAC, "blocked"),
        (3, None, "allowed"),
        (4, PIHOLE_MAC, "allowed"),
    ]

    fake.add(5, now - 5, "c.example")
    assert source._poll() == 1
    assert source._poll() == 0

    # A new collector process picks up after the newest stored query.
    fake.add(6, now - 1, "c.example")
    restarted = pihole.PiholeSource(db)
    assert restarted._poll() == 1
    assert [r[0] for r in stored()] == [1, 2, 3, 4, 5, 6]

    with get_sessionmaker()() as s:
        a = s.get(Domain, "a.example")
        assert (a.first_seen.timestamp(), a.last_seen.timestamp()) == pytest.approx(
            (now - 30, now - 10), abs=1e-3
        )
        assert s.scalar(select(func.count()).select_from(Domain)) == 4


@pytest.mark.db
def test_pihole_id_reset_is_detected(db, fake):
    now = time.time()
    fake.add(100, now - 60, "old.example")
    source = pihole.PiholeSource(db)
    assert source._poll() == 1
    # Pi-hole's database was reset: IDs start over, below the one we stored.
    fake.queries.clear()
    fake.add(1, now - 2, "new.example")
    assert source._poll() == 1
    assert [r[0] for r in stored()] == [1, 100]


@pytest.mark.db
def test_record_queries_ignores_repeats(db):
    q = pihole.Query(
        9, datetime.now(UTC) - timedelta(seconds=5), "192.0.2.44", "x.example", "A", "allowed"
    )
    with get_sessionmaker()() as s:
        assert record_queries(s, [q]) == 1
        assert record_queries(s, [q]) == 0
