"""DNS queries, and the answers they got, from Pi-hole v6's REST API.

Logs in once with the app password (POST /api/auth) and reuses the session, logging in
again when it expires and out when the collector stops: Pi-hole allows only a few API
sessions at a time. Each poll asks /api/queries for everything since the newest stored
query (minus a little overlap) and keeps the query IDs it hasn't stored yet; a unique
(pihole_id, time) index makes repeats harmless anyway, so restarts neither duplicate
nor drop queries as long as they're still in Pi-hole's memory (24 h by default).

The query log has no answers, so the same poll also reads Pi-hole's DNS server log
(/api/logs/dnsmasq, a buffer of the last 512 lines: a few minutes of traffic) for the
domain -> IP map; see dnslog.py.
"""

import asyncio
import contextlib
import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlencode, urlsplit

from sqlalchemy import func, select

from netmap.collector.arp import default_gateway
from netmap.collector.base import Source
from netmap.collector.dns import (
    VISIBILITY_CHECK,
    client_visibility,
    record_answers,
    record_check,
    record_queries,
)
from netmap.collector.dnslog import parse_answers
from netmap.db import get_sessionmaker
from netmap.db.models import DnsQuery

log = logging.getLogger(__name__)

PAGE_SIZE = 1000
# Re-read this much before the newest stored query, in case queries arrive out of order.
OVERLAP = timedelta(seconds=60)
# On the very first poll, take what Pi-hole still has in memory.
BACKFILL = timedelta(hours=24)
MAX_PAGES = 200
HTTP_TIMEOUT = 15.0
# How often to check that Pi-hole sees devices by their own IPs (see dns.client_visibility).
VISIBILITY_EVERY = timedelta(minutes=10)

# Pi-hole v6 query status -> dns_queries.status
BLOCKED = {
    "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
    "EXTERNAL_BLOCKED_EDE15", "SPECIAL_DOMAIN",
}  # fmt: skip
ALLOWED = {"FORWARDED", "RETRIED", "RETRIED_DNSSEC"}
CACHED = {"CACHE", "CACHE_STALE"}


def map_status(status: str | None) -> str:
    status = (status or "").upper()
    if status in BLOCKED:
        return "blocked"
    if status in ALLOWED:
        return "allowed"
    if status in CACHED:
        return "cached"
    return "other"


@dataclass(frozen=True)
class Query:
    id: int
    time: datetime
    client_ip: str
    domain: str
    query_type: str
    status: str


def parse_query(raw: dict) -> Query | None:
    try:
        return Query(
            id=int(raw["id"]),
            time=datetime.fromtimestamp(float(raw["time"]), UTC),
            client_ip=str(raw["client"]["ip"]),
            domain=str(raw["domain"]).rstrip(".").lower(),
            query_type=str(raw.get("type") or "?"),
            status=map_status(raw.get("status")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _message(body: dict) -> str:
    error = body.get("error") or {}
    return " ".join(str(x) for x in (error.get("message"), error.get("hint")) if x)


class PiholeError(Exception):
    pass


class AuthError(PiholeError):
    pass


class PiholeClient:
    """Blocking client for the parts of the v6 API the poller needs."""

    def __init__(self, url: str, password: str, verify_tls: bool = True) -> None:
        self.base = url.rstrip("/")
        self._password = password
        self._sid: str | None = None
        self._context = None
        if not verify_tls:
            self._context = ssl.create_default_context()
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self._context)
        )

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._sid:
            headers["X-FTL-SID"] = self._sid
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=HTTP_TIMEOUT) as resp:
                status, payload = resp.status, resp.read()
        except urllib.error.HTTPError as err:
            status, payload = err.code, err.read()
        except (OSError, ValueError) as err:
            raise PiholeError(f"can't reach Pi-hole at {self.base}: {err}") from err
        try:
            return status, json.loads(payload) if payload else {}
        except ValueError as err:
            # v5 and other non-v6 servers answer /api/* with an HTML 404 page.
            raise PiholeError(
                f"{self.base}{path} isn't the Pi-hole v6 API (HTTP {status})"
            ) from err

    def login(self) -> None:
        self._sid = None
        status, body = self._call("POST", "/api/auth", {"password": self._password})
        session = body.get("session") or {}
        if status != 200 or not session.get("valid") or not session.get("sid"):
            message = session.get("message") or (body.get("error") or {}).get("message")
            raise AuthError(f"Pi-hole login failed (HTTP {status}): {message or 'no session'}")
        self._sid = session["sid"]

    def logout(self) -> None:
        if self._sid:
            with contextlib.suppress(PiholeError):
                self._call("DELETE", "/api/auth")
            self._sid = None

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        """A call with the session, logging in first or again after it expires."""
        if self._sid is None:
            self.login()
        status, answer = self._call(method, path, body)
        if status == 401:
            self.login()
            status, answer = self._call(method, path, body)
        return status, answer

    def get(self, path: str, params: dict) -> dict:
        status, body = self.request("GET", f"{path}?{urlencode(params)}")
        if status != 200:
            raise PiholeError(f"GET {path}: HTTP {status} {_message(body)}".strip())
        return body

    def lookup(self, domain: str) -> dict:
        """Where ``domain`` stands in Pi-hole's lists: {"domains": [allow/deny entries
        matching it], "gravity": [subscribed lists that have it]}."""
        body = self.get(f"/api/search/{quote(domain, safe='')}", {"partial": "false", "N": 20})
        return body.get("search") or {}

    def deny(self, domain: str, comment: str) -> None:
        """Add ``domain`` to Pi-hole's exact deny list (for the default group)."""
        status, body = self.request(
            "POST", "/api/domains/deny/exact", {"domain": domain, "comment": comment}
        )
        errors = (body.get("processed") or {}).get("errors") or []
        if status not in (200, 201) or errors:
            message = _message(body) or "; ".join(str(e.get("error")) for e in errors)
            raise PiholeError(f"Pi-hole didn't block {domain} (HTTP {status}): {message}")

    def undeny(self, domain: str) -> None:
        """Take ``domain`` off Pi-hole's exact deny list."""
        path = f"/api/domains/deny/exact/{quote(domain, safe='')}"
        status, body = self.request("DELETE", path)
        if status not in (200, 204, 404):
            raise PiholeError(f"Pi-hole didn't unblock {domain} (HTTP {status}): {_message(body)}")

    def queries_since(self, since: datetime, until: datetime, after_id: int) -> list[Query]:
        """Queries in [since, until] with an ID above ``after_id``, oldest first."""
        found: dict[int, Query] = {}
        cursor = None
        for page in range(MAX_PAGES):
            params = {
                "from": int(since.timestamp()),
                "until": int(until.timestamp()) + 1,
                "length": PAGE_SIZE,
                "start": page * PAGE_SIZE,
            }
            if cursor is not None:
                params["cursor"] = cursor  # keeps later pages stable while queries arrive
            body = self.get("/api/queries", params)
            cursor = body.get("cursor", cursor)
            rows = body.get("queries") or []
            for q in filter(None, map(parse_query, rows)):
                if q.id > after_id:
                    found[q.id] = q
            if len(rows) < PAGE_SIZE:
                break
        else:
            log.warning("pihole: stopped after %d pages; the rest comes next poll", MAX_PAGES)
        return sorted(found.values(), key=lambda q: q.id)

    def log_since(self, next_id: int) -> tuple[list[dict], int, int | None]:
        """DNS server log lines from ``next_id`` on: (lines, the next ID to ask for, the
        FTL process ID, which changes, and restarts the numbering, when FTL restarts)."""
        body = self.get("/api/logs/dnsmasq", {"nextID": next_id})
        return body.get("log") or [], int(body.get("nextID", next_id)), body.get("pid")


class PiholeSource(Source):
    name = "pihole"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.pihole_poll_seconds
        self._client: PiholeClient | None = None
        self._last: tuple[int, datetime] | None = None  # newest stored (id, time)
        # The Pi-hole host's own LAN address: its queries arrive from 127.0.0.1.
        self._pihole_ip: str | None = None
        self._checked_at: datetime | None = None
        self._check_status: str | None = None
        self._log_next = 0  # dnsmasq log cursor; 0 reads the whole buffer
        self._log_pid: int | None = None

    def enabled(self) -> bool:
        return bool(self.settings.pihole_url and self.settings.pihole_password)

    def _newest_stored(self) -> tuple[int, datetime] | None:
        with get_sessionmaker()() as session:
            newest = session.scalar(
                select(func.max(DnsQuery.time)).where(DnsQuery.pihole_id.is_not(None))
            )
            if newest is None:
                return None
            top = session.scalar(
                select(func.max(DnsQuery.pihole_id)).where(DnsQuery.time == newest)
            )
        return int(top), newest

    def _poll(self) -> int:
        if self._client is None:
            self._client = PiholeClient(
                self.settings.pihole_url,
                self.settings.pihole_password.get_secret_value(),
                verify_tls=self.settings.pihole_verify_tls,
            )
            self._last = self._newest_stored()
            try:
                self._pihole_ip = socket.gethostbyname(urlsplit(self.settings.pihole_url).hostname)
            except (OSError, TypeError, UnicodeError):
                self._pihole_ip = None
        now = datetime.now(UTC)
        if self._last is None:
            since, after_id = now - BACKFILL, 0
        else:
            since, after_id = self._last[1] - OVERLAP, self._last[0]
        queries = self._client.queries_since(since, now, after_id)
        if self._last is not None and not queries:
            # Pi-hole's IDs restart when its database is reset: if nothing above our ID
            # came back, look again by time alone. The unique index drops repeats.
            restarted = self._client.queries_since(self._last[1], now, 0)
            queries = [q for q in restarted if q.time > self._last[1]]
        inserted = 0
        if queries:
            with get_sessionmaker()() as session:
                inserted = record_queries(session, queries, resolver_ip=self._pihole_ip)
            newest = queries[-1]
            latest = max(newest.time, self._last[1]) if self._last else newest.time
            self._last = (newest.id, latest)
        try:
            self._read_answers()
        except PiholeError as exc:  # the map lags; queries keep flowing
            log.warning("pihole: reading the DNS log for answers failed: %s", exc)
        return inserted

    def _read_answers(self) -> None:
        assert self._client is not None
        lines, next_id, pid = self._client.log_since(self._log_next)
        if pid != self._log_pid and self._log_pid is not None:
            lines, next_id, pid = self._client.log_since(0)  # FTL restarted: IDs began again
        elif self._log_next and next_id - self._log_next > len(lines):
            log.debug("pihole: %d DNS log lines rolled out of the buffer unread",
                      next_id - self._log_next - len(lines))  # fmt: skip
        self._log_next, self._log_pid = next_id, pid
        answers = parse_answers(lines)
        if answers:
            with get_sessionmaker()() as session:
                record_answers(session, answers)

    async def run_once(self) -> None:
        try:
            inserted = await asyncio.to_thread(self._poll)
        except AuthError as exc:
            log.warning("pihole: %s; check NETMAP_PIHOLE_PASSWORD (an app password)", exc)
            return
        except PiholeError as exc:
            log.warning("pihole: %s", exc)
            return
        if inserted:
            log.info("pihole: stored %d queries", inserted)
        now = datetime.now(UTC)
        if self._checked_at is None or now - self._checked_at >= VISIBILITY_EVERY:
            self._checked_at = now
            await asyncio.to_thread(self._check_visibility, now)

    def _check_visibility(self, now: datetime) -> None:
        gateway = default_gateway(self.settings.lan_iface)
        with get_sessionmaker()() as session:
            result = client_visibility(session, str(gateway) if gateway else None, now)
            record_check(session, VISIBILITY_CHECK, result, now)
        if result.status != self._check_status:  # log changes, not every check
            level = logging.WARNING if result.status == "warning" else logging.INFO
            log.log(level, "pihole: %s", result.message)
            self._check_status = result.status

    async def close(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.logout)
