"""DNS queries from Pi-hole v6's REST API.

Logs in once with the app password (POST /api/auth) and reuses the session, logging in
again when it expires and out when the collector stops: Pi-hole allows only a few API
sessions at a time. Each poll asks /api/queries for everything since the newest stored
query (minus a little overlap) and keeps the query IDs it hasn't stored yet; a unique
(pihole_id, time) index makes repeats harmless anyway, so restarts neither duplicate
nor drop queries as long as they're still in Pi-hole's memory (24 h by default).
"""

import asyncio
import contextlib
import json
import logging
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from sqlalchemy import func, select

from netmap.collector.base import Source
from netmap.collector.dns import record_queries
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

    def get(self, path: str, params: dict) -> dict:
        """GET with the session, logging in first or again after it expires."""
        if self._sid is None:
            self.login()
        full = f"{path}?{urlencode(params)}"
        status, body = self._call("GET", full)
        if status == 401:
            self.login()
            status, body = self._call("GET", full)
        if status != 200:
            message = (body.get("error") or {}).get("message", "")
            raise PiholeError(f"GET {path}: HTTP {status} {message}".strip())
        return body

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


class PiholeSource(Source):
    name = "pihole"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.pihole_poll_seconds
        self._client: PiholeClient | None = None
        self._last: tuple[int, datetime] | None = None  # newest stored (id, time)

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
        if not queries:
            return 0
        with get_sessionmaker()() as session:
            inserted = record_queries(session, queries)
        newest = queries[-1]
        self._last = (newest.id, max(newest.time, self._last[1] if self._last else newest.time))
        return inserted

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

    async def close(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.logout)
