"""Single-admin login: NETMAP_ADMIN_PASSWORD in, a signed session cookie out.

Sessions are stateless: the cookie carries its expiry and an HMAC of it. The signing key
mixes a random secret kept in the DB (so sessions survive restarts and can't be forged
from the source) with the password (so changing the password logs everyone out).

Cookies are HttpOnly and SameSite=Strict, and the API only takes JSON bodies, which
browsers won't send cross-site without CORS, so other sites can't act with the session.
Without a password the app stays open, and says so: see ``auth_enabled``.
"""

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from netmap.config import Settings
from netmap.db import get_sessionmaker
from netmap.db.models import AppSecret

COOKIE = "netmap_session"
SECRET_NAME = "session_signing_key"
# Failed logins allowed per client address within the window.
MAX_FAILURES = 5
FAILURE_WINDOW = 300.0


def auth_enabled(settings: Settings) -> bool:
    return settings.admin_password is not None


@lru_cache
def _db_secret() -> bytes:
    """The random half of the signing key, created on first use."""
    with get_sessionmaker()() as session:
        session.execute(
            insert(AppSecret)
            .values(name=SECRET_NAME, value=secrets.token_hex(32))
            .on_conflict_do_nothing()
        )
        session.commit()
        value = session.scalar(select(AppSecret.value).where(AppSecret.name == SECRET_NAME))
    return bytes.fromhex(value)


def signing_key(settings: Settings) -> bytes:
    password = settings.require("admin_password").get_secret_value().encode()
    return hmac.new(_db_secret(), b"netmap-session:" + password, hashlib.sha256).digest()


def make_token(key: bytes, expires: int) -> str:
    mac = hmac.new(key, f"v1.{expires}".encode(), hashlib.sha256).hexdigest()
    return f"v1.{expires}.{mac}"


def token_valid(key: bytes, token: str | None, now: float | None = None) -> bool:
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "v1" or not parts[1].isdigit():
        return False
    expected = make_token(key, int(parts[1]))
    return hmac.compare_digest(expected, token) and int(parts[1]) > (now or time.time())


def password_matches(settings: Settings, candidate: str) -> bool:
    actual = settings.require("admin_password").get_secret_value()
    # Compare digests so the comparison time doesn't depend on the password's length.
    return hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(), hashlib.sha256(actual.encode()).digest()
    )


class FailedLogins:
    """Recent failed logins per client address, for a simple lockout."""

    def __init__(self) -> None:
        self._times: dict[str, deque[float]] = defaultdict(deque)

    def _recent(self, client: str, now: float) -> deque[float]:
        times = self._times[client]
        while times and times[0] < now - FAILURE_WINDOW:
            times.popleft()
        return times

    def locked(self, client: str) -> bool:
        return len(self._recent(client, time.monotonic())) >= MAX_FAILURES

    def record(self, client: str) -> None:
        self._recent(client, time.monotonic()).append(time.monotonic())

    def clear(self, client: str) -> None:
        self._times.pop(client, None)
