"""Locates the IPs domains resolve to: country, city and network (ASN).

The IPs come from the passive DNS map Pi-hole's answers build (domain_ips), so nothing is
resolved here: a lookup from this host would go through Pi-hole and show up as the host's
own DNS traffic. Each IP is looked up once in the GeoIP databases (netmap.geoip) and again
after they're updated. A domain then takes the location of its most recently seen public
IP. Domains that were only ever blocked have no IPs, and stay unlocated.

The databases are downloaded on first run and kept current; how that's going shows on
the status bar as the "geoip" check.
"""

import asyncio
import logging
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap import geoip
from netmap.collector.base import Source
from netmap.collector.dns import CheckResult, record_check
from netmap.db import get_sessionmaker
from netmap.db.models import IpInfo

log = logging.getLogger(__name__)

GEOIP_CHECK = "geoip"
CHECK_INTERVAL = 300.0
# After a failed download, wait this long before trying again.
RETRY_AFTER = timedelta(hours=1)
# IPs per lookup batch: well under Postgres's bind parameter limit at 6 columns a row.
BATCH = 5000

_DUE_IPS = text("""
    SELECT DISTINCT d.ip FROM domain_ips d
    LEFT JOIN ip_info i ON i.ip = d.ip
    WHERE i.ip IS NULL OR i.looked_up_at < :loaded_at
    LIMIT :limit
""")

# Each domain takes its most recently seen IP that has a location (so a public address
# wins over a LAN one), and only rows whose values change are written.
_SUMMARIZE = text("""
    UPDATE domains d
    SET country = x.country, city = x.city, asn = x.asn, asn_org = x.asn_org,
        enriched_at = :now
    FROM (
        SELECT DISTINCT ON (di.domain) di.domain, i.country, i.city, i.asn, i.asn_org
        FROM domain_ips di JOIN ip_info i ON i.ip = di.ip
        ORDER BY di.domain, (i.country IS NULL AND i.asn IS NULL), di.last_seen DESC
    ) x
    WHERE d.domain = x.domain
      AND (d.enriched_at IS NULL
           OR (d.country, d.city, d.asn, d.asn_org)
              IS DISTINCT FROM (x.country, x.city, x.asn, x.asn_org))
""")


def enrich_ips(session: Session, lookup, loaded_at: datetime, now: datetime) -> int:
    """Look up every mapped IP not looked up since the databases were ``loaded_at``.
    ``lookup`` maps an IP string to a geoip.IpGeo. Commits. Returns how many."""
    total = 0
    while True:
        ips = session.scalars(_DUE_IPS, {"loaded_at": loaded_at, "limit": BATCH}).all()
        if not ips:
            return total
        rows = [{"ip": str(ip), **asdict(lookup(str(ip))), "looked_up_at": now} for ip in ips]
        stmt = insert(IpInfo).values(rows)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[IpInfo.ip],
                set_={c: stmt.excluded[c] for c in rows[0] if c != "ip"},
            )
        )
        session.commit()
        total += len(rows)
        if len(rows) < BATCH:
            return total


def summarize_domains(session: Session, now: datetime) -> int:
    """Copy each domain's location from its IPs. Commits. Returns domains changed."""
    changed = session.execute(_SUMMARIZE, {"now": now}).rowcount
    session.commit()
    return changed


class GeoipSource(Source):
    name = "geoip"
    interval_seconds = CHECK_INTERVAL

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self._dir = Path(settings.geoip_dir)
        self._db: geoip.GeoDb | None = None
        self._open: geoip.Meta | None = None  # what self._db was opened from
        self._attempted_at: datetime | None = None
        self._error: str | None = None  # the last failed download, until one succeeds

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        now = datetime.now(UTC)
        meta = self._refresh(now)
        if meta is not None and meta != self._open:
            if self._db is not None:
                self._db.close()
            self._db, self._open = geoip.GeoDb(self._dir), meta
        with get_sessionmaker()() as session:
            record_check(session, GEOIP_CHECK, self._status(meta), now)
            if self._db is None or meta is None:
                return
            looked_up = enrich_ips(session, self._db.lookup, meta.downloaded_at, now)
            changed = summarize_domains(session, now)
        if looked_up or changed:
            log.info("geoip: located %d IPs, %d domains changed", looked_up, changed)

    def _refresh(self, now: datetime) -> geoip.Meta | None:
        """Download the databases if they're due and it's time to try. Returns what's
        installed afterwards."""
        key = self.settings.maxmind_license_key
        key = key.get_secret_value() if key else None
        meta = geoip.read_meta(self._dir)
        refresh_after = timedelta(days=self.settings.geoip_refresh_days)
        if not geoip.is_due(meta, bool(key), now, refresh_after):
            return meta
        if self._attempted_at is not None and now - self._attempted_at < RETRY_AFTER:
            return meta
        self._attempted_at = now
        # Fall back to DB-IP only when there's nothing at all: stale data beats none, and
        # MaxMind is tried again in an hour.
        sources = [geoip.MAXMIND] if key else [geoip.DBIP]
        if key and meta is None:
            sources.append(geoip.DBIP)
        errors = []
        for source in sources:
            name = geoip.SOURCE_NAMES[source]
            try:
                fresh = geoip.download(self._dir, source, now, key=key, installed=meta)
            except (OSError, ValueError) as exc:  # URLError and timeouts are OSErrors
                errors.append(f"{name}: {exc}")
                log.warning("geoip: %s download failed: %s", name, exc)
                continue
            if fresh is not None:
                log.info("geoip: installed %s %s", name, fresh.version)
                meta = fresh
            break
        self._error = "; ".join(errors) or None
        return meta

    def _status(self, meta: geoip.Meta | None) -> CheckResult:
        if meta is None:
            return CheckResult(
                "warning",
                f"No GeoIP database yet, so domains have no country or network. Download "
                f"failed: {self._error or 'not tried yet'}",
                {},
            )
        name = geoip.SOURCE_NAMES[meta.source]
        details = {"source": meta.source, "version": meta.version}
        if self._error:
            return CheckResult(
                "warning",
                f"Using {name} {meta.version}; updating it failed ({self._error}). Check "
                "NETMAP_MAXMIND_LICENSE_KEY if MaxMind is failing.",
                details,
            )
        return CheckResult("ok", f"Locating IPs with {name} {meta.version}.", details)

    async def close(self) -> None:
        if self._db is not None:
            self._db.close()
