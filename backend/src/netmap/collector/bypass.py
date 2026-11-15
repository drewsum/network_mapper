"""Spots IoT devices that may skip Pi-hole: online for a while (NETMAP_DNS_BYPASS_HOURS, 24 by
default) yet with almost no DNS lookups through it (fewer than NETMAP_DNS_BYPASS_MIN_LOOKUPS,
10 by default). A device like that probably has a public DNS server built in, like Google's, or
uses encrypted DNS, so netmap can't see where it goes.

The hint means nothing when Pi-hole sees no one, so it isn't given when Pi-hole isn't set
up, has sent no queries lately, or sees every query as coming from the router.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from netmap.collector.dns import VISIBILITY_CHECK
from netmap.config import Settings
from netmap.db.models import DnsQuery, HealthCheck

# Pi-hole must have sent a query this recently for silence to mean anything.
RECENT = timedelta(hours=1)

# Online IoT devices: since when (their last online or first-seen event), their lookups
# since ``start``, and their last lookup ever.
_ONLINE_IOT = text("""
    WITH iot AS (
        SELECT dv.mac, COALESCE(
            (SELECT max(e.time) FROM device_events e
             WHERE e.mac = dv.mac AND e.kind IN ('online', 'new_device')),
            dv.first_seen) AS since
        FROM devices dv
        WHERE dv.merged_into IS NULL AND dv.online AND (dv.is_iot OR dv.category = 'iot')
          AND (CAST(:mac AS macaddr) IS NULL OR dv.mac = CAST(:mac AS macaddr))
    )
    SELECT CAST(i.mac AS text) AS mac, i.since,
           (SELECT COALESCE(sum(a.queries), 0) FROM dns_activity_1h a
            WHERE a.mac = i.mac AND a.bucket >= :start) AS lookups,
           (SELECT max(q.time) FROM dns_queries q WHERE q.mac = i.mac) AS last_lookup
    FROM iot i
""")


@dataclass
class DnsCheck:
    online_since: datetime
    lookups: int  # in the last NETMAP_DNS_BYPASS_HOURS
    last_lookup: datetime | None
    silent: bool  # online the whole window, with too few lookups


def unknown_reason(session: Session, settings: Settings, now: datetime) -> str | None:
    """Why silence can't be judged right now, or None if it can."""
    if not settings.pihole_url:
        return "Pi-hole isn't set up (NETMAP_PIHOLE_URL)."
    if settings.dns_bypass_min_lookups == 0:
        return "The check is off (NETMAP_DNS_BYPASS_MIN_LOOKUPS is 0)."
    check = session.get(HealthCheck, VISIBILITY_CHECK)
    if check is not None and check.status == "warning":
        return "Pi-hole can't tell devices apart right now, so it can't say who's quiet."
    if session.scalar(select(DnsQuery.time).where(DnsQuery.time >= now - RECENT).limit(1)) is None:
        return "Pi-hole hasn't sent any DNS queries in the last hour."
    return None


def dns_checks(
    session: Session, settings: Settings, now: datetime, mac: str | None = None
) -> dict[str, DnsCheck]:
    """Online IoT devices (or just ``mac``), and whether each is suspiciously quiet."""
    start = now - timedelta(hours=settings.dns_bypass_hours)
    rows = session.execute(_ONLINE_IOT, {"start": start, "mac": mac}).all()
    return {
        r.mac: DnsCheck(
            online_since=r.since,
            lookups=int(r.lookups),
            last_lookup=r.last_lookup,
            silent=r.since <= start and r.lookups < settings.dns_bypass_min_lookups,
        )
        for r in rows
    }
