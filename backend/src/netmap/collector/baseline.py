"""Learns what's normal for each device, and records departures from it.

A device's baseline is the sites (registrable domains), organizations, countries and
networks (AS numbers) it looks up, each with the number of days it did. Learning starts
with the device's first DNS lookup and lasts NETMAP_BASELINE_LEARNING_DAYS (7 by
default). After that, a site, organization, country or network seen for the first time
is recorded as a device event (new_domain, new_org, new_country, new_asn), and so is an
hour with far more lookups than the device's busy hours of the week before
(query_spike). Phones and computers still get a baseline, but no events: new sites are
everyday for them.

Baselines are built from the hourly DNS aggregate: all of it for a device without one
yet, then the last day each round, so domains the geoip and org jobs locate later still
count.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import Session

from netmap.collector.base import Source
from netmap.db import get_sessionmaker
from netmap.db.models import Device, DeviceBaseline, DeviceEvent, Domain
from netmap.orgs import OTHER

log = logging.getLogger(__name__)

# Devices that get no departure events.
UNWATCHED_CATEGORIES = ("phone", "computer")
# Each round looks at this much of the hourly aggregate again.
LOOKBACK = timedelta(hours=26)
# A spike is an hour with at least SPIKE_MIN lookups and SPIKE_FACTOR times the device's
# 95th-percentile hour over the SPIKE_WINDOW before it (quiet hours included).
SPIKE_MIN = 200
SPIKE_FACTOR = 4
SPIKE_WINDOW = timedelta(days=7)

# Names that never leave the LAN, and the registrable part of a public one: the last two
# labels, or three under a two-level suffix like co.uk.
_LOCAL = r"\.(arpa|local|lan|localdomain|localhost|internal|home)$"
_SITE = (
    r"COALESCE(CASE WHEN s.domain ~ '\.(com|net|org|gov|edu|ac|co|ne|or|go)\.[a-z]{2}$'"
    r" THEN substring(s.domain from '([^.]+\.[^.]+\.[^.]+)$')"
    r" ELSE substring(s.domain from '([^.]+\.[^.]+)$') END, s.domain)"
)

_UPSERT = text(
    """
    WITH seen AS (
        SELECT q.mac, q.bucket, lower(q.domain) AS domain FROM dns_activity_1h q
        JOIN devices dv ON dv.mac = q.mac AND dv.merged_into IS NULL
        WHERE (q.bucket >= :since
               OR NOT EXISTS (SELECT 1 FROM device_baselines b WHERE b.mac = q.mac))
          AND q.domain LIKE '%.%' AND lower(q.domain) !~ '"""
    + _LOCAL
    + """'
    ), keys AS (
        SELECT s.mac, s.bucket, k.key_type, k.key FROM seen s
        LEFT JOIN domains d ON d.domain = s.domain
        CROSS JOIN LATERAL (VALUES
            ('domain', """
    + _SITE
    + """),
            ('org', NULLIF(d.organization, :other)),
            ('country', d.country),
            ('asn', CAST(d.asn AS text))
        ) AS k(key_type, key)
        WHERE k.key IS NOT NULL
    )
    INSERT INTO device_baselines AS b (mac, key_type, key, hits, first_seen, last_seen)
    SELECT mac, key_type, key, count(DISTINCT CAST(bucket AT TIME ZONE 'UTC' AS date)),
           min(bucket), max(bucket)
    FROM keys GROUP BY mac, key_type, key
    ON CONFLICT (mac, key_type, key) DO UPDATE SET
        hits = b.hits + CAST(CAST(EXCLUDED.last_seen AT TIME ZONE 'UTC' AS date)
                             > CAST(b.last_seen AT TIME ZONE 'UTC' AS date) AS int),
        first_seen = LEAST(b.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(b.last_seen, EXCLUDED.last_seen)
    RETURNING CAST(mac AS text), key_type, key, first_seen, xmax = 0 AS inserted
"""
)

# Each device's lookups in ``hour``, if at least ``minimum``, and its 95th-percentile hour
# over the window before it.
_SPIKES = text("""
    WITH hours AS (
        SELECT generate_series(:hour - :window, :hour - INTERVAL '1 hour', INTERVAL '1 hour')
            AS bucket
    ), totals AS (
        SELECT mac, bucket, sum(queries) AS n FROM dns_activity_1h
        WHERE bucket >= :hour - :window AND bucket <= :hour
          AND mac = ANY(CAST(:macs AS macaddr[]))
        GROUP BY mac, bucket
    ), current AS (
        SELECT mac, n FROM totals WHERE bucket = :hour AND n >= :minimum
    )
    SELECT CAST(c.mac AS text), c.n,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY COALESCE(t.n, 0))
    FROM current c CROSS JOIN hours h
    LEFT JOIN totals t ON t.mac = c.mac AND t.bucket = h.bucket
    GROUP BY c.mac, c.n
""")

# One device's 95th-percentile hour over the window before ``now``.
_USUAL_PEAK = text("""
    SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY COALESCE(t.n, 0))
    FROM generate_series(:start, :end, INTERVAL '1 hour') AS h(bucket)
    LEFT JOIN (
        SELECT bucket, sum(queries) AS n FROM dns_activity_1h
        WHERE mac = :mac AND bucket >= :start AND bucket <= :end GROUP BY bucket
    ) t USING (bucket)
""")


@dataclass
class Learning:
    since: datetime  # the device's first lookup
    until: datetime  # learning ends; later firsts are departures

    def done(self, at: datetime) -> bool:
        return at >= self.until


def learning_periods(session: Session, days: float, macs=None) -> dict[str, Learning]:
    """Each device's learning period, for devices with a baseline."""
    stmt = select(DeviceBaseline.mac, func.min(DeviceBaseline.first_seen)).group_by(
        DeviceBaseline.mac
    )
    if macs is not None:
        stmt = stmt.where(DeviceBaseline.mac.in_(macs))
    return {
        str(mac): Learning(since, since + timedelta(days=days))
        for mac, since in session.execute(stmt).all()
    }


def _watched(session: Session) -> set[str]:
    rows = session.execute(
        select(Device.mac).where(Device.category.not_in(UNWATCHED_CATEGORIES))
    ).scalars()
    return {str(m) for m in rows}


def update_baselines(session: Session, now: datetime, days: float) -> int:
    """Add the last day's lookups to the baselines (all of them for a device without one),
    and record the departures among them. Commits. Returns how many were recorded."""
    rows = session.execute(_UPSERT, {"since": now - LOOKBACK, "other": OTHER}).all()
    new = [r for r in rows if r.inserted]
    learning = learning_periods(session, days, {r.mac for r in new})
    watched = _watched(session)
    departures = [r for r in new if r.mac in watched and learning[r.mac].done(r.first_seen)]
    networks = {r.key for r in departures if r.key_type == "asn"}
    names = (
        dict(
            session.execute(
                select(Domain.asn, func.min(Domain.asn_org))
                .where(Domain.asn.in_([int(k) for k in networks]))
                .group_by(Domain.asn)
            ).all()
        )
        if networks
        else {}
    )
    events = []
    for r in departures:
        details = {"key": r.key}
        if r.key_type == "asn" and names.get(int(r.key)):
            details["label"] = names[int(r.key)]
        events.append(
            {"time": r.first_seen, "mac": r.mac, "kind": f"new_{r.key_type}", "details": details}
        )
    if events:
        session.execute(insert(DeviceEvent), events)
    session.commit()
    return len(events)


def find_spikes(session: Session, now: datetime, days: float) -> int:
    """Record a query_spike for each watched, fully learned device whose last complete hour
    had far more lookups than usual. Commits. Returns how many were recorded."""
    # A few minutes' grace for Pi-hole's last queries of the hour to arrive.
    hour = (now - timedelta(minutes=5)).replace(minute=0, second=0, microsecond=0)
    hour -= timedelta(hours=1)
    watched = _watched(session)
    periods = learning_periods(session, days)
    macs = [m for m, lp in periods.items() if m in watched and lp.done(hour)]
    if not macs:
        return 0
    rows = session.execute(
        _SPIKES, {"hour": hour, "window": SPIKE_WINDOW, "macs": macs, "minimum": SPIKE_MIN}
    ).all()
    done = set(
        session.execute(
            select(DeviceEvent.mac).where(
                DeviceEvent.kind == "query_spike", DeviceEvent.time == hour
            )
        ).scalars()
    )
    done = {str(m) for m in done}
    events = [
        {
            "time": hour,
            "mac": mac,
            "kind": "query_spike",
            "details": {"lookups": int(n), "usual": round(peak)},
        }
        for mac, n, peak in rows
        if mac not in done and n > SPIKE_FACTOR * max(peak, 1)
    ]
    if events:
        session.execute(insert(DeviceEvent), events)
    session.commit()
    return len(events)


def usual_peak(session: Session, mac: str, now: datetime) -> int:
    """The device's 95th-percentile hour of lookups over the last week, quiet hours
    included."""
    end = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    peak = session.execute(
        _USUAL_PEAK, {"mac": mac, "start": end - SPIKE_WINDOW + timedelta(hours=1), "end": end}
    ).scalar()
    return round(peak or 0)


class BaselineSource(Source):
    name = "baseline"
    interval_seconds = 300.0

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        now = datetime.now(UTC)
        days = self.settings.baseline_learning_days
        with get_sessionmaker()() as session:
            new = update_baselines(session, now, days)
            spikes = find_spikes(session, now, days)
        if new or spikes:
            log.info("baseline: %d new sites/orgs/countries/networks, %d spikes", new, spikes)
