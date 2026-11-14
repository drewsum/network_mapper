"""DNS activity endpoints: what each device looked up, and when."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from netmap.api.deps import DB, Mac, get_device
from netmap.config import get_settings

router = APIRouter()

DEFAULT_RANGE = timedelta(hours=24)
MAX_RANGE = timedelta(days=400)

ORDER = {
    "queries": "queries DESC, domain",
    "last_seen": "last_seen DESC, domain",
    "domain": "domain",
}


class DeviceDomain(BaseModel):
    domain: str
    queries: int  # in the range
    blocked: int  # in the range
    first_seen: datetime  # the device's first query for it ever (see device_domains)
    last_seen: datetime  # latest query in the range
    new: bool  # first seen within the range
    organization: str | None
    category: str | None


class DeviceDomainPage(BaseModel):
    start: datetime
    end: datetime
    total: int  # domains in the range
    queries: int  # queries in the range, all domains
    blocked: int
    items: list[DeviceDomain]


# Per-domain counts for one device in [start, end). Raw rows give exact counts while the
# range is within raw retention; older ranges fall back to the hourly aggregate, so their
# edges are rounded to the hour.
_COUNTS = {
    "raw": """
        SELECT domain, count(*) AS queries,
               count(*) FILTER (WHERE status = 'blocked') AS blocked,
               max(time) AS last_seen
        FROM dns_queries
        WHERE mac = :mac AND time >= :start AND time < :end
        GROUP BY domain
    """,
    "hourly": """
        SELECT domain, sum(queries)::bigint AS queries, sum(blocked)::bigint AS blocked,
               max(bucket) + interval '1 hour' AS last_seen
        FROM dns_activity_1h
        WHERE mac = :mac AND bucket >= :start AND bucket < :end
        GROUP BY domain
    """,
}

_PAGE = """
WITH counts AS ({counts}),
page AS (SELECT * FROM counts ORDER BY {order} LIMIT :limit OFFSET :offset)
SELECT p.domain, p.queries, p.blocked, p.last_seen,
       (SELECT min(q.time) FROM dns_queries q
        WHERE q.mac = :mac AND q.domain = p.domain) AS raw_first,
       (SELECT min(a.bucket) FROM dns_activity_1d a
        WHERE a.mac = :mac AND a.domain = p.domain) AS day_first,
       d.organization, d.category
FROM page p LEFT JOIN domains d ON d.domain = p.domain
ORDER BY {order}
"""

_TOTALS = """
WITH counts AS ({counts})
SELECT count(*), coalesce(sum(queries), 0), coalesce(sum(blocked), 0) FROM counts
"""


def _first_seen(raw_first: datetime | None, day_first: datetime | None) -> datetime:
    """Exact from raw rows; the day it happened when raw rows have aged out (> retention)."""
    if raw_first is None:
        return day_first
    if day_first is not None and day_first < raw_first.astimezone(UTC).replace(
        hour=0, minute=0, second=0, microsecond=0
    ):
        return day_first
    return raw_first


@router.get("/api/devices/{mac}/domains", response_model=DeviceDomainPage)
def device_domains(
    mac: Mac,
    db: DB,
    start: datetime | None = None,
    end: datetime | None = None,
    sort: Literal["queries", "last_seen", "domain"] = "queries",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DeviceDomainPage:
    """Domains a device looked up in [start, end) (default: the last 24 hours), with query
    and block counts. ``first_seen`` is the device's first query for the domain ever, not
    just in the range: exact for the last NETMAP_RAW_RETENTION_DAYS, to the day before."""
    device = get_device(db, mac)
    end = (end or datetime.now(UTC)).astimezone(UTC)
    start = (start or end - DEFAULT_RANGE).astimezone(UTC)
    if not start < end <= start + MAX_RANGE:
        raise HTTPException(422, f"start must be before end, at most {MAX_RANGE.days} days")

    retention = timedelta(days=get_settings().raw_retention_days)
    counts = _COUNTS["raw" if start >= datetime.now(UTC) - retention else "hourly"]
    params = {"mac": device.mac, "start": start, "end": end, "limit": limit, "offset": offset}
    total, queries, blocked = db.execute(text(_TOTALS.format(counts=counts)), params).one()
    rows = db.execute(text(_PAGE.format(counts=counts, order=ORDER[sort])), params).all()

    items = []
    for r in rows:
        first = _first_seen(r.raw_first, r.day_first) or r.last_seen
        items.append(
            DeviceDomain(
                domain=r.domain,
                queries=r.queries,
                blocked=r.blocked,
                first_seen=first,
                last_seen=r.last_seen,
                new=first >= start,
                organization=r.organization,
                category=r.category,
            )
        )
    return DeviceDomainPage(
        start=start, end=end, total=total, queries=queries, blocked=blocked, items=items
    )
