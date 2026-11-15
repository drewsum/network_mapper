"""Network-wide DNS history: lookups over time, broken down by device, domain,
organization, country, network (ASN), category or allowed/blocked.

Reads the continuous aggregates, picking the finest one the range allows: per minute up
to 2 days (while it's kept, NETMAP_RAW_RETENTION_DAYS), per hour up to 2 weeks, per day
beyond. Ranges start on a bucket boundary, so the timeline and the breakdowns agree.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from netmap import categories
from netmap.api.deps import DB
from netmap.config import get_settings

router = APIRouter()

DEFAULT_RANGE = timedelta(hours=24)
MAX_RANGE = timedelta(days=400)

Dimension = Literal["device", "domain", "organization", "country", "asn", "category", "status"]

# dimension -> (key, label) SQL over the aggregate `a`, `domains d` and `devices dv`.
_DIMENSIONS = {
    "device": (
        "coalesce(a.mac::text, '')",
        "coalesce(dv.label, dv.hostname, dv.vendor || ' device', a.mac::text, 'Unknown client')",
    ),
    "domain": ("a.domain", "a.domain"),
    "organization": ("coalesce(d.organization, '')", "coalesce(d.organization, 'Not grouped yet')"),
    "country": ("coalesce(d.country, '')", "coalesce(d.country, '')"),
    "asn": (
        "coalesce(d.asn::text, '')",
        "CASE WHEN d.asn IS NULL THEN 'Unknown network' "
        "ELSE coalesce(d.asn_org || ' ', '') || '(AS' || d.asn || ')' END",
    ),
    "category": ("coalesce(d.category, '')", "coalesce(d.category, '')"),
}
# filter parameter -> SQL condition
_FILTERS = {
    "mac": "a.mac = CAST(:mac AS macaddr)",
    "domain": "a.domain = :domain",
    "organization": "d.organization = :organization",
    "country": "d.country = :country",
    "asn": "d.asn = CAST(:asn AS integer)",
    "category": "d.category = :category",
}

_FROM = """
FROM {view} a
LEFT JOIN domains d ON d.domain = a.domain
LEFT JOIN devices dv ON dv.mac = a.mac
WHERE a.bucket >= :first AND a.bucket < :end {filters}
"""

_TIMELINE = """
WITH counts AS (
    SELECT time_bucket(CAST(:bucket AS interval), a.bucket) AS t,
           sum(a.queries)::bigint AS queries, sum(a.blocked)::bigint AS blocked
    {from_}
    GROUP BY 1
)
SELECT s.t, coalesce(c.queries, 0), coalesce(c.blocked, 0)
FROM generate_series(:first, CAST(:end AS timestamptz) - interval '1 microsecond',
                     CAST(:bucket AS interval)) AS s(t)
LEFT JOIN counts c ON c.t = s.t
ORDER BY s.t
"""

_TOTALS = """
SELECT coalesce(sum(a.queries), 0)::bigint, coalesce(sum(a.blocked), 0)::bigint,
       count(DISTINCT a.domain), count(DISTINCT a.mac)
{from_}
"""

_BREAKDOWN = """
SELECT {key} AS key, min({label}) AS label, sum(a.queries)::bigint AS queries,
       sum(a.blocked)::bigint AS blocked, count(DISTINCT a.domain) AS domains
{from_}
GROUP BY 1 ORDER BY queries DESC, {key} = '', 1 LIMIT :limit
"""


class Point(BaseModel):
    time: datetime
    queries: int
    blocked: int


class Row(BaseModel):
    key: str  # what to filter on to narrow to this row ("" when unknown)
    label: str
    queries: int
    blocked: int
    domains: int


class History(BaseModel):
    start: datetime  # the requested start, moved back to a bucket boundary
    end: datetime
    bucket_seconds: int
    source: str  # the aggregate read
    queries: int
    blocked: int
    domains: int
    devices: int
    points: list[Point]
    by: Dimension
    rows: list[Row]  # the breakdown, most lookups first


def _source(start: datetime, end: datetime) -> tuple[timedelta, str]:
    span = end - start
    retention = timedelta(days=get_settings().raw_retention_days)
    per_minute = start >= datetime.now(UTC) - retention
    if span <= timedelta(hours=3) and per_minute:
        return timedelta(minutes=1), "dns_activity_1m"
    if span <= timedelta(days=2) and per_minute:
        return timedelta(minutes=15), "dns_activity_1m"
    if span <= timedelta(days=14):
        return timedelta(hours=1), "dns_activity_1h"
    return timedelta(days=1), "dns_activity_1d"


@router.get("/api/history", response_model=History)
def history(
    db: DB,
    start: datetime | None = None,
    end: datetime | None = None,
    by: Dimension = "device",
    limit: Annotated[int, Query(ge=1, le=500)] = 25,
    mac: Annotated[str | None, Query(pattern=r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")] = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
    organization: Annotated[str | None, Query(max_length=200)] = None,
    country: Annotated[str | None, Query(max_length=2)] = None,
    asn: Annotated[int | None, Query(ge=1)] = None,
    category: Annotated[str | None, Query(max_length=40)] = None,
) -> History:
    """DNS lookups in [start, end) (default: the last 24 hours) across the network, over
    time and broken down ``by`` one dimension. The filters narrow both to one device,
    domain, organization, country, network or category."""
    end = (end or datetime.now(UTC)).astimezone(UTC)
    start = (start or end - DEFAULT_RANGE).astimezone(UTC)
    if not start < end <= start + MAX_RANGE:
        raise HTTPException(422, f"start must be before end, at most {MAX_RANGE.days} days")
    bucket, view = _source(start, end)
    seconds = int(bucket.total_seconds())
    first = datetime.fromtimestamp(start.timestamp() // seconds * seconds, UTC)

    given = {
        "mac": mac.lower() if mac else None,
        "domain": domain.rstrip(".").lower() if domain else None,
        "organization": organization,
        "country": country.upper() if country else None,
        "asn": asn,
        "category": category,
    }
    given = {k: v for k, v in given.items() if v is not None}
    filters = "".join(f" AND {_FILTERS[k]}" for k in given)
    from_ = _FROM.format(view=view, filters=filters)
    params = {"first": first, "end": end, "bucket": bucket, "limit": limit, **given}

    points = [
        Point(time=t, queries=q, blocked=b)
        for t, q, b in db.execute(text(_TIMELINE.format(from_=from_)), params)
    ]
    queries, blocked, domains, devices = db.execute(text(_TOTALS.format(from_=from_)), params).one()
    if by == "status":
        rows = [
            Row(key="allowed", label="Allowed", queries=queries - blocked, blocked=0, domains=0),
            Row(key="blocked", label="Blocked", queries=blocked, blocked=blocked, domains=0),
        ]
    else:
        key, label = _DIMENSIONS[by]
        rows = [
            Row(key=k, label=lab, queries=q, blocked=b, domains=n)
            for k, lab, q, b, n in db.execute(
                text(_BREAKDOWN.format(key=key, label=label, from_=from_)), params
            )
        ]
        if by == "category":
            rows = [
                r.model_copy(update={"label": categories.LABELS.get(r.key, "Not categorized")})
                for r in rows
            ]
    return History(
        start=first,
        end=end,
        bucket_seconds=seconds,
        source=view,
        queries=queries,
        blocked=blocked,
        domains=domains,
        devices=devices,
        points=points,
        by=by,
        rows=rows,
    )
