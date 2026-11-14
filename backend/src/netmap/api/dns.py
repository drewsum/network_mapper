"""DNS activity endpoints: what each device looked up, and when."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy import select, text

from netmap.api.deps import DB, Mac, get_device
from netmap.config import get_settings
from netmap.db.models import DomainIP, IpInfo

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
    country: str | None  # ISO code, where its most recently seen public IP is
    asn: int | None
    asn_org: str | None  # the network that IP belongs to


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
       d.organization, d.category, d.country, d.asn, d.asn_org
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
                country=r.country,
                asn=r.asn,
                asn_org=r.asn_org,
            )
        )
    return DeviceDomainPage(
        start=start, end=end, total=total, queries=queries, blocked=blocked, items=items
    )


class DomainAddress(BaseModel):
    ip: str
    first_seen: datetime
    last_seen: datetime
    country: str | None
    city: str | None
    asn: int | None
    asn_org: str | None


class AddressDomain(BaseModel):
    domain: str
    first_seen: datetime
    last_seen: datetime


def _window(stmt, start: datetime | None, end: datetime | None):
    """Pairs seen at some point in [start, end]: their seen span overlaps the window."""
    if start is not None:
        stmt = stmt.where(DomainIP.last_seen >= start)
    if end is not None:
        stmt = stmt.where(DomainIP.first_seen <= end)
    return stmt


@router.get("/api/domains/{domain}/ips", response_model=list[DomainAddress])
def domain_ips(
    domain: Annotated[str, Path(max_length=253)],
    db: DB,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[DomainAddress]:
    """IPs the domain resolved to (from Pi-hole's answers), most recently seen first, with
    where each is (null until located, and for private addresses). With start/end, only
    those seen at some point in that window."""
    stmt = (
        select(DomainIP, IpInfo)
        .outerjoin(IpInfo, IpInfo.ip == DomainIP.ip)
        .where(DomainIP.domain == domain.rstrip(".").lower())
    )
    rows = db.execute(_window(stmt, start, end).order_by(DomainIP.last_seen.desc())).all()
    return [
        DomainAddress(
            ip=str(r.ip),
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            country=info.country if info else None,
            city=info.city if info else None,
            asn=info.asn if info else None,
            asn_org=info.asn_org if info else None,
        )
        for r, info in rows
    ]


@router.get("/api/ips/{ip}/domains", response_model=list[AddressDomain])
def ip_domains(
    ip: str, db: DB, start: datetime | None = None, end: datetime | None = None
) -> list[AddressDomain]:
    """Domains that resolved to the IP (shared hosting and CDNs give several), most
    recently seen first. With start/end, only those seen at some point in that window."""
    try:
        address = str(ip_address(ip))
    except ValueError as exc:
        raise HTTPException(422, "not an IP address") from exc
    stmt = select(DomainIP).where(DomainIP.ip == address)
    rows = db.scalars(_window(stmt, start, end).order_by(DomainIP.last_seen.desc())).all()
    return [
        AddressDomain(domain=r.domain, first_seen=r.first_seen, last_seen=r.last_seen) for r in rows
    ]
