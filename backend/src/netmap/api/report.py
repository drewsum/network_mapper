"""The IoT phone-home report: per IoT device, the sites it looks up, sorted into what's
expected (marked so by the user, or its maker's cloud) and what deserves a look (threats,
trackers and telemetry, other third parties, and sites marked unexpected), with lookups
at night. Exportable as CSV."""

import csv
import io
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Body, HTTPException, Path
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.api.deps import DB, Mac, get_device
from netmap.collector.baseline import LOCAL_NAME, site_sql
from netmap.db.models import Device, DeviceBaseline, DeviceName

router = APIRouter()

# Lookups between midnight and this hour, in the viewer's time zone, count as at night.
NIGHT_ENDS = 6

Status = Literal[
    "threat", "expected", "unexpected", "tracker", "maker", "infrastructure", "third_party"
]  # fmt: skip
# Statuses that deserve a look.
FLAGGED = ("threat", "unexpected", "tracker", "third_party")
# A site's category is its most telling domain's.
CATEGORY_RANK = ("ads", "analytics", "vendor", "cdn", "infrastructure", "unknown")
# Words in company names that say nothing about which company it is.
GENERIC_WORDS = {
    "inc", "llc", "ltd", "co", "corp", "corporation", "company", "technologies",
    "technology", "tech", "electronics", "electronic", "international", "group", "limited",
    "gmbh", "holdings", "systems", "the", "and", "communications", "networks", "devices",
}  # fmt: skip

_LOOKUPS = text(
    """
    WITH q AS (
        SELECT a.mac, lower(a.domain) AS domain, sum(a.queries) AS n, sum(a.blocked) AS b,
               COALESCE(sum(a.queries) FILTER (
                   WHERE EXTRACT(hour FROM a.bucket AT TIME ZONE :tz) < :night_ends), 0) AS night
        FROM dns_activity_1h a JOIN devices dv ON dv.mac = a.mac
        WHERE a.bucket >= :start AND dv.merged_into IS NULL
          AND (dv.is_iot OR dv.category = 'iot')
          AND a.domain LIKE '%.%' AND lower(a.domain) !~ '"""
    + LOCAL_NAME
    + """'
        GROUP BY a.mac, lower(a.domain)
    )
    SELECT CAST(q.mac AS text) AS mac, """
    + site_sql("q.domain")
    + """ AS site, q.domain, q.n, q.b, q.night,
           d.organization, d.category, COALESCE(d.is_blocklisted, false) AS threat
    FROM q LEFT JOIN domains d ON d.domain = q.domain
"""
)


class Site(BaseModel):
    site: str
    status: Status
    expected: bool | None  # the user's verdict; null if not given
    organization: str | None  # its busiest domain's
    category: str | None
    lookups: int
    night: int  # lookups between midnight and 6 am
    blocked: int
    domains: list[str]  # busiest first


class DeviceReport(BaseModel):
    mac: str
    label: str | None
    hostname: str | None
    vendor: str | None
    lookups: int
    night: int
    flagged: int  # sites that deserve a look
    sites: list[Site]  # those first, then by lookups


class Report(BaseModel):
    start: datetime
    tz: str
    devices: list[DeviceReport]


class Verdict(BaseModel):
    expected: bool | None = Field(description="true or false; null clears it")


def words(name: str | None) -> set[str]:
    """The telling words of a company name."""
    found = re.findall(r"[a-z0-9]+", (name or "").lower())
    return {w for w in found if len(w) >= 3 and w not in GENERIC_WORDS}


def _makers(db: Session, devices: list[Device]) -> dict[str, set[str]]:
    """Words naming each device's maker: its MAC vendor and its UPnP manufacturer."""
    makers = {str(d.mac): words(d.vendor) for d in devices}
    for mac, details in db.execute(
        select(DeviceName.mac, DeviceName.details).where(
            DeviceName.mac.in_([d.mac for d in devices]), DeviceName.details.is_not(None)
        )
    ).all():
        makers[str(mac)] |= words((details or {}).get("manufacturer"))
    return makers


def status(threat: bool, expected: bool | None, category: str | None, maker: bool) -> Status:
    if threat:
        return "threat"
    if expected is not None:
        return "expected" if expected else "unexpected"
    if category in ("ads", "analytics"):
        return "tracker"
    if maker:
        return "maker"
    if category in ("cdn", "infrastructure"):
        return "infrastructure"
    return "third_party"


def _tz(tz: str) -> str:
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(400, f"unknown time zone {tz!r}") from exc
    return tz


def build_report(db: Session, start: datetime, tz: str) -> Report:
    devices = list(
        db.scalars(
            select(Device)
            .where(Device.merged_into.is_(None), or_(Device.is_iot, Device.category == "iot"))
            .order_by(Device.label, Device.hostname, Device.mac)
        )
    )
    rows = db.execute(_LOOKUPS, {"start": start, "tz": tz, "night_ends": NIGHT_ENDS}).all()
    verdicts = {
        (str(mac), key): expected
        for mac, key, expected in db.execute(
            select(DeviceBaseline.mac, DeviceBaseline.key, DeviceBaseline.expected).where(
                DeviceBaseline.key_type == "domain", DeviceBaseline.expected.is_not(None)
            )
        ).all()
    }
    makers = _makers(db, devices)
    by_site: dict[tuple[str, str], list] = defaultdict(list)
    for r in rows:
        by_site[(r.mac, r.site)].append(r)
    sites: dict[str, list[Site]] = defaultdict(list)
    for (mac, site), domains in by_site.items():
        domains.sort(key=lambda r: -r.n)
        categories = [r.category for r in domains if r.category in CATEGORY_RANK]
        category = min(categories, key=CATEGORY_RANK.index) if categories else None
        organization = next((r.organization for r in domains if r.organization), None)
        maker = bool(words(organization) & makers.get(mac, set()))
        expected = verdicts.get((mac, site))
        sites[mac].append(
            Site(
                site=site,
                status=status(any(r.threat for r in domains), expected, category, maker),
                expected=expected,
                organization=organization,
                category=category,
                lookups=sum(r.n for r in domains),
                night=sum(r.night for r in domains),
                blocked=sum(r.b for r in domains),
                domains=[r.domain for r in domains],
            )
        )
    report = []
    for d in devices:
        mine = sorted(sites[str(d.mac)], key=lambda s: (s.status not in FLAGGED, -s.lookups))
        report.append(
            DeviceReport(
                mac=str(d.mac),
                label=d.label,
                hostname=d.hostname,
                vendor=d.vendor,
                lookups=sum(s.lookups for s in mine),
                night=sum(s.night for s in mine),
                flagged=sum(s.status in FLAGGED for s in mine),
                sites=mine,
            )
        )
    return Report(start=start, tz=tz, devices=report)


def _start(start: datetime | None) -> datetime:
    return start or datetime.now(UTC) - timedelta(days=7)


@router.get("/api/reports/iot", response_model=Report)
def iot_report(db: DB, start: datetime | None = None, tz: str = "UTC") -> Report:
    """Per IoT device, the sites it looked up since ``start`` (a week ago by default), with
    lookups at night in time zone ``tz``."""
    return build_report(db, _start(start), _tz(tz))


@router.get("/api/reports/iot.csv")
def iot_report_csv(db: DB, start: datetime | None = None, tz: str = "UTC") -> Response:
    """The IoT report as CSV, one row per device and site."""
    report = build_report(db, _start(start), _tz(tz))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["device", "mac", "vendor", "site", "status", "organization", "category",
         "lookups", f"night lookups (00-{NIGHT_ENDS:02d} {tz})", "blocked", "domains"]
    )  # fmt: skip
    for d in report.devices:
        for s in d.sites:
            writer.writerow(
                [d.label or d.hostname or d.vendor or d.mac, d.mac, d.vendor or "", s.site,
                 s.status, s.organization or "", s.category or "", s.lookups, s.night,
                 s.blocked, " ".join(s.domains)]
            )  # fmt: skip
    day = report.start.date().isoformat()
    return Response(
        out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="netmap-iot-report-{day}.csv"'},
    )


@router.put("/api/devices/{mac}/sites/{site}/expected", response_model=Verdict)
def set_expected(
    mac: Mac,
    site: Annotated[str, Path(max_length=253)],
    verdict: Annotated[Verdict, Body()],
    db: DB,
) -> Verdict:
    """Mark a site as expected, or not, for the device (null clears it). Kept in the
    device's baseline."""
    device = get_device(db, mac)
    site = site.lower()
    now = datetime.now(UTC)
    stmt = insert(DeviceBaseline).values(
        mac=device.mac, key_type="domain", key=site, hits=0, expected=verdict.expected,
        first_seen=now, last_seen=now,
    )  # fmt: skip
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=[DeviceBaseline.mac, DeviceBaseline.key_type, DeviceBaseline.key],
            set_={"expected": stmt.excluded.expected},
        )
    )
    db.commit()
    return verdict
