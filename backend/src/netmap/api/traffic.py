"""Captured traffic in bytes (the ``flows`` table): over time and broken down by device,
remote end or application, network-wide or for one device. Empty until the capture
service runs (docs/span.md).

The timeline reads raw flows (1-minute buckets) for ranges up to 2 days, then the hourly
and daily aggregates. Breakdowns by remote end and application need raw flows, so they
reach back NETMAP_RAW_RETENTION_DAYS at most.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from netmap.api.deps import DB, MAC_PATTERN, Mac, get_device

router = APIRouter()

MAX_RANGE = timedelta(days=400)
Dimension = Literal["device", "remote", "app"]

_DIMENSIONS = {
    "device": (
        "f.mac::text",
        "coalesce(dv.label, dv.hostname, dv.vendor || ' device', f.mac::text)",
    ),
    "remote": ("coalesce(f.domain, host(f.remote_ip))", "coalesce(f.domain, host(f.remote_ip))"),
    "app": ("coalesce(f.app, '')", "coalesce(f.app, 'Unrecognized')"),
}


def _source(start: datetime, end: datetime) -> tuple[timedelta, str, str]:
    """(bucket, relation, its time column) for a range."""
    span = end - start
    if span <= timedelta(hours=3):
        return timedelta(minutes=1), "flows", "time"
    if span <= timedelta(days=2):
        return timedelta(minutes=15), "flows", "time"
    if span <= timedelta(days=14):
        return timedelta(hours=1), "flow_activity_1h", "bucket"
    return timedelta(days=1), "flow_activity_1d", "bucket"


class TrafficPoint(BaseModel):
    time: datetime
    bytes_up: int
    bytes_down: int


class TrafficRow(BaseModel):
    key: str
    label: str
    bytes_up: int
    bytes_down: int
    flows: int  # rows (device x remote end x minute), a rough measure of how busy


class Traffic(BaseModel):
    start: datetime
    end: datetime
    bucket_seconds: int
    source: str
    captured: bool  # any traffic was ever captured; false: the capture service isn't set up
    bytes_up: int
    bytes_down: int
    points: list[TrafficPoint]
    by: Dimension
    rows: list[TrafficRow]


def _range(start: datetime | None, end: datetime | None, default: timedelta):
    end = (end or datetime.now(UTC)).astimezone(UTC)
    start = (start or end - default).astimezone(UTC)
    if not start < end <= start + MAX_RANGE:
        raise HTTPException(422, f"start must be before end, at most {MAX_RANGE.days} days")
    return start, end


@router.get("/api/traffic", response_model=Traffic)
def traffic(
    db: DB,
    start: datetime | None = None,
    end: datetime | None = None,
    by: Dimension = "device",
    limit: Annotated[int, Query(ge=1, le=500)] = 25,
    mac: Annotated[str | None, Query(pattern=MAC_PATTERN)] = None,
) -> Traffic:
    """Bytes up (from devices) and down in [start, end) (default: the last 24 hours), over
    time and broken down ``by`` device, remote end or application; for one device with
    ``mac``."""
    start, end = _range(start, end, timedelta(hours=24))
    bucket, relation, column = _source(start, end)
    seconds = int(bucket.total_seconds())
    first = datetime.fromtimestamp(start.timestamp() // seconds * seconds, UTC)
    params: dict = {"first": first, "end": end, "bucket": bucket, "limit": limit}
    where = breakdown_where = ""
    if mac:
        params["mac"] = mac.lower()
        where = " AND mac = CAST(:mac AS macaddr)"
        breakdown_where = " AND f.mac = CAST(:mac AS macaddr)"

    points = [
        TrafficPoint(time=t, bytes_up=u, bytes_down=d)
        for t, u, d in db.execute(
            text(f"""
                WITH sums AS (
                    SELECT time_bucket(CAST(:bucket AS interval), {column}) AS t,
                           sum(bytes_up)::bigint AS up, sum(bytes_down)::bigint AS down
                    FROM {relation}
                    WHERE {column} >= :first AND {column} < :end{where}
                    GROUP BY 1
                )
                SELECT s.t, coalesce(x.up, 0), coalesce(x.down, 0)
                FROM generate_series(:first, CAST(:end AS timestamptz) - interval '1 microsecond',
                                     CAST(:bucket AS interval)) AS s(t)
                LEFT JOIN sums x ON x.t = s.t
                ORDER BY s.t
            """),
            params,
        )
    ]
    key, label = _DIMENSIONS[by]
    rows = [
        TrafficRow(key=k, label=lab, bytes_up=u, bytes_down=d, flows=n)
        for k, lab, u, d, n in db.execute(
            text(f"""
                SELECT {key} AS key, min({label}), sum(f.bytes_up)::bigint AS up,
                       sum(f.bytes_down)::bigint AS down, count(*)
                FROM flows f LEFT JOIN devices dv ON dv.mac = f.mac
                WHERE f.time >= :first AND f.time < :end{breakdown_where}
                GROUP BY 1 ORDER BY sum(f.bytes_up + f.bytes_down) DESC, 1 LIMIT :limit
            """),
            params,
        )
    ]
    captured = db.execute(text("SELECT 1 FROM flows LIMIT 1")).first() is not None
    return Traffic(
        start=first,
        end=end,
        bucket_seconds=seconds,
        source=relation,
        captured=captured,
        bytes_up=sum(p.bytes_up for p in points),
        bytes_down=sum(p.bytes_down for p in points),
        points=points,
        by=by,
        rows=rows,
    )


class RemoteOut(BaseModel):
    remote: str  # domain, or IP when there's no name
    ip: str
    port: int
    protocol: str
    app: str | None
    outbound: bool | None
    bytes_up: int
    bytes_down: int
    last: datetime


class DeviceTraffic(BaseModel):
    hours: int
    bytes_up: int
    bytes_down: int
    remotes: list[RemoteOut]  # busiest first


@router.get("/api/devices/{mac}/traffic", response_model=DeviceTraffic)
def device_traffic(
    mac: Mac, db: DB, hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24
) -> DeviceTraffic:
    """Where a device's traffic went in the last ``hours``: each remote end and port."""
    device = get_device(db, mac)
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        text("""
            SELECT coalesce(domain, host(remote_ip)), host(remote_ip), remote_port, protocol,
                   max(app), bool_or(outbound), sum(bytes_up)::bigint, sum(bytes_down)::bigint,
                   max(time)
            FROM flows WHERE mac = :mac AND time >= :since
            GROUP BY 1, 2, 3, 4
            ORDER BY sum(bytes_up + bytes_down) DESC LIMIT 50
        """),
        {"mac": device.mac, "since": since},
    ).all()
    totals = db.execute(
        text("""
            SELECT coalesce(sum(bytes_up), 0)::bigint, coalesce(sum(bytes_down), 0)::bigint
            FROM flows WHERE mac = :mac AND time >= :since
        """),
        {"mac": device.mac, "since": since},
    ).one()
    return DeviceTraffic(
        hours=hours,
        bytes_up=totals[0],
        bytes_down=totals[1],
        remotes=[
            RemoteOut(
                remote=r[0],
                ip=r[1],
                port=r[2],
                protocol=r[3],
                app=r[4],
                outbound=r[5],
                bytes_up=r[6],
                bytes_down=r[7],
                last=r[8],
            )
            for r in rows
        ],
    )
