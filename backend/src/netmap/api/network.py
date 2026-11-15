"""The network map: every device, whether it's online, and how much DNS (and, with traffic
capture, how many bytes) it did lately."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select, text

from netmap.api.deps import DB
from netmap.collector.dns import VISIBILITY_CHECK
from netmap.collector.inventory import known_addresses
from netmap.db.models import Device, HealthCheck

router = APIRouter()


class MapDevice(BaseModel):
    mac: str
    label: str | None
    hostname: str | None
    vendor: str | None
    category: str
    online: bool
    ip: str | None
    queries: int  # DNS lookups in the window
    blocked: int
    bytes_up: int = 0  # captured traffic in the window
    bytes_down: int = 0


class NetworkMap(BaseModel):
    since: datetime  # start of the activity window
    router: str | None  # the router's MAC, when the default gateway is a known device
    captured: bool  # traffic capture is on: some traffic was captured in the window
    devices: list[MapDevice]


_ACTIVITY = text("""
    SELECT mac::text, count(*), count(*) FILTER (WHERE status = 'blocked')
    FROM dns_queries WHERE time >= :since AND mac IS NOT NULL
    GROUP BY mac
""")
_BYTES = text("""
    SELECT mac::text, sum(bytes_up)::bigint, sum(bytes_down)::bigint
    FROM flows WHERE time >= :since GROUP BY mac
""")


@router.get("/api/map", response_model=NetworkMap)
def network_map(db: DB, minutes: Annotated[int, Query(ge=1, le=1440)] = 60) -> NetworkMap:
    """Every device (merged ones left out), with its DNS lookups in the last ``minutes``.
    The router is the default gateway the Pi-hole visibility check last saw."""
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    activity = {mac: (q, b) for mac, q, b in db.execute(_ACTIVITY, {"since": since})}
    traffic = {mac: (u, d) for mac, u, d in db.execute(_BYTES, {"since": since})}
    ips = known_addresses(db)
    details = db.scalar(select(HealthCheck.details).where(HealthCheck.name == VISIBILITY_CHECK))
    router_ip = (details or {}).get("router_ip")
    devices = []
    router_mac = None
    for d in db.scalars(select(Device).where(Device.merged_into.is_(None))):
        mac = str(d.mac)
        ip = ips.get(d.mac)
        if router_ip and ip == router_ip:
            router_mac = mac
        queries, blocked = activity.get(mac, (0, 0))
        up, down = traffic.get(mac, (0, 0))
        devices.append(
            MapDevice(
                mac=mac,
                label=d.label,
                hostname=d.hostname,
                vendor=d.vendor,
                category=d.category,
                online=d.online,
                ip=ip,
                queries=queries,
                blocked=blocked,
                bytes_up=up,
                bytes_down=down,
            )
        )
    return NetworkMap(since=since, router=router_mac, captured=bool(traffic), devices=devices)
