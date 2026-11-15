"""Data export: each table worth keeping, as CSV or JSON, for spreadsheets and other tools.

``days`` limits the tables that grow over time (events, alerts, daily DNS lookups) to the
last N days; the rest are exported whole. Merged devices are included, with ``merged_into``
naming the device they were folded into.
"""

import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import text

from netmap.api.deps import DB

router = APIRouter()


@dataclass(frozen=True)
class Dataset:
    label: str
    sql: str
    # The column ``days`` filters on, for tables that grow over time.
    time_column: str | None = None
    order: str = ""


DATASETS = {
    "devices": Dataset(
        "Devices",
        "SELECT CAST(mac AS text) AS mac, label, hostname, hostname_source, vendor, category,"
        " is_iot, is_randomized_mac, online, notes, CAST(merged_into AS text) AS merged_into,"
        " first_seen, last_seen, ports_scanned_at FROM devices",
        order="first_seen",
    ),
    "addresses": Dataset(
        "IP addresses",
        "SELECT CAST(mac AS text) AS mac, host(ip) AS ip, first_seen, last_seen FROM device_ips",
        order="mac, first_seen",
    ),
    "ports": Dataset(
        "Open ports",
        "SELECT CAST(mac AS text) AS mac, port, protocol, service, banner, open, first_seen,"
        " last_seen FROM ports",
        order="mac, protocol, port",
    ),
    "upnp": Dataset(
        "UPnP port forwards",
        "SELECT external_port, protocol, host(internal_ip) AS internal_ip, internal_port,"
        " description, CAST(mac AS text) AS mac, active, first_seen, last_seen"
        " FROM upnp_mappings",
        order="external_port, protocol",
    ),
    "events": Dataset(
        "Device events",
        "SELECT time, CAST(mac AS text) AS mac, kind, host(ip) AS ip, port, protocol, details"
        " FROM device_events",
        time_column="time",
        order="time, id",
    ),
    "alerts": Dataset(
        "Alerts",
        "SELECT time, CAST(mac AS text) AS mac, kind, severity, message, details,"
        " acknowledged_at, notify, notified_at FROM alerts",
        time_column="time",
        order="time, id",
    ),
    "dns_daily": Dataset(
        "DNS lookups per day",
        "SELECT bucket AS day, CAST(mac AS text) AS mac, domain, queries, blocked"
        " FROM dns_activity_1d",
        time_column="bucket",
        order="bucket, mac, domain",
    ),
}

Name = Literal["devices", "addresses", "ports", "upnp", "events", "alerts", "dns_daily"]


class DatasetOut(BaseModel):
    name: str
    label: str
    by_time: bool


@router.get("/api/export", response_model=list[DatasetOut])
def list_datasets() -> list[DatasetOut]:
    """What can be exported."""
    return [
        DatasetOut(name=name, label=d.label, by_time=d.time_column is not None)
        for name, d in DATASETS.items()
    ]


def _rows(db: DB, dataset: Dataset, days: int | None) -> tuple[list[str], list[dict]]:
    sql, params = dataset.sql, {}
    if days is not None and dataset.time_column:
        sql += f" WHERE {dataset.time_column} >= :since"
        params["since"] = datetime.now(UTC) - timedelta(days=days)
    if dataset.order:
        sql += f" ORDER BY {dataset.order}"
    result = db.execute(text(sql), params)
    return list(result.keys()), [dict(r) for r in result.mappings()]


def _cell(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"))
    return value


@router.get("/api/export/{name}.{fmt}")
def export(
    name: Name,
    fmt: Literal["csv", "json"],
    db: DB,
    days: Annotated[int | None, Query(ge=1)] = None,
) -> Response:
    """One dataset as a CSV or JSON download."""
    columns, rows = _rows(db, DATASETS[name], days)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    filename = f"netmap-{name.replace('_', '-')}-{stamp}.{fmt}"
    if fmt == "json":
        body = json.dumps(jsonable_encoder(rows), indent=1)
        media = "application/json"
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(columns)
        writer.writerows([_cell(r[c]) for c in columns] for r in rows)
        body, media = out.getvalue(), "text/csv"
    disposition = f'attachment; filename="{filename}"'
    return Response(body, media_type=media, headers={"Content-Disposition": disposition})
