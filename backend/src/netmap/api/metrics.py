"""Prometheus metrics at /metrics (text exposition format), read from the database at
scrape time. deploy/grafana/netmap-dashboard.json is a dashboard for them.

Access: with NETMAP_METRICS_TOKEN set, Prometheus sends it as a bearer token
(``authorization: {credentials: ...}`` in its scrape config). Otherwise /metrics needs a
login like the API, or is open when no admin password is set.

Windowed values ("_5m") are gauges over the last 5 minutes: the database keeps a rolling
window of history, so there are no counters that only go up.
"""

import hmac
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from netmap import __version__
from netmap.api import auth
from netmap.api.deps import DB
from netmap.config import get_settings

router = APIRouter()
WINDOW = timedelta(minutes=5)


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Exposition:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.declared: set[str] = set()

    def add(self, metric: str, kind: str, help_: str, value: float, /, **labels) -> None:
        if metric not in self.declared:
            self.lines += [f"# HELP {metric} {help_}", f"# TYPE {metric} {kind}"]
            self.declared.add(metric)
        label = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items() if v is not None)
        self.lines.append(f"{metric}{{{label}}} {value:g}" if label else f"{metric} {value:g}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


_NAME = "coalesce(dv.label, dv.hostname, dv.vendor || ' device', dv.mac::text)"


def collect(db: Session, now: datetime) -> str:
    m = Exposition()
    m.add("netmap_info", "gauge", "netmap version.", 1, version=__version__)
    since = now - WINDOW

    devices = db.execute(
        text(f"""
            SELECT dv.mac::text, {_NAME}, dv.category, dv.online, dv.critical, dv.last_seen
            FROM devices dv WHERE dv.merged_into IS NULL ORDER BY dv.mac
        """)
    ).all()
    online = sum(1 for d in devices if d[3])
    m.add("netmap_devices", "gauge", "Devices known, by state.", online, state="online")
    m.add("netmap_devices", "gauge", "Devices known, by state.", len(devices) - online,
          state="offline")  # fmt: skip
    names = {}
    for mac, name, category, is_online, critical, last_seen in devices:
        names[mac] = name
        labels = {"mac": mac, "name": name, "category": category}
        m.add("netmap_device_online", "gauge", "1 if the device is online.", int(is_online),
              critical=str(critical).lower(), **labels)  # fmt: skip
        m.add("netmap_device_last_seen_timestamp_seconds", "gauge",
              "When the device was last heard from.", last_seen.timestamp(), **labels)  # fmt: skip

    for mac, status, n in db.execute(
        text("""
            SELECT mac::text, status, count(*) FROM dns_queries
            WHERE time >= :since AND mac IS NOT NULL GROUP BY 1, 2
        """),
        {"since": since},
    ):
        m.add("netmap_dns_queries_5m", "gauge", "DNS lookups in the last 5 minutes.", n,
              mac=mac, name=names.get(mac, mac), status=status)  # fmt: skip

    for mac, up, down in db.execute(
        text("""
            SELECT mac::text, sum(bytes_up)::bigint, sum(bytes_down)::bigint FROM flows
            WHERE time >= :since GROUP BY 1
        """),
        {"since": since},
    ):
        for direction, value in (("up", up), ("down", down)):
            m.add("netmap_traffic_bytes_5m", "gauge",
                  "Captured bytes in the last 5 minutes (up: sent by the device).", value,
                  mac=mac, name=names.get(mac, mac), direction=direction)  # fmt: skip

    for severity, n in db.execute(
        text("SELECT severity, count(*) FROM alerts WHERE acknowledged_at IS NULL GROUP BY 1")
    ):
        m.add("netmap_alerts_open", "gauge", "Alerts not yet acknowledged.", n, severity=severity)
    for kind, n in db.execute(
        text("SELECT kind, count(*) FROM alerts WHERE time >= :d GROUP BY 1"),
        {"d": now - timedelta(hours=24)},
    ):
        m.add("netmap_alerts_24h", "gauge", "Alerts raised in the last 24 hours.", n, kind=kind)

    for name, status, checked_at, details in db.execute(
        text("SELECT name, status, checked_at, details FROM health_checks ORDER BY name")
    ):
        m.add("netmap_check_ok", "gauge", "1 if the self-check passed.", int(status == "ok"),
              check=name)  # fmt: skip
        m.add("netmap_check_timestamp_seconds", "gauge", "When the self-check last ran.",
              checked_at.timestamp(), check=name)  # fmt: skip
        details = details or {}
        if name == "backup" and status == "ok":
            m.add("netmap_backup_last_success_timestamp_seconds", "gauge",
                  "When the last backup finished.", checked_at.timestamp())  # fmt: skip
            m.add("netmap_backup_bytes", "gauge", "Size of the latest backup.",
                  details.get("bytes", 0))  # fmt: skip
        if name == "capture":
            span = details.get("span") or {}
            for key, help_ in (("packets", "Packets nfstream processed."),
                               ("dropped", "Packets the kernel dropped before nfstream."),
                               ("flows", "Flows nfstream reported.")):  # fmt: skip
                if key in span:
                    m.add(f"netmap_capture_{key}_total", "counter",
                          help_ + " Since the capture service started.", span[key],
                          interface=span.get("interface"))  # fmt: skip
            nic = span.get("nic") or {}
            if "rx_missed_errors" in nic:
                m.add("netmap_capture_nic_missed_total", "counter",
                      "Packets the mirror NIC missed (its ring was full).",
                      nic["rx_missed_errors"], interface=span.get("interface"))  # fmt: skip
            if "netflow" in details:
                m.add("netmap_netflow_records_total", "counter",
                      "NetFlow/IPFIX records received since the capture service started.",
                      details["netflow"].get("records", 0))  # fmt: skip

    for mac, ap, signal in db.execute(
        text("SELECT mac::text, ap_name, signal_dbm FROM wifi_clients WHERE connected")
    ):
        if signal is not None:
            m.add("netmap_wifi_signal_dbm", "gauge", "Wi-Fi signal strength.", signal, mac=mac,
                  name=names.get(mac, mac), ap=ap)  # fmt: skip
    return m.text()


def _authorized(request: Request) -> bool:
    settings = get_settings()
    header = request.headers.get("authorization", "")
    if settings.metrics_token:
        token = settings.metrics_token.get_secret_value()
        return hmac.compare_digest(header.encode(), f"Bearer {token}".encode())
    if not auth.auth_enabled(settings):
        return True
    return auth.token_valid(auth.signing_key(settings), request.cookies.get(auth.COOKIE))


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def metrics(request: Request, db: DB) -> PlainTextResponse:
    if not _authorized(request):
        raise HTTPException(401, "set NETMAP_METRICS_TOKEN and send it as a bearer token")
    return PlainTextResponse(
        collect(db, datetime.now(UTC)), media_type="text/plain; version=0.0.4; charset=utf-8"
    )
