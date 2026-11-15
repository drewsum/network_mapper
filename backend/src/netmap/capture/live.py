"""Live throughput: bytes per device per second, published with Postgres NOTIFY on
``netmap_live`` every few seconds, for the API's WebSocket (api/live.py) to pass on."""

import json
import time
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from netmap.capture.flows import Row

CHANNEL = "netmap_live"
# NOTIFY payloads must stay under 8000 bytes; this many devices fit comfortably.
MAX_DEVICES = 120


class Meter:
    """Bytes per device since the last report."""

    def __init__(self) -> None:
        self.bytes: dict[str, list[int]] = {}
        self.since = time.monotonic()

    def add(self, rows: list[Row]) -> None:
        for r in rows:
            up_down = self.bytes.setdefault(r.mac, [0, 0])
            up_down[0] += r.bytes_up
            up_down[1] += r.bytes_down

    def report(self, now: datetime | None = None) -> dict:
        """{"time", "seconds", "devices": {mac: [up, down] bytes/second}}, busiest first;
        starts the next span."""
        elapsed = max(1e-3, time.monotonic() - self.since)
        busiest = sorted(self.bytes.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
        devices = {
            mac: [round(up / elapsed), round(down / elapsed)]
            for mac, (up, down) in busiest[:MAX_DEVICES]
        }
        self.bytes, self.since = {}, time.monotonic()
        return {
            "time": (now or datetime.now(UTC)).isoformat(),
            "seconds": round(elapsed, 1),
            "devices": devices,
        }


def publish(session: Session, report: dict) -> None:
    session.execute(text("SELECT pg_notify(:c, :p)"), {"c": CHANNEL, "p": json.dumps(report)})
    session.commit()
