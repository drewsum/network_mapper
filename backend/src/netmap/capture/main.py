"""`netmap capture`: runs whichever capture sources are configured, writes their flows
every NETMAP_CAPTURE_REPORT_SECONDS, publishes live throughput, runs packet captures, and
reports how capture is going as the "capture" check (System page and /metrics)."""

import asyncio
import contextlib
import logging
import queue
import signal
import time
from datetime import UTC, datetime
from pathlib import Path

from netmap.capture.flows import Buckets, Lan, Observation, load_lan, rows_for, write_rows
from netmap.capture.live import Meter, publish
from netmap.capture.netflow import NetflowListener
from netmap.capture.pcap import Captures
from netmap.capture.span import SpanCapture, interface_counters
from netmap.collector.dns import CheckResult, record_check
from netmap.config import Settings
from netmap.db import get_sessionmaker

log = logging.getLogger(__name__)

CHECK = "capture"
HEARTBEAT = "/tmp/netmap-capture-heartbeat"
LAN_REFRESH_SECONDS = 60
CHECK_SECONDS = 60
PCAP_TICK_SECONDS = 2
# Over this share of packets dropped in a minute, the check warns.
DROP_WARNING = 0.01


class Capture:
    """The configured sources and what they've produced."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.queue: queue.Queue[tuple[str, Observation]] = queue.Queue()
        self.span: SpanCapture | None = None
        self.netflow: NetflowListener | None = None
        self.captures: Captures | None = None
        self.buckets = Buckets()
        self.meter = Meter()
        self.lan: Lan | None = None
        self.lan_at = 0.0
        self.written = 0  # rows since the last check
        self.last: dict = {}  # counters at the last check

    @property
    def enabled(self) -> bool:
        return bool(self.settings.capture_interface or self.settings.netflow_port)

    async def start(self) -> None:
        s = self.settings
        if s.capture_interface:
            out = _Tagged(self.queue, "nfstream")
            self.span = SpanCapture(s.capture_interface, s.capture_report_seconds, out)
            self.span.start()
            self.captures = Captures(s.capture_interface, Path(s.captures_dir), s.pcap_keep)
            await asyncio.to_thread(self._with_session, self.captures.recover)
            log.info("capture: nfstream on %s", s.capture_interface)
        if s.netflow_port:
            self.netflow = NetflowListener(
                s.netflow_bind, s.netflow_port, _Tagged(self.queue, "netflow")
            )
            await self.netflow.start()

    def _with_session(self, fn) -> None:
        with get_sessionmaker()() as session:
            fn(session)

    def flush(self) -> int:
        """Write what the sources reported since the last flush; publish live rates."""
        observed: list[tuple[str, Observation]] = []
        with contextlib.suppress(queue.Empty):
            while True:
                observed.append(self.queue.get_nowait())
        with get_sessionmaker()() as session:
            if self.lan is None or time.monotonic() - self.lan_at > LAN_REFRESH_SECONDS:
                self.lan = load_lan(session, self.settings.require("lan_cidr"))
                self.lan_at = time.monotonic()
            for source, obs in observed:
                rows = rows_for(obs, self.lan, source)
                self.buckets.add(rows)
                self.meter.add(rows)
            written = write_rows(session, self.buckets.drain())
            publish(session, self.meter.report())
        self.written += written
        return written

    def check(self, now: datetime) -> CheckResult:
        details: dict = {"rows_written": self.written}
        problems, parts = [], []
        if self.span:
            stats = self.span.stats.as_dict()
            nic = interface_counters(self.span.source)
            details["span"] = {"interface": self.span.source, **stats, "nic": nic}
            last = self.last.get("span", {})
            packets = stats["packets"] - last.get("packets", 0)
            dropped = stats["dropped"] - last.get("dropped", 0)
            dropped += nic.get("rx_missed_errors", 0) - last.get("missed", 0)
            self.last["span"] = {
                "packets": stats["packets"],
                "dropped": stats["dropped"],
                "missed": nic.get("rx_missed_errors", 0),
            }
            if self.span.error:
                problems.append(f"nfstream on {self.span.source} stopped: {self.span.error}")
            elif packets + dropped and dropped / (packets + dropped) > DROP_WARNING:
                problems.append(
                    f"{dropped:,} of {packets + dropped:,} packets on {self.span.source} were "
                    "dropped in the last minute; the host can't keep up with the mirror port"
                )
            parts.append(f"{packets:,} packets on {self.span.source} ({dropped:,} dropped)")
        if self.netflow:
            stats = self.netflow.stats.as_dict()
            details["netflow"] = stats
            records = stats["records"] - self.last.get("records", 0)
            self.last["records"] = stats["records"]
            parts.append(f"{records:,} NetFlow/IPFIX records")
            if stats["records"] == 0 and stats["dropped_no_template"]:
                problems.append("NetFlow records are arriving but no templates yet")
        self.written = 0
        if problems:
            return CheckResult("warning", "; ".join(problems), details)
        return CheckResult("ok", "In the last minute: " + ", ".join(parts) + ".", details)


class _Tagged:
    """A queue view that tags each Observation with its source."""

    def __init__(self, q: queue.Queue, source: str) -> None:
        self.q, self.source = q, source

    def put(self, obs: Observation) -> None:
        self.q.put((self.source, obs))


async def _every(seconds: float, stop: asyncio.Event, fn) -> None:
    while not stop.is_set():
        try:
            await asyncio.to_thread(fn)
        except Exception:
            log.exception("capture: %s failed", getattr(fn, "__name__", fn))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=seconds)


async def run(settings: Settings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows
            loop.add_signal_handler(sig, stop.set)

    capture = Capture(settings)
    heartbeat = Path(HEARTBEAT)

    def beat() -> None:
        heartbeat.write_text(str(time.time()))

    if not capture.enabled:
        log.info(
            "capture: nothing to do; set NETMAP_CAPTURE_INTERFACE (a SPAN port) and/or "
            "NETMAP_NETFLOW_PORT (see docs/span.md)"
        )
        await _every(settings.collector_tick_seconds, stop, beat)
        return

    settings.require("lan_cidr")
    await capture.start()

    def check() -> None:
        now = datetime.now(UTC)
        with get_sessionmaker()() as session:
            record_check(session, CHECK, capture.check(now), now)

    def pcap() -> None:
        if capture.captures:
            capture._with_session(capture.captures.tick)

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(_every(settings.collector_tick_seconds, stop, beat))
            tg.create_task(_every(settings.capture_report_seconds, stop, capture.flush))
            tg.create_task(_every(CHECK_SECONDS, stop, check))
            if capture.captures:
                tg.create_task(_every(PCAP_TICK_SECONDS, stop, pcap))
    finally:
        if capture.netflow:
            capture.netflow.close()
        if capture.captures:
            capture._with_session(capture.captures.stop_all)
        capture.flush()
    log.info("capture stopped")
