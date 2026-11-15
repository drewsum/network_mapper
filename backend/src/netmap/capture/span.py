"""Flows from a SPAN mirror port, metered by nfstream (nDPI) on NETMAP_CAPTURE_INTERFACE.

nfstream reports a flow when it ends, goes idle, or has run for NETMAP_CAPTURE_REPORT_SECONDS
(its active timeout), so a long download shows up in pieces that add up. It names the
application (nDPI) and the server the client asked for (TLS SNI, HTTP Host, ...). Packets
the kernel dropped before nfstream saw them are counted from its performance report.
See docs/span.md for setting up the mirror port.
"""

import contextlib
import logging
import queue
import threading
from collections import OrderedDict
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from netmap.capture.flows import Observation, protocol_name

log = logging.getLogger(__name__)

CONNECTION_CACHE = 50_000  # connections remembered


class Stats:
    """nfstream's counters, from its performance report (all since it started)."""

    def __init__(self) -> None:
        self.processed = 0
        self.ignored = 0
        self.dropped = 0
        self.flows = 0

    def as_dict(self) -> dict:
        return {
            "packets": self.processed,
            "ignored": self.ignored,
            "dropped": self.dropped,
            "flows": self.flows,
        }


def interface_counters(iface: str) -> dict[str, int]:
    """The NIC's own receive counters (/sys/class/net), which count drops before the
    kernel's capture buffer: missed (the NIC's ring overflowed) and dropped."""
    base = Path("/sys/class/net") / iface / "statistics"
    out = {}
    for name in ("rx_packets", "rx_bytes", "rx_dropped", "rx_missed_errors"):
        with contextlib.suppress(OSError, ValueError):
            out[name] = int((base / name).read_text())
    return out


def observation(flow) -> Observation:
    """An nfstream NFlow as an Observation. ``src`` is the side that sent first."""
    return Observation(
        time=datetime.fromtimestamp(flow.bidirectional_last_seen_ms / 1000, UTC),
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=protocol_name(flow.protocol),
        bytes_out=flow.src2dst_bytes,
        bytes_in=flow.dst2src_bytes,
        packets=flow.bidirectional_packets,
        src_mac=flow.src_mac or None,
        dst_mac=flow.dst_mac or None,
        app=_app(flow.application_name),
        sni=flow.requested_server_name or None,
    )


def _app(name: str | None) -> str | None:
    """nDPI's "TLS.YouTube" is YouTube over TLS; keep the most specific part."""
    if not name or name == "Unknown":
        return None
    return name.rsplit(".", 1)[-1]


class Connections:
    """What each connection's first report said: who opened it, the application, the
    server name. nfstream starts a fresh flow after each active timeout, taking whoever
    sends next for the client (often the server, mid-download), and nDPI guesses again
    without the handshake (a download's later pieces come back as "Protobuf"). Later
    pieces are turned back the first one's way round and keep its labels."""

    def __init__(self, size: int = CONNECTION_CACHE) -> None:
        self.size = size
        self.seen: OrderedDict[tuple, Observation] = OrderedDict()

    @staticmethod
    def _key(obs: Observation) -> tuple:
        ends = sorted([(obs.src_ip, obs.src_port), (obs.dst_ip, obs.dst_port)])
        return (*ends, obs.protocol)

    def apply(self, obs: Observation) -> Observation:
        key = self._key(obs)
        first = self.seen.get(key)
        if first is None:
            self.seen[key] = obs
            if len(self.seen) > self.size:
                self.seen.popitem(last=False)
            return obs
        self.seen.move_to_end(key)
        if (obs.src_ip, obs.src_port) != (first.src_ip, first.src_port):
            obs = replace(
                obs, src_ip=obs.dst_ip, dst_ip=obs.src_ip, src_port=obs.dst_port,
                dst_port=obs.src_port, src_mac=obs.dst_mac, dst_mac=obs.src_mac,
                bytes_out=obs.bytes_in, bytes_in=obs.bytes_out,
            )  # fmt: skip
        if first.app is None and first.sni is None:  # the first learned nothing; maybe this did
            self.seen[key] = replace(first, app=obs.app, sni=obs.sni)
            return obs
        return replace(obs, app=first.app or obs.app, sni=first.sni or obs.sni)


class SpanCapture:
    """Runs nfstream in a thread, putting Observations on ``out``."""

    def __init__(self, source: str, report_seconds: int, out: queue.Queue) -> None:
        self.source = source  # an interface, or a pcap file (tests, replays)
        self.report_seconds = report_seconds
        self.out = out
        self.stats = Stats()
        self.error: str | None = None
        self.thread = threading.Thread(target=self._run, name="nfstream", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _streamer(self):
        import nfstream.streamer
        from nfstream import NFStreamer

        stats = self.stats

        def performance(performances, is_linux, flows_count):
            # Replaces nfstream's report, which prints these instead.
            stats.flows = flows_count.value
            stats.processed = sum(m[1].value for m in performances)
            if is_linux:
                stats.dropped = sum(m[0].value for m in performances)
                stats.ignored = sum(m[2].value for m in performances)
            else:
                stats.dropped = max((m[0].value for m in performances), default=0)
                stats.ignored = max((m[2].value for m in performances), default=0)

        nfstream.streamer.update_performances = performance
        return NFStreamer(
            source=self.source,
            decode_tunnels=True,
            promiscuous_mode=True,
            idle_timeout=self.report_seconds,
            active_timeout=self.report_seconds,
            n_dissections=20,
            statistical_analysis=False,
            n_meters=1,
            performance_report=self.report_seconds,
        )

    def _run(self) -> None:
        try:
            connections = Connections()
            for flow in self._streamer():
                self.out.put(connections.apply(observation(flow)))
        except Exception as exc:  # a missing interface, no permission, ...
            self.error = str(exc) or type(exc).__name__
            log.exception("nfstream stopped")
        else:
            self.error = self.error or "nfstream stopped"
