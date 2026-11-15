"""Packet captures of one device, asked for in the UI (api/captures.py) and run here with
tcpdump on the SPAN interface.

Each capture is a ring of RING_FILES files in NETMAP_CAPTURES_DIR: when the ring is full the
oldest file is overwritten, so a capture never takes more than its size limit and holds the
latest packets. It ends at its time limit, or when someone presses Stop (the API sets
``ended_at``). Only the newest NETMAP_PCAP_KEEP captures' files are kept.
"""

import logging
import re
import shutil
import signal
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from netmap.db.models import PacketCapture

log = logging.getLogger(__name__)

RING_FILES = 4
PCAP_HEADER = 24  # the global header at the start of every classic pcap file


def ring_files(directory: Path, capture_id: int) -> list[Path]:
    """A capture's files, oldest first."""
    files = [p for p in directory.glob(f"capture-{capture_id}.pcap*") if p.is_file()]
    return sorted(files, key=lambda p: (p.stat().st_mtime, p.name))


def ring_bytes(directory: Path, capture_id: int) -> int:
    return sum(p.stat().st_size for p in ring_files(directory, capture_id))


def merged(files: list[Path], chunk: int = 1 << 20):
    """One pcap from a ring's files: the first whole, the rest without their headers.
    tcpdump starts each file whole, so they concatenate cleanly."""
    for n, path in enumerate(files):
        with path.open("rb") as f:
            if n:
                f.seek(PCAP_HEADER)
            while block := f.read(chunk):
                yield block


def tcpdump_command(binary: str, iface: str, mac: str, path: Path, max_bytes: int) -> list[str]:
    # -C is in kilobytes with a "k" suffix (tcpdump 4.99+), so small limits hold too.
    file_kb = max(1, max_bytes // RING_FILES // 1000)
    return [
        binary, "-i", iface, "-n", "-U", "-s", "0", "-w", str(path),
        "-C", f"{file_kb}k", "-W", str(RING_FILES), "ether", "host", mac,
    ]  # fmt: skip


_CAPTURED = re.compile(r"(\d+) packets? captured")


class Captures:
    """Starts, watches and ends captures; call ``tick`` every few seconds."""

    def __init__(
        self,
        iface: str,
        directory: Path,
        keep: int,
        binary: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.iface = iface
        self.directory = directory
        self.keep = keep
        self.binary = binary or shutil.which("tcpdump") or "tcpdump"
        self.clock = clock
        self.running: dict[int, subprocess.Popen] = {}

    def recover(self, session: Session) -> None:
        """Captures left running by a previous run of the service end now. Commits."""
        session.execute(
            update(PacketCapture)
            .where(PacketCapture.status == "running")
            .values(status="stopped", ended_at=self.clock(), error="the capture service restarted")
        )
        session.commit()

    def tick(self, session: Session) -> None:
        now = self.clock()
        for c in session.scalars(
            select(PacketCapture).where(PacketCapture.status.in_(("pending", "running")))
        ).all():
            if c.status == "pending":
                self._start(c, now)
            else:
                self._watch(c, now)
        session.commit()
        self._prune(session)

    def stop_all(self, session: Session) -> None:
        for c in session.scalars(
            select(PacketCapture).where(PacketCapture.status == "running")
        ).all():
            self._finish(c, self.clock(), "stopped", "the capture service stopped")
        session.commit()

    def _start(self, c: PacketCapture, now: datetime) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"capture-{c.id}.pcap"
        cmd = tcpdump_command(self.binary, self.iface, str(c.mac), path, c.max_bytes)
        try:
            self.running[c.id] = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
            )
        except OSError as exc:
            c.status, c.ended_at, c.error = "failed", now, f"couldn't run tcpdump: {exc}"
            return
        c.status, c.started_at = "running", now
        log.info("capture %d: %s on %s", c.id, c.mac, self.iface)

    def _watch(self, c: PacketCapture, now: datetime) -> None:
        proc = self.running.get(c.id)
        if proc is None:  # not ours (we restarted); recover() handles those
            return
        c.bytes = ring_bytes(self.directory, c.id)
        if proc.poll() is not None:
            # tcpdump quit by itself: a bad interface, no permission, ...
            err = (proc.stderr.read() if proc.stderr else "").strip()
            self._finish(c, now, "failed", _last_line(err) or f"tcpdump exited {proc.returncode}")
        elif c.ended_at is not None:
            self._finish(c, now, "stopped")
        elif c.started_at and now >= c.started_at + timedelta(seconds=c.max_seconds):
            self._finish(c, now, "done")

    def _finish(self, c: PacketCapture, now: datetime, status: str, error: str | None = None):
        proc = self.running.pop(c.id, None)
        if proc is not None:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)  # tcpdump flushes and prints its counts
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            out = proc.stderr.read() if proc.stderr else ""
            if m := _CAPTURED.search(out):
                c.packets = int(m.group(1))
        c.status, c.ended_at = status, c.ended_at or now
        c.error = error if status == "failed" or error else c.error
        c.bytes = ring_bytes(self.directory, c.id)
        log.info("capture %d: %s, %d bytes", c.id, status, c.bytes)

    def _prune(self, session: Session) -> None:
        """Delete the files of finished captures older than the newest ``keep``."""
        ids = session.scalars(
            select(PacketCapture.id)
            .where(PacketCapture.status.notin_(("pending", "running")))
            .order_by(PacketCapture.id.desc())
            .offset(self.keep)
        ).all()
        for capture_id in ids:
            for path in ring_files(self.directory, capture_id):
                path.unlink(missing_ok=True)


def _last_line(text: str) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""
