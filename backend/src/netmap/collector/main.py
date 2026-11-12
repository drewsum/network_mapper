import asyncio
import contextlib
import logging
import signal
import time
from pathlib import Path

from netmap.collector.base import Source
from netmap.config import Settings

log = logging.getLogger(__name__)

# Sources register here as milestones land (M1 discovery, M2 Pi-hole, ...).
SOURCE_TYPES: list[type[Source]] = []


async def _loop(source: Source, stop: asyncio.Event) -> None:
    while not stop.is_set():
        started = time.monotonic()
        try:
            await source.run_once()
        except Exception:
            log.exception("source %s failed", source.name)
        delay = max(0.0, source.interval_seconds - (time.monotonic() - started))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=delay)


async def _heartbeat(settings: Settings, stop: asyncio.Event) -> None:
    path = Path(settings.collector_heartbeat_file)
    while not stop.is_set():
        path.write_text(str(time.time()))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=settings.collector_tick_seconds)


async def run(settings: Settings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows
            loop.add_signal_handler(sig, stop.set)

    sources = [cls(settings) for cls in SOURCE_TYPES]
    active = [s for s in sources if s.enabled()]
    for s in sources:
        log.info("source %s: %s", s.name, "enabled" if s in active else "disabled")
    if not active:
        log.info("no sources enabled yet; collector is idling")

    async with asyncio.TaskGroup() as tg:
        tg.create_task(_heartbeat(settings, stop))
        for s in active:
            tg.create_task(_loop(s, stop))
    log.info("collector stopped")
