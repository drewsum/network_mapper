"""Collector data sources.

Each source (ARP discovery, Pi-hole poller, later SPAN capture, ...) is a ``Source``
the collector runs on its own interval. Sources decide from settings whether they're
enabled, so a missing env var disables a source instead of crashing the collector.
"""

from abc import ABC, abstractmethod

from netmap.config import Settings


class Source(ABC):
    name: str
    interval_seconds: float

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def enabled(self) -> bool:
        return True

    @abstractmethod
    async def run_once(self) -> None: ...

    async def close(self) -> None:  # noqa: B027 - optional hook, a no-op by default
        """Release outside resources (like an API session) when the collector stops."""
