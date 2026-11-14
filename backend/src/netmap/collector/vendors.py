"""Keeps the oui_vendors table current and device vendors resolved from it.

On first run the table is filled from the bundled snapshot, so vendors show up without
internet access. After that the IEEE registries are downloaded whenever the loaded copy
is older than oui_refresh_days; a failed download keeps the current copy and is retried
on the next check.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from netmap import oui
from netmap.collector.base import Source
from netmap.collector.inventory import apply_vendors
from netmap.db import get_sessionmaker
from netmap.db.models import OuiVendor

log = logging.getLogger(__name__)

# How often to check whether the registry is due for a refresh.
CHECK_INTERVAL = 3600.0


def replace_vendors(session: Session, entries: dict[str, str], loaded_at: datetime | None) -> None:
    """Swap the whole registry for ``entries`` and re-resolve every device. Commits."""
    session.execute(delete(OuiVendor))
    session.execute(
        insert(OuiVendor),
        [{"prefix": p, "vendor": v, "loaded_at": loaded_at} for p, v in entries.items()],
    )
    apply_vendors(session)
    session.commit()


class OuiSource(Source):
    name = "oui"
    interval_seconds = CHECK_INTERVAL

    async def run_once(self) -> None:
        await asyncio.to_thread(self._refresh)

    def _refresh(self) -> None:
        refresh_after = timedelta(days=self.settings.oui_refresh_days)
        with get_sessionmaker()() as session:
            count, newest = session.execute(
                select(func.count(), func.max(OuiVendor.loaded_at))
            ).one()
            if count == 0:
                entries = oui.read_bundle()
                replace_vendors(session, entries, loaded_at=None)
                log.info("oui: loaded %d prefixes from the bundled snapshot", len(entries))
            now = datetime.now(UTC)
            if newest is not None and newest > now - refresh_after:
                return
            try:
                entries = oui.download()
            except OSError as exc:  # URLError and timeouts are OSErrors
                log.warning("oui: IEEE download failed, keeping current data: %s", exc)
                return
            replace_vendors(session, entries, loaded_at=now)
            log.info("oui: refreshed %d prefixes from the IEEE", len(entries))
