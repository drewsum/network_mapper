"""Categorizes domains (netmap/categories.py) and matches them against threat blocklists
(netmap/blocklists.py).

Lists are downloaded when they're older than NETMAP_BLOCKLIST_REFRESH_HOURS (a day by
default) and kept in the database, so a restart doesn't download them again. A list
that fails to download keeps its last copy and is tried again in an hour. A domain is a
hit when it, or any IP it has resolved to, is on a list; domains Pi-hole blocks count as
hits on "pihole". Lists of malware URLs leave out popular sites, using the Tranco list
downloaded with them (see netmap/blocklists.py). How downloads are going shows on the
status bar as the "blocklists" check.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap import blocklists, categories
from netmap.collector.base import Source
from netmap.collector.dns import CheckResult, record_check
from netmap.collector.orgs import classifier
from netmap.db import get_sessionmaker
from netmap.db.models import Blocklist, BlocklistDomain, BlocklistNetwork, Domain

log = logging.getLogger(__name__)

BLOCKLIST_CHECK = "blocklists"
RETRY_AFTER = timedelta(hours=1)
BATCH = 10000

# Each domain's hits: its own name on a domain list, any IP it resolved to inside a
# listed network, and Pi-hole blocking it. Sorted, so unchanged rows compare equal.
_HITS = text("""
    SELECT domain, array_agg(DISTINCT list ORDER BY list) FROM (
        SELECT b.domain, b.list FROM blocklist_domains b JOIN domains d USING (domain)
        UNION ALL
        SELECT di.domain, n.list FROM domain_ips di
        JOIN blocklist_networks n ON di.ip <<= n.network
        UNION ALL
        SELECT domain, :pihole FROM domains WHERE pihole_blocked
    ) hits
    GROUP BY domain
""")


def store_list(session: Session, name: str, entries: blocklists.Entries, now: datetime) -> None:
    """Replace a list's entries. Commits."""
    session.execute(delete(BlocklistDomain).where(BlocklistDomain.list == name))
    session.execute(delete(BlocklistNetwork).where(BlocklistNetwork.list == name))
    domains = [{"list": name, "domain": d} for d in sorted(entries.domains)]
    networks = [{"list": name, "network": str(n)} for n in sorted(entries.networks, key=str)]
    for model, rows in ((BlocklistDomain, domains), (BlocklistNetwork, networks)):
        for start in range(0, len(rows), BATCH):
            session.execute(insert(model).values(rows[start : start + BATCH]))
    stmt = insert(Blocklist).values(name=name, entries=len(entries), refreshed_at=now)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[Blocklist.name],
            set_={"entries": stmt.excluded.entries, "refreshed_at": stmt.excluded.refreshed_at},
        )
    )
    session.commit()


def drop_list(session: Session, name: str) -> None:
    """Forget a list that's no longer used (its abuse.ch key was removed). Commits."""
    session.execute(delete(BlocklistDomain).where(BlocklistDomain.list == name))
    session.execute(delete(BlocklistNetwork).where(BlocklistNetwork.list == name))
    session.execute(delete(Blocklist).where(Blocklist.name == name))
    session.commit()


def assign_categories(session: Session) -> int:
    """Set every domain's category, blocklist hits and threat flag. Commits. Returns how
    many domains changed."""
    hits = dict(session.execute(_HITS, {"pihole": blocklists.PIHOLE}).all())
    orgs = classifier(session)
    suffixes = categories.bundled()
    rows = session.execute(
        select(
            Domain.domain,
            Domain.organization,
            Domain.pihole_blocked,
            Domain.category,
            Domain.blocklists,
            Domain.is_blocklisted,
        )
    ).all()
    changed = []
    for domain, org, blocked, category, lists, flagged in rows:
        new_lists = hits.get(domain, [])
        new = {
            "category": categories.categorize(domain, orgs.category(org), blocked, suffixes),
            "blocklists": new_lists,
            "is_blocklisted": any(x != blocklists.PIHOLE for x in new_lists),
        }
        if (new["category"], new["blocklists"], new["is_blocklisted"]) != (
            category,
            list(lists or []),
            flagged,
        ):
            changed.append({"domain": domain, **new})
    if changed:
        session.execute(update(Domain), changed)
    session.commit()
    return len(changed)


class CategorySource(Source):
    name = "categories"
    interval_seconds = 300.0

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self._attempted: dict[str, datetime] = {}
        self._errors: dict[str, str] = {}  # list name -> last failed download
        self._popular: frozenset[str] | None = None  # for one round's downloads only

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        now = datetime.now(UTC)
        with get_sessionmaker()() as session:
            self._refresh(session, now)
            record_check(session, BLOCKLIST_CHECK, self._status(session), now)
            changed = assign_categories(session)
        if changed:
            log.info("categories: %d domains changed", changed)

    def _key(self) -> str | None:
        key = self.settings.abusech_auth_key
        return key.get_secret_value() if key else None

    def _refresh(self, session: Session, now: datetime) -> None:
        """Download the lists that are due and that it's time to try."""
        key = self._key()
        refresh_after = timedelta(hours=self.settings.blocklist_refresh_hours)
        stored = dict(session.execute(select(Blocklist.name, Blocklist.refreshed_at)).all())
        for bl in blocklists.LISTS:
            if bl.needs_key and not key:
                self._errors.pop(bl.name, None)
                if bl.name in stored:
                    drop_list(session, bl.name)
                continue
            refreshed = stored.get(bl.name)
            if refreshed is not None and now - refreshed < refresh_after:
                continue
            attempted = self._attempted.get(bl.name)
            if attempted is not None and now - attempted < RETRY_AFTER:
                continue
            self._attempted[bl.name] = now
            try:
                popular = self._popular_sites() if bl.url_hosts else None
                entries = blocklists.download(bl, key, popular)
            except (OSError, ValueError) as exc:  # URLError and timeouts are OSErrors
                self._errors[bl.name] = str(exc)
                log.warning("blocklists: %s download failed: %s", bl.label, exc)
                continue
            store_list(session, bl.name, entries, now)
            self._errors.pop(bl.name, None)
            log.info("blocklists: %s has %d entries", bl.label, len(entries))
        self._popular = None  # 100k names: not worth keeping between rounds

    def _popular_sites(self) -> frozenset[str]:
        """The Tranco list, downloaded at most once a round. Raises like download()."""
        if self._popular is None:
            try:
                self._popular = blocklists.download_popular()
            except (OSError, ValueError) as exc:
                raise ValueError(f"Tranco list of popular sites: {exc}") from exc
        return self._popular

    def _status(self, session: Session) -> CheckResult:
        stored = dict(session.execute(select(Blocklist.name, Blocklist.entries)).all())
        details = {"lists": stored}
        skipped = [bl.label for bl in blocklists.LISTS if bl.needs_key and not self._key()]
        note = f" {' and '.join(skipped)} need NETMAP_ABUSECH_AUTH_KEY." if skipped else ""
        if self._errors:
            failed = "; ".join(
                f"{blocklists.BY_NAME[n].label}: {e}" for n, e in sorted(self._errors.items())
            )
            return CheckResult("warning", f"Blocklist download failed ({failed}).{note}", details)
        if not stored:
            return CheckResult("unknown", f"No blocklists downloaded yet.{note}", details)
        names = ", ".join(blocklists.LABELS[n] for n in sorted(stored))
        total = sum(stored.values())
        return CheckResult("ok", f"Matching against {names} ({total:,} entries).{note}", details)
