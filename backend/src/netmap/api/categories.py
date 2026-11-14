"""Domain categories and threat blocklist hits (netmap/categories.py, netmap/blocklists.py)."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from netmap import blocklists, categories
from netmap.api.deps import DB
from netmap.config import get_settings
from netmap.db.models import Blocklist, Domain

router = APIRouter()


class Category(BaseModel):
    category: str
    label: str
    domains: int


class BlocklistOut(BaseModel):
    name: str
    label: str
    url: str  # the list's home, never the download URL (which can hold the abuse.ch key)
    entries: int | None  # null until downloaded
    refreshed_at: datetime | None
    needs_key: bool  # needs NETMAP_ABUSECH_AUTH_KEY, and it isn't set


class FlaggedDomain(BaseModel):
    domain: str
    organization: str | None
    category: str | None
    blocklists: list[str]
    last_seen: datetime


class Blocklists(BaseModel):
    lists: list[BlocklistOut]
    labels: dict[str, str]  # list name -> display name, "pihole" included
    flagged: list[FlaggedDomain]  # on a threat list, most recently seen first


HOMES = {
    "firehol_level1": "https://iplists.firehol.org/?ipset=firehol_level1",
    "feodo": "https://feodotracker.abuse.ch/",
    "urlhaus": "https://urlhaus.abuse.ch/",
    "threatfox": "https://threatfox.abuse.ch/",
}


@router.get("/api/categories", response_model=list[Category])
def list_categories(db: DB) -> list[Category]:
    """Every category with how many domains are in it, in a fixed order."""
    counts = dict(db.execute(select(Domain.category, func.count()).group_by(Domain.category)).all())
    return [
        Category(category=c, label=label, domains=counts.get(c, 0))
        for c, label in categories.LABELS.items()
    ]


@router.get("/api/blocklists", response_model=Blocklists)
def list_blocklists(db: DB, limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> Blocklists:
    """The threat lists, their last download, and the domains on them."""
    stored = {b.name: b for b in db.scalars(select(Blocklist))}
    has_key = get_settings().abusech_auth_key is not None
    lists = [
        BlocklistOut(
            name=bl.name,
            label=bl.label,
            url=HOMES[bl.name],
            entries=stored[bl.name].entries if bl.name in stored else None,
            refreshed_at=stored[bl.name].refreshed_at if bl.name in stored else None,
            needs_key=bl.needs_key and not has_key,
        )
        for bl in blocklists.LISTS
    ]
    rows = db.scalars(
        select(Domain).where(Domain.is_blocklisted).order_by(Domain.last_seen.desc()).limit(limit)
    )
    flagged = [
        FlaggedDomain(
            domain=d.domain,
            organization=d.organization,
            category=d.category,
            blocklists=d.blocklists,
            last_seen=d.last_seen,
        )
        for d in rows
    ]
    return Blocklists(lists=lists, labels=blocklists.LABELS, flagged=flagged)
