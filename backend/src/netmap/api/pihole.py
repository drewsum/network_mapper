"""Blocking a domain in Pi-hole from the app: where it stands in Pi-hole's lists, and adding
it to (or taking it off) Pi-hole's exact deny list. Each request logs in to Pi-hole and out
again, since Pi-hole allows only a few API sessions at a time."""

import contextlib
import re
from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel
from sqlalchemy import select

from netmap.api.deps import DB
from netmap.collector.pihole import PiholeClient, PiholeError
from netmap.config import get_settings
from netmap.db.models import Domain

router = APIRouter()

LABEL = r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?"
DOMAIN_PATTERN = rf"^{LABEL}(\.{LABEL})+$"
DomainName = Annotated[str, Path(max_length=253)]
COMMENT = "Blocked from netmap"


class PiholeState(BaseModel):
    configured: bool  # NETMAP_PIHOLE_URL and NETMAP_PIHOLE_PASSWORD are set
    domain: str
    denied: bool  # on Pi-hole's exact deny list, enabled
    deny_rules: list[str]  # other deny entries matching it (regexes, wildcards)
    allowed: bool  # an allow entry matches it, which beats any block
    lists: list[str]  # subscribed blocklists that have it
    blocked: bool  # Pi-hole would block it now
    last_blocked: bool | None  # whether Pi-hole blocked its last query netmap saw


@contextlib.contextmanager
def _pihole() -> Iterator[PiholeClient]:
    settings = get_settings()
    if not (settings.pihole_url and settings.pihole_password):
        raise HTTPException(400, "Pi-hole isn't set up: set NETMAP_PIHOLE_URL and _PASSWORD.")
    client = PiholeClient(
        settings.pihole_url,
        settings.pihole_password.get_secret_value(),
        verify_tls=settings.pihole_verify_tls,
    )
    try:
        yield client
    except PiholeError as exc:
        raise HTTPException(502, str(exc)) from exc
    finally:
        client.logout()


def state(client: PiholeClient, domain: str, last_blocked: bool | None) -> PiholeState:
    found = client.lookup(domain)
    entries = [e for e in found.get("domains") or [] if e.get("enabled", True)]
    denies = [e for e in entries if e.get("type") == "deny"]
    denied = any(e.get("kind") == "exact" and e.get("domain") == domain for e in denies)
    allowed = any(e.get("type") == "allow" for e in entries)
    lists = [
        g.get("address", "?")
        for g in found.get("gravity") or []
        if g.get("type", "block") == "block" and g.get("enabled", True)
    ]
    return PiholeState(
        configured=True,
        domain=domain,
        denied=denied,
        deny_rules=[e["domain"] for e in denies if not (e.get("kind") == "exact"
                                                        and e.get("domain") == domain)],
        allowed=allowed,
        lists=list(dict.fromkeys(lists)),
        blocked=not allowed and bool(denies or lists),
        last_blocked=last_blocked,
    )  # fmt: skip


def _last_blocked(db, domain: str) -> bool | None:
    return db.scalar(select(Domain.pihole_blocked).where(Domain.domain == domain))


def _clean(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    if not re.match(DOMAIN_PATTERN, domain):
        raise HTTPException(422, "not a domain name")
    return domain


@router.get("/api/pihole/domains/{domain}", response_model=PiholeState)
def pihole_state(domain: DomainName, db: DB) -> PiholeState:
    """Where ``domain`` stands in Pi-hole's lists, asked of Pi-hole now."""
    domain = _clean(domain)
    settings = get_settings()
    if not (settings.pihole_url and settings.pihole_password):
        return PiholeState(configured=False, domain=domain, denied=False, deny_rules=[],
                           allowed=False, lists=[], blocked=False,
                           last_blocked=_last_blocked(db, domain))  # fmt: skip
    with _pihole() as client:
        return state(client, domain, _last_blocked(db, domain))


@router.put("/api/pihole/deny/{domain}", response_model=PiholeState)
def block(domain: DomainName, db: DB) -> PiholeState:
    """Add ``domain`` to Pi-hole's exact deny list, for every device."""
    domain = _clean(domain)
    with _pihole() as client:
        if not state(client, domain, None).denied:
            client.deny(domain, COMMENT)
        return state(client, domain, _last_blocked(db, domain))


@router.delete("/api/pihole/deny/{domain}", response_model=PiholeState)
def unblock(domain: DomainName, db: DB) -> PiholeState:
    """Take ``domain`` off Pi-hole's exact deny list (its blocklists still apply)."""
    domain = _clean(domain)
    with _pihole() as client:
        client.undeny(domain)
        return state(client, domain, _last_blocked(db, domain))
