"""Groups domains by organization (netmap.orgs), as they're first seen and as their
networks become known. Changing a rule in the app regroups everything at once (see
api/orgs.py); this job catches new domains and ones the geoip job just located.
"""

import asyncio
import logging

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from netmap.collector.base import Source
from netmap.db import get_sessionmaker
from netmap.db.models import Domain, OrgRule
from netmap.orgs import Classifier

log = logging.getLogger(__name__)


def classifier(session: Session) -> Classifier:
    rules = session.execute(select(OrgRule.kind, OrgRule.value, OrgRule.organization)).all()
    return Classifier(rules)


def assign_organizations(session: Session) -> int:
    """Set every domain's organization. Commits. Returns how many changed."""
    orgs = classifier(session)
    rows = session.execute(select(Domain.domain, Domain.asn, Domain.organization)).all()
    changed = [
        {"domain": domain, "organization": org}
        for domain, asn, current in rows
        if (org := orgs.classify(domain, asn)) != current
    ]
    if changed:
        session.execute(update(Domain), changed)
    session.commit()
    return len(changed)


class OrganizationSource(Source):
    name = "orgs"
    interval_seconds = 300.0

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        with get_sessionmaker()() as session:
            changed = assign_organizations(session)
        if changed:
            log.info("orgs: %d domains regrouped", changed)
