"""Storing DNS queries (from Pi-hole) and keeping the domains table current."""

from collections.abc import Sequence
from typing import Protocol

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.collector.inventory import known_addresses
from netmap.db.models import DnsQuery, Domain

# Rows per INSERT: well under Postgres's 65535 bind parameters at 7 columns a row.
BATCH = 5000


class QueryLike(Protocol):
    @property
    def id(self) -> int: ...
    @property
    def time(self): ...
    @property
    def client_ip(self) -> str: ...
    @property
    def domain(self) -> str: ...
    @property
    def query_type(self) -> str: ...
    @property
    def status(self) -> str: ...


def record_queries(session: Session, queries: Sequence[QueryLike]) -> int:
    """Store queries not stored yet, each credited to the device that has its client IP
    now (the poller runs seconds behind, so that's the device that asked). Commits.
    Returns how many were new."""
    ip_to_mac = {ip: mac for mac, ip in known_addresses(session).items()}
    inserted = 0
    for start in range(0, len(queries), BATCH):
        rows = [
            {
                "time": q.time,
                "pihole_id": q.id,
                "client_ip": q.client_ip,
                "mac": ip_to_mac.get(q.client_ip),
                "domain": q.domain,
                "query_type": q.query_type,
                "status": q.status,
            }
            for q in queries[start : start + BATCH]
        ]
        stmt = (
            insert(DnsQuery)
            .values(rows)
            .on_conflict_do_nothing(
                index_elements=[DnsQuery.pihole_id, DnsQuery.time],
                index_where=DnsQuery.pihole_id.is_not(None),
            )
            .returning(DnsQuery.seq)
        )
        inserted += len(session.execute(stmt).all())

    seen: dict[str, list] = {}
    for q in queries:
        span = seen.setdefault(q.domain, [q.time, q.time])
        span[0], span[1] = min(span[0], q.time), max(span[1], q.time)
    if seen:
        stmt = insert(Domain).values(
            [{"domain": d, "first_seen": lo, "last_seen": hi} for d, (lo, hi) in seen.items()]
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[Domain.domain],
                set_={
                    "first_seen": func.least(Domain.first_seen, stmt.excluded.first_seen),
                    "last_seen": func.greatest(Domain.last_seen, stmt.excluded.last_seen),
                },
            )
        )
    session.commit()
    return inserted
