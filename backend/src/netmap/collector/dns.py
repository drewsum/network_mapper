"""Storing DNS queries (from Pi-hole) and keeping the domains table current."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Protocol

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.collector.dnslog import Answer
from netmap.collector.inventory import known_addresses
from netmap.db.models import DnsQuery, Domain, DomainIP, HealthCheck

VISIBILITY_CHECK = "pihole_client_visibility"
VISIBILITY_WINDOW = timedelta(hours=1)
# Fewer queries than this in the window says nothing either way.
VISIBILITY_MIN_QUERIES = 50
# Warn when at least this share of queries reaches Pi-hole from the router.
ROUTER_SHARE_WARNING = 0.5

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


def record_queries(
    session: Session, queries: Sequence[QueryLike], resolver_ip: str | None = None
) -> int:
    """Store queries not stored yet, each credited to the device that has its client IP
    now (the poller runs seconds behind, so that's the device that asked). Loopback
    clients are the DNS server's own host, credited to ``resolver_ip`` if given. Commits.
    Returns how many were new."""
    ip_to_mac = {ip: mac for mac, ip in known_addresses(session).items()}

    def mac_for(client_ip: str) -> str | None:
        if resolver_ip and ip_address(client_ip).is_loopback:
            client_ip = resolver_ip
        return ip_to_mac.get(client_ip)

    inserted = 0
    for start in range(0, len(queries), BATCH):
        rows = [
            {
                "time": q.time,
                "pihole_id": q.id,
                "client_ip": q.client_ip,
                "mac": mac_for(q.client_ip),
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

    # domain -> [first seen, last seen, whether that last query was blocked]
    seen: dict[str, list] = {}
    for q in queries:
        span = seen.setdefault(q.domain, [q.time, q.time, q.status == "blocked"])
        span[0] = min(span[0], q.time)
        if q.time >= span[1]:
            span[1], span[2] = q.time, q.status == "blocked"
    if seen:
        stmt = insert(Domain).values(
            [
                {"domain": d, "first_seen": lo, "last_seen": hi, "pihole_blocked": blocked}
                for d, (lo, hi, blocked) in seen.items()
            ]
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[Domain.domain],
                set_={
                    "first_seen": func.least(Domain.first_seen, stmt.excluded.first_seen),
                    "last_seen": func.greatest(Domain.last_seen, stmt.excluded.last_seen),
                    "pihole_blocked": case(
                        (stmt.excluded.last_seen >= Domain.last_seen, stmt.excluded.pihole_blocked),
                        else_=Domain.pihole_blocked,
                    ),
                },
            )
        )
    session.commit()
    return inserted


def record_answers(session: Session, answers: Sequence[Answer]) -> int:
    """Grow the passive DNS map: when each domain was seen resolving to each IP. Commits.
    Returns how many (domain, ip) pairs were touched."""
    spans: dict[tuple[str, str], list[datetime]] = {}
    for a in answers:
        span = spans.setdefault((a.domain, a.ip), [a.time, a.time])
        span[0], span[1] = min(span[0], a.time), max(span[1], a.time)
    if not spans:
        return 0
    items = list(spans.items())
    for start in range(0, len(items), BATCH):
        stmt = insert(DomainIP).values(
            [
                {"domain": d, "ip": ip, "first_seen": lo, "last_seen": hi}
                for (d, ip), (lo, hi) in items[start : start + BATCH]
            ]
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[DomainIP.domain, DomainIP.ip],
                set_={
                    "first_seen": func.least(DomainIP.first_seen, stmt.excluded.first_seen),
                    "last_seen": func.greatest(DomainIP.last_seen, stmt.excluded.last_seen),
                },
            )
        )
    session.commit()
    return len(spans)


@dataclass(frozen=True)
class CheckResult:
    status: str  # ok | warning | unknown
    message: str
    details: dict


def client_visibility(session: Session, router_ip: str | None, now: datetime) -> CheckResult:
    """Does Pi-hole see each device's own IP? If the router forwards DNS for the network,
    every query arrives from the router and none can be traced to a device."""
    rows = session.execute(
        select(DnsQuery.client_ip, func.count())
        .where(DnsQuery.time >= now - VISIBILITY_WINDOW, DnsQuery.pihole_id.is_not(None))
        .group_by(DnsQuery.client_ip)
    ).all()
    counts = {str(ip): n for ip, n in rows}
    total = sum(counts.values())
    via_router = counts.get(router_ip, 0) if router_ip else 0
    clients = sorted(ip for ip in counts if ip != router_ip and not ip_address(ip).is_loopback)
    details = {
        "window_minutes": int(VISIBILITY_WINDOW.total_seconds() // 60),
        "queries": total,
        "router_ip": router_ip,
        "router_queries": via_router,
        "clients": len(clients),
    }
    if total < VISIBILITY_MIN_QUERIES:
        return CheckResult(
            "unknown", f"Only {total} DNS queries in the last hour; too few to check.", details
        )
    share = via_router / total
    if share >= ROUTER_SHARE_WARNING:
        return CheckResult(
            "warning",
            f"{share:.0%} of DNS queries reach Pi-hole from the router ({router_ip}), so they "
            "can't be traced to devices. Point the router's DHCP DNS setting at Pi-hole: see "
            "docs/pihole.md.",
            details,
        )
    if len(clients) < 2:
        return CheckResult(
            "warning",
            f"Pi-hole saw only {len(clients)} client in the last hour; devices may be using "
            "another DNS server. See docs/pihole.md.",
            details,
        )
    return CheckResult(
        "ok",
        f"Pi-hole sees {len(clients)} clients by their own IPs ({share:.0%} via the router).",
        details,
    )


def record_check(session: Session, name: str, result: CheckResult, now: datetime) -> None:
    """Store a check's latest result. Commits."""
    stmt = insert(HealthCheck).values(
        name=name, status=result.status, message=result.message, details=result.details,
        checked_at=now,
    )  # fmt: skip
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[HealthCheck.name],
            set_={
                "status": stmt.excluded.status,
                "message": stmt.excluded.message,
                "details": stmt.excluded.details,
                "checked_at": stmt.excluded.checked_at,
            },
        )
    )
    session.commit()
