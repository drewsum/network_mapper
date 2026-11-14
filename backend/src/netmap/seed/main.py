"""Synthetic data seeder so the app can be developed without LAN access.

Device IPs are drawn from NETMAP_LAN_CIDR; external reply IPs come from the RFC 5737
documentation ranges, so nothing here resembles anyone's real network.
"""

import ipaddress
import logging
import math
import random
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, insert, select, text

from netmap.config import Settings
from netmap.db import get_engine
from netmap.db.models import Device, DeviceIP, Domain, DomainIP
from netmap.db.policies import refresh_all_aggregates
from netmap.seed.catalog import CATALOG, DeviceSpec, DomainSpec

log = logging.getLogger(__name__)

EXTERNAL_POOLS = [ipaddress.ip_network(n) for n in ("198.51.100.0/24", "203.0.113.0/24")]
SEEDED_TABLES = [
    "dns_queries", "domain_ips", "domains", "device_baselines", "alerts",
    "ports", "upnp_mappings", "device_ips", "devices",
]  # fmt: skip


@dataclass
class SeedData:
    devices: list[dict] = field(default_factory=list)
    device_ips: list[dict] = field(default_factory=list)
    domains: dict[str, dict] = field(default_factory=dict)
    domain_ips: list[dict] = field(default_factory=list)
    # (device mac, device ip, DomainSpec, reply ips, offline_since)
    streams: list[tuple[str, str, DomainSpec, list[str], datetime | None]] = field(
        default_factory=list
    )


def random_mac(rng: random.Random, randomized: bool) -> str:
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] &= 0b11111100  # unicast, universally administered
    if randomized:
        octets[0] |= 0b00000010  # locally administered (private/randomized MAC)
    return ":".join(f"{o:02x}" for o in octets)


def hour_multiplier(pattern: str, hour: int) -> float:
    """Shape of activity over a local day, 0..~1.6."""
    if pattern == "diurnal":
        return 0.05 if hour < 6 else 0.3 + 0.7 * math.sin(math.pi * (hour - 6) / 18) ** 2 * 1.6
    if pattern == "night":
        return 1.5 if 1 <= hour <= 4 else 0.2
    return 1.0


def poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:  # normal approximation keeps this fast for busy streams
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    threshold, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= threshold:
            return k
        k += 1


def build(lan_cidr: ipaddress.IPv4Network, now: datetime, rng: random.Random) -> SeedData:
    hosts = list(lan_cidr.hosts())
    # Skip the first few addresses (typically router / infrastructure) and shuffle the rest.
    pool = hosts[10:] if len(hosts) > 64 else hosts[1:]
    rng.shuffle(pool)
    total = sum(spec.count for spec in CATALOG)
    if len(pool) < total:
        raise ValueError(f"NETMAP_LAN_CIDR {lan_cidr} is too small for {total} seeded devices")

    data = SeedData()
    for spec in CATALOG:
        for n in range(spec.count):
            _add_device(data, spec, n, str(pool.pop()), now, rng)
    return data


def _add_device(
    data: SeedData, spec: DeviceSpec, n: int, ip: str, now: datetime, rng: random.Random
) -> None:
    suffix = f"-{n + 1}" if spec.count > 1 else ""
    mac = random_mac(rng, spec.randomized_mac)
    offline_since = now - timedelta(days=spec.offline_days) if spec.offline_days else None
    first_seen = now - timedelta(days=rng.randint(31, 400))
    last_seen = offline_since or now
    data.devices.append({
        "mac": mac,
        "label": spec.label + (f" {n + 1}" if spec.count > 1 else ""),
        "hostname": spec.hostname + suffix,
        "hostname_source": "seed",
        "vendor": spec.vendor,
        "category": spec.category,
        "is_iot": spec.is_iot,
        "is_randomized_mac": spec.randomized_mac,
        "online": offline_since is None,
        "first_seen": first_seen,
        "last_seen": last_seen,
    })  # fmt: skip
    data.device_ips.append({"mac": mac, "ip": ip, "first_seen": first_seen, "last_seen": last_seen})

    for dom in spec.domains:
        if dom.domain not in data.domains:
            pool = EXTERNAL_POOLS[len(data.domains) % len(EXTERNAL_POOLS)]
            replies = sorted({str(pool[rng.randrange(1, 255)]) for _ in range(rng.randint(1, 3))})
            data.domains[dom.domain] = {
                "domain": dom.domain,
                "organization": dom.organization,
                "category": dom.category,
                "country": dom.country,
                "asn": dom.asn,
                "asn_org": dom.organization,
                "is_blocklisted": dom.pattern == "blocked",
                "enriched_at": now,
                "replies": replies,
            }
            data.domain_ips.extend({"domain": dom.domain, "ip": r} for r in replies)
        data.streams.append((mac, ip, dom, data.domains[dom.domain]["replies"], offline_since))


def generate_queries(
    data: SeedData, start: datetime, end: datetime, rng: random.Random
) -> Iterator[tuple]:
    """Yield dns_queries rows (time, client_ip, mac, domain, query_type, status, reply_ips)."""
    hour = start.replace(minute=0, second=0, microsecond=0)
    while hour < end:
        for mac, ip, dom, replies, offline_since in data.streams:
            if offline_since and hour >= offline_since:
                continue
            blocked = dom.pattern == "blocked"
            shape = "diurnal" if blocked else dom.pattern
            for _ in range(poisson(rng, dom.rate * hour_multiplier(shape, hour.hour))):
                t = hour + timedelta(seconds=rng.random() * 3600)
                if t >= end:
                    continue
                qtype = "AAAA" if rng.random() < 0.3 else "A"
                if blocked:
                    yield (t, ip, mac, dom.domain, qtype, "blocked", None)
                else:
                    status = "cached" if rng.random() < 0.35 else "allowed"
                    yield (t, ip, mac, dom.domain, qtype, status, replies if qtype == "A" else [])
        hour += timedelta(hours=1)


def seed(settings: Settings, days: int, reset: bool, rng_seed: int) -> None:
    lan_cidr = settings.require("lan_cidr")
    engine = get_engine()
    rng = random.Random(rng_seed)
    now = datetime.now(UTC)

    with engine.begin() as conn:
        if reset:
            conn.execute(text(f"TRUNCATE {', '.join(SEEDED_TABLES)} CASCADE"))
            log.info("wiped existing data")
        elif conn.execute(select(Device.mac).limit(1)).first() is not None:
            raise SystemExit("database already has devices; rerun with --reset to wipe it")

        data = build(lan_cidr, now, rng)
        conn.execute(insert(Device), data.devices)
        conn.execute(insert(DeviceIP), data.device_ips)
        conn.execute(
            insert(Domain),
            [{k: v for k, v in dom.items() if k != "replies"} for dom in data.domains.values()],
        )
        conn.execute(insert(DomainIP), data.domain_ips)
    log.info("seeded %d devices, %d domains", len(data.devices), len(data.domains))

    rows = _copy_queries(engine, generate_queries(data, now - timedelta(days=days), now, rng))
    log.info("seeded %d dns queries over %d days", rows, days)

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)
    log.info("continuous aggregates refreshed")


def _copy_queries(engine: Engine, rows: Iterator[tuple]) -> int:
    count = 0
    raw = engine.raw_connection()
    try:
        cur = raw.driver_connection.cursor()
        with cur.copy(
            "COPY dns_queries (time, client_ip, mac, domain, query_type, status, reply_ips) "
            "FROM STDIN"
        ) as copy:
            copy.set_types(["timestamptz", "inet", "text", "text", "text", "text", "inet[]"])
            for row in rows:
                copy.write_row(row)
                count += 1
        raw.commit()
    finally:
        raw.close()
    return count
