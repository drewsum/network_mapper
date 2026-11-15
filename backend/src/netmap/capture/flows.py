"""From what a capture source saw to rows in ``flows``.

A source reports observations: some bytes between two endpoints over a span of time. Each
LAN endpoint is a device, found by its IP in the inventory (the frame's MAC when the
inventory doesn't know the IP yet), and gets a row with the other end as the remote one;
traffic between two LAN devices so counts for both. Rows are 1-minute buckets, summed in
memory and added to what's already stored, so a flow reported every few seconds adds up.
The remote end is labelled with the name the device connected to (the TLS SNI or HTTP
host), or else a domain that Pi-hole saw resolve to that IP (passive DNS).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Network, ip_address

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.collector.dns import VISIBILITY_CHECK
from netmap.db.models import Flow

PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}
BATCH = 2000  # rows per INSERT, well under Postgres's parameter limit


def protocol_name(number: int) -> str:
    return PROTOCOLS.get(number, str(number))


@dataclass(frozen=True)
class Observation:
    """Bytes between two endpoints up to ``time`` (the last packet). ``src`` opened the
    connection when the source knows (nfstream does); its port is the client's."""

    time: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_out: int  # src -> dst
    bytes_in: int  # dst -> src
    packets: int
    src_mac: str | None = None
    dst_mac: str | None = None
    app: str | None = None
    sni: str | None = None


@dataclass
class Row:
    time: datetime
    mac: str
    remote_ip: str
    remote_port: int
    protocol: str
    bytes_up: int
    bytes_down: int
    packets: int
    outbound: bool
    app: str | None = None
    sni: str | None = None
    source: str | None = None  # nfstream | netflow

    @property
    def key(self) -> tuple:
        return (self.time, self.mac, self.remote_ip, self.remote_port, self.protocol)


def minute(t: datetime) -> datetime:
    return t.astimezone(UTC).replace(second=0, microsecond=0)


def _ignored(ip: str, lan: IPv4Network) -> bool:
    """Discovery chatter and broadcasts: multicast, link-local, the LAN's broadcast."""
    a = ip_address(ip)
    return a.is_multicast or a.is_link_local or a.is_unspecified or a == lan.broadcast_address


@dataclass
class Lan:
    """What counts as a device on the LAN. IPv4: an address in the LAN's range, its device
    looked up by IP. IPv6 has no such range here, so a v6 address counts when the frame's
    MAC is a known device's, other than the router's (which forwards everyone's)."""

    network: IPv4Network
    macs: dict[str, str] = field(default_factory=dict)  # {ip: mac}
    devices: set[str] = field(default_factory=set)
    router: str | None = None

    def device(self, ip: str, frame_mac: str | None) -> str | None:
        a = ip_address(ip)
        if a.version == 4:
            return (self.macs.get(ip) or frame_mac) if a in self.network else None
        mac = frame_mac.lower() if frame_mac else None
        return mac if mac in self.devices and mac != self.router else None


def rows_for(obs: Observation, lan: Lan, source: str | None = None) -> list[Row]:
    """A row for each LAN end of ``obs``; none for traffic that doesn't touch the LAN or
    is broadcast or multicast."""
    if _ignored(obs.dst_ip, lan.network) or _ignored(obs.src_ip, lan.network):
        return []
    t = minute(obs.time)
    rows = []
    ends = (
        (obs.src_ip, obs.src_mac, obs.dst_ip, obs.bytes_out, obs.bytes_in, True),
        (obs.dst_ip, obs.dst_mac, obs.src_ip, obs.bytes_in, obs.bytes_out, False),
    )
    for ip, frame_mac, remote, up, down, outbound in ends:
        mac = lan.device(ip, frame_mac)
        if mac:
            rows.append(
                Row(t, mac.lower(), remote, obs.dst_port, obs.protocol, up, down, obs.packets,
                    outbound, obs.app, obs.sni, source)
            )  # fmt: skip
    return rows


@dataclass
class Buckets:
    """Rows summed by key until they're written."""

    rows: dict[tuple, Row] = field(default_factory=dict)

    def add(self, rows: Iterable[Row]) -> None:
        for r in rows:
            have = self.rows.get(r.key)
            if have is None:
                self.rows[r.key] = Row(**r.__dict__)
                continue
            have.bytes_up += r.bytes_up
            have.bytes_down += r.bytes_down
            have.packets += r.packets
            have.app = have.app or r.app
            have.sni = have.sni or r.sni

    def drain(self) -> list[Row]:
        rows, self.rows = list(self.rows.values()), {}
        return rows


_MACS = text("""
    SELECT DISTINCT ON (di.ip) host(di.ip), coalesce(d.merged_into, d.mac)::text
    FROM device_ips di JOIN devices d ON d.mac = di.mac
    ORDER BY di.ip, di.last_seen DESC
""")
_DOMAINS = text("""
    SELECT DISTINCT ON (ip) host(ip), domain FROM domain_ips
    WHERE ip = ANY(CAST(:ips AS inet[]))
    ORDER BY ip, last_seen DESC
""")


def load_lan(session: Session, network: IPv4Network) -> Lan:
    """The inventory's view of the LAN: which device holds each IP (merged devices
    resolved), every device, and the router (the gateway Pi-hole's check last saw)."""
    macs = dict(session.execute(_MACS).all())
    devices = {str(m) for m in session.scalars(text("SELECT mac::text FROM devices"))}
    router_ip = session.scalar(
        text("SELECT details->>'router_ip' FROM health_checks WHERE name = :n"),
        {"n": VISIBILITY_CHECK},
    )
    return Lan(network, macs, devices, macs.get(router_ip) if router_ip else None)


def write_rows(session: Session, rows: list[Row]) -> int:
    """Add ``rows`` to ``flows``, labelling remote ends with their domain. Commits."""
    if not rows:
        return 0
    unnamed = sorted({r.remote_ip for r in rows if not r.sni})
    domains = dict(session.execute(_DOMAINS, {"ips": unnamed}).all()) if unnamed else {}
    values = [
        {**r.__dict__,
         "domain": r.sni.lower().rstrip(".") if r.sni else domains.get(r.remote_ip)}
        for r in rows
    ]  # fmt: skip
    for start in range(0, len(values), BATCH):
        stmt = insert(Flow).values(values[start : start + BATCH])
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["time", "mac", "remote_ip", "remote_port", "protocol"],
                set_={
                    "bytes_up": Flow.bytes_up + stmt.excluded.bytes_up,
                    "bytes_down": Flow.bytes_down + stmt.excluded.bytes_down,
                    "packets": Flow.packets + stmt.excluded.packets,
                    "app": text("coalesce(flows.app, excluded.app)"),
                    "sni": text("coalesce(flows.sni, excluded.sni)"),
                    "domain": text("coalesce(flows.domain, excluded.domain)"),
                    "outbound": text("coalesce(flows.outbound, excluded.outbound)"),
                },
            )
        )
    session.commit()
    return len(values)
