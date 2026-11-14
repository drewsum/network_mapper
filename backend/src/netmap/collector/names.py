"""Hostname discovery: what devices call themselves, from DHCP, mDNS, SSDP, NetBIOS and
reverse DNS.

Listening: one AF_PACKET socket with a kernel BPF filter receives the UDP traffic of
those protocols on the LAN interface: DHCP requests (hostname, option 55 fingerprint),
mDNS announcements, SSDP alive notifications, and the replies to the queries below. It
binds no port, so it can't clash with a host mDNS responder or DHCP server.

Asking, every names_interval_seconds: an mDNS reverse lookup of every known IP, an SSDP
search, a NetBIOS node status request to every known IP, and PTR lookups at the DNS server
(the Pi-hole by default). Each SSDP device's description document is then fetched for its
friendly name, model and manufacturer. Linux only, like ARP discovery.

Every source's answer is stored (device_names); the displayed hostname is the one from
the best source in hostname_precedence.
"""

import asyncio
import ctypes
import logging
import re
import socket
import struct
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from urllib.parse import urlsplit

from netmap.collector.arp import find_interface, interface_addresses
from netmap.collector.base import Source
from netmap.collector.inventory import NameHint, apply_hostnames, known_addresses, record_names
from netmap.collector.protocols import (
    DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT,
    ETH_P_IP,
    GOOGLECAST_SERVICE,
    M_SEARCH,
    MDNS_GROUP,
    MDNS_PORT,
    NETBIOS_NS_PORT,
    SSDP_GROUP,
    SSDP_PORT,
    TYPE_PTR,
    UdpPacket,
    UpnpDevice,
    build_node_status,
    build_query,
    cast_friendly_name,
    ip_from_reverse,
    names_for_ip,
    parse_description,
    parse_dhcp,
    parse_dns,
    parse_node_status,
    parse_ssdp_location,
    parse_udp,
    reverse_name,
    udp_port_filter,
)
from netmap.collector.upnp import lan_request
from netmap.db import get_sessionmaker

log = logging.getLogger(__name__)

PORTS = [DHCP_SERVER_PORT, NETBIOS_NS_PORT, SSDP_PORT, MDNS_PORT]
DNS_PORT = 53
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4

# Seconds to wait for replies after sending the queries.
REPLY_WAIT = 3.0
SEND_GAP = 0.005
# Reverse lookups per mDNS query packet; every responder answers only its own.
MDNS_BATCH = 20
DESCRIPTION_TTL = timedelta(hours=6)
MAX_LOCATIONS_PER_DEVICE = 4
# Hints about devices ARP hasn't recorded yet wait this long for it to.
PENDING_TTL = timedelta(hours=1)

# Names that identify nothing: UUIDs and long hex strings (common for cast devices), and
# the name Pi-hole gives its own address in reverse lookups.
_JUNK_NAME = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}"
    r"|localhost|pi\.hole",
    re.IGNORECASE,
)


def clean_name(name: str | None) -> str | None:
    """A displayable hostname, or None for empty and meaningless names."""
    name = " ".join((name or "").split()).rstrip(".")
    if name.lower().endswith(".local"):
        name = name[: -len(".local")]
    if not name or len(name) > 253 or _JUNK_NAME.fullmatch(name):
        return None
    return name


def hints_from_packet(
    pkt: UdpPacket, network: IPv4Network, now: datetime
) -> tuple[list[NameHint], str | None]:
    """Name hints in one captured datagram, and an SSDP description URL if it announces one."""
    if pkt.dst_port == DHCP_SERVER_PORT and pkt.src_port == DHCP_CLIENT_PORT:
        # Clients ask before they have an address, so the source IP can be 0.0.0.0.
        req = parse_dhcp(pkt.payload)
        if req is None:
            return [], None
        details = {"fingerprint": req.fingerprint, "vendor_class": req.vendor_class}
        details = {k: v for k, v in details.items() if v} or None
        name = clean_name(req.hostname)
        if name is None and details is None:
            return [], None
        return [NameHint(req.mac, "dhcp", name, details, now)], None

    if pkt.src_ip not in network:
        return [], None
    name, source = None, ""
    if pkt.src_port == MDNS_PORT:
        msg = parse_dns(pkt.payload)
        if msg and msg.is_response:
            candidates = [cast_friendly_name(msg), *names_for_ip(msg, pkt.src_ip)]
            name = next(filter(None, map(clean_name, candidates)), None)
        source = "mdns"
    elif pkt.src_port == NETBIOS_NS_PORT:
        name = clean_name(parse_node_status(pkt.payload))
        source = "netbios"
    elif SSDP_PORT in (pkt.src_port, pkt.dst_port):
        return [], parse_ssdp_location(pkt.payload)
    if name is None:
        return [], None
    return [NameHint(pkt.src_mac, source, name, None, now)], None


def fetch_description(url: str, ip: str) -> UpnpDevice | None:
    """A device's UPnP description, fetched only from the device itself (plain HTTP)."""
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != ip:
        return None
    try:
        return parse_description(lan_request(url))
    except OSError:
        return None


def _attach_filter(sock: socket.socket, program: list[tuple[int, int, int, int]]) -> None:
    code = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *ins) for ins in program))
    fprog = struct.pack("HP", len(program), ctypes.addressof(code))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)


def _resolv_conf_server() -> str | None:
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver" and "." in fields[1]:
                    return fields[1]
    except OSError:
        pass
    return None


class NameSource(Source):
    name = "names"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.names_interval_seconds
        self._iface = ""
        self._ip = IPv4Address(0)
        self._sock: socket.socket | None = None
        # Sends every query and holds the multicast memberships that let the NIC pass
        # mDNS/SSDP traffic up to the packet socket. Reverse DNS replies arrive here too.
        self._udp: socket.socket | None = None
        self._hints: dict[tuple[str, str], NameHint] = {}
        self._locations: dict[str, tuple[str, set[str]]] = {}  # mac -> (ip, description URLs)
        self._descriptions: dict[str, tuple[datetime, UpnpDevice | None]] = {}
        self._ip_to_mac: dict[str, str] = {}
        self._dns_server: str | None = None

    def enabled(self) -> bool:
        if sys.platform != "linux" or self.settings.lan_cidr is None:
            return False
        self._iface = self.settings.lan_iface or find_interface(self.settings.lan_cidr) or ""
        return bool(self._iface)

    def _open(self) -> None:
        _, self._ip = interface_addresses(self._iface)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        _attach_filter(sock, udp_port_filter(PORTS))
        sock.bind((self._iface, 0))
        sock.setblocking(False)

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("", 0))
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, self._ip.packed)
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        for group in (MDNS_GROUP, SSDP_GROUP):
            membership = IPv4Address(group).packed + self._ip.packed
            udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        udp.setblocking(False)

        loop = asyncio.get_running_loop()
        loop.add_reader(sock.fileno(), self._on_frame)
        loop.add_reader(udp.fileno(), self._on_udp)
        self._sock, self._udp = sock, udp
        with get_sessionmaker()() as session:
            # Picks up a changed hostname_precedence for every device.
            apply_hostnames(session, self.settings.hostname_sources)
            session.commit()
        log.info("names: listening on %s", self._iface)

    def _add(self, hint: NameHint) -> None:
        key = (hint.mac, hint.source)
        old = self._hints.get(key)
        if old is not None:
            hint = NameHint(
                hint.mac,
                hint.source,
                hint.name or old.name,
                {**(old.details or {}), **(hint.details or {})} or None,
                hint.seen_at,
            )
        self._hints[key] = hint

    def _on_frame(self) -> None:
        assert self._sock is not None
        while True:
            try:
                frame, addr = self._sock.recvfrom(65535)
            except BlockingIOError:
                return
            if addr[2] == PACKET_OUTGOING:
                continue
            pkt = parse_udp(frame)
            if pkt is None:
                continue
            hints, location = hints_from_packet(pkt, self.settings.lan_cidr, datetime.now(UTC))
            for hint in hints:
                self._add(hint)
            if location:
                _, urls = self._locations.setdefault(pkt.src_mac, (str(pkt.src_ip), set()))
                if len(urls) < MAX_LOCATIONS_PER_DEVICE:
                    urls.add(location)

    def _on_udp(self) -> None:
        assert self._udp is not None
        while True:
            try:
                data, (ip, port) = self._udp.recvfrom(65535)
            except OSError:  # BlockingIOError once drained
                return
            # mDNS, SSDP and NetBIOS replies are read off the packet socket; drop them here.
            if port != DNS_PORT or ip != self._dns_server:
                continue
            msg = parse_dns(data)
            for record in msg.records if msg else []:
                target = ip_from_reverse(record.name) if record.type == TYPE_PTR else None
                mac = self._ip_to_mac.get(str(target))
                name = clean_name(record.value)
                if mac and name:
                    self._add(NameHint(mac, "rdns", name, None, datetime.now(UTC)))

    def _dns(self) -> str | None:
        if self.settings.rdns_server:
            return str(self.settings.rdns_server)
        host = urlsplit(self.settings.pihole_url or "").hostname
        if host:
            try:
                return socket.gethostbyname(host)
            except OSError:
                log.warning("names: can't resolve the Pi-hole host %s for reverse DNS", host)
        return _resolv_conf_server()

    def _prepare(self) -> tuple[dict[str, str], str | None]:
        with get_sessionmaker()() as session:
            known = known_addresses(session)
        return known, self._dns()

    async def _query(self, targets: list[str]) -> None:
        assert self._udp is not None
        udp, loop = self._udp, asyncio.get_running_loop()

        # Legacy unicast mDNS (sent from a port other than 5353): answers come straight back.
        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        cast = build_query(0, [(GOOGLECAST_SERVICE, TYPE_PTR)])
        await loop.sock_sendto(udp, cast, (MDNS_GROUP, MDNS_PORT))
        for i in range(0, len(targets), MDNS_BATCH):
            batch = [(reverse_name(ip), TYPE_PTR) for ip in targets[i : i + MDNS_BATCH]]
            await loop.sock_sendto(udp, build_query(i + 1, batch), (MDNS_GROUP, MDNS_PORT))

        udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        await loop.sock_sendto(udp, M_SEARCH, (SSDP_GROUP, SSDP_PORT))

        for i, ip in enumerate(targets):
            await loop.sock_sendto(udp, build_node_status(i), (ip, NETBIOS_NS_PORT))
            if self._dns_server:
                query = build_query(i, [(reverse_name(ip), TYPE_PTR)], recursion=True)
                await loop.sock_sendto(udp, query, (self._dns_server, DNS_PORT))
            await asyncio.sleep(SEND_GAP)

    async def _describe(self) -> None:
        """Fetch new or stale description documents and turn them into ssdp hints."""
        now = datetime.now(UTC)
        stale = now - DESCRIPTION_TTL
        self._descriptions = {u: d for u, d in self._descriptions.items() if d[0] > stale}
        todo = {
            url: ip
            for ip, urls in self._locations.values()
            for url in urls
            if url not in self._descriptions
        }
        fetched = await asyncio.gather(
            *(asyncio.to_thread(fetch_description, url, ip) for url, ip in todo.items())
        )
        self._descriptions.update((url, (now, d)) for url, d in zip(todo, fetched, strict=True))

        for mac, (_, urls) in self._locations.items():
            found = [d for u in sorted(urls) if (d := self._descriptions[u][1])]
            if not found:
                continue
            best = next((d for d in found if d.friendly_name), found[0])
            details = {k: v for k, v in asdict(best).items() if v}
            self._add(NameHint(mac, "ssdp", clean_name(best.friendly_name), details, now))
        self._locations.clear()

    async def run_once(self) -> None:
        if self._sock is None:
            self._open()
        known, self._dns_server = await asyncio.to_thread(self._prepare)
        self._ip_to_mac = {ip: mac for mac, ip in known.items()}
        await self._query([ip for ip in self._ip_to_mac if ip != str(self._ip)])
        await asyncio.sleep(REPLY_WAIT)
        await self._describe()

        hints, self._hints = self._hints, {}
        recorded = await asyncio.to_thread(self._record, list(hints.values()))
        # Keep hints about devices ARP hasn't recorded yet, unless newer ones arrived.
        cutoff = datetime.now(UTC) - PENDING_TTL
        for key, hint in hints.items():
            if hint.mac not in recorded and hint.seen_at > cutoff:
                self._hints.setdefault(key, hint)
        log.info("names: round done, %d devices named", len(recorded))

    def _record(self, hints: list[NameHint]) -> set[str]:
        with get_sessionmaker()() as session:
            return record_names(session, hints, self.settings.hostname_sources)
