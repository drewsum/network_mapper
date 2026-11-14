"""ARP discovery: a periodic sweep of the LAN plus passive listening to all ARP traffic.

One AF_PACKET socket bound to ETH_P_ARP does both: the kernel hands it every ARP frame
on the interface (replies to our sweep, and other hosts' requests and announcements),
so no packet library or BPF filter is needed. Needs CAP_NET_RAW and Linux; on other
platforms the source disables itself.
"""

import asyncio
import logging
import socket
import struct
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

from netmap.collector.base import Source
from netmap.collector.inventory import Sighting, record_sightings
from netmap.db import get_sessionmaker

log = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2
BROADCAST = b"\xff" * 6
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927
# Ethernet header + ARP payload for IPv4 over Ethernet.
_ETH = struct.Struct("!6s6sH")
_ARP = struct.Struct("!HHBBH6s4s6s4s")

# Seconds to wait for replies after sending the sweep.
REPLY_WAIT = 3.0
# Pause between requests, so a /24 sweep doesn't burst 254 frames at once.
SEND_GAP = 0.005
# Larger networks are only listened to: a sweep would take longer than the interval.
MAX_SWEEP_ADDRESSES = 1024


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def build_request(src_mac: bytes, src_ip: IPv4Address, target: IPv4Address) -> bytes:
    return _ETH.pack(BROADCAST, src_mac, ETH_P_ARP) + _ARP.pack(
        1, 0x0800, 6, 4, ARP_REQUEST, src_mac, src_ip.packed, b"\x00" * 6, target.packed
    )


def parse_sender(frame: bytes, network: IPv4Network) -> tuple[str, str] | None:
    """(mac, ip) of the host that sent an ARP frame, if it's a usable sighting on ``network``.

    Both requests and replies count: the sender fields describe the sender either way.
    Probes (sender IP 0.0.0.0), IPs outside the LAN and broadcast/zero MACs are skipped.
    """
    if len(frame) < _ETH.size + _ARP.size:
        return None
    htype, ptype, hlen, plen, op, sha, spa, _, _ = _ARP.unpack_from(frame, _ETH.size)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4) or op not in (ARP_REQUEST, ARP_REPLY):
        return None
    ip = IPv4Address(spa)
    if ip not in network or ip in (network.network_address, network.broadcast_address):
        return None
    if sha in (BROADCAST, b"\x00" * 6) or sha[0] & 1:  # multicast bit
        return None
    return format_mac(sha), str(ip)


def _ifreq(sock: socket.socket, request: int, iface: str) -> bytes:
    import fcntl  # Linux only; imported here so the module (and its tests) load anywhere

    return fcntl.ioctl(sock.fileno(), request, struct.pack("256s", iface.encode()[:15]))


def interface_addresses(iface: str) -> tuple[bytes, IPv4Address]:
    """MAC and IPv4 address of a local interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        mac = _ifreq(s, SIOCGIFHWADDR, iface)[18:24]
        ip = IPv4Address(_ifreq(s, SIOCGIFADDR, iface)[20:24])
    return mac, ip


def find_interface(network: IPv4Network) -> str | None:
    """First local interface with an IPv4 address on ``network``."""
    for _, name in socket.if_nameindex():
        try:
            _, ip = interface_addresses(name)
        except OSError:  # no IPv4 address, or not an Ethernet-like interface
            continue
        if ip in network:
            return name
    return None


class ArpSource(Source):
    name = "arp"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.arp_sweep_interval_seconds
        self._sock: socket.socket | None = None
        self._iface = ""
        self._mac = b""
        self._ip = IPv4Address(0)
        self._seen: dict[str, Sighting] = {}

    def enabled(self) -> bool:
        if sys.platform != "linux" or self.settings.lan_cidr is None:
            return False
        self._iface = self.settings.lan_iface or find_interface(self.settings.lan_cidr) or ""
        if not self._iface:
            # e.g. the dev stack's bridge network, which can't see the LAN.
            log.info("arp: no interface has an address on %s", self.settings.lan_cidr)
        return bool(self._iface)

    def _open(self) -> None:
        network, iface = self.settings.lan_cidr, self._iface
        self._mac, self._ip = interface_addresses(iface)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((iface, 0))
        sock.setblocking(False)
        asyncio.get_running_loop().add_reader(sock.fileno(), self._on_readable)
        self._sock = sock
        log.info("arp: listening on %s (%s, %s)", iface, format_mac(self._mac), self._ip)
        if network.num_addresses > MAX_SWEEP_ADDRESSES:
            log.warning("arp: %s is too large to sweep; listening passively only", network)

    def _on_readable(self) -> None:
        assert self._sock is not None
        while True:
            try:
                frame = self._sock.recv(2048)
            except BlockingIOError:
                return
            sender = parse_sender(frame, self.settings.lan_cidr)
            if sender:
                mac, ip = sender
                self._seen[mac] = Sighting(ip, datetime.now(UTC))

    async def _sweep(self) -> None:
        assert self._sock is not None
        if self.settings.lan_cidr.num_addresses > MAX_SWEEP_ADDRESSES:
            return
        loop = asyncio.get_running_loop()
        for host in self.settings.lan_cidr.hosts():
            if host != self._ip:
                await loop.sock_sendall(self._sock, build_request(self._mac, self._ip, host))
                await asyncio.sleep(SEND_GAP)
        await asyncio.sleep(REPLY_WAIT)

    async def run_once(self) -> None:
        if self._sock is None:
            self._open()
        await self._sweep()
        now = datetime.now(UTC)
        # This host never hears its own ARP, so record it directly.
        self._seen[format_mac(self._mac)] = Sighting(str(self._ip), now)
        seen, self._seen = self._seen, {}
        offline_after = timedelta(seconds=self.settings.device_offline_after_seconds)
        await asyncio.to_thread(self._record, seen, now, offline_after)
        log.info("arp: sweep done, %d devices heard", len(seen))

    @staticmethod
    def _record(seen: dict[str, Sighting], now: datetime, offline_after: timedelta) -> None:
        with get_sessionmaker()() as session:
            record_sightings(session, seen, now, offline_after)
