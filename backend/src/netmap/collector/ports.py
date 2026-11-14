"""Periodic port/service scan of online devices.

TCP: a connect scan of ports common on home networks (no raw sockets needed), with a
banner grab. Services that speak first (SSH, FTP, ...) send their banner; HTTP ports get
a HEAD request and report their Server header. UDP: blind scanning needs ICMP from raw
sockets, so only services with a request that always gets an answer are probed (DNS, NTP,
SSDP, mDNS), and a reply means open.

Gentle by design: each device gets a few probes at a time (small IoT TCP stacks fall over
under load), and each is scanned again only after port_scan_interval_seconds, which also
means a collector restart doesn't trigger a rescan.
"""

import asyncio
import contextlib
import logging
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select

from netmap.collector.arp import find_interface
from netmap.collector.base import Source
from netmap.collector.inventory import known_addresses, record_scan
from netmap.collector.protocols import M_SEARCH, TYPE_A, TYPE_PTR, build_query, reverse_name
from netmap.db import get_sessionmaker
from netmap.db.models import Device

log = logging.getLogger(__name__)

TCP_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1080: "socks", 1400: "sonos", 1883: "mqtt", 2049: "nfs", 3000: "http", 3306: "mysql",
    3389: "rdp", 3483: "slimproto", 4070: "spotify", 4443: "https", 5000: "http",
    5001: "https", 5357: "wsd", 5432: "postgres", 5900: "vnc", 6379: "redis",
    6466: "androidtv-remote", 6467: "androidtv-pairing", 6668: "tuya", 7000: "airplay",
    7100: "http", 8000: "http", 8008: "http", 8009: "cast", 8060: "roku", 8080: "http",
    8081: "http", 8083: "http", 8088: "http", 8123: "home-assistant", 8443: "https",
    8554: "rtsp", 8883: "mqtts", 8888: "http", 9000: "http", 9080: "http",
    9100: "jetdirect", 9443: "https", 9999: "kasa", 10001: "ubiquiti", 32400: "plex",
    49152: "upnp", 49153: "upnp", 55443: "yeelight", 62078: "iphone-sync",
}  # fmt: skip
HTTP_PORTS = {
    p for p, s in TCP_SERVICES.items() if s in ("http", "roku", "home-assistant", "upnp", "plex")
}
NTP_REQUEST = b"\x1b" + b"\x00" * 47  # version 3, client mode


def udp_probes(ip: str) -> dict[int, tuple[str, bytes]]:
    return {
        53: ("dns", build_query(0x4E4D, [("localhost", TYPE_A)], recursion=True)),
        123: ("ntp", NTP_REQUEST),
        1900: ("ssdp", M_SEARCH),
        5353: ("mdns", build_query(0x4E4D, [(reverse_name(ip), TYPE_PTR)])),
    }


CONNECT_TIMEOUT = 1.5
BANNER_TIMEOUT = 1.5
UDP_TIMEOUT = 1.5
PROBES_PER_HOST = 4
PROBES_TOTAL = 32
HOSTS_PER_RUN = 8
CHECK_INTERVAL = 60.0
BANNER_MAX = 200


def summarize_banner(data: bytes) -> str | None:
    """One readable line from what a service sent: an HTTP Server header, else line one."""
    data = data.strip()
    if not data or sum(32 <= b < 127 or b in b"\r\n\t" for b in data) < 0.9 * len(data):
        return None  # nothing, or binary (TLS and the like)
    lines = data.decode("ascii", "replace").splitlines()
    if lines[0].startswith("HTTP/"):
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep and key.strip().lower() == "server" and value.strip():
                return value.strip()[:BANNER_MAX]
    return lines[0].strip()[:BANNER_MAX] or None


async def _read(reader: asyncio.StreamReader) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(1024), BANNER_TIMEOUT)
    except (TimeoutError, OSError):
        return b""


async def probe_tcp(ip: str, port: int) -> tuple[bool, str | None]:
    """(open, banner) for one TCP port."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_TIMEOUT)
    except (TimeoutError, OSError):
        return False, None
    try:
        data = await _read(reader)
        if not data and port in HTTP_PORTS:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            with contextlib.suppress(OSError):
                await writer.drain()
                data = await _read(reader)
        return True, summarize_banner(data)
    finally:
        writer.close()
        with contextlib.suppress(TimeoutError, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


class _Reply(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.answered: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.answered.done():
            self.answered.set_result(True)

    def error_received(self, exc: Exception) -> None:  # ICMP port unreachable
        if not self.answered.done():
            self.answered.set_result(False)


async def probe_udp(ip: str, port: int, request: bytes) -> bool:
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(_Reply, remote_addr=(ip, port))
    except OSError:
        return False
    try:
        transport.sendto(request)
        return await asyncio.wait_for(proto.answered, UDP_TIMEOUT)
    except TimeoutError:
        return False
    finally:
        transport.close()


async def scan_host(
    ip: str, total: asyncio.Semaphore
) -> dict[tuple[int, str], tuple[str, str | None]]:
    """Open ports of one host, as {(port, protocol): (service, banner)}."""
    per_host = asyncio.Semaphore(PROBES_PER_HOST)
    found: dict[tuple[int, str], tuple[str, str | None]] = {}

    async def tcp(port: int, service: str) -> None:
        async with per_host, total:
            is_open, banner = await probe_tcp(ip, port)
        if is_open:
            found[(port, "tcp")] = (service, banner)

    async def udp(port: int, service: str, request: bytes) -> None:
        async with per_host, total:
            if await probe_udp(ip, port, request):
                found[(port, "udp")] = (service, None)

    async with asyncio.TaskGroup() as tg:
        for port, service in TCP_SERVICES.items():
            tg.create_task(tcp(port, service))
        for port, (service, request) in udp_probes(ip).items():
            tg.create_task(udp(port, service, request))
    return found


class PortScanSource(Source):
    name = "ports"
    interval_seconds = CHECK_INTERVAL

    def enabled(self) -> bool:
        # Linux on the LAN only, like ARP: the dev stack's seeded devices have made-up IPs
        # that may belong to real hosts on the developer's network.
        if sys.platform != "linux" or self.settings.lan_cidr is None:
            return False
        if self.settings.port_scan_interval_seconds == 0:
            return False
        return bool(self.settings.lan_iface or find_interface(self.settings.lan_cidr))

    def _due(self) -> dict[str, str]:
        """Online devices whose last scan is older than the interval, as {mac: ip}."""
        cutoff = datetime.now(UTC) - timedelta(seconds=self.settings.port_scan_interval_seconds)
        with get_sessionmaker()() as session:
            macs = session.scalars(
                select(Device.mac)
                .where(
                    Device.online,
                    or_(Device.ports_scanned_at.is_(None), Device.ports_scanned_at < cutoff),
                )
                .order_by(Device.ports_scanned_at.asc().nulls_first())
            ).all()
            addresses = known_addresses(session)
        return {mac: addresses[mac] for mac in macs if mac in addresses}

    async def run_once(self) -> None:
        due = dict(list((await asyncio.to_thread(self._due)).items())[:HOSTS_PER_RUN])
        if not due:
            return
        total = asyncio.Semaphore(PROBES_TOTAL)
        results = await asyncio.gather(*(scan_host(ip, total) for ip in due.values()))
        now = datetime.now(UTC)
        await asyncio.to_thread(self._record, dict(zip(due, results, strict=True)), now)
        log.info(
            "ports: scanned %d devices, %d open ports",
            len(due), sum(len(r) for r in results),
        )  # fmt: skip

    @staticmethod
    def _record(results: dict, now: datetime) -> None:
        with get_sessionmaker()() as session:
            for mac, found in results.items():
                record_scan(session, mac, found, now)
