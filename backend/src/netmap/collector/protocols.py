"""Wire formats for hostname discovery: UDP-in-Ethernet frames, DNS/mDNS, DHCP, NetBIOS
and SSDP. Pure parsing and building, no sockets, so all of it is testable anywhere.

Parsers return None (or an empty result) for anything malformed instead of raising:
their input is whatever any device on the LAN chose to send.
"""

import ipaddress
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from ipaddress import IPv4Address

ETH_P_IP = 0x0800
UDP = 17

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
NETBIOS_NS_PORT = 137
SSDP_PORT = 1900
MDNS_PORT = 5353
MDNS_GROUP = "224.0.0.251"
SSDP_GROUP = "239.255.255.250"
# Cast devices announce this service; its TXT "fn" is the name the owner gave the device.
GOOGLECAST_SERVICE = "_googlecast._tcp.local"

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_NBSTAT = 33
CLASS_IN = 1
# mDNS: ask for a unicast reply (the "QU" bit in the question class).
CLASS_UNICAST_RESPONSE = 0x8000

_ETH = struct.Struct("!6s6sH")
_DNS_HEADER = struct.Struct("!HHHHHH")
_RR = struct.Struct("!HHIH")
_DHCP_MAGIC = b"\x63\x82\x53\x63"
_DHCP_FIXED = 236  # BOOTP header up to the options' magic cookie


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


# --- Ethernet / IPv4 / UDP ------------------------------------------------------------


@dataclass(frozen=True)
class UdpPacket:
    src_mac: str
    src_ip: IPv4Address
    dst_ip: IPv4Address
    src_port: int
    dst_port: int
    payload: bytes


def parse_udp(frame: bytes) -> UdpPacket | None:
    """The UDP datagram in an Ethernet frame, if it carries one (unfragmented IPv4)."""
    if len(frame) < _ETH.size + 20:
        return None
    _, src_mac, ethertype = _ETH.unpack_from(frame)
    if ethertype != ETH_P_IP:
        return None
    ip = frame[_ETH.size :]
    version, ihl = ip[0] >> 4, (ip[0] & 0x0F) * 4
    total_len = struct.unpack_from("!H", ip, 2)[0]
    frag = struct.unpack_from("!H", ip, 6)[0]
    if version != 4 or ihl < 20 or ip[9] != UDP or frag & 0x1FFF or frag & 0x2000:
        return None
    ip = ip[: min(total_len, len(ip))]
    if len(ip) < ihl + 8:
        return None
    src_port, dst_port, udp_len = struct.unpack_from("!HHH", ip, ihl)
    payload = ip[ihl + 8 : ihl + max(udp_len, 8)]
    return UdpPacket(
        format_mac(src_mac),
        IPv4Address(ip[12:16]),
        IPv4Address(ip[16:20]),
        src_port,
        dst_port,
        payload,
    )


def udp_port_filter(ports: list[int]) -> list[tuple[int, int, int, int]]:
    """Classic BPF program accepting unfragmented IPv4 UDP frames to or from ``ports``.

    Attached to the packet socket, it keeps everything else (the host's file-sharing
    traffic, say) in the kernel. Instructions are (code, jt, jf, k).
    """
    n = len(ports)
    drop = 9 + 2 * n
    accept = drop + 1

    def jump(code: int, k: int, at: int, true: int, false: int) -> tuple[int, int, int, int]:
        return code, true - at - 1, false - at - 1, k

    prog = [
        (0x28, 0, 0, 12),  # ldh [12]: ethertype
        jump(0x15, ETH_P_IP, 1, 2, drop),
        (0x30, 0, 0, 23),  # ldb [23]: IP protocol
        jump(0x15, UDP, 3, 4, drop),
        (0x28, 0, 0, 20),  # ldh [20]: flags and fragment offset
        jump(0x45, 0x1FFF, 5, drop, 6),  # jset: drop non-first fragments
        (0xB1, 0, 0, 14),  # ldxb 4*([14]&0xf): IP header length
        (0x48, 0, 0, 14),  # ldh [x+14]: source port
    ]
    prog += [jump(0x15, p, 8 + i, accept, 9 + i) for i, p in enumerate(ports)]
    prog.append((0x48, 0, 0, 16))  # ldh [x+16]: destination port
    prog += [jump(0x15, p, 9 + n + i, accept, 10 + n + i) for i, p in enumerate(ports)]
    prog += [(0x06, 0, 0, 0), (0x06, 0, 0, 0x40000)]  # ret 0 (drop), ret 256 KiB (accept)
    return prog


# --- DNS / mDNS -----------------------------------------------------------------------


@dataclass(frozen=True)
class Record:
    name: str
    type: int
    value: str  # dotted IP for A, a domain name for PTR, newline-joined strings for TXT


@dataclass(frozen=True)
class DnsMessage:
    id: int
    is_response: bool
    records: list[Record]  # A, PTR and TXT records from every section


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def reverse_name(ip: IPv4Address | str) -> str:
    return IPv4Address(ip).reverse_pointer


def build_query(qid: int, questions: list[tuple[str, int]], *, recursion=False, qu=False) -> bytes:
    flags = 0x0100 if recursion else 0
    qclass = CLASS_IN | (CLASS_UNICAST_RESPONSE if qu else 0)
    body = b"".join(encode_name(n) + struct.pack("!HH", t, qclass) for n, t in questions)
    return _DNS_HEADER.pack(qid, flags, len(questions), 0, 0, 0) + body


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """A possibly compressed name at ``offset``, and the offset just past it."""
    labels: list[str] = []
    end = None
    for _ in range(128):  # bounds pointer loops
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("bad label")
        offset += 1
        if length == 0:
            return ".".join(labels), end if end is not None else offset
        if offset + length > len(data):
            raise ValueError("truncated label")
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    raise ValueError("name too long")


def parse_dns(data: bytes) -> DnsMessage | None:
    try:
        qid, flags, qd, an, ns, ar = _DNS_HEADER.unpack_from(data)
        offset = _DNS_HEADER.size
        for _ in range(qd):
            _, offset = read_name(data, offset)
            offset += 4
        records = []
        for _ in range(an + ns + ar):
            name, offset = read_name(data, offset)
            rtype, _, _, rdlen = _RR.unpack_from(data, offset)
            offset += _RR.size
            if offset + rdlen > len(data):
                return None
            if rtype == TYPE_A and rdlen == 4:
                records.append(Record(name, rtype, str(IPv4Address(data[offset : offset + 4]))))
            elif rtype == TYPE_PTR:
                records.append(Record(name, rtype, read_name(data, offset)[0]))
            elif rtype == TYPE_TXT:
                records.append(Record(name, rtype, _txt_strings(data[offset : offset + rdlen])))
            offset += rdlen
    except (struct.error, IndexError, ValueError):
        return None
    return DnsMessage(qid, bool(flags & 0x8000), records)


def _txt_strings(rdata: bytes) -> str:
    strings, i = [], 0
    while i < len(rdata):
        strings.append(rdata[i + 1 : i + 1 + rdata[i]].decode("utf-8", "replace"))
        i += 1 + rdata[i]
    return "\n".join(strings)


def cast_friendly_name(msg: DnsMessage) -> str | None:
    """The owner-given name in a cast device's service announcement (TXT key "fn")."""
    for r in msg.records:
        if r.type == TYPE_TXT and r.name.lower().endswith("." + GOOGLECAST_SERVICE):
            for entry in r.value.split("\n"):
                key, sep, value = entry.partition("=")
                if sep and key.lower() == "fn" and value.strip():
                    return value.strip()
    return None


def names_for_ip(msg: DnsMessage, ip: IPv4Address) -> list[str]:
    """Names a DNS message gives ``ip``: A records pointing at it, or its reverse PTR."""
    rev = reverse_name(ip)
    found = []
    for r in msg.records:
        if r.type == TYPE_A and r.value == str(ip):
            found.append(r.name)
        elif r.type == TYPE_PTR and r.name.lower() == rev:
            found.append(r.value)
    return found


def ip_from_reverse(name: str) -> IPv4Address | None:
    parts = name.lower().removesuffix(".").removesuffix(".in-addr.arpa").split(".")
    try:
        return IPv4Address(".".join(reversed(parts)))
    except ipaddress.AddressValueError:
        return None


# --- DHCP -----------------------------------------------------------------------------


@dataclass(frozen=True)
class DhcpRequest:
    mac: str
    hostname: str | None
    # Option 55, the parameter request list: a fingerprint of the client's OS/DHCP stack.
    fingerprint: str | None
    vendor_class: str | None


def parse_dhcp(payload: bytes) -> DhcpRequest | None:
    """Client details from a DHCP request (BOOTREQUEST); None for anything else."""
    if len(payload) < _DHCP_FIXED + 4 or payload[0] != 1 or payload[1:3] != b"\x01\x06":
        return None
    if payload[_DHCP_FIXED : _DHCP_FIXED + 4] != _DHCP_MAGIC:
        return None
    options: dict[int, bytes] = {}
    i = _DHCP_FIXED + 4
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(payload) or i + 2 + payload[i + 1] > len(payload):
            break  # truncated option
        length = payload[i + 1]
        options.setdefault(code, payload[i + 2 : i + 2 + length])
        i += 2 + length

    def text(code: int) -> str | None:
        value = options.get(code, b"").decode("utf-8", "replace").strip("\x00 ")
        return value or None

    params = options.get(55)
    return DhcpRequest(
        mac=format_mac(payload[28:34]),
        hostname=text(12),
        fingerprint=",".join(str(b) for b in params) if params else None,
        vendor_class=text(60),
    )


# --- NetBIOS --------------------------------------------------------------------------


def _netbios_encode(name: bytes) -> bytes:
    """First-level encoding (RFC 1001): each nibble becomes a letter from A."""
    return bytes(c for b in name for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))


def build_node_status(qid: int) -> bytes:
    """A NetBIOS node status request for the wildcard name: 'what are your names?'"""
    name = _netbios_encode(b"*" + b"\x00" * 15)
    return (
        _DNS_HEADER.pack(qid, 0, 1, 0, 0, 0)
        + bytes([len(name)])
        + name
        + b"\x00"
        + struct.pack("!HH", TYPE_NBSTAT, CLASS_IN)
    )


def parse_node_status(data: bytes) -> str | None:
    """The machine name (unique name, suffix 0x00) from a node status response."""
    try:
        _, flags, _, an, _, _ = _DNS_HEADER.unpack_from(data)
        if not flags & 0x8000 or an < 1:
            return None
        _, offset = read_name(data, _DNS_HEADER.size)
        rtype, _, _, _ = _RR.unpack_from(data, offset)
        if rtype != TYPE_NBSTAT:
            return None
        offset += _RR.size
        count = data[offset]
        offset += 1
        for _ in range(count):
            entry = data[offset : offset + 18]
            if len(entry) < 18:
                return None
            name, suffix, name_flags = entry[:15], entry[15], int.from_bytes(entry[16:], "big")
            offset += 18
            if suffix == 0 and not name_flags & 0x8000:  # 0x8000: group name
                return name.decode("ascii", "replace").strip() or None
    except (struct.error, IndexError, ValueError):
        return None
    return None


# --- SSDP / UPnP ----------------------------------------------------------------------

M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def parse_ssdp_location(payload: bytes) -> str | None:
    """LOCATION of a search response or an alive NOTIFY; None for searches and byebyes."""
    try:
        text = payload.decode("utf-8", "replace")
    except UnicodeDecodeError:
        return None
    lines = text.split("\r\n")
    start = lines[0].upper()
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    if start.startswith("NOTIFY "):
        if headers.get("nts", "").lower() != "ssdp:alive":
            return None
    elif not start.startswith("HTTP/1.1 200"):
        return None
    return headers.get("location") or None


@dataclass(frozen=True)
class UpnpDevice:
    friendly_name: str | None
    manufacturer: str | None
    model: str | None
    model_number: str | None
    device_type: str | None


def parse_description(xml: bytes) -> UpnpDevice | None:
    """The root device of a UPnP device description document."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    device = root.find("{*}device")
    if device is None:
        device = root.find("device")
    if device is None:
        return None

    def field(tag: str) -> str | None:
        el = device.find(f"{{*}}{tag}")
        if el is None:
            el = device.find(tag)
        value = " ".join((el.text or "").split()) if el is not None else ""
        return value or None

    return UpnpDevice(
        friendly_name=field("friendlyName"),
        manufacturer=field("manufacturer"),
        model=field("modelName"),
        model_number=field("modelNumber"),
        device_type=field("deviceType"),
    )
