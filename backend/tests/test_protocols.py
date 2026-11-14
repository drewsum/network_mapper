"""Hostname discovery wire formats and per-packet hint extraction."""

import struct
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network

from netmap.collector import protocols as p
from netmap.collector.names import PORTS, clean_name, fetch_description, hints_from_packet

NET = IPv4Network("192.0.2.0/24")
DEVICE_IP = "192.0.2.4"
DEVICE_MAC = b"\xb8\x27\xeb\x00\x00\x04"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def frame(payload, sport, dport, src=DEVICE_IP, dst="192.0.2.255", proto=17, frag=0):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, frag, 64, proto, 0,
        IPv4Address(src).packed, IPv4Address(dst).packed,
    )  # fmt: skip
    return b"\xff" * 6 + DEVICE_MAC + b"\x08\x00" + ip + udp


def run_bpf(prog, pkt):
    """Just enough of a classic BPF interpreter for udp_port_filter's opcodes."""
    a = x = pc = 0
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        if code == 0x28:
            a = int.from_bytes(pkt[k : k + 2], "big")
        elif code == 0x30:
            a = pkt[k]
        elif code == 0x48:
            a = int.from_bytes(pkt[x + k : x + k + 2], "big")
        elif code == 0xB1:
            x = 4 * (pkt[k] & 0x0F)
        elif code == 0x15:
            pc += jt if a == k else jf
        elif code == 0x45:
            pc += jt if a & k else jf
        elif code == 0x06:
            return k
        else:
            raise AssertionError(f"unexpected opcode {code:#x}")


def test_bpf_filter_passes_only_discovery_udp():
    prog = p.udp_port_filter(PORTS)
    assert all(0 <= jt < 256 and 0 <= jf < 256 for _, jt, jf, _ in prog)
    assert run_bpf(prog, frame(b"x", 68, 67))
    assert run_bpf(prog, frame(b"x", 5353, 5353))
    assert run_bpf(prog, frame(b"x", 1900, 40000))  # SSDP search response
    assert run_bpf(prog, frame(b"x", 137, 40000))
    assert not run_bpf(prog, frame(b"x", 445, 50000))  # SMB-sized traffic stays in the kernel
    assert not run_bpf(prog, frame(b"x", 5353, 5353, proto=6))  # TCP
    assert not run_bpf(prog, frame(b"x", 5353, 5353, frag=0x0010))  # later fragment
    assert not run_bpf(prog, b"\xff" * 12 + b"\x08\x06" + b"\x00" * 28)  # ARP


def test_parse_udp():
    pkt = p.parse_udp(frame(b"hello", 5353, 5353, dst=p.MDNS_GROUP) + b"\x00" * 10)  # padding
    assert pkt == p.UdpPacket(
        "b8:27:eb:00:00:04", IPv4Address(DEVICE_IP), IPv4Address(p.MDNS_GROUP), 5353, 5353, b"hello"
    )
    assert p.parse_udp(frame(b"x", 1, 2, proto=6)) is None
    assert p.parse_udp(b"\x00" * 20) is None


def mdns_reply(name="kitchen-pi.local", ip=DEVICE_IP):
    """A PTR answer for ip's reverse name, plus an A record whose name is a pointer."""
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 1)
    rev = p.encode_name(p.reverse_name(ip))
    target = p.encode_name(name)
    ptr = rev + struct.pack("!HHIH", p.TYPE_PTR, 0x8001, 120, len(target)) + target
    pointer = struct.pack("!H", 0xC000 | (len(header) + len(rev) + 10))
    a = pointer + struct.pack("!HHIH", p.TYPE_A, 0x8001, 120, 4) + IPv4Address(ip).packed
    return header + ptr + a


def test_parse_dns_follows_compression():
    msg = p.parse_dns(mdns_reply())
    assert msg.is_response
    assert p.names_for_ip(msg, IPv4Address(DEVICE_IP)) == ["kitchen-pi.local"] * 2
    assert p.names_for_ip(msg, IPv4Address("192.0.2.5")) == []


def test_cast_friendly_name_from_txt():
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    txt = b"".join(bytes([len(s)]) + s for s in (b"id=abc", b"fn=Kitchen speaker", b"md=Nest"))
    name = p.encode_name("Google-Nest-Mini-abc." + p.GOOGLECAST_SERVICE)
    reply = header + name + struct.pack("!HHIH", p.TYPE_TXT, 0x8001, 120, len(txt)) + txt
    msg = p.parse_dns(reply)
    assert msg.records[0].value == "id=abc\nfn=Kitchen speaker\nmd=Nest"
    assert p.cast_friendly_name(msg) == "Kitchen speaker"
    assert p.cast_friendly_name(p.parse_dns(mdns_reply())) is None


def test_parse_dns_rejects_garbage():
    assert p.parse_dns(b"\x00\x01") is None
    loop = struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 0, 0) + b"\xc0\x0c"  # name points at itself
    assert p.parse_dns(loop) is None
    truncated = mdns_reply()[:-3]
    assert p.parse_dns(truncated) is None


def test_build_query_round_trips():
    q = p.build_query(7, [(p.reverse_name(DEVICE_IP), p.TYPE_PTR)], recursion=True)
    qid, flags, qd, *_ = struct.unpack_from("!HHHHHH", q)
    assert (qid, flags, qd) == (7, 0x0100, 1)
    assert p.read_name(q, 12) == ("4.2.0.192.in-addr.arpa", len(q) - 4)
    assert p.ip_from_reverse("4.2.0.192.in-addr.arpa.") == IPv4Address(DEVICE_IP)
    assert p.ip_from_reverse("_services._dns-sd._udp.local") is None


def dhcp_request(options: bytes, op=1):
    fixed = bytes([op, 1, 6, 0]) + b"\x00" * 24 + DEVICE_MAC + b"\x00" * 202
    return fixed + b"\x63\x82\x53\x63" + options + b"\xff"


def test_parse_dhcp():
    opts = b"\x35\x01\x03" + b"\x0c\x0eLiving-Room-Pi" + b"\x37\x04\x01\x03\x06\x0f"
    opts += b"\x3c\x0fandroid-dhcp-14"
    assert p.parse_dhcp(dhcp_request(opts)) == p.DhcpRequest(
        "b8:27:eb:00:00:04", "Living-Room-Pi", "1,3,6,15", "android-dhcp-14"
    )
    assert p.parse_dhcp(dhcp_request(opts, op=2)) is None  # server reply
    assert p.parse_dhcp(dhcp_request(b"\x0c\x40short")).hostname is None  # truncated option


def node_status_reply(names):
    encoded = p._netbios_encode(b"*" + b"\x00" * 15)
    entries = b"".join(
        n.ljust(15).encode() + bytes([s]) + struct.pack("!H", f) for n, s, f in names
    )
    rdata = bytes([len(names)]) + entries + b"\x00" * 6
    return (
        struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        + bytes([32]) + encoded + b"\x00"
        + struct.pack("!HHIH", p.TYPE_NBSTAT, 1, 0, len(rdata)) + rdata
    )  # fmt: skip


def test_netbios_node_status():
    req = p.build_node_status(3)
    assert req[13:45] == b"CK" + b"AA" * 15
    reply = node_status_reply(
        [("WORKGROUP", 0x00, 0x8400), ("DESKTOP-ABC", 0x20, 0x0400), ("DESKTOP-ABC", 0x00, 0x0400)]
    )
    assert p.parse_node_status(reply) == "DESKTOP-ABC"
    assert p.parse_node_status(req) is None  # a request, not a response
    assert p.parse_node_status(reply[:60]) is None


def test_ssdp_location():
    response = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.0.2.4:49152/desc.xml\r\n\r\n"
    assert p.parse_ssdp_location(response) == "http://192.0.2.4:49152/desc.xml"
    alive = b"NOTIFY * HTTP/1.1\r\nNTS: ssdp:alive\r\nLOCATION: http://192.0.2.4/d.xml\r\n\r\n"
    assert p.parse_ssdp_location(alive) == "http://192.0.2.4/d.xml"
    assert p.parse_ssdp_location(alive.replace(b"alive", b"byebye")) is None
    assert p.parse_ssdp_location(p.M_SEARCH) is None


DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
    <friendlyName>Living Room  TV</friendlyName>
    <manufacturer>Example Corp</manufacturer>
    <modelName>X-1000</modelName>
  </device>
</root>"""


def test_parse_description():
    assert p.parse_description(DESCRIPTION) == p.UpnpDevice(
        "Living Room TV", "Example Corp", "X-1000", None, "urn:dial-multiscreen-org:device:dial:1"
    )
    assert p.parse_description(b"<root><device><friendlyName>Bare</friendlyName></device></root>")
    assert p.parse_description(b"not xml") is None
    assert p.parse_description(b"<root/>") is None


def test_fetch_description_only_asks_the_announcing_device():
    assert fetch_description("http://198.51.100.9/desc.xml", DEVICE_IP) is None
    assert fetch_description("file:///etc/passwd", DEVICE_IP) is None


def test_clean_name():
    assert clean_name("kitchen-pi.local.") == "kitchen-pi"
    assert clean_name("  Living   Room ") == "Living Room"
    assert clean_name("3f2504e0-4f89-11d3-9a0c-0305e82c3301.local") is None
    assert clean_name("a1b2c3d4e5f60718293a4b5c") is None
    assert clean_name("localhost") is None
    assert clean_name("pi.hole") is None
    assert clean_name("") is None
    assert clean_name(None) is None


def test_hints_from_dhcp_mdns_netbios_and_ssdp():
    opts = b"\x0c\x0eLiving-Room-Pi\x37\x02\x01\x03"
    (h,), _ = hints_from_packet(
        p.parse_udp(frame(dhcp_request(opts), 68, 67, src="0.0.0.0")), NET, NOW
    )
    assert (h.mac, h.source, h.name, h.details) == (
        "b8:27:eb:00:00:04",
        "dhcp",
        "Living-Room-Pi",
        {"fingerprint": "1,3"},
    )

    (h,), _ = hints_from_packet(p.parse_udp(frame(mdns_reply(), 5353, 5353)), NET, NOW)
    assert (h.source, h.name) == ("mdns", "kitchen-pi")

    reply = node_status_reply([("NAS-BOX", 0, 0x0400)])
    (h,), _ = hints_from_packet(p.parse_udp(frame(reply, 137, 40000)), NET, NOW)
    assert (h.source, h.name) == ("netbios", "NAS-BOX")

    notify = b"NOTIFY * HTTP/1.1\r\nNTS: ssdp:alive\r\nLOCATION: http://192.0.2.4/d.xml\r\n\r\n"
    assert hints_from_packet(p.parse_udp(frame(notify, 1900, 1900)), NET, NOW) == (
        [],
        "http://192.0.2.4/d.xml",
    )


def test_hints_ignore_other_networks_and_unnamed_replies():
    outside = frame(mdns_reply(ip="198.51.100.4"), 5353, 5353, src="198.51.100.4")
    assert hints_from_packet(p.parse_udp(outside), NET, NOW) == ([], None)
    other_ip = frame(mdns_reply(ip="192.0.2.99"), 5353, 5353)  # answers about someone else
    assert hints_from_packet(p.parse_udp(other_ip), NET, NOW) == ([], None)
    query = frame(p.build_query(0, [("x.local", p.TYPE_A)]), 5353, 5353)
    assert hints_from_packet(p.parse_udp(query), NET, NOW) == ([], None)
