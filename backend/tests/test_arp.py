from ipaddress import IPv4Address, IPv4Network

from netmap.collector.arp import build_request, format_mac, parse_sender

NET = IPv4Network("192.0.2.0/24")
MAC = bytes.fromhex("020000aabbcc")


def frame(sender_ip: str, sender_mac: bytes = MAC) -> bytes:
    return build_request(sender_mac, IPv4Address(sender_ip), IPv4Address("192.0.2.1"))


def test_request_layout():
    f = build_request(MAC, IPv4Address("192.0.2.10"), IPv4Address("192.0.2.20"))
    assert len(f) == 42
    assert f[:6] == b"\xff" * 6 and f[6:12] == MAC and f[12:14] == b"\x08\x06"
    assert f[20:22] == b"\x00\x01"  # who-has
    assert f[38:42] == IPv4Address("192.0.2.20").packed


def test_sender_of_request_and_reply():
    assert parse_sender(frame("192.0.2.10"), NET) == ("02:00:00:aa:bb:cc", "192.0.2.10")
    reply = bytearray(frame("192.0.2.11"))
    reply[21] = 2
    assert parse_sender(bytes(reply), NET) == ("02:00:00:aa:bb:cc", "192.0.2.11")


def test_unusable_frames_are_skipped():
    assert parse_sender(frame("0.0.0.0"), NET) is None  # probe
    assert parse_sender(frame("198.51.100.7"), NET) is None  # off-LAN
    assert parse_sender(frame("192.0.2.255"), NET) is None  # broadcast address
    assert parse_sender(frame("192.0.2.10", b"\xff" * 6), NET) is None
    assert parse_sender(frame("192.0.2.10", bytes.fromhex("01005e000001")), NET) is None
    assert parse_sender(frame("192.0.2.10")[:30], NET) is None  # truncated


def test_format_mac():
    assert format_mac(MAC) == "02:00:00:aa:bb:cc"
