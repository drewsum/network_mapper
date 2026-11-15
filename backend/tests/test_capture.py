"""The capture service: from observations to flow rows, NetFlow/IPFIX decoding, nfstream on
pcaps, live throughput, and packet captures."""

import io
import os
import queue
import socket
import struct
import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from pathlib import Path

import dpkt
import pytest
from sqlalchemy import insert, select, text

from netmap.capture.flows import Buckets, Lan, Observation, load_lan, rows_for, write_rows
from netmap.capture.live import Meter
from netmap.capture.netflow import Decoder
from netmap.capture.pcap import Captures, merged, ring_files, tcpdump_command
from netmap.cli import main
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, DeviceIP, DomainIP, Flow, PacketCapture

LAN = IPv4Network("192.0.2.0/24")
DEV, CAM, ROUTER = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:fe"
T = datetime(2026, 11, 15, 12, 0, 30, tzinfo=UTC)


def obs(src, dst, sport, dport, out=1000, back=5000, **kw) -> Observation:
    return Observation(T, src, dst, sport, dport, "tcp", out, back, 10, **kw)


def lan(**kw) -> Lan:
    return Lan(LAN, {"192.0.2.10": DEV, "192.0.2.20": CAM, "192.0.2.1": ROUTER},
               {DEV, CAM, ROUTER}, ROUTER, **kw)  # fmt: skip


# -- rows -------------------------------------------------------------------------------


def test_outbound_flow_is_one_row_for_the_device():
    [row] = rows_for(obs("192.0.2.10", "203.0.113.5", 50000, 443), lan(), "nfstream")
    assert (row.mac, row.remote_ip, row.remote_port) == (DEV, "203.0.113.5", 443)
    assert (row.bytes_up, row.bytes_down, row.outbound) == (1000, 5000, True)
    assert row.time == datetime(2026, 11, 15, 12, 0, tzinfo=UTC) and row.source == "nfstream"


def test_inbound_flow_keeps_the_server_port():
    [row] = rows_for(obs("203.0.113.5", "192.0.2.20", 40000, 554), lan())
    assert (row.mac, row.remote_port, row.outbound) == (CAM, 554, False)
    assert (row.bytes_up, row.bytes_down) == (5000, 1000)


def test_lan_to_lan_counts_for_both_devices():
    rows = rows_for(obs("192.0.2.20", "192.0.2.10", 40000, 8080), lan())
    assert {(r.mac, r.remote_ip, r.outbound, r.bytes_up) for r in rows} == {
        (CAM, "192.0.2.10", True, 1000),
        (DEV, "192.0.2.20", False, 5000),
    }


def test_broadcast_and_multicast_are_ignored_and_unknown_ips_use_the_frame_mac():
    assert rows_for(obs("192.0.2.10", "224.0.0.251", 5353, 5353), lan()) == []
    assert rows_for(obs("192.0.2.10", "192.0.2.255", 137, 137), lan()) == []
    assert rows_for(obs("198.51.100.1", "203.0.113.5", 1, 2), lan()) == []
    [row] = rows_for(obs("192.0.2.99", "203.0.113.5", 5000, 80, src_mac="02:AA:00:00:00:09"), lan())
    assert row.mac == "02:aa:00:00:00:09"


def test_ipv6_counts_by_frame_mac_but_never_for_the_router():
    o = obs("2001:db8::10", "2001:db8:ffff::1", 50000, 443, src_mac=DEV, dst_mac=ROUTER)
    [row] = rows_for(o, lan())
    assert row.mac == DEV and row.remote_ip == "2001:db8:ffff::1"


def test_buckets_add_up_repeated_reports():
    b = Buckets()
    for _ in range(3):
        b.add(rows_for(obs("192.0.2.10", "203.0.113.5", 50000, 443, sni="a.example"), lan()))
    [row] = b.drain()
    assert (row.bytes_up, row.bytes_down, row.packets, row.sni) == (3000, 15000, 30, "a.example")
    assert b.drain() == []


def test_meter_reports_bytes_per_second(monkeypatch):
    m = Meter()
    m.add(rows_for(obs("192.0.2.10", "203.0.113.5", 50000, 443), lan()))
    m.since = time.monotonic() - 10
    report = m.report()
    assert report["devices"][DEV] == [100, 500] and 9.5 < report["seconds"] < 11
    assert m.report()["devices"] == {}


# -- the flows table --------------------------------------------------------------------


@pytest.fixture
def db(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "TRUNCATE devices, flows, domains, domain_ips, health_checks, packet_captures "
                "CASCADE"
            )
        )
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [{"mac": DEV}, {"mac": CAM}, {"mac": ROUTER}])
        s.execute(insert(DeviceIP), [{"mac": DEV, "ip": "192.0.2.10"},
                                     {"mac": CAM, "ip": "192.0.2.20"}])  # fmt: skip
        s.execute(text("INSERT INTO domains (domain) VALUES ('cdn.example')"))
        s.execute(insert(DomainIP), [{"domain": "cdn.example", "ip": "203.0.113.5"}])
        s.commit()
        yield s


@pytest.mark.db
def test_written_rows_add_to_stored_ones_and_get_domains(db):
    loaded = load_lan(db, LAN)
    assert loaded.macs["192.0.2.10"] == DEV and loaded.devices >= {DEV, CAM}
    for _ in range(2):
        rows = rows_for(obs("192.0.2.10", "203.0.113.5", 50000, 443, app="YouTube"), loaded)
        rows += rows_for(obs("192.0.2.20", "198.51.100.7", 40000, 443, sni="Cam.Example."), loaded)
        assert write_rows(db, rows) == 2
    flows = {str(f.remote_ip): f for f in db.scalars(select(Flow))}
    assert flows["203.0.113.5"].bytes_down == 10000 and flows["203.0.113.5"].packets == 20
    assert flows["203.0.113.5"].domain == "cdn.example" and flows["203.0.113.5"].app == "YouTube"
    assert flows["198.51.100.7"].domain == "cam.example"  # the SNI beats passive DNS


# -- NetFlow / IPFIX --------------------------------------------------------------------


def ip4(a: str) -> bytes:
    return socket.inet_aton(a)


def v5_packet(records) -> bytes:
    header = struct.pack("!HHIIIIBBH", 5, len(records), 100_000, int(T.timestamp()), 0, 1, 0, 0, 0)
    body = b""
    for src, dst, sport, dport, octets, packets in records:
        body += struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH", ip4(src), ip4(dst), ip4("0.0.0.0"), 0, 0, packets,
            octets, 90_000, 99_000, sport, dport, 0, 0, 6, 0, 0, 0, 0, 0, 0,
        )  # fmt: skip
    return header + body


FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4), (56, 6)]


def record(src, dst, sport, dport, octets, packets, mac=b"\x02\x00\x00\x00\x00\x01") -> bytes:
    return ip4(src) + ip4(dst) + struct.pack("!HHBII", sport, dport, 6, octets, packets) + mac


def v9_packet(template: bool, records) -> bytes:
    sets = b""
    if template:
        t = struct.pack("!HH", 256, len(FIELDS)) + b"".join(struct.pack("!HH", *f) for f in FIELDS)
        sets += struct.pack("!HH", 0, 4 + len(t)) + t
    if records:
        data = b"".join(record(*r) for r in records)
        data += b"\x00" * (-len(data) % 4)  # padding
        sets += struct.pack("!HH", 256, 4 + len(data)) + data
    return struct.pack("!HHIIII", 9, 0, 100_000, int(T.timestamp()), 1, 7) + sets


def ipfix_packet(records) -> bytes:
    fields = [*FIELDS, (0x8000 | 100, 4)]  # plus an enterprise element with its number
    t = struct.pack("!HH", 300, len(fields))
    for element, length in fields:
        t += struct.pack("!HH", element, length) + (
            b"\x00\x00\x01\x02" if element & 0x8000 else b""
        )
    data = b"".join(record(*r) + b"\xde\xad\xbe\xef" for r in records)
    sets = struct.pack("!HH", 2, 4 + len(t)) + t + struct.pack("!HH", 300, 4 + len(data)) + data
    return struct.pack("!HHIII", 10, 16 + len(sets), int(T.timestamp()), 1, 3) + sets


def test_netflow_v5_records_read_client_to_server():
    d = Decoder()
    records = [
        ("192.0.2.10", "203.0.113.5", 50000, 443, 1200, 3),
        ("203.0.113.5", "192.0.2.10", 443, 50000, 9000, 7),
    ]
    out = d.decode(v5_packet(records), "192.0.2.1")
    assert [(o.src_ip, o.dst_port, o.bytes_out, o.bytes_in) for o in out] == [
        ("192.0.2.10", 443, 1200, 0),
        ("192.0.2.10", 443, 0, 9000),  # turned around: the low port is the server's
    ]
    assert out[0].time == T - timedelta(seconds=1)  # 1 s before export, by uptime
    b = Buckets()
    for o in out:
        b.add(rows_for(o, lan(), "netflow"))
    [row] = b.drain()
    assert (row.mac, row.bytes_up, row.bytes_down, row.source) == (DEV, 1200, 9000, "netflow")


def test_netflow_v9_needs_its_template_first():
    d = Decoder()
    rec = ("192.0.2.20", "198.51.100.7", 40000, 80, 777, 2)
    assert d.decode(v9_packet(False, [rec]), "192.0.2.1") == []
    assert d.stats.no_template == 1
    d.decode(v9_packet(True, []), "192.0.2.1")
    [o] = d.decode(v9_packet(False, [rec]), "192.0.2.1")
    assert (o.src_ip, o.dst_ip, o.dst_port, o.bytes_out, o.src_mac) == (
        "192.0.2.20", "198.51.100.7", 80, 777, DEV)  # fmt: skip
    assert d.decode(v9_packet(False, [rec]), "198.51.100.99") == []  # templates are per exporter


def test_ipfix_skips_enterprise_elements_and_bad_datagrams_are_counted():
    d = Decoder()
    out = d.decode(ipfix_packet([("192.0.2.10", "203.0.113.5", 50000, 443, 64, 1)] * 2), "x")
    assert len(out) == 2 and out[0].bytes_out == 64
    assert d.decode(b"\x00\x07garbage", "x") == [] and d.stats.malformed == 1


# -- nfstream on pcaps ------------------------------------------------------------------


def frame(src_mac, dst_mac, src, dst, sport, dport, payload=b"", flags=0x18) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload, seq=1)
    ip = dpkt.ip.IP(src=ip4(src), dst=ip4(dst), p=6, data=tcp, ttl=64)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=bytes.fromhex(src_mac.replace(":", "")), dst=bytes.fromhex(dst_mac.replace(":", "")),
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    )  # fmt: skip
    return bytes(eth)


def download_pcap(path: Path, seconds: int, per_second: int, size: int) -> int:
    """A device downloading over HTTP for ``seconds``; returns the bytes the server sent,
    as whole Ethernet frames (what nfstream counts, like a switch port's counters)."""
    t0 = time.time() - seconds - 60
    a, b = "192.0.2.10", "203.0.113.5"
    get = b"GET /big HTTP/1.1\r\nHost: dl.example\r\n\r\n"
    packets = [
        (frame(DEV, ROUTER, a, b, 50000, 80, flags=0x02), t0, False),
        (frame(ROUTER, DEV, b, a, 80, 50000, flags=0x12), t0 + 0.01, True),
        (frame(DEV, ROUTER, a, b, 50000, 80, get), t0 + 0.02, False),
    ]
    for i in range(seconds * per_second):
        data = frame(ROUTER, DEV, b, a, 80, 50000, b"x" * size)
        packets.append((data, t0 + 0.05 + i / per_second, True))
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        for pkt, ts, _ in packets:
            w.writepkt(pkt, ts)
    return sum(len(pkt) for pkt, _, from_server in packets if from_server)


def nfstream_or_skip():
    try:
        import nfstream  # noqa: F401
    except ImportError as exc:  # Windows without Npcap: run these in the Linux image
        pytest.skip(f"nfstream can't load here: {exc}")


def test_nfstream_bytes_match_what_was_sent(tmp_path):
    """A 35-second download, reported every 10 seconds, adds up to exactly what was sent."""
    nfstream_or_skip()
    from netmap.capture.span import SpanCapture

    pcap = tmp_path / "download.pcap"
    sent = download_pcap(pcap, seconds=35, per_second=20, size=1400)
    out: queue.Queue = queue.Queue()
    span = SpanCapture(str(pcap), 10, out)
    span.start()
    span.thread.join(60)
    observed = []
    while not out.empty():
        observed.append(out.get())
    assert len(observed) >= 3  # reported in pieces, not once at the end
    b = Buckets()
    for o in observed:
        b.add(rows_for(o, lan()))
    rows = b.drain()
    assert {r.mac for r in rows} == {DEV}
    assert sum(r.bytes_down for r in rows) == sent
    assert {r.app for r in rows} == {"HTTP"} and {r.sni for r in rows} == {"dl.example"}
    assert {(r.remote_port, r.outbound) for r in rows} == {(80, True)}


def test_later_pieces_of_a_connection_keep_its_direction_and_labels():
    from netmap.capture.span import Connections

    c = Connections(size=2)
    first = obs("192.0.2.10", "203.0.113.5", 50000, 80, app="HTTP", sni="dl.example")
    assert c.apply(first) == first
    # Mid-download, nfstream's next piece starts with the server's packet.
    later = c.apply(obs("203.0.113.5", "192.0.2.10", 80, 50000, out=9000, back=40, app="Protobuf"))
    assert (later.src_ip, later.dst_port, later.bytes_out, later.bytes_in) == (
        "192.0.2.10", 80, 40, 9000)  # fmt: skip
    assert (later.app, later.sni) == ("HTTP", "dl.example")
    [row] = rows_for(later, lan())
    assert (row.remote_port, row.outbound, row.bytes_down) == (80, True, 9000)

    other = obs("192.0.2.10", "203.0.113.5", 50001, 443)
    assert c.apply(other) == other  # nothing known yet
    assert (
        c.apply(obs("192.0.2.10", "203.0.113.5", 50001, 443, sni="late.example")).sni
        == "late.example"
    )
    assert c.apply(other).sni == "late.example"


# -- packet captures --------------------------------------------------------------------


def write_pcap(path: Path, n: int, t0: float) -> None:
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        for i in range(n):
            w.writepkt(frame(DEV, ROUTER, "192.0.2.10", "203.0.113.5", 5000, 80, b"p"), t0 + i)


def test_ring_files_merge_into_one_pcap_in_order(tmp_path):
    for n, (name, count) in enumerate((("capture-7.pcap1", 2), ("capture-7.pcap0", 3))):
        write_pcap(tmp_path / name, count, 1000.0 + 10 * n)
        os.utime(tmp_path / name, (1000.0 + n, 1000.0 + n))  # the ring wrapped: 1 is older
    (tmp_path / "capture-70.pcap0").write_bytes(b"other capture")
    files = ring_files(tmp_path, 7)
    assert [p.name for p in files] == ["capture-7.pcap1", "capture-7.pcap0"]
    times = [ts for ts, _ in dpkt.pcap.Reader(io.BytesIO(b"".join(merged(files))))]
    assert times == sorted(times) and len(times) == 5


def test_tcpdump_ring_is_bounded():
    cmd = tcpdump_command("tcpdump", "eth1", DEV, Path("/c/capture-3.pcap"), 20_000_000)
    assert cmd[cmd.index("-C") + 1] == "5" and cmd[cmd.index("-W") + 1] == "4"

    def ring(max_bytes):
        c = tcpdump_command("tcpdump", "eth1", DEV, Path("/c/x.pcap"), max_bytes)
        return int(c[c.index("-W") + 1]), int(c[c.index("-C") + 1])

    assert ring(2_000_000) == (2, 1)  # never more than asked for
    assert ring(1_000_000) == (1, 1)
    assert ring(5_000_000) == (4, 1)
    assert cmd[-3:] == ["ether", "host", DEV]


class FakeProc:
    def __init__(self, cmd, **_):
        self.cmd, self.code = cmd, None
        Path(cmd[cmd.index("-w") + 1] + "0").write_bytes(b"x" * 100)
        self.stderr = io.StringIO("12 packets captured\n")

    def poll(self):
        return self.code

    def send_signal(self, _):
        self.code = 0

    def wait(self, timeout=None):
        return self.code


@pytest.mark.db
def test_captures_run_until_their_time_limit_or_stop(db, tmp_path, monkeypatch):
    import netmap.capture.pcap as pcap

    monkeypatch.setattr(pcap.subprocess, "Popen", FakeProc)
    now = [datetime(2026, 11, 15, tzinfo=UTC)]
    c = Captures("eth1", tmp_path, keep=1, clock=lambda: now[0])
    db.execute(text("TRUNCATE packet_captures"))
    db.add_all([PacketCapture(mac=DEV, max_seconds=60, max_bytes=10**6),
                PacketCapture(mac=CAM, max_seconds=600, max_bytes=10**6)])  # fmt: skip
    db.commit()
    c.tick(db)
    first, second = db.scalars(select(PacketCapture).order_by(PacketCapture.id)).all()
    assert first.status == second.status == "running"

    now[0] += timedelta(seconds=61)
    second.ended_at = now[0]  # Stop pressed in the UI
    db.commit()
    c.tick(db)
    db.refresh(first)
    db.refresh(second)
    assert (first.status, first.packets, first.bytes) == ("done", 12, 100)
    assert second.status == "stopped"
    assert ring_files(tmp_path, first.id) == []  # only the newest finished one (keep=1) stays
    assert ring_files(tmp_path, second.id)
