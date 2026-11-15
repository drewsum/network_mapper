"""Flows from a router's NetFlow v5/v9 or IPFIX export, on UDP NETMAP_NETFLOW_PORT.

The alternative to a SPAN port when the router can export flows (OPNsense, pfSense,
OpenWrt with softflowd, ...). Have it export from its LAN interface, so records carry the
devices' own addresses rather than the NAT'd WAN one; see docs/span.md.

Records are one-way and say nothing about who opened the connection, so each is turned
around to read client -> server, taking the lower port for the server's (well-known
ports are low; clients pick high ones). v9 and IPFIX records are decoded with the
templates the exporter sends now and then; records arriving before their template are
counted and dropped.
"""

import asyncio
import logging
import queue
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

from netmap.capture.flows import Observation, protocol_name

log = logging.getLogger(__name__)

# Information element IDs (IANA IPFIX registry; NetFlow v9 uses the same numbers).
OCTETS, PACKETS, PROTOCOL, SRC_PORT, SRC_V4, DST_PORT, DST_V4 = 1, 2, 4, 7, 8, 11, 12
END_UPTIME, SRC_V6, DST_V6, SRC_MAC, DST_MAC = 21, 27, 28, 56, 80
OCTETS_TOTAL, PACKETS_TOTAL = 85, 86
END_SECONDS, END_MILLIS = 151, 153
VARIABLE = 65535


@dataclass
class Stats:
    packets: int = 0
    records: int = 0
    no_template: int = 0
    malformed: int = 0
    exporters: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "datagrams": self.packets,
            "records": self.records,
            "dropped_no_template": self.no_template,
            "malformed": self.malformed,
            "exporters": sorted(self.exporters),
        }


Template = list[tuple[int, int]]  # (element id, length)


def _uint(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _mac(b: bytes) -> str | None:
    return ":".join(f"{x:02x}" for x in b) if len(b) == 6 and any(b) else None


def server_first(obs: Observation) -> bool:
    """Whether a one-way record runs server -> client, by its ports."""
    return 0 < obs.src_port < obs.dst_port


def client_to_server(obs: Observation) -> Observation:
    if not server_first(obs):
        return obs
    return Observation(
        time=obs.time, src_ip=obs.dst_ip, dst_ip=obs.src_ip, src_port=obs.dst_port,
        dst_port=obs.src_port, protocol=obs.protocol, bytes_out=obs.bytes_in,
        bytes_in=obs.bytes_out, packets=obs.packets, src_mac=obs.dst_mac, dst_mac=obs.src_mac,
    )  # fmt: skip


class Decoder:
    """Decodes export datagrams, keeping each exporter's templates."""

    def __init__(self) -> None:
        self.templates: dict[tuple, Template] = {}
        self.stats = Stats()

    def decode(self, data: bytes, exporter: str) -> list[Observation]:
        self.stats.packets += 1
        self.stats.exporters.add(exporter)
        try:
            version = _uint(data[:2])
            if version == 5:
                out = self._v5(data)
            elif version == 9:
                out = self._v9(data, exporter)
            elif version == 10:
                out = self._ipfix(data, exporter)
            else:
                raise ValueError(f"version {version}")
        except (ValueError, IndexError, struct.error) as exc:
            self.stats.malformed += 1
            log.debug("netflow: bad datagram from %s: %s", exporter, exc)
            return []
        self.stats.records += len(out)
        return [client_to_server(o) for o in out]

    # -- v5 ------------------------------------------------------------------------------

    def _v5(self, data: bytes) -> list[Observation]:
        count, uptime, secs, nsecs = struct.unpack_from("!HIII", data, 2)
        now = datetime.fromtimestamp(secs + nsecs / 1e9, UTC)
        out = []
        for i in range(count):
            r = data[24 + 48 * i : 24 + 48 * (i + 1)]
            if len(r) < 48:
                raise ValueError("truncated v5 record")
            packets, octets, _first, last, sport, dport = struct.unpack_from("!IIIIHH", r, 16)
            out.append(
                Observation(
                    time=now - timedelta(milliseconds=(uptime - last) % 2**32),
                    src_ip=str(ip_address(r[0:4])), dst_ip=str(ip_address(r[4:8])),
                    src_port=sport, dst_port=dport, protocol=protocol_name(r[38]),
                    bytes_out=octets, bytes_in=0, packets=packets,
                )
            )  # fmt: skip
        return out

    # -- v9 ------------------------------------------------------------------------------

    def _v9(self, data: bytes, exporter: str) -> list[Observation]:
        uptime, secs, _seq, source_id = struct.unpack_from("!IIII", data, 4)
        export = datetime.fromtimestamp(secs, UTC)
        out = []
        for set_id, body in _sets(data, 20):
            if set_id == 0:
                self._templates(body, (exporter, 9, source_id), ipfix=False)
            elif set_id >= 256:
                out += self._records(body, (exporter, 9, source_id, set_id), export, uptime)
        return out

    # -- IPFIX ---------------------------------------------------------------------------

    def _ipfix(self, data: bytes, exporter: str) -> list[Observation]:
        length, secs, _seq, domain = struct.unpack_from("!HIII", data, 2)
        export = datetime.fromtimestamp(secs, UTC)
        out = []
        for set_id, body in _sets(data[:length], 16):
            if set_id == 2:
                self._templates(body, (exporter, 10, domain), ipfix=True)
            elif set_id >= 256:
                out += self._records(body, (exporter, 10, domain, set_id), export, None)
        return out

    def _templates(self, body: bytes, scope: tuple, ipfix: bool) -> None:
        i = 0
        while i + 4 <= len(body):
            template_id, count = struct.unpack_from("!HH", body, i)
            i += 4
            fields: Template = []
            for _ in range(count):
                element, length = struct.unpack_from("!HH", body, i)
                i += 4
                if ipfix and element & 0x8000:  # enterprise-specific: skip its number
                    element = -1
                    i += 4
                fields.append((element, length))
            self.templates[(*scope, template_id)] = fields

    def _records(
        self, body: bytes, key: tuple, export: datetime, uptime: int | None
    ) -> list[Observation]:
        template = self.templates.get(key)
        if template is None:
            self.stats.no_template += 1
            return []
        out = []
        i = 0
        fixed = sum(n for _, n in template if n != VARIABLE)
        while len(body) - i >= max(fixed, 1):
            values: dict[int, bytes] = {}
            for element, length in template:
                if length == VARIABLE:
                    length = body[i]
                    i += 1
                    if length == 255:
                        length = _uint(body[i : i + 2])
                        i += 2
                if i + length > len(body):
                    raise ValueError("truncated record")
                values[element] = body[i : i + length]
                i += length
            obs = _observation(values, export, uptime)
            if obs:
                out.append(obs)
        return out


def _sets(data: bytes, offset: int):
    """(set id, body) for each FlowSet / Set after the header; padding is skipped."""
    i = offset
    while i + 4 <= len(data):
        set_id, length = struct.unpack_from("!HH", data, i)
        if length < 4:
            raise ValueError("bad set length")
        yield set_id, data[i + 4 : i + length]
        i += length


def _observation(v: dict[int, bytes], export: datetime, uptime: int | None) -> Observation | None:
    if SRC_V4 in v and DST_V4 in v:
        src, dst = ip_address(v[SRC_V4]), ip_address(v[DST_V4])
    elif SRC_V6 in v and DST_V6 in v:
        src, dst = ip_address(v[SRC_V6]), ip_address(v[DST_V6])
    else:
        return None  # not an IP flow record (e.g. options data)
    if END_MILLIS in v:
        end = datetime.fromtimestamp(_uint(v[END_MILLIS]) / 1000, UTC)
    elif END_SECONDS in v:
        end = datetime.fromtimestamp(_uint(v[END_SECONDS]), UTC)
    elif END_UPTIME in v and uptime is not None:
        end = export - timedelta(milliseconds=(uptime - _uint(v[END_UPTIME])) % 2**32)
    else:
        end = export
    return Observation(
        time=end, src_ip=str(src), dst_ip=str(dst),
        src_port=_uint(v.get(SRC_PORT, b"")), dst_port=_uint(v.get(DST_PORT, b"")),
        protocol=protocol_name(_uint(v.get(PROTOCOL, b"\x00"))),
        bytes_out=_uint(v.get(OCTETS) or v.get(OCTETS_TOTAL) or b""), bytes_in=0,
        packets=_uint(v.get(PACKETS) or v.get(PACKETS_TOTAL) or b""),
        src_mac=_mac(v.get(SRC_MAC, b"")), dst_mac=_mac(v.get(DST_MAC, b"")),
    )  # fmt: skip


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, decoder: Decoder, out: queue.Queue) -> None:
        self.decoder, self.out = decoder, out

    def datagram_received(self, data: bytes, addr) -> None:
        for obs in self.decoder.decode(data, addr[0]):
            self.out.put(obs)


class NetflowListener:
    """Listens for exports on ``bind``:``port``, putting Observations on ``out``."""

    def __init__(self, bind: str, port: int, out: queue.Queue) -> None:
        self.bind, self.port, self.out = bind, port, out
        self.decoder = Decoder()
        self.transport: asyncio.DatagramTransport | None = None

    @property
    def stats(self) -> Stats:
        return self.decoder.stats

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self.decoder, self.out), local_addr=(self.bind, self.port)
        )
        log.info("netflow: listening on %s:%d/udp", self.bind, self.port)

    def close(self) -> None:
        if self.transport:
            self.transport.close()
