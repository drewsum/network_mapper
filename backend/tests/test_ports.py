"""Port scanner probes, against throwaway servers on loopback."""

import asyncio
import socket

from netmap.collector import ports


def test_summarize_banner():
    assert ports.summarize_banner(b"SSH-2.0-dropbear_2022.83\r\n") == "SSH-2.0-dropbear_2022.83"
    http = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: lighttpd/1.4.59\r\n\r\n"
    assert ports.summarize_banner(http) == "lighttpd/1.4.59"
    assert ports.summarize_banner(b"HTTP/1.0 404 Not Found\r\n\r\n") == "HTTP/1.0 404 Not Found"
    assert ports.summarize_banner(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03") is None  # TLS
    assert ports.summarize_banner(b"") is None
    assert len(ports.summarize_banner(b"x" * 500)) == ports.BANNER_MAX


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def serve(handler) -> tuple[asyncio.Server, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_probe_tcp_grabs_banners(monkeypatch):
    async def speaks_first(reader, writer):
        writer.write(b"220 printer FTP ready\r\n")
        await writer.drain()
        writer.close()

    async def http(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.0 200 OK\r\nServer: tiny-iot/2.1\r\n\r\n")
        await writer.drain()
        writer.close()

    async def silent(reader, writer):
        await asyncio.sleep(5)

    async def run():
        ftp, ftp_port = await serve(speaks_first)
        web, web_port = await serve(http)
        quiet, quiet_port = await serve(silent)
        monkeypatch.setattr(ports, "HTTP_PORTS", {web_port})
        monkeypatch.setattr(ports, "BANNER_TIMEOUT", 0.3)
        async with ftp, web, quiet:
            return await asyncio.gather(
                ports.probe_tcp("127.0.0.1", ftp_port),
                ports.probe_tcp("127.0.0.1", web_port),
                ports.probe_tcp("127.0.0.1", quiet_port),
                ports.probe_tcp("127.0.0.1", free_port()),
            )

    assert asyncio.run(run()) == [
        (True, "220 printer FTP ready"),
        (True, "tiny-iot/2.1"),
        (True, None),
        (False, None),
    ]


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


def test_probe_udp_and_scan_host(monkeypatch):
    monkeypatch.setattr(ports, "UDP_TIMEOUT", 0.3)

    async def run():
        loop = asyncio.get_running_loop()
        echo, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        udp_port = echo.get_extra_info("sockname")[1]
        server, tcp_port = await serve(lambda r, w: w.close())
        monkeypatch.setattr(ports, "TCP_SERVICES", {tcp_port: "http", free_port(): "ssh"})
        monkeypatch.setattr(ports, "HTTP_PORTS", set())
        monkeypatch.setattr(
            ports,
            "udp_probes",
            lambda ip: {udp_port: ("ntp", b"x"), free_port(socket.SOCK_DGRAM): ("dns", b"x")},
        )
        try:
            async with server:
                return tcp_port, udp_port, await ports.scan_host("127.0.0.1", asyncio.Semaphore(4))
        finally:
            echo.close()

    tcp_port, udp_port, found = asyncio.run(run())
    assert found == {(tcp_port, "tcp"): ("http", None), (udp_port, "udp"): ("ntp", None)}
