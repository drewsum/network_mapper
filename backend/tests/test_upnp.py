"""UPnP IGD port mapping reads, against a fake router on loopback."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netmap.collector import upnp
from netmap.config import Settings

WAN_IP = "urn:schemas-upnp-org:service:WANIPConnection:1"

DESCRIPTION = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList><service>
      <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
      <controlURL>/l3f</controlURL>
    </service></serviceList>
    <deviceList><device>
      <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <deviceList><device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList><service>
          <serviceType>{WAN_IP}</serviceType>
          <controlURL>/ctl/IPConn</controlURL>
        </service></serviceList>
      </device></deviceList>
    </device></deviceList>
  </device>
</root>""".encode()

MAPPINGS = [
    ("51413", "UDP", "192.0.2.10", "51413", "Transmission", "1"),
    ("8443", "TCP", "192.0.2.20", "443", "", "0"),
]


def entry_response(index: int) -> tuple[int, bytes]:
    if index >= len(MAPPINGS):
        fault = (
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>'
            "<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
            '<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode>'
            "<errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError>"
            "</detail></s:Fault></s:Body></s:Envelope>"
        )
        return 500, fault.encode()
    ext, proto, client, internal, desc, enabled = MAPPINGS[index]
    body = (
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        f'<u:GetGenericPortMappingEntryResponse xmlns:u="{WAN_IP}">'
        f"<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>"
        f"<NewProtocol>{proto}</NewProtocol><NewInternalPort>{internal}</NewInternalPort>"
        f"<NewInternalClient>{client}</NewInternalClient><NewEnabled>{enabled}</NewEnabled>"
        f"<NewPortMappingDescription>{desc}</NewPortMappingDescription>"
        "<NewLeaseDuration>0</NewLeaseDuration>"
        "</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"
    )
    return 200, body.encode()


class FakeRouter(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, DESCRIPTION) if self.path == "/rootDesc.xml" else self._send(404, b"")

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        assert self.headers["SOAPAction"] == f'"{WAN_IP}#GetGenericPortMappingEntry"'
        index = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
        self._send(*entry_response(index))


@pytest.fixture
def router():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_reads_every_mapping_until_the_end_of_list_fault(router):
    location = f"{router}/rootDesc.xml"
    service = upnp.find_wan_service(upnp.lan_request(location), location)
    assert service == upnp.WanService(WAN_IP, f"{router}/ctl/IPConn")
    assert upnp.get_mappings(service) == [
        upnp.Mapping(51413, "udp", "192.0.2.10", 51413, "Transmission", True),
        upnp.Mapping(8443, "tcp", "192.0.2.20", 443, None, False),
    ]


def test_other_faults_and_unreachable_routers_raise_oserror(router, monkeypatch):
    monkeypatch.setattr(
        upnp, "parse_mapping_response", lambda xml: (_ for _ in ()).throw(upnp.SoapFault("501"))
    )
    with pytest.raises(OSError, match="501"):
        upnp.get_mappings(upnp.WanService(WAN_IP, f"{router}/ctl/IPConn"))
    with pytest.raises(OSError):
        upnp.lan_request("http://127.0.0.1:9/nothing-here")


def test_find_wan_service_handles_url_base_and_junk():
    xml = DESCRIPTION.replace(b"<device>", b"<URLBase>http://192.0.2.1:5000/</URLBase><device>", 1)
    assert upnp.find_wan_service(xml, "http://192.0.2.1:1900/d.xml").control_url == (
        "http://192.0.2.1:5000/ctl/IPConn"
    )
    no_wan = DESCRIPTION.replace(WAN_IP.encode(), b"urn:schemas-upnp-org:service:Other:1")
    assert upnp.find_wan_service(no_wan, "http://192.0.2.1/") is None
    assert upnp.find_wan_service(b"<html>", "http://192.0.2.1/") is None


def test_soap_request():
    body, headers = upnp.soap_request(
        WAN_IP, "GetGenericPortMappingEntry", {"NewPortMappingIndex": "3"}
    )
    assert b'<u:GetGenericPortMappingEntry xmlns:u="' + WAN_IP.encode() + b'">' in body
    assert b"<NewPortMappingIndex>3</NewPortMappingIndex>" in body
    assert headers["SOAPAction"] == f'"{WAN_IP}#GetGenericPortMappingEntry"'


def test_router_without_upnp_is_reported_once(monkeypatch):
    monkeypatch.setenv("NETMAP_LAN_CIDR", "192.0.2.0/24")
    source = upnp.UpnpSource(Settings())  # type: ignore[call-arg]
    messages = []

    async def nothing():
        return None

    monkeypatch.setattr(source, "_discover", nothing)
    monkeypatch.setattr(upnp.log, "info", lambda msg, *args: messages.append(msg % args))
    asyncio.run(source.run_once())
    asyncio.run(source.run_once())
    assert sum("no UPnP gateway" in m for m in messages) == 1
