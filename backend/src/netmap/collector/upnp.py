"""Router port mappings from its UPnP Internet Gateway Device (IGD) service.

Devices on the LAN can ask the router to forward an external port to them (game
consoles, cameras, NAS apps); this lists those forwards and which device they point at.
The gateway is found by an SSDP search; its description document names the control URL
of its WAN connection service, which is asked for one mapping at a time
(GetGenericPortMappingEntry) until it reports the end of the list. Routers without UPnP,
or with it switched off, simply never answer the search.
"""

import asyncio
import http.client
import logging
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from urllib.parse import urljoin, urlsplit

from netmap.collector.arp import find_interface, interface_addresses
from netmap.collector.base import Source
from netmap.collector.inventory import record_upnp
from netmap.collector.protocols import SSDP_GROUP, SSDP_PORT, parse_ssdp_location
from netmap.db import get_sessionmaker

log = logging.getLogger(__name__)

IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
)
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
SEARCH_WAIT = 3.0
HTTP_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 256 * 1024
# Stop paging after this many entries, whatever the router says.
MAX_MAPPINGS = 512
# UPnP errors meaning "no entry at this index": the end of the list.
END_OF_LIST = {"713", "714"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# LAN devices only: no proxies from the environment, and no redirects elsewhere.
lan_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def lan_request(url: str, body: bytes | None = None, headers: dict | None = None) -> bytes:
    """GET (or POST ``body`` to) a URL on the LAN. Raises OSError on failure.

    HTTP error responses are returned like any other body: SOAP faults arrive as 500s.
    """
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        resp = lan_opener.open(req, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError as err:
        resp = err
    except (ValueError, http.client.HTTPException) as err:
        raise OSError(str(err)) from err
    with resp:
        data = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise OSError("response too large")
    return data


def search_request(st: str) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {st}\r\n"
        "\r\n"
    ).encode()


@dataclass(frozen=True)
class WanService:
    service_type: str
    control_url: str


def find_wan_service(xml: bytes, location: str) -> WanService | None:
    """The WAN connection service in an IGD description, with an absolute control URL."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    base = root.findtext("{*}URLBase") or location
    for service in root.iter():
        if not service.tag.endswith("}service") and service.tag != "service":
            continue
        stype = (
            service.findtext("{*}serviceType") or service.findtext("serviceType") or ""
        ).strip()
        control = (
            service.findtext("{*}controlURL") or service.findtext("controlURL") or ""
        ).strip()
        if control and any(f":service:{name}:" in stype for name in WAN_SERVICES):
            return WanService(stype, urljoin(base, control))
    return None


def soap_request(service_type: str, action: str, args: dict[str, str]) -> tuple[bytes, dict]:
    params = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{params}</u:{action}></s:Body>'
        "</s:Envelope>"
    ).encode()
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#{action}"',
    }
    return body, headers


@dataclass(frozen=True)
class Mapping:
    external_port: int
    protocol: str
    internal_ip: str
    internal_port: int
    description: str | None
    enabled: bool


class SoapFault(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(f"UPnP error {code}")
        self.code = code


def parse_mapping_response(xml: bytes) -> Mapping | None:
    """One GetGenericPortMappingEntry response. Raises SoapFault for a UPnP error."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    code = next((el.text for el in root.iter() if el.tag.endswith("errorCode")), None)
    if code is not None:
        raise SoapFault(code.strip())
    values = {el.tag.rsplit("}", 1)[-1]: (el.text or "").strip() for el in root.iter()}
    try:
        return Mapping(
            external_port=int(values["NewExternalPort"]),
            protocol=values["NewProtocol"].lower(),
            internal_ip=str(IPv4Address(values["NewInternalClient"])),
            internal_port=int(values["NewInternalPort"]),
            description=values.get("NewPortMappingDescription") or None,
            enabled=values.get("NewEnabled", "1") in ("1", "true"),
        )
    except (KeyError, ValueError):
        return None


def get_mappings(service: WanService) -> list[Mapping]:
    """Every port mapping the gateway has. Raises OSError if it can't be asked."""
    found = []
    for index in range(MAX_MAPPINGS):
        body, headers = soap_request(
            service.service_type, "GetGenericPortMappingEntry", {"NewPortMappingIndex": str(index)}
        )
        try:
            mapping = parse_mapping_response(lan_request(service.control_url, body, headers))
        except SoapFault as fault:
            if fault.code in END_OF_LIST:
                break
            raise OSError(str(fault)) from fault
        if mapping is None:  # unparseable: stop rather than page through garbage
            break
        found.append(mapping)
    return found


class _Responses(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.locations: list[tuple[str, str]] = []

    def datagram_received(self, data: bytes, addr) -> None:
        location = parse_ssdp_location(data)
        if location:
            self.locations.append((addr[0], location))


class UpnpSource(Source):
    name = "upnp"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.upnp_poll_interval_seconds
        self._iface = ""
        self._service: WanService | None = None
        self._reported_missing = False

    def enabled(self) -> bool:
        if sys.platform != "linux" or self.settings.lan_cidr is None:
            return False
        self._iface = self.settings.lan_iface or find_interface(self.settings.lan_cidr) or ""
        return bool(self._iface)

    async def _discover(self) -> WanService | None:
        """The gateway's WAN service, from an SSDP search. Only LAN hosts are trusted."""
        network: IPv4Network = self.settings.lan_cidr
        _, ip = interface_addresses(self._iface)
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_datagram_endpoint(_Responses, local_addr=(str(ip), 0))
        try:
            for st in IGD_TYPES:
                transport.sendto(search_request(st), (SSDP_GROUP, SSDP_PORT))
            await asyncio.sleep(SEARCH_WAIT)
        finally:
            transport.close()
        for src, location in dict.fromkeys(proto.locations):
            host = urlsplit(location).hostname
            if host != src or IPv4Address(src) not in network:
                continue
            try:
                xml = await asyncio.to_thread(lan_request, location)
            except OSError:
                continue
            service = find_wan_service(xml, location)
            if service and urlsplit(service.control_url).hostname == src:
                return service
        return None

    async def run_once(self) -> None:
        if self._service is None:
            self._service = await self._discover()
            if self._service is None:
                if not self._reported_missing:
                    log.info("upnp: no UPnP gateway answered; is UPnP enabled on the router?")
                    self._reported_missing = True
                return
            log.info("upnp: gateway at %s", self._service.control_url)
            self._reported_missing = False
        try:
            mappings = await asyncio.to_thread(get_mappings, self._service)
        except OSError as exc:
            log.warning("upnp: reading port mappings failed, will search again: %s", exc)
            self._service = None
            return
        await asyncio.to_thread(self._record, mappings, datetime.now(UTC))
        log.info("upnp: %d port mappings", len(mappings))

    @staticmethod
    def _record(mappings: list[Mapping], now: datetime) -> None:
        with get_sessionmaker()() as session:
            record_upnp(session, mappings, now)
