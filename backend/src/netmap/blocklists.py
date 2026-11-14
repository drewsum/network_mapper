"""Threat blocklists that domains and the IPs they resolve to are matched against.

- FireHOL level1 (IP networks: attackers, malware, hijacked and bogon ranges), and
  abuse.ch Feodo Tracker (botnet command-and-control IPs) download without an account.
- abuse.ch URLhaus (malware download sites) and ThreatFox (malware and botnet domains
  and IPs) need a free abuse.ch Auth-Key in NETMAP_ABUSECH_AUTH_KEY; without one they
  are skipped.

Private and reserved networks are dropped from every list, so a LAN address never counts
as a hit (FireHOL level1 includes the bogon ranges on purpose, for firewalls).

URLhaus and ThreatFox list malware URLs, and many are on file-sharing platforms (GitHub,
Google Drive, jsDelivr). So a host taken from a URL is dropped when it, or a domain it's
under, is among the most popular sites on the Tranco list; abuse.ch's retired host files
did the same. Domains listed as such (ThreatFox's domain IOCs) are kept.
"""

import contextlib
import csv
import io
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from urllib.parse import urlsplit

from netmap.orgs import normalize_suffix

Network = IPv4Network | IPv6Network


@dataclass
class Entries:
    domains: set[str] = field(default_factory=set)
    networks: set[Network] = field(default_factory=set)

    def __len__(self) -> int:
        return len(self.domains) + len(self.networks)

    def add_host(self, host: str, popular: frozenset[str] = frozenset()) -> None:
        """A hostname or IP from a list; junk and non-public addresses are dropped, and so
        are hostnames that are, or are under, a ``popular`` domain."""
        host = host.strip().strip("[]")
        try:
            self.add_network(host)
            return
        except ValueError:
            pass
        try:
            domain = normalize_suffix(host)
        except ValueError:
            return
        labels = domain.split(".")
        if len(labels) < 2 or any(".".join(labels[i:]) in popular for i in range(len(labels))):
            return
        self.domains.add(domain)

    def add_network(self, value: str) -> None:
        """Raises ValueError if ``value`` isn't an IP or network."""
        net = ip_network(value.strip(), strict=False)
        if net.is_global:
            self.networks.add(net)


def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def parse_netset(text: str, popular: frozenset[str] = frozenset()) -> Entries:
    """One IP or CIDR network a line, '#' comments (FireHOL, Feodo Tracker)."""
    out = Entries()
    for line in _lines(text):
        with contextlib.suppress(ValueError):
            out.add_network(line.split()[0])
    return out


def _csv_rows(text: str) -> tuple[list[str], Iterable[list[str]]]:
    """abuse.ch CSV exports: the header is the last '#' comment line before the data."""
    header: list[str] = []
    data = []
    for line in text.splitlines():
        if line.startswith("#"):
            if "," in line:
                header = next(csv.reader([line.lstrip("# ")]))
        elif line.strip():
            data.append(line)
    return [h.strip().strip('"').lower() for h in header], csv.reader(data, skipinitialspace=True)


def _host_of(value: str) -> str:
    """A URL's host, or host:port without the port."""
    value = value.strip()
    if "://" in value:
        return urlsplit(value).hostname or ""
    if value.startswith("["):  # [IPv6]:port
        return value[1:].partition("]")[0]
    host, sep, port = value.rpartition(":")
    return host if sep and port.isdigit() and host.count(":") == 0 else value


def parse_urlhaus(text: str, popular: frozenset[str] = frozenset()) -> Entries:
    """URLhaus CSV export: the host of each malware URL, unless it's a ``popular`` site."""
    header, rows = _csv_rows(text)
    col = header.index("url") if "url" in header else 2
    out = Entries()
    for row in rows:
        if len(row) > col:
            out.add_host(_host_of(row[col]), popular)
    return out


def parse_threatfox(text: str, popular: frozenset[str] = frozenset()) -> Entries:
    """ThreatFox CSV export: domain, URL and ip:port IOCs (hashes are skipped). A URL's
    host is skipped if it's a ``popular`` site."""
    header, rows = _csv_rows(text)
    value = header.index("ioc_value") if "ioc_value" in header else 2
    kind = header.index("ioc_type") if "ioc_type" in header else 3
    out = Entries()
    for row in rows:
        if len(row) <= max(value, kind):
            continue
        ioc = row[kind].strip()
        if ioc == "url":
            out.add_host(_host_of(row[value]), popular)
        elif ioc in ("domain", "ip:port"):
            out.add_host(_host_of(row[value]))
    return out


@dataclass(frozen=True)
class Blocklist:
    name: str
    label: str
    url: str  # "{key}" is replaced with the abuse.ch Auth-Key
    parse: Callable[[str, frozenset[str]], Entries]
    needs_key: bool = False
    # Lists hosts from URLs, so needs the popular sites to leave out.
    url_hosts: bool = False


LISTS = (
    Blocklist(
        "firehol_level1",
        "FireHOL level1",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        parse_netset,
    ),
    Blocklist(
        "feodo",
        "abuse.ch Feodo Tracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        parse_netset,
    ),
    Blocklist(
        "urlhaus",
        "abuse.ch URLhaus",
        "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        parse_urlhaus,
        needs_key=True,
        url_hosts=True,
    ),
    Blocklist(
        "threatfox",
        "abuse.ch ThreatFox",
        "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
        parse_threatfox,
        needs_key=True,
        url_hosts=True,
    ),
)
BY_NAME = {b.name: b for b in LISTS}
# Domains Pi-hole blocks count as hits on this list (see collector/categories.py).
PIHOLE = "pihole"
LABELS = {PIHOLE: "Pi-hole", **{b.name: b.label for b in LISTS}}

POPULAR_URL = "https://tranco-list.eu/top-1m.csv.zip"
POPULAR_TOP = 100_000


def _unzip(payload: bytes) -> bytes:
    if not payload.startswith(b"PK"):
        return payload
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        if not names:
            raise ValueError("empty zip archive")
        return archive.read(names[0])


def _fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "netmap"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
    return _unzip(payload).decode("utf-8", errors="replace")


def parse_popular(text: str, top: int = POPULAR_TOP) -> frozenset[str]:
    """Tranco's "rank,domain" CSV -> its first ``top`` domains."""
    out = set()
    for line in text.splitlines()[:top]:
        _, _, domain = line.strip().partition(",")
        if domain:
            out.add(domain.lower())
    return frozenset(out)


def download_popular(timeout: float = 120.0) -> frozenset[str]:
    """The most popular sites (Tranco). Raises OSError or ValueError."""
    popular = parse_popular(_fetch(POPULAR_URL, timeout))
    if len(popular) < POPULAR_TOP // 2:
        raise ValueError(f"the Tranco list had only {len(popular)} domains")
    return popular


def download(
    blocklist: Blocklist,
    key: str | None = None,
    popular: frozenset[str] | None = None,
    timeout: float = 120.0,
) -> Entries:
    """Fetch and parse a list. Lists of URL hosts need the ``popular`` sites. Raises
    OSError (URLError, timeouts) or ValueError. An abuse.ch key goes in the URL, so
    errors name the status only, never the URL."""
    if blocklist.needs_key and not key:
        raise ValueError(f"{blocklist.label} needs NETMAP_ABUSECH_AUTH_KEY")
    if blocklist.url_hosts and not popular:
        raise ValueError("no list of popular sites to leave out")
    text = _fetch(blocklist.url.format(key=key or ""), timeout)
    entries = blocklist.parse(text, popular or frozenset())
    if not entries:
        raise ValueError(f"{blocklist.label} download had no entries")
    return entries
