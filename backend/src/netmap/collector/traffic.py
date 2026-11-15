"""Detections from captured traffic (the ``flows`` table, filled by `netmap capture`):

- DNS that skips Pi-hole: plain DNS (port 53) or DNS over TLS (853) to any server but
  Pi-hole, and DNS over HTTPS to well-known resolvers;
- lateral traffic: a device other than a phone or computer opening a connection to another
  device on the LAN (not the router or Pi-hole);
- upload-heavy hours: a device sending more than NETMAP_UPLOAD_HEAVY_MB to the internet in
  an hour, and NETMAP_UPLOAD_HEAVY_RATIO times what it received;
- unencrypted protocols to the internet: HTTP, Telnet, FTP, POP3, IMAP, SMTP, MQTT.

Each looks at the minutes written since its last round, leaving the newest two (still being
added to). Each thing alerts once a day per device; lateral traffic once a month per pair.
Nothing is found without captured traffic.
"""

import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from ipaddress import ip_address
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.orm import Session

from netmap.collector.baseline import UNWATCHED_CATEGORIES
from netmap.collector.dns import VISIBILITY_CHECK
from netmap.config import Settings
from netmap.db.models import CollectorCursor

CURSOR = "alerts.flows"
SETTLE = timedelta(minutes=2)
DAILY = timedelta(hours=24)
MONTHLY = timedelta(days=30)

# Resolvers' DNS-over-HTTPS hostnames. nDPI also names DoH/DoT traffic it recognizes.
DOH_HOSTS = (
    "dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net",
    "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard-dns.com", "dns.adguard.com",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.mullvad.net", "doh.libredns.gr",
)  # fmt: skip
DOH_APPS = ("DoH_DoT", "DNSoverHTTPS")

# nDPI application -> what to call it; and, when nDPI has no name, the usual port.
UNENCRYPTED_APPS = {
    "HTTP": "HTTP", "Telnet": "Telnet", "FTP_CONTROL": "FTP", "FTP_DATA": "FTP",
    "POP3": "POP3", "IMAP": "IMAP", "SMTP": "SMTP", "MQTT": "MQTT",
}  # fmt: skip
UNENCRYPTED_PORTS = {
    ("tcp", 80): "HTTP", ("tcp", 23): "Telnet", ("tcp", 21): "FTP", ("tcp", 110): "POP3",
    ("tcp", 143): "IMAP", ("tcp", 25): "SMTP", ("tcp", 1883): "MQTT",
}  # fmt: skip
# Plain HTTP that's fine: certificate status and revocation checks, and the captive-portal
# checks every phone and computer makes.
HARMLESS_HTTP = (
    "ocsp.", "crl.", ".pki.goog", "ocsp-", "connectivitycheck.", "captive.apple.com",
    "msftconnecttest.com", "msftncsi.com", "detectportal.firefox.com", "nmcheck.gnome.org",
    "clients3.google.com", "ctldl.windowsupdate.com", "network-test.debian.org",
    "connectivity-check.ubuntu.com",
)  # fmt: skip


@dataclass
class Hit:
    """A detection, for the alert engine: who, what, and the details to keep."""

    time: datetime
    mac: str
    kind: str
    message: str
    details: dict
    dedup_key: str
    window: timedelta  # repeats of dedup_key inside it are skipped


def span(session: Session, now: datetime) -> tuple[datetime, datetime] | None:
    """Minutes [start, end) to look at this round, moving the cursor on; the first round
    only sets the cursor."""
    end = (now - SETTLE).replace(second=0, microsecond=0)
    cursor = session.get(CollectorCursor, CURSOR)
    if cursor is None:
        session.add(CollectorCursor(name=CURSOR, value=int(end.timestamp())))
        return None
    start = datetime.fromtimestamp(cursor.value, UTC)
    if end <= start:
        return None
    cursor.value = int(end.timestamp())
    return start, end


@lru_cache(maxsize=8)
def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def infrastructure_ips(session: Session, settings: Settings) -> set[str]:
    """The router's and Pi-hole's IPs: talking to them is expected."""
    ips = set()
    router = session.scalar(
        text("SELECT details->>'router_ip' FROM health_checks WHERE name = :n"),
        {"n": VISIBILITY_CHECK},
    )
    if router:
        ips.add(router)
    host = urlsplit(settings.pihole_url or "").hostname
    if host:
        try:
            ips.add(str(ip_address(host)))
        except ValueError:
            if resolved := _resolve(host):
                ips.add(resolved)
    return ips


def _macs_at(session: Session, ips: set[str]) -> set[str]:
    if not ips:
        return set()
    rows = session.execute(
        text("SELECT DISTINCT mac::text FROM device_ips WHERE host(ip) = ANY(:ips)"),
        {"ips": sorted(ips)},
    )
    return {r[0] for r in rows}


_FLOWS = text("""
    SELECT f.mac::text AS mac, host(f.remote_ip) AS remote, f.remote_port AS port, f.protocol,
           f.app, coalesce(f.sni, f.domain) AS name, f.outbound, max(f.time) AS last,
           sum(f.bytes_up)::bigint AS up, sum(f.bytes_down)::bigint AS down,
           coalesce(dv.category, 'unknown') AS category
    FROM flows f
    LEFT JOIN devices dv ON dv.mac = f.mac
    WHERE f.time >= :start AND f.time < :end AND dv.merged_into IS NULL
    GROUP BY 1, 2, 3, 4, 5, 6, 7, dv.category
""")
_UPLOADS = text("""
    SELECT f.mac::text AS mac, sum(f.bytes_up)::bigint AS up, sum(f.bytes_down)::bigint AS down,
           (array_agg(coalesce(f.domain, host(f.remote_ip)) ORDER BY f.bytes_up DESC))[1] AS top
    FROM flows f
    WHERE f.time >= :start AND f.time < :end AND NOT (f.remote_ip <<= CAST(:lan AS cidr))
    GROUP BY 1
""")


def _is_doh(name: str | None, app: str | None) -> bool:
    return (app in DOH_APPS) or (name or "").lower().rstrip(".") in DOH_HOSTS


def _unencrypted(protocol: str, port: int, app: str | None, name: str | None) -> str | None:
    what = UNENCRYPTED_APPS.get(app) if app else UNENCRYPTED_PORTS.get((protocol, port))
    if what == "HTTP" and any(h in (name or "").lower() for h in HARMLESS_HTTP):
        return None
    return what


def detect(session: Session, settings: Settings, now: datetime, name_of) -> list[Hit]:
    """What the minutes since the last round show. ``name_of(mac)`` names a device."""
    window = span(session, now)
    if window is None or settings.lan_cidr is None:
        return []
    start, end = window
    lan = settings.lan_cidr
    infra = infrastructure_ips(session, settings)
    infra_macs = _macs_at(session, infra)
    hits: list[Hit] = []
    for f in session.execute(_FLOWS, {"start": start, "end": end}).mappings():
        if not f["outbound"]:
            continue
        remote = ip_address(f["remote"])
        remote_lan = remote.version == 4 and remote in lan
        who = name_of(f["mac"])
        to = f["name"] or f["remote"]
        # DNS that doesn't go through Pi-hole. Pi-hole's own upstream queries are its job.
        if f["mac"] not in infra_macs and f["remote"] not in infra:
            if f["port"] in (53, 853) and f["protocol"] in ("udp", "tcp"):
                how = "DNS over TLS" if f["port"] == 853 else "DNS"
                hits.append(Hit(
                    f["last"], f["mac"], "dns_bypass",
                    f"{who} sent {how} to {to} (port {f['port']}) instead of Pi-hole",
                    {"source": "traffic", "remote": f["remote"], "port": f["port"],
                     "protocol": f["protocol"], "name": f["name"]},
                    f"dns_bypass:{f['mac']}:traffic:{f['remote']}:{f['port']}", DAILY,
                ))  # fmt: skip
            elif _is_doh(f["name"], f["app"]) and not remote_lan:
                hits.append(Hit(
                    f["last"], f["mac"], "dns_bypass",
                    f"{who} used DNS over HTTPS ({to}), which Pi-hole can't see or filter",
                    {"source": "traffic", "remote": f["remote"], "port": f["port"],
                     "protocol": f["protocol"], "name": f["name"], "app": f["app"]},
                    f"dns_bypass:{f['mac']}:doh:{to}", DAILY,
                ))  # fmt: skip
        if remote_lan:
            if f["category"] not in UNWATCHED_CATEGORIES and f["remote"] not in infra:
                peer = name_of_ip(session, f["remote"], name_of)
                hits.append(Hit(
                    f["last"], f["mac"], "lateral_traffic",
                    f"{who} connected to {peer} on the LAN (port {f['port']}/{f['protocol']})",
                    {"remote": f["remote"], "peer": peer, "port": f["port"],
                     "protocol": f["protocol"], "app": f["app"],
                     "bytes": int(f["up"] + f["down"])},
                    f"lateral_traffic:{f['mac']}:{f['remote']}:{f['port']}/{f['protocol']}",
                    MONTHLY,
                ))  # fmt: skip
            continue
        what = _unencrypted(f["protocol"], f["port"], f["app"], f["name"])
        if what:
            hits.append(Hit(
                f["last"], f["mac"], "unencrypted",
                f"{who} used unencrypted {what} to {to} (port {f['port']})",
                {"protocol_name": what, "remote": f["remote"], "port": f["port"],
                 "name": f["name"], "app": f["app"]},
                f"unencrypted:{f['mac']}:{what}", DAILY,
            ))  # fmt: skip
    hits += upload_heavy(session, settings, start, end, name_of)
    return hits


def upload_heavy(
    session: Session, settings: Settings, start: datetime, end: datetime, name_of
) -> list[Hit]:
    """Each whole hour that ended in [start, end), checked for upload-heavy devices."""
    hits = []
    hour = start.replace(minute=0) + (timedelta(hours=1) if start.minute else timedelta())
    limit = settings.upload_heavy_mb * 1_000_000
    while hour + timedelta(hours=1) <= end:
        params = {"start": hour, "end": hour + timedelta(hours=1), "lan": str(settings.lan_cidr)}
        rows = session.execute(_UPLOADS, params).mappings()
        for r in rows:
            if r["up"] > limit and r["up"] >= settings.upload_heavy_ratio * r["down"]:
                mb = r["up"] / 1_000_000
                hits.append(Hit(
                    hour + timedelta(hours=1), r["mac"], "upload_heavy",
                    f"{name_of(r['mac'])} sent {mb:,.0f} MB to the internet in an hour, "
                    f"mostly to {r['top']}",
                    {"bytes_up": int(r["up"]), "bytes_down": int(r["down"]), "top": r["top"],
                     "hour": hour.isoformat()},
                    f"upload_heavy:{r['mac']}", DAILY,
                ))  # fmt: skip
        hour += timedelta(hours=1)
    return hits


def name_of_ip(session: Session, ip: str, name_of) -> str:
    mac = session.scalar(
        text(
            "SELECT mac::text FROM device_ips WHERE host(ip) = :ip ORDER BY last_seen DESC LIMIT 1"
        ),
        {"ip": ip},
    )
    return f"{name_of(mac)} ({ip})" if mac else ip
