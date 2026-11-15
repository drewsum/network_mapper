"""Which access point each Wi-Fi device is on, and how strong its signal is, from a UniFi
Network controller (NETMAP_UNIFI_*) and/or OpenWrt access points (NETMAP_OPENWRT_*).

- UniFi: logs in with a local account (a read-only "View Only" admin is enough) and reads
  the connected clients and the APs' names. Works with UniFi OS consoles (UDM, Cloud Key,
  UniFi OS Server) and the older self-hosted controller.
- OpenWrt: calls ubus over HTTP (the uhttpd-mod-ubus package, included with LuCI) on each
  AP: iwinfo's list of associated stations per wireless interface.

Clients not reported any more are kept, marked disconnected, so the device page can say
where a device was last seen. How polling goes shows as the "wifi" check.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.collector.base import Source
from netmap.collector.dns import CheckResult, record_check
from netmap.db import get_sessionmaker
from netmap.db.models import WifiClient
from netmap.httpjson import HttpError, JsonClient

log = logging.getLogger(__name__)

CHECK = "wifi"
UNIFI_RADIOS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}
NO_SESSION = "0" * 32  # ubus's anonymous session id, used to log in


class WifiError(Exception):
    pass


@dataclass
class Station:
    mac: str
    source: str
    ap_name: str | None
    ap_mac: str | None
    ssid: str | None
    band: str | None
    channel: int | None
    signal_dbm: int | None
    rx_rate_kbps: int | None
    tx_rate_kbps: int | None
    connected_since: datetime | None


def band_for(mhz: float | None) -> str | None:
    if not mhz:
        return None
    return "2.4 GHz" if mhz < 3000 else "5 GHz" if mhz < 5925 else "6 GHz"


def _int(v) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


# -- UniFi -------------------------------------------------------------------------------


class Unifi:
    def __init__(
        self, client: JsonClient, username: str, password: str, site: str = "default"
    ) -> None:
        self.client, self.username, self.password, self.site = client, username, password, site
        self.prefix: str | None = None  # "/proxy/network" on UniFi OS, "" on the old one
        self.headers: dict[str, str] = {}

    def login(self) -> None:
        creds = {"username": self.username, "password": self.password}
        status, _, headers = self.client.call("POST", "/api/auth/login", creds)
        if status == 200:
            self.prefix = "/proxy/network"
            csrf = headers.get("X-CSRF-Token") or headers.get("x-csrf-token")
            self.headers = {"X-CSRF-Token": csrf} if csrf else {}
            return
        if status in (401, 403):
            raise WifiError("UniFi rejected the login (NETMAP_UNIFI_USERNAME / _PASSWORD)")
        status, _, _ = self.client.call("POST", "/api/login", creds)
        if status == 200:
            self.prefix = ""
            return
        raise WifiError(f"UniFi login failed (HTTP {status})")

    def _get(self, path: str) -> list[dict]:
        if self.prefix is None:
            self.login()
        url = f"{self.prefix}/api/s/{self.site}{path}"
        status, body, _ = self.client.call("GET", url, headers=self.headers)
        if status == 401:
            self.login()
            url = f"{self.prefix}/api/s/{self.site}{path}"
            status, body, _ = self.client.call("GET", url, headers=self.headers)
        if status != 200 or not isinstance(body, dict):
            raise WifiError(f"UniFi answered HTTP {status} for {path}")
        return body.get("data") or []

    def stations(self, now: datetime) -> list[Station]:
        aps = {d.get("mac"): d.get("name") for d in self._get("/stat/device") if d.get("mac")}
        out = []
        for c in self._get("/stat/sta"):
            if c.get("is_wired") or not c.get("mac"):
                continue
            uptime = _int(c.get("uptime"))
            out.append(Station(
                mac=c["mac"].lower(), source="unifi",
                ap_name=aps.get(c.get("ap_mac")) or c.get("last_uplink_name"),
                ap_mac=c.get("ap_mac"), ssid=c.get("essid"),
                band=UNIFI_RADIOS.get(c.get("radio"), c.get("radio")),
                channel=_int(c.get("channel")), signal_dbm=_int(c.get("signal") or c.get("rssi")),
                rx_rate_kbps=_int(c.get("rx_rate")), tx_rate_kbps=_int(c.get("tx_rate")),
                connected_since=now - timedelta(seconds=uptime) if uptime else None,
            ))  # fmt: skip
        return out


# -- OpenWrt -----------------------------------------------------------------------------


class OpenWrt:
    def __init__(self, client: JsonClient, username: str, password: str) -> None:
        self.client, self.username, self.password = client, username, password
        self.session: str | None = None
        self._id = 0

    def _call(self, session: str, obj: str, method: str, args: dict | None = None):
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": "call",
                "params": [session, obj, method, args or {}]}  # fmt: skip
        status, answer, _ = self.client.call("POST", "/ubus", body)
        if status != 200 or not isinstance(answer, dict):
            raise WifiError(f"{self.client.base}: ubus answered HTTP {status}")
        if "error" in answer:
            raise WifiError(f"{self.client.base}: ubus {obj}.{method}: {answer['error']}")
        result = answer.get("result") or [None]
        code = result[0]
        if code == 6:  # UBUS_STATUS_PERMISSION_DENIED: not logged in, or no ACL for it
            return None
        if code != 0:
            raise WifiError(f"{self.client.base}: ubus {obj}.{method} failed ({code})")
        return result[1] if len(result) > 1 else {}

    def login(self) -> None:
        creds = {"username": self.username, "password": self.password}
        result = self._call(NO_SESSION, "session", "login", creds)
        if not result or not result.get("ubus_rpc_session"):
            raise WifiError(f"{self.client.base}: OpenWrt rejected the login")
        self.session = result["ubus_rpc_session"]

    def call(self, obj: str, method: str, args: dict | None = None):
        if self.session is None:
            self.login()
        result = self._call(self.session, obj, method, args)
        if result is None:  # the session expired
            self.login()
            result = self._call(self.session, obj, method, args)
            if result is None:
                raise WifiError(f"{self.client.base}: no permission for {obj}.{method}")
        return result

    def stations(self, now: datetime) -> list[Station]:
        board = self.call("system", "board") or {}
        ap = board.get("hostname") or self.client.base
        out = []
        for dev in (self.call("iwinfo", "devices") or {}).get("devices", []):
            info = self.call("iwinfo", "info", {"device": dev}) or {}
            ap_mac = (info.get("bssid") or "").lower() or None
            for s in (self.call("iwinfo", "assoclist", {"device": dev}) or {}).get("results", []):
                connected = _int(s.get("connected_time"))
                out.append(Station(
                    mac=s["mac"].lower(), source="openwrt", ap_name=ap, ap_mac=ap_mac,
                    ssid=info.get("ssid"), band=band_for(info.get("frequency")),
                    channel=_int(info.get("channel")), signal_dbm=_int(s.get("signal")),
                    rx_rate_kbps=_int((s.get("rx") or {}).get("rate")),
                    tx_rate_kbps=_int((s.get("tx") or {}).get("rate")),
                    connected_since=now - timedelta(seconds=connected) if connected else None,
                ))  # fmt: skip
        return out


# -- storing -----------------------------------------------------------------------------


def store(session: Session, source: str, stations: list[Station], now: datetime) -> None:
    """Upsert ``source``'s stations; its others are now disconnected. Commits."""
    seen = {}
    for s in stations:  # a client on two radios at once: keep the stronger
        if s.mac not in seen or (s.signal_dbm or -999) > (seen[s.mac].signal_dbm or -999):
            seen[s.mac] = s
    if seen:
        rows = [{**s.__dict__, "connected": True, "last_seen": now} for s in seen.values()]
        stmt = insert(WifiClient).values(rows)
        cols = [c for c in rows[0] if c != "mac"]
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[WifiClient.mac], set_={c: stmt.excluded[c] for c in cols}
            )
        )
    session.execute(
        update(WifiClient)
        .where(WifiClient.source == source, WifiClient.connected, WifiClient.mac.notin_(seen))
        .values(connected=False)
    )
    session.commit()


class WifiSource(Source):
    name = "wifi"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.interval_seconds = settings.wifi_poll_seconds
        s = settings
        self.pollers: list[tuple[str, object]] = []
        if s.unifi_url and s.unifi_username and s.unifi_password:
            client = JsonClient(s.unifi_url, s.unifi_verify_tls)
            password = s.unifi_password.get_secret_value()
            self.pollers.append(("unifi", Unifi(client, s.unifi_username, password, s.unifi_site)))
        if s.openwrt_password:
            for url in s.openwrt_hosts:
                client = JsonClient(url, s.openwrt_verify_tls)
                password = s.openwrt_password.get_secret_value()
                self.pollers.append(("openwrt", OpenWrt(client, s.openwrt_username, password)))

    def enabled(self) -> bool:
        return bool(self.pollers)

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        now = datetime.now(UTC)
        stations: dict[str, list[Station]] = {}
        problems = []
        for source, poller in self.pollers:
            try:
                stations.setdefault(source, []).extend(poller.stations(now))
            except (WifiError, HttpError, KeyError, TypeError) as exc:
                problems.append(str(exc))
                stations.pop(source, None)  # partial: don't mark the rest disconnected
                log.warning("wifi: %s", exc)
        with get_sessionmaker()() as session:
            for source, found in stations.items():
                store(session, source, found, now)
            clients = sum(len(v) for v in stations.values())
            aps = len({s.ap_name for v in stations.values() for s in v})
            message = f"{clients} Wi-Fi client{'s' if clients != 1 else ''} on {aps} access point"
            message += "s." if aps != 1 else "."
            result = (
                CheckResult("warning", "; ".join(problems), {"clients": clients})
                if problems
                else CheckResult("ok", message, {"clients": clients, "access_points": aps})
            )
            record_check(session, CHECK, result, now)
