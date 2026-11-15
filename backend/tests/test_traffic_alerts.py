"""Detections from captured traffic, critical-device alerts, Fingerbank and Wi-Fi."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import insert, select, text

from netmap.cli import main
from netmap.collector import fingerbank, wifi
from netmap.collector.alerts import raise_alerts
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Alert, Device, DeviceIP, DeviceName, Flow, HealthCheck, WifiClient

PLUG, LAPTOP, NAS, PIHOLE, ROUTER = (f"00:dd:00:00:00:0{i}" for i in range(1, 6))
NOW = datetime.now(UTC).replace(second=0, microsecond=0)
MIN = timedelta(minutes=1)


@pytest.fixture
def session(db_env, monkeypatch):
    monkeypatch.setenv("NETMAP_PIHOLE_URL", "http://192.0.2.53")
    get_settings.cache_clear()
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, flows, alerts, alert_rules, collector_cursors, "
                          "health_checks, wifi_clients, device_names CASCADE"))  # fmt: skip
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [
            {"mac": PLUG, "label": "Plug", "category": "iot", "online": True},
            {"mac": LAPTOP, "label": "Laptop", "category": "computer", "online": True},
            {"mac": NAS, "label": "NAS", "category": "infrastructure", "online": True},
            {"mac": PIHOLE, "label": "Pi-hole", "category": "infrastructure", "online": True},
            {"mac": ROUTER, "label": "Router", "category": "infrastructure", "online": True},
        ])  # fmt: skip
        s.execute(insert(DeviceIP), [
            {"mac": PLUG, "ip": "192.0.2.10"}, {"mac": LAPTOP, "ip": "192.0.2.11"},
            {"mac": NAS, "ip": "192.0.2.12"}, {"mac": PIHOLE, "ip": "192.0.2.53"},
            {"mac": ROUTER, "ip": "192.0.2.1"},
        ])  # fmt: skip
        s.add(HealthCheck(name="pihole_client_visibility", status="ok", message="",
                          details={"router_ip": "192.0.2.1"}, checked_at=NOW))  # fmt: skip
        s.commit()
        yield s


def flow(mac, remote, port, *, minutes_ago=5, protocol="tcp", up=1000, down=1000, outbound=True,
         app=None, sni=None, domain=None):  # fmt: skip
    return {"time": NOW - minutes_ago * MIN, "mac": mac, "remote_ip": remote, "remote_port": port,
            "protocol": protocol, "bytes_up": up, "bytes_down": down, "packets": 10,
            "outbound": outbound, "app": app, "sni": sni, "domain": domain,
            "source": "nfstream"}  # fmt: skip


def kinds(session):
    session.expire_all()
    return sorted((a.kind, str(a.mac)) for a in session.scalars(select(Alert)))


def first_round(session):
    """Sets the flows cursor 10 minutes back, as if the engine ran then."""
    raise_alerts(session, get_settings(), NOW - 8 * MIN)


@pytest.mark.db
def test_traffic_detections_raise_alerts_once(session):
    first_round(session)
    session.execute(insert(Flow), [
        flow(PLUG, "198.51.100.8", 53, protocol="udp"),               # public DNS
        flow(PLUG, "203.0.113.9", 443, sni="dns.google"),             # DoH
        flow(PIHOLE, "198.51.100.8", 53, protocol="udp"),             # Pi-hole's own upstream
        flow(LAPTOP, "192.0.2.53", 53, protocol="udp"),               # through Pi-hole: fine
        flow(PLUG, "192.0.2.12", 445),                                # IoT -> NAS: lateral
        flow(LAPTOP, "192.0.2.12", 445),                              # a computer: fine
        flow(PLUG, "192.0.2.1", 80),                                  # the router: fine
        flow(PLUG, "203.0.113.20", 80, app="HTTP", domain="api.plug.example"),
        flow(LAPTOP, "203.0.113.21", 80, app="HTTP", sni="ocsp.digicert.com"),  # harmless
        flow(NAS, "203.0.113.22", 21),                                # FTP, by port
        flow(PLUG, "203.0.113.5", 443, outbound=False, protocol="udp", up=10, down=10),
        flow(LAPTOP, "198.51.100.8", 53, protocol="udp", minutes_ago=1),  # still settling
    ])  # fmt: skip
    session.commit()
    raise_alerts(session, get_settings(), NOW)
    assert kinds(session) == sorted([
        ("dns_bypass", PLUG), ("dns_bypass", PLUG), ("lateral_traffic", PLUG),
        ("unencrypted", PLUG), ("unencrypted", NAS),
    ])  # fmt: skip
    messages = {a.message for a in session.scalars(select(Alert))}
    assert "Plug sent DNS to 198.51.100.8 (port 53) instead of Pi-hole" in messages
    assert "Plug connected to NAS (192.0.2.12) on the LAN (port 445/tcp)" in messages
    assert "NAS used unencrypted FTP to 203.0.113.22 (port 21)" in messages

    # The same things again later the same day: nothing new. The settling one comes in.
    session.execute(insert(Flow), [flow(PLUG, "198.51.100.8", 53, protocol="udp", minutes_ago=-3)])
    session.commit()
    raise_alerts(session, get_settings(), NOW + 6 * MIN)
    assert ("dns_bypass", LAPTOP) in kinds(session) and len(kinds(session)) == 6


@pytest.mark.db
def test_upload_heavy_hours(session, monkeypatch):
    monkeypatch.setenv("NETMAP_UPLOAD_HEAVY_MB", "100")
    get_settings.cache_clear()
    hour = NOW.replace(minute=0) - timedelta(hours=2)  # whole, even at :00
    raise_alerts(session, get_settings(), hour + 2 * MIN)  # cursor at the hour's start
    session.execute(insert(Flow), [
        flow(PLUG, "203.0.113.7", 443, up=150_000_000, down=1_000_000, domain="cloud.example",
             minutes_ago=int((NOW - hour).total_seconds() // 60) - 10),
        flow(NAS, "192.0.2.11", 445, up=900_000_000, down=0,
             minutes_ago=int((NOW - hour).total_seconds() // 60) - 20),  # LAN: doesn't count
        flow(LAPTOP, "203.0.113.8", 443, up=200_000_000, down=100_000_000,
             minutes_ago=int((NOW - hour).total_seconds() // 60) - 30),  # balanced
    ])  # fmt: skip
    session.commit()
    raise_alerts(session, get_settings(), NOW)
    [alert] = [a for a in session.scalars(select(Alert)) if a.kind == "upload_heavy"]
    assert str(alert.mac) == PLUG and "150 MB" in alert.message and "cloud.example" in alert.message


@pytest.mark.db
def test_critical_device_offline_reminded_and_back(session, monkeypatch):
    monkeypatch.setenv("NETMAP_CRITICAL_REMIND_HOURS", "2")
    get_settings.cache_clear()
    cam = session.get(Device, PLUG)
    cam.critical, cam.offline_grace_minutes = True, 10
    cam.last_seen = NOW - 5 * MIN
    session.commit()
    raise_alerts(session, get_settings(), NOW)
    assert kinds(session) == []  # inside its grace period

    raise_alerts(session, get_settings(), NOW + 6 * MIN)
    assert kinds(session) == [("critical_offline", PLUG)]
    a = session.scalars(select(Alert)).one()
    assert a.severity == "critical" and a.notify == "pending" and "11 minutes" in a.message

    raise_alerts(session, get_settings(), NOW + 60 * MIN)
    assert len(kinds(session)) == 1  # not yet time for a reminder
    raise_alerts(session, get_settings(), NOW + 130 * MIN)
    assert kinds(session) == [("critical_offline", PLUG)] * 2

    cam = session.get(Device, PLUG)
    cam.last_seen = NOW + 131 * MIN  # heard again
    session.commit()
    for _ in range(2):
        raise_alerts(session, get_settings(), NOW + 132 * MIN)
    assert kinds(session) == [*[("critical_offline", PLUG)] * 2, ("critical_online", PLUG)]
    back = session.scalars(select(Alert).where(Alert.kind == "critical_online")).one()
    assert back.message == "Plug is back online after 2.3 hours"


@pytest.mark.db
def test_critical_alerts_are_off_for_unmarked_devices(session):
    session.get(Device, LAPTOP).last_seen = NOW - timedelta(days=2)
    session.commit()
    raise_alerts(session, get_settings(), NOW)
    assert kinds(session) == []


# -- Fingerbank -------------------------------------------------------------------------


class FakeFingerbank:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def call(self, method, path, body=None, headers=None):
        self.calls.append(path)
        for fingerprint, (status, body) in self.answers.items():
            if f"dhcp_fingerprint={fingerprint.replace(',', '%2C')}" in path:
                return status, body, {}
        return 404, None, {}


CAM_ANSWER = {
    "device": {"name": "Google Nest Cam", "parents": [{"name": "Internet of Things (IoT)"}]},
    "device_name": "Internet of Things (IoT)/Google Nest Cam", "score": 87,
}  # fmt: skip


@pytest.mark.db
def test_fingerbank_names_devices_and_fills_unknown_categories(session):
    session.execute(insert(Device), [{"mac": "00:dd:00:00:00:a1"}, {"mac": "00:dd:00:00:00:a2"}])
    session.execute(insert(DeviceName), [
        {"mac": "00:dd:00:00:00:a1", "source": "dhcp", "details": {"fingerprint": "1,3,6,15"}},
        {"mac": "00:dd:00:00:00:a2", "source": "dhcp", "details": {"fingerprint": "9,9"}},
        {"mac": LAPTOP, "source": "dhcp", "details": {"fingerprint": "1,3,6,15"}},
    ])  # fmt: skip
    session.commit()
    client = FakeFingerbank({"1,3,6,15": (200, CAM_ANSWER)})
    result = fingerbank.lookup_round(session, client, "k3y", NOW)
    assert result.status == "ok" and result.details == {"identified": 2, "looked_up": 3}
    assert all("mac=00%3Add%3A00%3A00%3A00%3A00" in c for c in client.calls)  # vendor half only
    session.expire_all()
    cam = session.get(Device, "00:dd:00:00:00:a1")
    assert cam.category == "iot" and cam.is_iot and cam.fingerbank["device"] == "Google Nest Cam"
    assert session.get(Device, LAPTOP).category == "computer"  # set by hand: kept
    assert session.get(Device, "00:dd:00:00:00:a2").fingerbank["device"] is None
    assert fingerbank.due(session, NOW) == []  # nothing again until it changes or a month
    assert len(fingerbank.due(session, NOW + timedelta(days=31))) == 3


@pytest.mark.db
def test_fingerbank_bad_key_is_a_warning(session):
    session.execute(insert(DeviceName), [{"mac": PLUG, "source": "dhcp",
                                          "details": {"fingerprint": "1,3"}}])  # fmt: skip
    session.commit()
    result = fingerbank.lookup_round(session, FakeFingerbank({"1,3": (401, None)}), "bad", NOW)
    assert result.status == "warning" and "rejected the API key" in result.message


def test_fingerbank_categories():
    assert fingerbank.category_for(["Apple iPhone", "Phone, Tablet or Wearable"]) == "phone"
    assert fingerbank.category_for(["Roku", "Smart TV/Set-top box"]) == "media"
    assert fingerbank.category_for(["Synology", "Storage Device"]) == "infrastructure"
    assert fingerbank.category_for(["Windows OS"]) == "computer"
    assert fingerbank.category_for(["Mystery"]) is None


# -- Wi-Fi ------------------------------------------------------------------------------


class FakeHttp:
    def __init__(self, routes, base="https://ap.example"):
        self.routes, self.base, self.calls = routes, base, []

    def call(self, method, path, body=None, headers=None):
        self.calls.append((method, path, body, headers))
        handler = self.routes[(method, path)]
        return handler(body) if callable(handler) else handler


def test_unifi_os_clients():
    http = FakeHttp({
        ("POST", "/api/auth/login"): (200, {}, {"X-CSRF-Token": "tok"}),
        ("GET", "/proxy/network/api/s/default/stat/device"): (
            200, {"data": [{"mac": "aa:aa:00:00:00:01", "name": "Hall AP"}]}, {}),
        ("GET", "/proxy/network/api/s/default/stat/sta"): (200, {"data": [
            {"mac": "00:DD:00:00:00:01", "ap_mac": "aa:aa:00:00:00:01", "essid": "home",
             "radio": "na", "channel": 36, "signal": -61, "rx_rate": 866000, "uptime": 600},
            {"mac": "00:dd:00:00:00:03", "is_wired": True},
        ]}, {}),
    })  # fmt: skip
    [s] = wifi.Unifi(http, "viewer", "pw").stations(NOW)
    assert (s.mac, s.ap_name, s.band, s.signal_dbm) == (PLUG, "Hall AP", "5 GHz", -61)
    assert s.connected_since == NOW - timedelta(minutes=10)
    assert http.calls[1][3] == {"X-CSRF-Token": "tok"}


def test_openwrt_clients():
    def ubus(body):
        _, obj, method, _args = body["params"]
        answers = {
            ("session", "login"): {"ubus_rpc_session": "s1"},
            ("system", "board"): {"hostname": "attic-ap"},
            ("iwinfo", "devices"): {"devices": ["phy0-ap0"]},
            ("iwinfo", "info"): {"ssid": "home", "channel": 6, "frequency": 2437,
                                 "bssid": "AA:BB:00:00:00:01"},
            ("iwinfo", "assoclist"): {"results": [{"mac": "00:DD:00:00:00:02", "signal": -70,
                                                   "rx": {"rate": 72200}, "tx": {"rate": 65000},
                                                   "connected_time": 30}]},
        }  # fmt: skip
        return 200, {"jsonrpc": "2.0", "id": body["id"], "result": [0, answers[(obj, method)]]}, {}

    [s] = wifi.OpenWrt(FakeHttp({("POST", "/ubus"): ubus}), "root", "pw").stations(NOW)
    assert (s.mac, s.ap_name, s.ssid, s.band, s.channel, s.signal_dbm) == (
        LAPTOP, "attic-ap", "home", "2.4 GHz", 6, -70)  # fmt: skip
    assert (s.rx_rate_kbps, s.ap_mac) == (72200, "aa:bb:00:00:00:01")


@pytest.mark.db
def test_wifi_clients_not_reported_any_more_are_disconnected(session):
    def station(mac, signal):
        return wifi.Station(mac, "unifi", "AP", None, "home", "5 GHz", 36, signal, None, None, None)

    wifi.store(session, "unifi", [station(PLUG, -60), station(LAPTOP, -50)], NOW)
    wifi.store(session, "unifi", [station(PLUG, -65)], NOW + MIN)
    rows = {str(w.mac): w for w in session.scalars(select(WifiClient))}
    assert rows[PLUG].connected and rows[PLUG].signal_dbm == -65
    assert not rows[LAPTOP].connected and rows[LAPTOP].last_seen == NOW
