"""The alert engine, rules, notifications and the DNS bypass check, against a real DB."""

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, select, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.alerts import LABELS_BY_KIND, Rules, raise_alerts
from netmap.collector.notify import NotifyError, compose, send_pending
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import (
    Alert,
    AlertRule,
    Device,
    DeviceEvent,
    DnsQuery,
    Domain,
    UpnpMapping,
)
from netmap.db.policies import refresh_all_aggregates

pytestmark = pytest.mark.db

PLUG, PHONE, CAM = "00:cc:00:00:00:01", "00:cc:00:00:00:02", "00:cc:00:00:00:03"
NOW = datetime.now(UTC).replace(microsecond=0)
HOUR = timedelta(hours=1)


def q(mac, domain, time):
    return {"time": time, "client_ip": "192.0.2.9", "mac": mac, "domain": domain,
            "query_type": "A", "status": "allowed"}  # fmt: skip


def refresh():
    with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        refresh_all_aggregates(conn)


@pytest.fixture
def session(db_env, monkeypatch):
    monkeypatch.setenv("NETMAP_PIHOLE_URL", "http://pihole.invalid")
    get_settings.cache_clear()
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "TRUNCATE devices, device_events, dns_queries, domains, alerts, alert_rules,"
                " collector_cursors, upnp_mappings, health_checks CASCADE"
            )
        )
    with get_sessionmaker()() as s:
        s.execute(
            insert(Device),
            [
                {"mac": PLUG, "label": "Plug", "category": "iot", "online": True,
                 "first_seen": NOW - 48 * HOUR},
                {"mac": PHONE, "label": "Phone", "category": "phone", "online": True,
                 "first_seen": NOW - 48 * HOUR},
                {"mac": CAM, "label": "Cam", "category": "iot", "online": True,
                 "first_seen": NOW - 48 * HOUR},
            ],
        )  # fmt: skip
        s.commit()
        yield s


def alerts(session):
    session.expire_all()
    return session.scalars(select(Alert).order_by(Alert.id)).all()


def event(session, mac, kind, **kw):
    session.execute(insert(DeviceEvent), [{"time": NOW, "mac": mac, "kind": kind, **kw}])
    session.commit()


def settings():
    return get_settings()


def test_events_raise_alerts_by_default_action(session):
    event(session, PLUG, "new_device", ip="192.0.2.1")
    # The first round starts the cursor: history raises nothing.
    assert raise_alerts(session, settings(), NOW) == 0
    event(session, PLUG, "offline")
    event(session, PHONE, "offline")  # muted: phones come and go
    event(session, PLUG, "new_country", details={"key": "DE"})
    event(session, PLUG, "new_asn", details={"key": "64500"})  # muted by default
    event(session, PLUG, "new_domain", details={"key": "example.com"})
    event(session, PLUG, "online")  # not an alert kind
    assert raise_alerts(session, settings(), NOW) == 3
    got = {(a.kind, a.severity, a.notify, a.message) for a in alerts(session)}
    assert got == {
        ("offline", "info", None, "Plug went offline"),
        ("new_country", "warning", "pending", "Plug reached a new country: DE"),
        ("new_domain", "info", None, "Plug looked up a new site: example.com"),
    }
    assert raise_alerts(session, settings(), NOW) == 0


def test_rules_most_specific_wins():
    rules = Rules(
        {(PLUG, "offline"): "notify", (PLUG, None): "mute", (None, "new_device"): "record"}
    )
    assert rules.action(PLUG, "offline", "iot") == "notify"
    assert rules.action(PLUG, "new_device", "iot") == "mute"
    assert rules.action(CAM, "new_device", "iot") == "record"
    assert rules.action(CAM, "blocklist_hit", "iot") == "notify"
    assert rules.action(PHONE, "offline", "phone") == "mute"
    assert Rules({(None, None): "record"}).action(PHONE, "offline", "phone") == "record"


def test_rules_and_snoozes_apply(session):
    raise_alerts(session, settings(), NOW)
    session.execute(
        insert(AlertRule),
        [
            {"mac": PLUG, "kind": "new_country", "action": "mute"},
            {"mac": CAM, "kind": "new_country", "action": "mute", "until": NOW - HOUR},
            {"mac": PHONE, "kind": "offline", "action": "notify"},
        ],
    )
    for mac in (PLUG, CAM):
        event(session, mac, "new_country", details={"key": "FR"})
    event(session, PHONE, "offline")
    raise_alerts(session, settings(), NOW)
    assert {(str(a.mac), a.kind, a.notify) for a in alerts(session)} == {
        (CAM, "new_country", "pending"),  # its snooze lapsed
        (PHONE, "offline", "pending"),
    }


def test_threat_lookups_alert_once_a_day(session):
    session.execute(insert(Domain), [{"domain": "bad.example", "is_blocklisted": True,
                                      "blocklists": ["pihole", "urlhaus"]}])  # fmt: skip
    session.execute(insert(DnsQuery), [q(PLUG, "bad.example", NOW - 2 * HOUR)])
    session.commit()
    refresh()
    raise_alerts(session, settings(), NOW)
    raise_alerts(session, settings(), NOW + HOUR)
    [hit] = alerts(session)
    assert (hit.kind, hit.severity, hit.notify) == ("blocklist_hit", "critical", "pending")
    assert (
        hit.message
        == "Plug looked up bad.example, which is on a threat blocklist (abuse.ch URLhaus)"
    )
    assert hit.details["domain"] == "bad.example"
    # A day on, only a new lookup raises it again.
    raise_alerts(session, settings(), NOW + 25 * HOUR)
    assert len(alerts(session)) == 1
    session.execute(insert(DnsQuery), [q(PLUG, "bad.example", NOW + 24 * HOUR)])
    session.commit()
    refresh()
    raise_alerts(session, settings(), NOW + 26 * HOUR)
    assert len(alerts(session)) == 2


def test_new_upnp_forwards_alert(session):
    def forward(port):
        session.execute(
            insert(UpnpMapping),
            [{"external_port": port, "protocol": "TCP", "internal_ip": "192.0.2.3",
              "internal_port": 554, "description": "camera", "mac": CAM, "first_seen": NOW}],
        )  # fmt: skip
        session.commit()

    forward(8000)
    raise_alerts(session, settings(), NOW)  # already there: nothing
    forward(8554)
    raise_alerts(session, settings(), NOW)
    [a] = alerts(session)
    assert a.kind == "upnp_forward" and a.notify == "pending"
    assert a.message == (
        "Cam opened port 8554/TCP on the router to the internet for camera (UPnP), "
        "forwarded to 192.0.2.3:554"
    )


def quiet_cam(session):
    """Cam has been online two days without a lookup; the plug keeps Pi-hole busy."""
    session.execute(insert(DeviceEvent), [{"time": NOW - 40 * HOUR, "mac": CAM, "kind": "online"}])
    session.execute(insert(DnsQuery), [q(PLUG, f"d{i}.example", NOW - i * HOUR) for i in range(20)])
    session.commit()
    refresh()


def test_quiet_iot_devices_may_bypass_pihole(session):
    quiet_cam(session)
    raise_alerts(session, settings(), NOW)
    [a] = alerts(session)
    assert (str(a.mac), a.kind, a.notify) == (CAM, "dns_bypass", "pending")
    assert a.details["lookups"] == 0
    # Once, until it looks something up or comes back online.
    raise_alerts(session, settings(), NOW + HOUR)
    assert len(alerts(session)) == 1

    client = TestClient(create_app())
    assert client.get(f"/api/devices/{CAM}/dns-check").json()["status"] == "silent"
    assert client.get(f"/api/devices/{PLUG}/dns-check").json()["status"] == "ok"
    assert client.get(f"/api/devices/{PHONE}/dns-check").json()["status"] == "not_iot"


def test_bypass_threshold_is_configurable_and_needs_pihole(session, monkeypatch):
    quiet_cam(session)
    monkeypatch.setenv("NETMAP_DNS_BYPASS_HOURS", "48")  # online 40 h: too soon to tell
    get_settings.cache_clear()
    raise_alerts(session, settings(), NOW)
    assert alerts(session) == []
    client = TestClient(create_app())
    assert client.get(f"/api/devices/{CAM}/dns-check").json()["status"] == "too_soon"

    monkeypatch.setenv("NETMAP_DNS_BYPASS_HOURS", "24")
    monkeypatch.setenv("NETMAP_DNS_BYPASS_MIN_LOOKUPS", "0")  # off
    get_settings.cache_clear()
    raise_alerts(session, settings(), NOW)
    assert alerts(session) == []

    monkeypatch.delenv("NETMAP_DNS_BYPASS_MIN_LOOKUPS")
    monkeypatch.delenv("NETMAP_PIHOLE_URL")  # no Pi-hole, no telling
    get_settings.cache_clear()
    raise_alerts(session, settings(), NOW)
    assert alerts(session) == []
    check = TestClient(create_app()).get(f"/api/devices/{CAM}/dns-check").json()
    assert check["status"] == "unknown" and "NETMAP_PIHOLE_URL" in check["reason"]


class FakeNotifier:
    def __init__(self, fail=False):
        self.sent: list[tuple[str, str, str]] = []
        self.fail = fail

    def send(self, title, body, severity="info"):
        if self.fail:
            raise NotifyError("no route")
        self.sent.append((title, body, severity))


def pending(session, *specs, at=NOW):
    session.execute(
        insert(Alert),
        [{"time": at, "mac": PLUG, "kind": kind, "severity": sev, "message": msg,
          "dedup_key": key, "notify": "pending"} for kind, sev, msg, key in specs],
    )  # fmt: skip
    session.commit()


def test_notifications_batch_dedup_and_rate_limit(session):
    n = FakeNotifier()
    pending(session, ("offline", "info", "Plug went offline", "offline:p"),
            ("blocklist_hit", "critical", "Plug looked up bad", "hit:p"),
            ("offline", "info", "Plug went offline again", "offline:p"))  # fmt: skip
    assert send_pending(session, NOW, n, 10, LABELS_BY_KIND) == 2
    assert n.sent == [("netmap: 2 alerts", "• Plug went offline\n• Plug looked up bad", "critical")]
    assert [a.notify for a in alerts(session)] == ["sent", "sent", "duplicate"]

    # The same thing within the hour isn't sent again.
    pending(session, ("offline", "info", "Plug went offline", "offline:p"), at=NOW + HOUR / 2)
    assert send_pending(session, NOW + HOUR / 2, n, 10, LABELS_BY_KIND) == 0
    assert alerts(session)[-1].notify == "duplicate"

    # Past the hourly cap, alerts wait.
    pending(session, ("new_device", "warning", "New device", "new:x"), at=NOW + HOUR / 2)
    assert send_pending(session, NOW + HOUR / 2, n, 1, LABELS_BY_KIND) == 0
    assert alerts(session)[-1].notify == "pending"
    assert send_pending(session, NOW + 2 * HOUR, n, 1, LABELS_BY_KIND) == 1
    assert n.sent[-1] == ("netmap: New device", "New device", "warning")


def test_failed_notifications_wait_and_then_give_up(session):
    pending(session, ("new_device", "warning", "New device", "new:x"))
    with pytest.raises(NotifyError):
        send_pending(session, NOW, FakeNotifier(fail=True), 10, LABELS_BY_KIND)
    assert alerts(session)[0].notify == "pending"
    assert send_pending(session, NOW + 25 * HOUR, FakeNotifier(), 10, LABELS_BY_KIND) == 0
    assert alerts(session)[0].notify == "failed"


def test_compose_lists_ten_and_counts_the_rest():
    many = [Alert(kind="offline", severity="info", message=f"m{i}") for i in range(12)]
    title, body, severity = compose(many, LABELS_BY_KIND)
    assert title == "netmap: 12 alerts" and severity == "info"
    assert body.splitlines()[-1] == "…and 2 more" and len(body.splitlines()) == 11


def test_alerts_api_acknowledge_and_rules(session):
    pending(session, ("offline", "info", "Plug went offline", "a"),
            ("blocklist_hit", "critical", "Plug looked up bad", "b"))  # fmt: skip
    client = TestClient(create_app())
    page = client.get("/api/alerts").json()
    assert page["open"] == 2 and [a["device"] for a in page["items"]] == ["Plug", "Plug"]
    assert client.get("/api/alerts/summary").json() == {"open": 2, "critical": 1}
    first = page["items"][-1]["id"]
    assert client.patch(f"/api/alerts/{first}", json={"acknowledged": True}).json()[
        "acknowledged_at"
    ]
    assert client.get("/api/alerts").json()["open"] == 1
    assert len(client.get("/api/alerts?state=all").json()["items"]) == 2
    assert client.post("/api/alerts/acknowledge", json={"mac": PLUG}).json() == {"acknowledged": 1}
    assert client.get("/api/alerts/summary").json() == {"open": 0, "critical": 0}

    rule = client.put("/api/alert-rules", json={"mac": PLUG, "kind": "offline", "action": "notify"})
    assert rule.status_code == 200, rule.text
    again = client.put("/api/alert-rules", json={"mac": PLUG, "kind": "offline", "action": "mute"})
    assert again.json()["id"] == rule.json()["id"] and again.json()["action"] == "mute"
    client.put("/api/alert-rules", json={"kind": "new_asn", "action": "record"})
    listed = client.get(f"/api/alert-rules?mac={PLUG}").json()
    assert [(r["mac"], r["kind"]) for r in listed["rules"]] == [
        (None, "new_asn"),
        (PLUG, "offline"),
    ]
    assert [r["mac"] for r in client.get("/api/alert-rules").json()["rules"]] == [None]
    offline = next(k for k in listed["kinds"] if k["kind"] == "offline")
    assert offline["default_action"] == "record" and "phones" in offline["note"]
    assert (
        client.put("/api/alert-rules", json={"kind": "nope", "action": "mute"}).status_code == 422
    )
    assert client.delete(f"/api/alert-rules/{rule.json()['id']}").status_code == 204
    assert len(client.get(f"/api/alert-rules?mac={PLUG}").json()["rules"]) == 1


@pytest.fixture
def hook():
    """A local webhook for Apprise's json:// service."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"json://127.0.0.1:{server.server_address[1]}", received
    server.shutdown()


def test_notification_settings_and_test_button(session, monkeypatch, hook):
    client = TestClient(create_app())
    assert client.get("/api/notifications").json()["configured"] is False
    assert client.post("/api/notifications/test").status_code == 400

    url, received = hook
    monkeypatch.setenv("NETMAP_APPRISE_URLS", url)
    monkeypatch.setenv("NETMAP_PUBLIC_URL", "http://netmap.test:8000/")
    get_settings.cache_clear()
    state = client.get("/api/notifications").json()
    assert (state["configured"], state["services"], state["link"]) == (True, 1, True)
    result = client.post("/api/notifications/test").json()
    assert result == {"sent": True, "message": "Sent to 1 service."}
    assert received[0]["title"] == "netmap: test"
    assert received[0]["message"].endswith("http://netmap.test:8000/#/alerts")
