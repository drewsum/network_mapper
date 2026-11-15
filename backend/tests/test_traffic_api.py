"""Traffic, packet capture, live throughput and metrics endpoints, and the device fields
M7 adds (critical, Fingerbank, Wi-Fi)."""

import io
import json
from datetime import UTC, datetime, timedelta

import dpkt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text
from starlette.websockets import WebSocketDisconnect

from netmap.api.app import create_app
from netmap.capture.live import publish
from netmap.cli import main
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Device, Flow, HealthCheck, PacketCapture, WifiClient

pytestmark = pytest.mark.db

TV, CAM = "00:ee:00:00:00:01", "00:ee:00:00:00:02"
MIN = timedelta(minutes=1)


def now() -> datetime:
    """This minute: windows like "the last 5 minutes" are measured when each test runs."""
    return datetime.now(UTC).replace(second=0, microsecond=0)


def flow(mac, remote, minutes_ago, up, down, domain=None, app=None, port=443):
    return {"time": now() - minutes_ago * MIN, "mac": mac, "remote_ip": remote, "remote_port": port,
            "protocol": "tcp", "bytes_up": up, "bytes_down": down, "packets": 5,
            "outbound": True, "domain": domain, "app": app, "source": "nfstream"}  # fmt: skip


@pytest.fixture
def client(db_env, tmp_path, monkeypatch):
    monkeypatch.setenv("NETMAP_CAPTURES_DIR", str(tmp_path))
    get_settings.cache_clear()
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, flows, health_checks, wifi_clients, "
                          "packet_captures CASCADE"))  # fmt: skip
    with get_sessionmaker()() as s:
        s.execute(insert(Device), [
            {"mac": TV, "label": "TV", "category": "media", "online": True},
            {"mac": CAM, "label": "Cam", "category": "iot", "online": True,
             "fingerbank": {"device": "Google Nest Cam", "score": 87}},
        ])  # fmt: skip
        s.execute(insert(Flow), [
            flow(TV, "203.0.113.5", 3, 1_000, 900_000, "video.example", "Netflix"),
            flow(TV, "203.0.113.5", 2, 2_000, 800_000, "video.example", "Netflix"),
            flow(TV, "203.0.113.6", 2, 500, 500),
            flow(CAM, "198.51.100.4", 1, 50_000, 1_000, "cam.example", "TLS"),
            flow(CAM, "198.51.100.4", 60 * 30, 7, 7),  # 30 hours ago
        ])  # fmt: skip
        s.add(WifiClient(mac=CAM, source="unifi", ap_name="Hall AP", ssid="home", band="5 GHz",
                         signal_dbm=-58, connected=True, last_seen=now()))  # fmt: skip
        s.commit()
    with TestClient(create_app()) as c:
        yield c


def test_traffic_over_time_and_by_device_remote_app(client):
    t = client.get("/api/traffic").json()
    assert t["captured"] and t["source"] == "flows" and t["bucket_seconds"] == 900
    assert (t["bytes_up"], t["bytes_down"]) == (53_500, 1_701_500)
    assert [(r["label"], r["bytes_down"]) for r in t["rows"]] == [("TV", 1_700_500), ("Cam", 1_000)]
    remote = client.get("/api/traffic", params={"by": "remote", "mac": TV}).json()
    assert [r["key"] for r in remote["rows"]] == ["video.example", "203.0.113.6"]
    apps = client.get("/api/traffic", params={"by": "app"}).json()
    assert {r["label"] for r in apps["rows"]} == {"Netflix", "TLS", "Unrecognized"}
    week = client.get("/api/traffic", params={"start": (now() - timedelta(days=7)).isoformat()})
    assert week.json()["source"] == "flow_activity_1h"


def test_device_traffic_lists_remote_ends(client):
    d = client.get(f"/api/devices/{TV}/traffic", params={"hours": 1}).json()
    assert (d["bytes_up"], d["bytes_down"]) == (3_500, 1_700_500)
    assert d["remotes"][0] | {"last": None} == {
        "remote": "video.example", "ip": "203.0.113.5", "port": 443, "protocol": "tcp",
        "app": "Netflix", "outbound": True, "bytes_up": 3_000, "bytes_down": 1_700_000,
        "last": None,
    }  # fmt: skip
    assert client.get(f"/api/devices/{CAM}/traffic").json()["bytes_up"] == 50_000


def test_map_carries_bytes(client):
    m = client.get("/api/map").json()
    assert m["captured"]
    tv = next(d for d in m["devices"] if d["mac"] == TV)
    assert (tv["bytes_up"], tv["bytes_down"]) == (3_500, 1_700_500)


def test_device_detail_and_critical_settings(client):
    d = client.get(f"/api/devices/{CAM}").json()
    assert d["fingerbank"]["device"] == "Google Nest Cam"
    assert d["wifi"]["ap_name"] == "Hall AP" and d["wifi"]["signal_dbm"] == -58
    assert d["critical"] is False and d["critical_grace_default"] == 5
    d = client.patch(f"/api/devices/{CAM}", json={"critical": True, "offline_grace_minutes": 15})
    assert d.json()["critical"] and d.json()["offline_grace_minutes"] == 15
    assert client.patch(f"/api/devices/{CAM}", json={"offline_grace_minutes": 1}).status_code == 422
    assert client.patch(f"/api/devices/{CAM}", json={"critical": None}).status_code == 422
    assert client.get(f"/api/devices/{TV}").json()["wifi"] is None


def capture_check(age=timedelta(0)):
    with get_sessionmaker()() as s:
        span = {"interface": "eth1", "packets": 10, "dropped": 2}
        s.merge(HealthCheck(name="capture", status="ok", message="", checked_at=now() - age,
                            details={"span": span}))  # fmt: skip
        s.commit()


def test_captures_need_the_capture_service(client):
    state = client.get(f"/api/devices/{CAM}/captures").json()
    assert not state["available"] and "NETMAP_CAPTURE_INTERFACE" in state["reason"]
    assert client.post(f"/api/devices/{CAM}/captures", json={}).status_code == 409
    capture_check(age=timedelta(minutes=10))
    assert "hasn't reported" in client.get(f"/api/devices/{CAM}/captures").json()["reason"]


def test_capture_start_stop_download(client, tmp_path):
    capture_check()
    r = client.post(f"/api/devices/{CAM}/captures", json={"minutes": 2, "megabytes": 5})
    assert r.status_code == 201 and r.json()["status"] == "pending"
    cid = r.json()["id"]
    assert client.post(f"/api/devices/{CAM}/captures", json={}).status_code == 409  # one at a time
    too_big = client.post(f"/api/devices/{TV}/captures", json={"minutes": 5000})
    assert too_big.status_code == 422

    with get_sessionmaker()() as s:  # what the capture service would do
        c = s.get(PacketCapture, cid)
        c.status, c.started_at = "running", now()
        s.commit()
    for name, t0 in ((f"capture-{cid}.pcap0", 10.0), (f"capture-{cid}.pcap1", 20.0)):
        with (tmp_path / name).open("wb") as f:
            w = dpkt.pcap.Writer(f)
            w.writepkt(b"\x00" * 60, t0)
    stopped = client.post(f"/api/devices/{CAM}/captures/{cid}/stop").json()
    assert stopped["ended_at"] and stopped["downloadable"]

    pcap = client.get(f"/api/devices/{CAM}/captures/{cid}.pcap")
    assert pcap.status_code == 200 and "netmap-00ee00000002-" in pcap.headers["content-disposition"]
    assert len(list(dpkt.pcap.Reader(io.BytesIO(pcap.content)))) == 2
    assert client.get(f"/api/devices/{TV}/captures/{cid}.pcap").status_code == 404


def test_metrics(client, monkeypatch):
    capture_check()
    body = client.get("/metrics").text
    assert 'netmap_devices{state="online"} 2' in body
    assert (
        'netmap_traffic_bytes_5m{mac="00:ee:00:00:00:01",name="TV",direction="down"} 1.7005e+06'
        in body
    )
    assert 'netmap_wifi_signal_dbm{mac="00:ee:00:00:00:02",name="Cam",ap="Hall AP"} -58' in body
    assert 'netmap_capture_dropped_total{interface="eth1"} 2' in body
    assert "# TYPE netmap_check_ok gauge" in body

    monkeypatch.setenv("NETMAP_METRICS_TOKEN", "s3cret")
    get_settings.cache_clear()
    assert client.get("/metrics").status_code == 401
    ok = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200


def logged_out(monkeypatch) -> TestClient:
    """A client of an app with an admin password."""
    monkeypatch.setenv("NETMAP_ADMIN_PASSWORD", "pw")
    get_settings.cache_clear()
    return TestClient(create_app())


def test_metrics_need_a_login_without_a_token(client, monkeypatch):
    with logged_out(monkeypatch) as c:
        assert c.get("/metrics").status_code == 401
        c.post("/api/auth/login", json={"password": "pw"})
        assert c.get("/metrics").status_code == 200


def test_live_throughput_over_websocket(client):
    other = "00:ee:00:00:00:09"
    with get_sessionmaker()() as s:
        s.execute(insert(Flow), [flow(other, "203.0.113.9", 1, 6_000, 12_000)])
        s.commit()
    with client.websocket_connect("/api/live") as ws:
        first = ws.receive_json()
        assert first["seconds"] == 60 and first["devices"][other] == [100, 200]
        with get_sessionmaker()() as s:
            publish(s, {"time": now().isoformat(), "seconds": 10, "devices": {TV: [10, 2000]}})
        assert ws.receive_json()["devices"] == {TV: [10, 2000]}


def test_live_refuses_other_sites_and_strangers(client, monkeypatch):
    evil = {"Origin": "https://evil.example"}
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect("/api/live", headers=evil),
    ):
        pass
    assert exc.value.code == 4401
    with logged_out(monkeypatch) as c:
        with pytest.raises(WebSocketDisconnect), c.websocket_connect("/api/live"):
            pass
        c.post("/api/auth/login", json={"password": "pw"})
        with c.websocket_connect("/api/live") as ws:
            assert "devices" in json.loads(ws.receive_text())
