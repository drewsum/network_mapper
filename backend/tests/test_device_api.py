"""Device inventory API: edits, merging, history. Against a real DB."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.inventory import (
    NameHint,
    Sighting,
    apply_vendors,
    record_names,
    record_scan,
    record_sightings,
)
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import OuiVendor

pytestmark = pytest.mark.db

OLD, NEW, OTHER = "3e:fc:9a:00:00:01", "3e:fc:9a:00:00:02", "00:aa:00:00:00:03"
T0 = datetime(2026, 1, 1, 12, tzinfo=UTC)
OFFLINE_AFTER = timedelta(minutes=10)
PRECEDENCE = ["ssdp", "mdns", "dhcp", "netbios", "rdns"]


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, oui_vendors CASCADE"))
    with get_sessionmaker()() as s:
        yield s


@pytest.fixture
def client(session):
    return TestClient(create_app())


def sight(session, mac, ip, at):
    record_sightings(session, {mac: Sighting(ip, at)}, at, OFFLINE_AFTER)


def test_openapi_docs(client):
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/api/devices/{mac}", "/api/devices/{mac}/merge", "/api/devices/{mac}/events"} <= set(
        paths
    )


def test_edits_persist_and_survive_rediscovery(session, client):
    sight(session, OTHER, "192.0.2.3", T0)
    edit = {"label": "Kitchen plug", "category": "iot", "is_iot": True, "notes": "behind fridge"}
    assert client.patch(f"/api/devices/{OTHER}", json=edit).status_code == 200

    # Discovery keeps running: sightings, a vendor refresh, a discovered name.
    session.execute(insert(OuiVendor), [{"prefix": "00aa00", "vendor": "Big Co"}])
    sight(session, OTHER, "192.0.2.33", T0 + timedelta(minutes=2))
    apply_vendors(session)
    session.commit()
    record_names(session, [NameHint(OTHER, "dhcp", "HS103", None, T0)], PRECEDENCE)

    device = client.get(f"/api/devices/{OTHER}").json()
    assert {k: device[k] for k in edit} == edit
    assert (device["vendor"], device["hostname"], device["ip"]) == ("Big Co", "HS103", "192.0.2.33")
    listed = client.get("/api/devices").json()
    assert [(d["label"], d["ip"]) for d in listed] == [("Kitchen plug", "192.0.2.33")]

    # Partial updates touch only what's sent; blank or null clears text fields.
    client.patch(f"/api/devices/{OTHER}", json={"label": "  ", "notes": None})
    device = client.get(f"/api/devices/{OTHER}").json()
    assert (device["label"], device["notes"], device["category"]) == (None, None, "iot")


@pytest.mark.parametrize(
    "body", [{"category": "toaster"}, {"category": None}, {"is_iot": None}, {"vendor": "x"}]
)
def test_invalid_edits_are_rejected(session, client, body):
    sight(session, OTHER, "192.0.2.3", T0)
    assert client.patch(f"/api/devices/{OTHER}", json=body).status_code == 422


def test_merge_combines_history(session, client):
    # The same phone under its old and new private MACs.
    sight(session, OLD, "192.0.2.44", T0)
    record_names(
        session, [NameHint(OLD, "dhcp", "Pixel-8", {"fingerprint": "1,3"}, T0)], PRECEDENCE
    )
    record_scan(session, OLD, {(5353, "udp"): ("mdns", None)}, T0)
    client.patch(f"/api/devices/{OLD}", json={"label": "Drew's phone", "category": "phone"})
    later = T0 + timedelta(days=1)
    sight(session, NEW, "192.0.2.45", later)

    merged = client.post(f"/api/devices/{OLD}/merge", json={"into": NEW}).json()
    assert merged["mac"] == NEW
    assert merged["aliases"] == [OLD]
    assert (merged["label"], merged["category"], merged["hostname"]) == (
        "Drew's phone", "phone", "Pixel-8"
    )  # fmt: skip
    assert merged["first_seen"].startswith("2026-01-01T12:00")
    assert {i["ip"] for i in merged["ips"]} == {"192.0.2.44", "192.0.2.45"}
    events = client.get(f"/api/devices/{NEW}/events").json()
    assert [e["kind"] for e in events].count("new_device") == 2
    assert [p["port"] for p in client.get(f"/api/devices/{NEW}/ports").json()] == [5353]
    assert [d["mac"] for d in client.get("/api/devices").json()] == [NEW]
    assert client.get(f"/api/devices/{OLD}").json()["merged_into"] == NEW

    # The old MAC turning up again counts for the merged device.
    sight(session, OLD, "192.0.2.46", later + timedelta(minutes=1))
    assert "192.0.2.46" in {i["ip"] for i in client.get(f"/api/devices/{NEW}").json()["ips"]}
    assert client.get(f"/api/devices/{OLD}").json()["online"] is False

    # Merging the survivor onward keeps every alias one hop from the final device.
    sight(session, OTHER, "192.0.2.3", later)
    final = client.post(f"/api/devices/{NEW}/merge", json={"into": OTHER}).json()
    assert final["aliases"] == [OLD, NEW]
    # An alias was already merged, so it can't be merged again.
    assert client.post(f"/api/devices/{OLD}/merge", json={"into": OTHER}).status_code == 409


def test_merge_and_edit_errors(session, client):
    sight(session, OTHER, "192.0.2.3", T0)
    assert client.post(f"/api/devices/{OTHER}/merge", json={"into": OTHER}).status_code == 400
    assert client.post(f"/api/devices/{OTHER}/merge", json={"into": NEW}).status_code == 404
    assert client.post(f"/api/devices/{OTHER}/merge", json={"into": "nope"}).status_code == 422
    sight(session, NEW, "192.0.2.4", T0)
    client.post(f"/api/devices/{NEW}/merge", json={"into": OTHER})
    assert client.patch(f"/api/devices/{NEW}", json={"label": "x"}).status_code == 409


def test_events_page_newest_first(session, client):
    for minute in range(5):
        sight(session, OTHER, f"192.0.2.{10 + minute}", T0 + timedelta(minutes=minute))
    first = client.get(f"/api/devices/{OTHER}/events", params={"limit": 3}).json()
    assert [e["ip"] for e in first] == ["192.0.2.14", "192.0.2.13", "192.0.2.12"]
    rest = client.get(f"/api/devices/{OTHER}/events", params={"before": first[-1]["time"]}).json()
    assert [e["kind"] for e in rest][-2:] == ["online", "new_device"]
    assert client.get(f"/api/devices/{NEW}/events").status_code == 404
