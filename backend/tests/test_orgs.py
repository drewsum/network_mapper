"""Grouping domains by organization: the bundled map, app rules and the API."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from netmap import orgs
from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector.orgs import assign_organizations
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Domain

BASE = orgs.OrgMap(
    suffixes={"amazonaws.com": "AWS", "tuyaus.com": "Tuya", "example.com": "Example"},
    asns={16509: "AWS"},
)


def test_bundled_map_loads():
    m = orgs.bundled()  # also checks no suffix or ASN is listed twice
    assert m.suffixes["googleapis.com"] == "Google"
    assert m.asns[16509] == "AWS"
    assert all(s == orgs.normalize_suffix(s) for s in m.suffixes)


def test_suffix_beats_network_and_unknowns_are_other():
    c = orgs.Classifier(base=BASE)
    assert c.classify("a1.tuyaus.com", 16509) == "Tuya"  # Tuya's domain, hosted on AWS
    assert c.classify("bucket.s3.amazonaws.com", None) == "AWS"
    assert c.classify("amazonaws.com", None) == "AWS"
    assert c.classify("nobody.test", 16509) == "AWS"  # unclaimed: named by its host
    assert c.classify("nobody.test", 64500) == orgs.OTHER
    assert c.classify("nobody.test", None) == orgs.OTHER
    assert c.classify("notexample.com", None) == orgs.OTHER  # whole labels only


def test_app_rules_take_precedence():
    rules = [
        (orgs.SUFFIX, "example.com", "Mine"),
        (orgs.SUFFIX, "iot.amazonaws.com", "Vendor"),
        (orgs.ASN, "16509", "Cloud"),
    ]
    c = orgs.Classifier(rules, base=BASE)
    assert c.classify("www.example.com", None) == "Mine"
    assert c.classify("x.iot.amazonaws.com", None) == "Vendor"
    assert c.classify("s3.amazonaws.com", None) == "AWS"
    assert c.classify("nobody.test", 16509) == "Cloud"
    assert c.classify("a1.tuyaus.com", 16509) == "Tuya"  # a suffix still beats a network
    assert {"Mine", "Vendor", "Cloud", "Tuya", orgs.OTHER} <= set(c.names())


def test_parse_map_rejects_duplicates_and_junk():
    with pytest.raises(ValueError, match="both A and B"):
        orgs.parse_map({"A": {"domains": ["x.com"]}, "B": {"domains": ["X.com."]}})
    with pytest.raises(ValueError, match="both"):
        orgs.parse_map({"A": {"asns": [1]}, "B": {"asns": ["AS1"]}})
    with pytest.raises(ValueError, match="only"):
        orgs.parse_map({"A": {"domain": ["x.com"]}})
    with pytest.raises(ValueError, match="domain name"):
        orgs.parse_map({"A": {"domains": ["not a domain"]}})


def test_normalize():
    assert orgs.normalize_suffix(" .Example.COM. ") == "example.com"
    assert orgs.normalize_asn("as15169") == 15169
    assert orgs.normalize_name("  Philips   Hue ") == "Philips Hue"
    for bad in ("", "a..b", "-x.com", "x" * 64 + ".com"):
        with pytest.raises(ValueError):
            orgs.normalize_suffix(bad)
    for bad in ("", "AS", "0", "-1", "12a", str(2**32)):
        with pytest.raises(ValueError):
            orgs.normalize_asn(bad)
    with pytest.raises(ValueError):
        orgs.normalize_name("   ")


# --- against a real DB ---


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE domains, org_rules"))
    with get_sessionmaker()() as s:
        yield s


def add_domains(session, *rows):
    """rows: (domain, asn)"""
    for domain, asn in rows:
        session.add(Domain(domain=domain, asn=asn))
    session.commit()


def org_of(session, domain):
    session.expire_all()
    return session.get(Domain, domain).organization


@pytest.mark.db
def test_assign_writes_only_changes(session):
    add_domains(
        session,
        ("a1.tuyaus.com", 16509),
        ("unclaimed.test", 16509),
        ("blocked-only.test", None),
    )
    assert assign_organizations(session) == 3
    assert org_of(session, "a1.tuyaus.com") == "Tuya"
    assert org_of(session, "unclaimed.test") == "AWS"
    assert org_of(session, "blocked-only.test") == orgs.OTHER
    assert assign_organizations(session) == 0


@pytest.mark.db
def test_rule_api_regroups_right_away(session):
    add_domains(session, ("cam.vendor.test", 16509), ("other.test", None))
    assign_organizations(session)
    client = TestClient(create_app())

    r = client.post(
        "/api/org-rules",
        json={"kind": "suffix", "value": ".Vendor.TEST", "organization": " Acme  Cams "},
    )
    assert r.status_code == 200, r.text
    rule = r.json()
    assert (rule["value"], rule["organization"], rule["regrouped"]) == (
        "vendor.test", "Acme Cams", 1
    )  # fmt: skip
    assert org_of(session, "cam.vendor.test") == "Acme Cams"

    # Same suffix again: replaced, not duplicated.
    r = client.post(
        "/api/org-rules", json={"kind": "suffix", "value": "vendor.test", "organization": "Acme"}
    )
    assert r.json()["id"] == rule["id"]
    assert [x["organization"] for x in client.get("/api/org-rules").json()] == ["Acme"]

    r = client.post("/api/org-rules", json={"kind": "asn", "value": "AS64500", "organization": "X"})
    assert r.json()["value"] == "64500"
    assert client.post(
        "/api/org-rules", json={"kind": "asn", "value": "x.com", "organization": "X"}
    ).status_code == 422  # fmt: skip

    names = {o["name"]: o["domains"] for o in client.get("/api/organizations").json()}
    assert names["Acme"] == 1 and names[orgs.OTHER] == 1 and names["Google"] == 0

    r = client.delete(f"/api/org-rules/{rule['id']}")
    assert r.status_code == 200 and r.json()["regrouped"] == 1
    assert org_of(session, "cam.vendor.test") == "AWS"  # back to its network
    assert client.delete(f"/api/org-rules/{rule['id']}").status_code == 404
