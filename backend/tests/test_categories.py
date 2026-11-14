"""Domain categories and threat blocklist matching."""

import io
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import insert, text

from netmap import blocklists, categories, orgs
from netmap.api.app import create_app
from netmap.cli import main
from netmap.collector import categories as job
from netmap.collector import pihole
from netmap.collector.categories import assign_categories, store_list
from netmap.collector.dns import record_queries
from netmap.collector.orgs import assign_organizations
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Domain, DomainIP

# Global IPv6 addresses: the documentation ranges aren't public, so lists drop them, and
# the repo's IP check covers IPv4 only.
LISTED_NET = "2001:4860:4860::/48"
LISTED_IP = "2001:4860:4860::8888"
UNLISTED_IP = "2606:4700:4700::1111"


def test_bundled_lists_load():
    m = categories.bundled()  # also checks no suffix is listed twice
    assert m["doubleclick.net"] == categories.ADS
    assert m["google-analytics.com"] == categories.ANALYTICS
    assert orgs.bundled().categories["Cloudflare"] == categories.CDN
    assert orgs.bundled().categories["Google"] == categories.VENDOR


def test_category_precedence():
    suffixes = {"metrics.vendor.test": categories.ANALYTICS, "adnet.test": categories.ADS}

    def cat(domain, org_category=categories.VENDOR, blocked=False):
        return categories.categorize(domain, org_category, blocked, suffixes)

    assert cat("x.metrics.vendor.test") == categories.ANALYTICS  # the list beats the org
    assert cat("cdn.adnet.test", categories.CDN) == categories.ADS
    assert cat("telemetry.vendor.test") == categories.ANALYTICS  # a label says so
    assert cat("pagead2.vendor.test") == categories.ADS
    assert cat("eu-stats-1.vendor.test") == categories.ANALYTICS
    assert cat("ads.test") == categories.VENDOR  # the registrable name itself doesn't count
    assert cat("loads.vendor.test") == categories.VENDOR  # whole words only
    assert cat("api.vendor.test", blocked=True) == categories.ADS  # Pi-hole blocks it
    assert cat("api.vendor.test", categories.CDN) == categories.CDN


def test_org_categories():
    c = orgs.Classifier([(orgs.SUFFIX, "mine.test", "My Thing")])
    assert c.category("Cloudflare") == categories.CDN
    assert c.category("My Thing") == categories.VENDOR
    assert c.category(orgs.OTHER) == categories.UNKNOWN
    assert c.category(None) == categories.UNKNOWN
    with pytest.raises(ValueError, match="category"):
        orgs.parse_map({"A": {"domains": ["a.test"], "category": "nope"}})


def test_parse_netset_drops_private_networks():
    e = blocklists.parse_netset(
        f"# FireHOL\n0.0.0.0/8\n127.0.0.0/8\n{LISTED_NET}  # comment\njunk\n\n{UNLISTED_IP}\n"
    )
    assert {str(n) for n in e.networks} == {LISTED_NET, f"{UNLISTED_IP}/128"}
    assert not e.domains


def test_parse_urlhaus():
    csv = (
        "################\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-11-14 10:00:00","http://Evil.Example.net:8080/x.sh","online","",'
        '"malware_download","elf","https://urlhaus.abuse.ch/url/1/","someone"\n'
        f'"2","2026-11-14 10:00:00","http://[{LISTED_IP}]/a","online","","malware_download",'
        '"","",""\n'
        '"3","2026-11-14 10:00:00","http://127.0.0.1/a","online","","","","",""\n'
        '"4","2026-11-14 10:00:00","https://raw.githubusercontent.com/u/r/x.exe","online",'
        '"","","","",""\n'
    )
    e = blocklists.parse_urlhaus(csv, frozenset({"githubusercontent.com"}))
    assert e.domains == {"evil.example.net"}  # not the file-sharing site
    assert {str(n) for n in e.networks} == {f"{LISTED_IP}/128"}


def test_parse_threatfox_zip():
    csv = (
        '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type"\n'
        '"2026-11-01","1","c2.bad.example","domain","botnet_cc"\n'
        '"2026-11-01","2","https://drop.bad.example/p","url","payload_delivery"\n'
        f'"2026-11-01","3","[{LISTED_IP}]:443","ip:port","botnet_cc"\n'
        '"2026-11-01","4","d41d8cd98f00b204e9800998ecf8427e","md5_hash","payload"\n'
        '"2026-11-01","5","https://github.com/u/r/raw/x.zip","url","payload_delivery"\n'
        '"2026-11-01","6","pub-1.r2.dev","domain","botnet_cc"\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("full.csv", csv)
    popular = frozenset({"github.com", "r2.dev"})
    e = blocklists.parse_threatfox(blocklists._unzip(buf.getvalue()).decode(), popular)
    # A URL on a popular site is dropped; a domain listed as such is kept.
    assert e.domains == {"c2.bad.example", "drop.bad.example", "pub-1.r2.dev"}
    assert {str(n) for n in e.networks} == {f"{LISTED_IP}/128"}


def test_keyed_lists_need_the_key_and_popular_sites():
    with pytest.raises(ValueError, match="NETMAP_ABUSECH_AUTH_KEY"):
        blocklists.download(blocklists.BY_NAME["urlhaus"])
    with pytest.raises(ValueError, match="popular"):
        blocklists.download(blocklists.BY_NAME["urlhaus"], key="k")


def test_parse_popular():
    text = "1,google.com\n2,GitHub.com\n3,third.example\n"
    assert blocklists.parse_popular(text, top=2) == {"google.com", "github.com"}


# --- against a real DB ---


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(
            text(
                "TRUNCATE dns_queries, domains, domain_ips, blocklists, blocklist_domains, "
                "blocklist_networks"
            )
        )
    with get_sessionmaker()() as s:
        yield s


def add(session, domain, asn=None, blocked=False, ips=()):
    session.add(Domain(domain=domain, asn=asn, pihole_blocked=blocked))
    if ips:  # a Core insert: the ORM can't match INET values it gets back to these
        session.execute(insert(DomainIP).values([{"domain": domain, "ip": ip} for ip in ips]))
    session.commit()


def get(session, domain):
    session.expire_all()
    return session.get(Domain, domain)


@pytest.mark.db
def test_assign_categories_and_hits(session):
    now = datetime.now(UTC)
    add(session, "c2.bad.example")
    add(session, "api.vendor.test", asn=13335, ips=[LISTED_IP, UNLISTED_IP])
    add(session, "tracker.test", blocked=True)
    add(session, "www.google.com", ips=[UNLISTED_IP])
    store_list(session, "threatfox", blocklists.Entries(domains={"c2.bad.example"}), now)
    nets = blocklists.parse_netset(LISTED_NET)
    store_list(session, "firehol_level1", nets, now)
    store_list(session, "firehol_level1", nets, now)  # replaces, doesn't duplicate
    assign_organizations(session)

    assert assign_categories(session) == 4
    bad = get(session, "c2.bad.example")
    assert (bad.blocklists, bad.is_blocklisted, bad.category) == (
        ["threatfox"], True, categories.UNKNOWN
    )  # fmt: skip
    hosted = get(session, "api.vendor.test")
    assert (hosted.blocklists, hosted.is_blocklisted, hosted.category) == (
        ["firehol_level1"], True, categories.CDN
    )  # fmt: skip
    tracker = get(session, "tracker.test")
    assert (tracker.blocklists, tracker.is_blocklisted, tracker.category) == (
        [blocklists.PIHOLE], False, categories.ADS
    )  # fmt: skip
    google = get(session, "www.google.com")
    assert (google.blocklists, google.is_blocklisted, google.category) == (
        [], False, categories.VENDOR
    )  # fmt: skip
    assert assign_categories(session) == 0  # only changes are written

    client = TestClient(create_app())
    cats = {c["category"]: c["domains"] for c in client.get("/api/categories").json()}
    assert cats[categories.ADS] == 1 and cats[categories.CDN] == 1
    body = client.get("/api/blocklists").json()
    assert {d["domain"] for d in body["flagged"]} == {"c2.bad.example", "api.vendor.test"}
    lists = {x["name"]: x for x in body["lists"]}
    assert lists["firehol_level1"]["entries"] == 1
    assert lists["urlhaus"]["needs_key"] is True and lists["urlhaus"]["entries"] is None
    assert "{key}" not in lists["urlhaus"]["url"]


@pytest.mark.db
def test_ingest_tracks_whether_the_latest_query_was_blocked(session):
    now = datetime.now(UTC)

    def q(i, seconds_ago, status):
        at = now - timedelta(seconds=seconds_ago)
        return pihole.Query(i, at, "192.0.2.44", "t.example", "A", status)

    record_queries(session, [q(1, 30, "allowed"), q(2, 20, "blocked")])
    assert get(session, "t.example").pihole_blocked is True
    record_queries(session, [q(3, 10, "allowed")])
    assert get(session, "t.example").pihole_blocked is False
    record_queries(session, [q(4, 60, "blocked")])  # older than what's stored: ignored
    assert get(session, "t.example").pihole_blocked is False


@pytest.mark.db
def test_source_downloads_when_due_and_drops_keyless_lists(session, monkeypatch, db_env):
    calls = []

    def fake_download(bl, key=None, popular=None):
        calls.append(bl.name)
        if bl.name == "feodo":
            raise OSError("HTTP Error 503: Service Unavailable")
        return blocklists.parse_netset(LISTED_NET)

    monkeypatch.setattr(job.blocklists, "download", fake_download)
    now = datetime.now(UTC)
    store_list(session, "urlhaus", blocklists.Entries(domains={"x.bad.example"}), now)
    source = job.CategorySource(db_env)

    source._refresh(session, now)
    assert calls == ["firehol_level1", "feodo"]  # the keyed lists are skipped without a key
    stored = set(session.scalars(text("SELECT name FROM blocklists")))
    assert stored == {"firehol_level1"}  # urlhaus dropped with the key gone
    status = source._status(session)
    assert status.status == "warning" and "Feodo" in status.message

    calls.clear()
    source._refresh(session, now + timedelta(minutes=5))
    assert calls == []  # firehol is fresh, feodo waits an hour before retrying
    source._refresh(session, now + timedelta(hours=1, minutes=1))
    assert calls == ["feodo"]


@pytest.mark.db
def test_tranco_is_fetched_once_a_round_and_failures_are_reported(session, monkeypatch, db_env):
    monkeypatch.setenv("NETMAP_ABUSECH_AUTH_KEY", "k")
    get_settings.cache_clear()
    fetched = []

    def fake_popular():
        fetched.append(1)
        if len(fetched) > 1:
            raise OSError("timed out")
        return frozenset({"github.com"})

    def fake_download(bl, key=None, popular=None):
        assert (popular is not None) == bl.url_hosts
        return blocklists.parse_netset(LISTED_NET)

    monkeypatch.setattr(job.blocklists, "download_popular", fake_popular)
    monkeypatch.setattr(job.blocklists, "download", fake_download)
    source = job.CategorySource(get_settings())
    now = datetime.now(UTC)
    source._refresh(session, now)
    assert len(fetched) == 1  # shared by URLhaus and ThreatFox
    assert source._popular is None  # not kept after the round

    source._refresh(session, now + timedelta(days=2))
    status = source._status(session)
    assert status.status == "warning" and "Tranco" in status.message
