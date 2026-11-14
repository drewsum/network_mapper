"""GeoIP databases (download, refresh, lookups) and locating the domain -> IP map."""

import asyncio
import gzip
import io
import json
import tarfile
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

import maxminddb
import pytest
from sqlalchemy import select, text

from netmap import geoip
from netmap.cli import main
from netmap.collector.geoip import GeoipSource, enrich_ips, summarize_domains
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Domain, DomainIP, HealthCheck, IpInfo

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
WEEK = timedelta(days=7)
CITY = {"203.0.113.7": {"country": {"iso_code": "DE"}, "city": {"names": {"en": "Berlin"}}}}
ASN = {"203.0.113.7": {"autonomous_system_number": 64500, "autonomous_system_organization": "Ex"}}


class FakeReader:
    """Stands in for maxminddb's reader: the test "databases" are JSON {ip: record}."""

    def __init__(self, path) -> None:
        try:
            self.records = json.loads(Path(path).read_text(encoding="utf-8"))
        except ValueError as exc:
            raise maxminddb.InvalidDatabaseError(str(exc)) from exc

    def get(self, ip):
        return self.records.get(ip)

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def fake_mmdb(monkeypatch):
    monkeypatch.setattr(geoip.maxminddb, "open_database", FakeReader)


def gz(records) -> bytes:
    return gzip.compress(json.dumps(records).encode())


def tgz(edition, records) -> bytes:
    data = json.dumps(records).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"{edition}_20261101/{edition}.mmdb")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def server(monkeypatch):
    """Fake download server: URL -> bytes; anything else fails like a 404."""
    files: dict[str, bytes] = {}
    fetched: list[str] = []

    def fetch(url, dest, timeout):
        fetched.append(url)
        if url not in files:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        dest.write_bytes(files[url])

    monkeypatch.setattr(geoip, "_fetch", fetch)
    return files, fetched


def dbip_url(kind, month):
    return geoip.DBIP_URL.format(kind=kind, month=month)


def maxmind_url(edition, key="k"):
    return geoip.MAXMIND_URL.format(edition=edition, key=key)


def serve_dbip(files, month):
    files[dbip_url("city-lite", month)] = gz(CITY)
    files[dbip_url("asn-lite", month)] = gz(ASN)


def test_parse_records():
    assert geoip.parse_records(CITY["203.0.113.7"], ASN["203.0.113.7"]) == geoip.IpGeo(
        "DE", "Berlin", 64500, "Ex"
    )
    assert geoip.parse_records(None, None) == geoip.IpGeo(None, None, None, None)
    assert geoip.parse_records({"country": {"iso_code": "US"}}, {}).city is None


def test_is_due():
    maxmind = geoip.Meta(geoip.MAXMIND, "2026-11-01", NOW - timedelta(days=1))
    dbip = geoip.Meta(geoip.DBIP, "2026-11", NOW - timedelta(days=20))
    assert geoip.is_due(None, False, NOW, WEEK)
    assert not geoip.is_due(maxmind, True, NOW, WEEK)
    assert geoip.is_due(maxmind, True, NOW + WEEK, WEEK)
    assert geoip.is_due(maxmind, False, NOW, WEEK)  # key removed: switch to DB-IP
    assert not geoip.is_due(dbip, False, NOW, WEEK)  # this month's release, however old
    assert geoip.is_due(dbip, True, NOW, WEEK)  # key added: switch to MaxMind
    assert geoip.is_due(dbip, False, NOW + timedelta(days=30), WEEK)  # December's is out


def test_dbip_falls_back_to_last_month_then_skips_it(server, tmp_path):
    files, fetched = server
    serve_dbip(files, "2026-10")  # November's isn't out yet
    meta = geoip.download(tmp_path, geoip.DBIP, NOW)
    assert (meta.source, meta.version) == (geoip.DBIP, "2026-10")
    assert geoip.read_meta(tmp_path) == meta
    assert geoip.GeoDb(tmp_path).lookup("203.0.113.7").country == "DE"
    assert not list(tmp_path.glob(".download-*"))

    fetched.clear()  # still no November release: October isn't fetched again
    assert geoip.download(tmp_path, geoip.DBIP, NOW, installed=meta) is None
    assert fetched == [dbip_url("city-lite", "2026-11")]


def test_maxmind_archives_are_unpacked(server, tmp_path):
    files, _ = server
    files[maxmind_url("GeoLite2-City")] = tgz("GeoLite2-City", CITY)
    files[maxmind_url("GeoLite2-ASN")] = tgz("GeoLite2-ASN", ASN)
    meta = geoip.download(tmp_path, geoip.MAXMIND, NOW, key="k")
    assert (meta.source, meta.version) == (geoip.MAXMIND, "2026-11-02")
    assert geoip.GeoDb(tmp_path).lookup("203.0.113.7") == geoip.IpGeo("DE", "Berlin", 64500, "Ex")


def test_failed_or_corrupt_download_keeps_what_was_installed(server, tmp_path):
    files, _ = server
    serve_dbip(files, "2026-10")
    before = geoip.download(tmp_path, geoip.DBIP, NOW)
    files[dbip_url("city-lite", "2026-11")] = gzip.compress(b"not a database")
    files[dbip_url("asn-lite", "2026-11")] = gz(ASN)
    with pytest.raises(ValueError, match="corrupt"):
        geoip.download(tmp_path, geoip.DBIP, NOW, installed=before)
    with pytest.raises(OSError):
        geoip.download(tmp_path, geoip.MAXMIND, NOW, key="bad")
    assert geoip.read_meta(tmp_path) == before
    assert geoip.GeoDb(tmp_path).lookup("203.0.113.7").country == "DE"


# --- against a real DB ---


@pytest.fixture
def session(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE domains, domain_ips, ip_info, health_checks"))
    with get_sessionmaker()() as s:
        yield s


def located(session, domain):
    session.expire_all()
    d = session.get(Domain, domain)
    return d.country, d.city, d.asn, d.asn_org


def add_map(session, *rows):
    """rows: (domain, ip, last_seen)"""
    for domain in {r[0] for r in rows}:
        session.merge(Domain(domain=domain))
    for domain, ip, seen in rows:
        session.add(DomainIP(domain=domain, ip=ip, first_seen=seen, last_seen=seen))
    session.commit()


def lookup(ip):
    city, asn = CITY.get(ip), ASN.get(ip)
    return geoip.parse_records(city, asn)


@pytest.mark.db
def test_domains_take_their_newest_public_ip(session):
    add_map(
        session,
        ("cdn.example", "203.0.113.7", NOW - timedelta(hours=2)),
        ("cdn.example", "192.0.2.1", NOW),  # newer, but no location (unknown to the DB)
        ("lan.example", "192.0.2.1", NOW),
    )
    assert enrich_ips(session, lookup, NOW - WEEK, NOW) == 2
    assert summarize_domains(session, NOW) == 2
    assert located(session, "cdn.example") == ("DE", "Berlin", 64500, "Ex")
    assert located(session, "lan.example") == (None, None, None, None)
    assert session.get(Domain, "lan.example").enriched_at is not None

    # Nothing new: nothing looked up or written. Newer databases: everything again.
    assert enrich_ips(session, lookup, NOW - WEEK, NOW) == 0
    assert summarize_domains(session, NOW) == 0
    later = NOW + timedelta(hours=1)
    assert enrich_ips(session, lookup, NOW + timedelta(minutes=1), later) == 2
    rows = session.scalars(select(IpInfo.looked_up_at)).all()
    assert rows == [later, later]


@pytest.mark.db
def test_source_downloads_dbip_without_a_key_and_locates(session, db_env, server, tmp_path):
    files, _ = server
    month = datetime.now(UTC).strftime("%Y-%m")
    serve_dbip(files, month)
    add_map(session, ("cdn.example", "203.0.113.7", NOW))
    db_env.geoip_dir = str(tmp_path / "geoip")
    source = GeoipSource(db_env)
    asyncio.run(source.run_once())
    assert located(session, "cdn.example") == ("DE", "Berlin", 64500, "Ex")
    check = session.get(HealthCheck, "geoip")
    assert check.status == "ok" and check.details == {"source": "dbip", "version": month}
    asyncio.run(source.close())


@pytest.mark.db
def test_source_keeps_dbip_when_maxmind_fails(session, db_env, server, tmp_path, monkeypatch):
    files, fetched = server
    serve_dbip(files, datetime.now(UTC).strftime("%Y-%m"))
    monkeypatch.setenv("NETMAP_MAXMIND_LICENSE_KEY", "bad")
    from netmap.config import Settings

    settings = Settings(geoip_dir=str(tmp_path / "geoip"))
    source = GeoipSource(settings)
    asyncio.run(source.run_once())  # MaxMind refuses the key; DB-IP fills in
    session.expire_all()
    check = session.get(HealthCheck, "geoip")
    assert check.status == "warning" and "DB-IP Lite" in check.message
    assert "bad" not in check.message  # the key never shows up in messages
    assert check.details["source"] == "dbip"

    fetched.clear()
    asyncio.run(source.run_once())  # within the hour: no new attempt
    assert fetched == []
    asyncio.run(source.close())
