"""Country, city and ASN of public IP addresses, from local MaxMind-format databases.

With a free MaxMind license key (NETMAP_MAXMIND_LICENSE_KEY) the GeoLite2 City and ASN
databases are used; without one, or while MaxMind can't be reached, the DB-IP Lite ones
(CC BY 4.0, no key, a new release each month). Both use the same .mmdb record layout.
Files live in NETMAP_GEOIP_DIR as city.mmdb and asn.mmdb, with meta.json saying where
they came from and when. Each is downloaded to a temporary file and moved into place, so
a failed download never leaves a half-written database behind.
"""

import gzip
import json
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import maxminddb

MAXMIND = "maxmind"
DBIP = "dbip"
SOURCE_NAMES = {MAXMIND: "MaxMind GeoLite2", DBIP: "DB-IP Lite"}

# Local name -> MaxMind edition / DB-IP file kind.
MAXMIND_EDITIONS = {"city": "GeoLite2-City", "asn": "GeoLite2-ASN"}
DBIP_KINDS = {"city": "city-lite", "asn": "asn-lite"}

MAXMIND_URL = (
    "https://download.maxmind.com/app/geoip_download?edition_id={edition}"
    "&license_key={key}&suffix=tar.gz"
)
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-{month}.mmdb.gz"
META = "meta.json"


@dataclass(frozen=True)
class Meta:
    source: str  # maxmind | dbip
    version: str  # DB-IP's release month; the download date for MaxMind
    downloaded_at: datetime


@dataclass(frozen=True)
class IpGeo:
    country: str | None  # ISO 3166-1 alpha-2
    city: str | None
    asn: int | None
    asn_org: str | None


def read_meta(directory: Path) -> Meta | None:
    """What's installed in ``directory``, or None if the databases aren't all there."""
    try:
        raw = json.loads((directory / META).read_text())
        meta = Meta(raw["source"], raw["version"], datetime.fromisoformat(raw["downloaded_at"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not all((directory / f"{name}.mmdb").is_file() for name in MAXMIND_EDITIONS):
        return None
    return meta


def is_due(meta: Meta | None, has_key: bool, now: datetime, refresh_after: timedelta) -> bool:
    """Whether to download: nothing installed, a license key added or removed since, or a
    newer release out (MaxMind's twice-weekly updates, picked up every refresh_after;
    DB-IP's monthly ones)."""
    if meta is None or meta.source != (MAXMIND if has_key else DBIP):
        return True
    if meta.source == MAXMIND:
        return now - meta.downloaded_at >= refresh_after
    return meta.version != now.strftime("%Y-%m")


def _fetch(url: str, dest: Path, timeout: float) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "netmap"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)


def _mmdb_from_tar(archive: Path, dest: Path) -> None:
    """MaxMind ships each database as <edition>_<date>/<edition>.mmdb in a .tar.gz."""
    with tarfile.open(archive, "r:gz") as tar:
        member = next((m for m in tar if m.isfile() and m.name.endswith(".mmdb")), None)
        if member is None:
            raise ValueError("no .mmdb file in the MaxMind archive")
        with tar.extractfile(member) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)


def _mmdb_from_gzip(archive: Path, dest: Path) -> None:
    with gzip.open(archive, "rb") as src, open(dest, "wb") as out:
        shutil.copyfileobj(src, out)


def _download_maxmind(key: str, work: Path, timeout: float) -> dict[str, Path]:
    files = {}
    for name, edition in MAXMIND_EDITIONS.items():
        archive = work / f"{name}.tar.gz"
        # The key is in the URL: errors from urllib name the status, never the URL.
        _fetch(MAXMIND_URL.format(edition=edition, key=key), archive, timeout)
        files[name] = work / f"{name}.mmdb"
        _mmdb_from_tar(archive, files[name])
    return files


def _download_dbip(month: str, work: Path, timeout: float) -> dict[str, Path]:
    files = {}
    for name, kind in DBIP_KINDS.items():
        archive = work / f"{name}.mmdb.gz"
        _fetch(DBIP_URL.format(kind=kind, month=month), archive, timeout)
        files[name] = work / f"{name}.mmdb"
        _mmdb_from_gzip(archive, files[name])
    return files


def _months_back(now: datetime) -> list[str]:
    """This month and last: a new DB-IP release goes up a day or so into the month."""
    last = now.replace(day=1) - timedelta(days=1)
    return [now.strftime("%Y-%m"), last.strftime("%Y-%m")]


def download(
    directory: Path,
    source: str,
    now: datetime,
    key: str | None = None,
    installed: Meta | None = None,
    timeout: float = 300.0,
) -> Meta | None:
    """Download and install both databases from ``source``. Returns None, downloading
    nothing, when DB-IP has no release newer than the ``installed`` one. Raises OSError or
    ValueError if a download fails, leaving whatever was installed before in place."""
    have = installed.version if installed is not None and installed.source == DBIP else None
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory, prefix=".download-") as tmp:
        work = Path(tmp)
        if source == MAXMIND:
            if not key:
                raise ValueError("MaxMind needs a license key")
            files, version = _download_maxmind(key, work, timeout), now.strftime("%Y-%m-%d")
        else:
            months = _months_back(now)
            for month in months:
                if have is not None and month <= have:
                    return None
                try:
                    files, version = _download_dbip(month, work, timeout), month
                    break
                except urllib.error.HTTPError as exc:
                    # 404 until the month's release is out; anything else is a failure.
                    if exc.code != 404 or month == months[-1]:
                        raise
        for name, path in files.items():
            try:
                maxminddb.open_database(str(path)).close()
            except maxminddb.InvalidDatabaseError as exc:
                raise ValueError(f"downloaded {name} database is corrupt: {exc}") from exc
        for name, path in files.items():
            os.replace(path, directory / f"{name}.mmdb")
    meta = Meta(source, version, now.astimezone(UTC))
    (directory / META).write_text(
        json.dumps(
            {"source": source, "version": version, "downloaded_at": meta.downloaded_at.isoformat()}
        )
    )
    return meta


class GeoDb:
    """Open readers for the installed databases."""

    def __init__(self, directory: Path) -> None:
        self.city = maxminddb.open_database(str(directory / "city.mmdb"))
        self.asn = maxminddb.open_database(str(directory / "asn.mmdb"))

    def lookup(self, ip: str) -> IpGeo:
        return parse_records(self.city.get(ip), self.asn.get(ip))

    def close(self) -> None:
        self.city.close()
        self.asn.close()


def parse_records(city: dict | None, asn: dict | None) -> IpGeo:
    """GeoLite2 and DB-IP share these fields. Private and reserved IPs have no records."""
    city, asn = city or {}, asn or {}
    country = (city.get("country") or {}).get("iso_code")
    name = ((city.get("city") or {}).get("names") or {}).get("en")
    number = asn.get("autonomous_system_number")
    return IpGeo(
        country=country,
        city=name,
        asn=int(number) if number is not None else None,
        asn_org=asn.get("autonomous_system_organization"),
    )
