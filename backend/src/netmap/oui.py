"""IEEE MAC address block registry: which organization a MAC prefix is assigned to.

A snapshot of the registries ships in the package (data/oui.tsv.gz), so vendors resolve
offline from the first run; the collector refreshes the DB copy from the IEEE weekly.
Prefixes are lowercase hex without separators: 6 digits for MA-L, 7 for MA-M, 9 for MA-S
and the older IAB blocks. Lookups pick the longest matching prefix.
"""

import csv
import gzip
import io
import urllib.request
from collections.abc import Iterable, Iterator
from pathlib import Path

BUNDLE = Path(__file__).parent / "data" / "oui.tsv.gz"

REGISTRY_URLS = (
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
    "https://standards-oui.ieee.org/iab/iab.csv",
)
# Blocks registered without a public owner carry this name; they resolve to no vendor.
PRIVATE = "private"


def parse_registry(text: str) -> Iterator[tuple[str, str]]:
    """(prefix, vendor) pairs from one IEEE registry CSV."""
    for row in csv.DictReader(io.StringIO(text)):
        prefix = row["Assignment"].strip().lower()
        vendor = " ".join(row["Organization Name"].split())
        if prefix and vendor and vendor.lower() != PRIVATE:
            yield prefix, vendor


def download(timeout: float = 60.0) -> dict[str, str]:
    """All registries from the IEEE, as {prefix: vendor}. Raises on any failed download."""
    entries: dict[str, str] = {}
    for url in REGISTRY_URLS:
        req = urllib.request.Request(url, headers={"User-Agent": "netmap"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            entries.update(parse_registry(resp.read().decode("utf-8")))
    return entries


def read_bundle(path: Path = BUNDLE) -> dict[str, str]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return dict(line.rstrip("\n").split("\t", 1) for line in f if line.strip())


def write_bundle(entries: Iterable[tuple[str, str]], path: Path = BUNDLE) -> None:
    # mtime=0 keeps the file byte-identical when the registry hasn't changed.
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        gz.write("".join(f"{p}\t{v}\n" for p, v in sorted(entries)).encode())
