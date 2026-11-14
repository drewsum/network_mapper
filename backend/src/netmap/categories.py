"""What kind of traffic a domain is: ads, telemetry, a vendor's cloud, a CDN, ...

A domain's category is, in order:

1. the longest matching suffix in the bundled list (data/categories.yaml), which names
   ad and analytics services that sit under bigger organizations (google-analytics.com
   is Google, but it's analytics),
2. "analytics" or "ads" when a label of its name says so (telemetry.example.com,
   ads.example.com),
3. "ads" when Pi-hole blocks it: its blocklists are mostly ad and tracker lists,
4. its organization's category (netmap/orgs.py): "vendor" for most, "cdn" for CDN and
   hosting networks, and "unknown" for domains grouped as Other.
"""

import re
from functools import cache
from pathlib import Path

import yaml

BUNDLE = Path(__file__).parent / "data" / "categories.yaml"

ADS = "ads"
ANALYTICS = "analytics"
VENDOR = "vendor"
CDN = "cdn"
INFRASTRUCTURE = "infrastructure"
UNKNOWN = "unknown"
LABELS = {
    ADS: "Ads & trackers",
    ANALYTICS: "Telemetry & analytics",
    VENDOR: "Vendor cloud",
    CDN: "CDN & hosting",
    INFRASTRUCTURE: "Internet infrastructure",
    UNKNOWN: "Unknown",
}
# What an organization in the org map may be.
ORG_CATEGORIES = (VENDOR, CDN, ANALYTICS, ADS, INFRASTRUCTURE)

# Words that name a label's purpose, matched against the parts of each label left of the
# last two (so "ads.example.com" counts, "ads.com" doesn't), split on "-" and with
# trailing digits dropped ("pagead2" -> "pagead").
KEYWORDS = {
    ANALYTICS: {
        "analytics", "telemetry", "metrics", "metric", "stats", "statistics", "tracking",
        "tracker", "crashlytics", "crash", "crashes", "crashreports", "beacon", "beacons",
        "diagnostics", "insights", "measurement",
    },
    ADS: {
        "ad", "ads", "adserver", "adservice", "adservices", "adsystem", "adsrv",
        "advertising", "adtech", "pagead", "adx",
    },
}  # fmt: skip
_SPLIT = re.compile(r"[-_]")


def parse_map(raw: object) -> dict[str, str]:
    """{category: [suffixes]} -> {suffix: category}. Raises ValueError on anything
    malformed, or a suffix listed twice."""
    from netmap.orgs import normalize_suffix  # here: netmap.orgs imports this module

    if not isinstance(raw, dict):
        raise ValueError("expected a mapping of category -> [suffixes]")
    out: dict[str, str] = {}
    for category, suffixes in raw.items():
        if category not in LABELS or category == UNKNOWN:
            raise ValueError(f"unknown category {category!r}")
        if not isinstance(suffixes, list):
            raise ValueError(f"{category}: expected a list of domain suffixes")
        for value in suffixes:
            suffix = normalize_suffix(value)
            if suffix in out:
                raise ValueError(f"{suffix} is listed under both {out[suffix]} and {category}")
            out[suffix] = category
    return out


@cache
def bundled() -> dict[str, str]:
    return parse_map(yaml.safe_load(BUNDLE.read_text(encoding="utf-8")))


def by_keyword(domain: str) -> str | None:
    for label in domain.split(".")[:-2]:
        for word in _SPLIT.split(label):
            word = word.rstrip("0123456789")
            for category, words in KEYWORDS.items():
                if word in words:
                    return category
    return None


def categorize(
    domain: str, org_category: str, blocked: bool, suffixes: dict[str, str] | None = None
) -> str:
    """``org_category`` is the category of the domain's organization; ``blocked`` whether
    Pi-hole blocks it."""
    suffixes = bundled() if suffixes is None else suffixes
    labels = domain.split(".")
    for i in range(len(labels)):
        category = suffixes.get(".".join(labels[i:]))
        if category is not None:
            return category
    return by_keyword(domain) or (ADS if blocked else org_category)
