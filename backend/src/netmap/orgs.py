"""Which organization a domain belongs to: AWS, Google, Tuya, Apple, ...

A curated map ships in the package (data/organizations.yaml), matching domain suffixes
and networks (ASNs). Rules added in the app (the org_rules table) take precedence over it.
A domain is classified, in order, by:

1. the longest matching suffix among the app's rules,
2. the longest matching suffix in the bundled map,
3. the network its most recently seen IP is in: the app's rules, then the bundled map,

and is grouped as "Other" if nothing matches. Each organization in the map also has a
category (netmap/categories.py): "vendor" unless its entry says otherwise.
"""

import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import yaml

from netmap import categories

BUNDLE = Path(__file__).parent / "data" / "organizations.yaml"
OTHER = "Other"
SUFFIX = "suffix"
ASN = "asn"
RULE_KINDS = (SUFFIX, ASN)
MAX_NAME = 100

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_suffix(value: str) -> str:
    """'.Example.COM.' -> 'example.com'. Raises ValueError if it isn't a domain name."""
    suffix = value.strip().strip(".").lower()
    labels = suffix.split(".")
    if not suffix or len(suffix) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"not a domain name: {value!r}")
    return suffix


def normalize_asn(value: str | int) -> int:
    """'AS15169', '15169' or 15169 -> 15169. Raises ValueError otherwise."""
    text = str(value).strip().upper().removeprefix("AS")
    if not text.isdigit() or not 0 < int(text) < 2**32:
        raise ValueError(f"not an AS number: {value!r}")
    return int(text)


def normalize_name(value: str) -> str:
    name = " ".join(value.split())
    if not name or len(name) > MAX_NAME:
        raise ValueError(f"organization name must be 1-{MAX_NAME} characters")
    return name


@dataclass(frozen=True)
class OrgMap:
    suffixes: dict[str, str] = field(default_factory=dict)
    asns: dict[int, str] = field(default_factory=dict)
    categories: dict[str, str] = field(default_factory=dict)  # organization -> category


def parse_map(raw: object) -> OrgMap:
    """{organization: {domains: [...], asns: [...], category: ...}} -> OrgMap. Raises
    ValueError on anything malformed, or a suffix or ASN listed under two organizations."""
    if not isinstance(raw, dict):
        raise ValueError("expected a mapping of organization -> {domains, asns, category}")
    suffixes: dict[str, str] = {}
    asns: dict[int, str] = {}
    cats: dict[str, str] = {}
    for org, entry in raw.items():
        org = normalize_name(str(org))
        if not isinstance(entry, dict) or not set(entry) <= {"domains", "asns", "category"}:
            raise ValueError(f"{org}: expected only 'domains', 'asns' and 'category'")
        category = entry.get("category", categories.VENDOR)
        if category not in categories.ORG_CATEGORIES:
            raise ValueError(
                f"{org}: category must be one of {', '.join(categories.ORG_CATEGORIES)}"
            )
        cats[org] = category
        for key, target, normalize in (
            ("domains", suffixes, normalize_suffix),
            ("asns", asns, normalize_asn),
        ):
            values = entry.get(key) or []
            if not isinstance(values, list):
                raise ValueError(f"{org}: '{key}' must be a list")
            for value in values:
                value = normalize(value)
                if value in target:
                    raise ValueError(f"{value} is listed under both {target[value]} and {org}")
                target[value] = org
    return OrgMap(suffixes, asns, cats)


@cache
def bundled() -> OrgMap:
    return parse_map(yaml.safe_load(BUNDLE.read_text(encoding="utf-8")))


def _by_suffix(suffixes: dict[str, str], domain: str) -> str | None:
    labels = domain.split(".")
    for i in range(len(labels)):
        org = suffixes.get(".".join(labels[i:]))
        if org is not None:
            return org
    return None


class Classifier:
    """The bundled map plus the app's rules, given as (kind, value, organization)."""

    def __init__(self, rules=(), base: OrgMap | None = None) -> None:
        self.base = base if base is not None else bundled()
        self.rules = OrgMap()
        for kind, value, org in rules:
            if kind == SUFFIX:
                self.rules.suffixes[value] = org
            elif kind == ASN:
                self.rules.asns[int(value)] = org

    def classify(self, domain: str, asn: int | None) -> str:
        org = _by_suffix(self.rules.suffixes, domain) or _by_suffix(self.base.suffixes, domain)
        if org is None and asn is not None:
            org = self.rules.asns.get(asn) or self.base.asns.get(asn)
        return org or OTHER

    def category(self, org: str | None) -> str:
        """An organization's category: the map's, "vendor" for ones only the app's rules
        name, and "unknown" for Other."""
        if org is None or org == OTHER:
            return categories.UNKNOWN
        return self.base.categories.get(org, categories.VENDOR)

    def names(self) -> list[str]:
        """Every organization the map and rules know of."""
        known = {OTHER}
        for m in (self.base, self.rules):
            known.update(m.suffixes.values(), m.asns.values())
        return sorted(known, key=str.casefold)
