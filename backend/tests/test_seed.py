import random
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, ip_address

import pytest

from netmap.seed.catalog import CATALOG
from netmap.seed.main import EXTERNAL_POOLS, build, generate_queries, random_mac

NOW = datetime(2026, 1, 15, 12, tzinfo=UTC)
CIDR = IPv4Network("192.0.2.0/24")


@pytest.fixture
def data():
    return build(CIDR, NOW, random.Random(1))


def test_device_ips_come_from_configured_cidr(data):
    assert len(data.devices) == sum(s.count for s in CATALOG)
    ips = [ip_address(r["ip"]) for r in data.device_ips]
    assert all(ip in CIDR for ip in ips)
    assert len(set(ips)) == len(ips)


def test_reply_ips_use_documentation_ranges(data):
    for row in data.domain_ips:
        assert any(ip_address(row["ip"]) in net for net in EXTERNAL_POOLS)


def test_cidr_too_small():
    with pytest.raises(ValueError, match="too small"):
        build(IPv4Network("192.0.2.0/29"), NOW, random.Random(1))


@pytest.mark.parametrize("randomized", [True, False])
def test_random_mac_admin_bit(randomized):
    first = int(random_mac(random.Random(7), randomized).split(":")[0], 16)
    assert first & 1 == 0  # always unicast
    assert bool(first & 2) is randomized


def test_build_is_deterministic():
    a = build(CIDR, NOW, random.Random(5))
    b = build(CIDR, NOW, random.Random(5))
    assert a.devices == b.devices


def test_queries_respect_offline_and_blocked(data):
    rows = list(generate_queries(data, NOW - timedelta(days=10), NOW, random.Random(2)))
    assert rows
    assert all(NOW - timedelta(days=10) <= r[0] < NOW for r in rows)

    offline = {d["mac"]: d["last_seen"] for d in data.devices if not d["online"]}
    assert offline
    for t, _ip, mac, *_ in rows:
        if mac in offline:
            assert t < offline[mac]

    blocked = [r for r in rows if r[5] == "blocked"]
    assert blocked and all(r[6] is None for r in blocked)


def test_silent_device_has_no_queries(data):
    silent = {d["mac"] for d in data.devices if d["hostname"] == "chromecast"}
    rows = generate_queries(data, NOW - timedelta(days=1), NOW, random.Random(3))
    assert not silent & {r[2] for r in rows}
