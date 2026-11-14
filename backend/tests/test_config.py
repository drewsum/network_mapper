from ipaddress import IPv4Network

import pytest

from netmap.config import MissingSettingError, Settings, get_settings

NETWORK_FIELDS = ["lan_cidr", "pihole_url", "rdns_server", "pihole_password", "maxmind_license_key"]


def test_network_settings_have_no_defaults():
    settings = get_settings()
    for name in NETWORK_FIELDS:
        assert getattr(settings, name) is None, name


def test_settings_read_from_prefixed_env(monkeypatch):
    monkeypatch.setenv("NETMAP_LAN_CIDR", "192.0.2.0/24")
    monkeypatch.setenv("NETMAP_PIHOLE_URL", "http://pihole.example")
    monkeypatch.setenv("NETMAP_RAW_RETENTION_DAYS", "14")
    settings = Settings()  # type: ignore[call-arg]
    assert settings.lan_cidr == IPv4Network("192.0.2.0/24")
    assert settings.pihole_url == "http://pihole.example"
    assert settings.raw_retention_days == 14


def test_empty_env_counts_as_unset(monkeypatch):
    monkeypatch.setenv("NETMAP_LAN_CIDR", "")
    monkeypatch.setenv("NETMAP_PIHOLE_PASSWORD", "")
    monkeypatch.setenv("NETMAP_RAW_RETENTION_DAYS", "")
    settings = Settings()  # type: ignore[call-arg]
    assert settings.lan_cidr is None
    assert settings.pihole_password is None
    assert settings.raw_retention_days == 30


def test_require_raises_for_missing_setting():
    with pytest.raises(MissingSettingError, match="NETMAP_LAN_CIDR"):
        get_settings().require("lan_cidr")


def test_database_url_is_required(monkeypatch):
    monkeypatch.delenv("NETMAP_DATABASE_URL")
    with pytest.raises(ValueError):
        Settings()  # type: ignore[call-arg]


def test_hostname_precedence_is_normalized(monkeypatch):
    monkeypatch.setenv("NETMAP_HOSTNAME_PRECEDENCE", " DHCP, mdns,dhcp ")
    assert Settings().hostname_sources == ["dhcp", "mdns"]  # type: ignore[call-arg]


def test_hostname_precedence_rejects_unknown_sources(monkeypatch):
    monkeypatch.setenv("NETMAP_HOSTNAME_PRECEDENCE", "dhcp,llmnr")
    with pytest.raises(ValueError, match="llmnr"):
        Settings()  # type: ignore[call-arg]
