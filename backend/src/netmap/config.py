"""Application settings.

Every network-specific value (CIDRs, IPs, URLs, interfaces, credentials) comes from
environment variables prefixed with ``NETMAP_``. Nothing network-specific has a default
here, so the same image runs unchanged on a dev machine and on the TrueNAS host.
"""

from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MissingSettingError(RuntimeError):
    def __init__(self, name: str) -> None:
        super().__init__(f"NETMAP_{name.upper()} must be set for this command")


class Settings(BaseSettings):
    # Empty vars count as unset: the server compose file passes every setting as
    # ${VAR:-}, so a blank optional value must fall back to its default.
    model_config = SettingsConfigDict(
        env_prefix="NETMAP_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    database_url: str = Field(description="SQLAlchemy URL, e.g. postgresql+psycopg://...")

    # Network-specific: no defaults on purpose.
    lan_cidr: IPv4Network | None = None
    # Interface on lan_cidr for ARP discovery; found automatically when unset.
    lan_iface: str | None = None
    pihole_url: str | None = None
    # DNS server for reverse lookups of device IPs. Defaults to the Pi-hole host, then
    # to the system resolver.
    rdns_server: IPv4Address | None = None
    pihole_password: SecretStr | None = None
    maxmind_license_key: SecretStr | None = None
    # Password for the web UI and API. Unset leaves both open to anyone on the LAN.
    admin_password: SecretStr | None = None

    # Retention, in days. Raw rows are dropped after raw_retention_days; the
    # continuous aggregates keep their own (longer) windows.
    raw_retention_days: int = Field(default=30, ge=1)
    agg_1h_retention_days: int = Field(default=90, ge=1)
    agg_1d_retention_days: int = Field(default=365, ge=1)
    compress_after_days: int = Field(default=2, ge=1)

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    web_dist_dir: str | None = None
    # How long a login lasts.
    session_days: float = Field(default=30.0, gt=0)
    log_level: str = "INFO"

    collector_heartbeat_file: str = "/tmp/netmap-collector-heartbeat"
    collector_tick_seconds: float = Field(default=10.0, gt=0)
    arp_sweep_interval_seconds: float = Field(default=120.0, ge=10)
    # A device goes offline when nothing has been heard from it for this long.
    device_offline_after_seconds: float = Field(default=600.0, ge=60)
    # How old the MAC vendor registry may get before it's downloaded again from the IEEE.
    oui_refresh_days: float = Field(default=7.0, ge=1)
    # Seconds between hostname discovery rounds (mDNS, SSDP, NetBIOS and reverse DNS queries).
    names_interval_seconds: float = Field(default=300.0, ge=30)
    # Which discovery source names a device when several do, best first. Sources left out
    # are still recorded but never used for the displayed hostname.
    hostname_precedence: str = "ssdp,mdns,dhcp,netbios,rdns"
    # Seconds before an online device's ports are scanned again; 0 turns scanning off.
    port_scan_interval_seconds: float = Field(default=21600.0, ge=0)
    # Seconds between reads of the router's UPnP port mappings.
    upnp_poll_interval_seconds: float = Field(default=300.0, ge=30)

    @field_validator("hostname_precedence")
    @classmethod
    def _known_sources(cls, value: str) -> str:
        from netmap.db.models import NAME_SOURCES  # here: netmap.db imports this module

        sources = [s.strip().lower() for s in value.split(",") if s.strip()]
        unknown = set(sources) - set(NAME_SOURCES)
        if unknown:
            raise ValueError(f"unknown sources {sorted(unknown)}; use {', '.join(NAME_SOURCES)}")
        return ",".join(dict.fromkeys(sources))

    @property
    def hostname_sources(self) -> list[str]:
        return self.hostname_precedence.split(",") if self.hostname_precedence else []

    def require(self, name: str):
        value = getattr(self, name)
        if value is None:
            raise MissingSettingError(name)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
