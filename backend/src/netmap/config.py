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
    # Pi-hole v6 web address and an app password (Settings > Web interface / API).
    pihole_url: str | None = None
    # DNS server for reverse lookups of device IPs. Defaults to the Pi-hole host, then
    # to the system resolver.
    rdns_server: IPv4Address | None = None
    pihole_password: SecretStr | None = None
    maxmind_license_key: SecretStr | None = None
    # Free abuse.ch Auth-Key (auth.abuse.ch): adds the URLhaus and ThreatFox blocklists.
    abusech_auth_key: SecretStr | None = None
    # Seconds between reads of Pi-hole's query log.
    pihole_poll_seconds: float = Field(default=15.0, ge=5)
    # Pi-hole's HTTPS certificate is self-signed by default; false skips checking it.
    pihole_verify_tls: bool = True
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
    # Addresses of reverse proxies whose X-Forwarded-For/-Proto headers to trust, comma
    # separated (IPs or CIDRs, or * for any). Needed for HTTPS through a proxy on another host
    # or container: login cookies are then marked Secure, and logins are rate-limited per
    # real client.
    trusted_proxies: str | None = None
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
    # Where the GeoIP databases are kept (a volume, so restarts don't download them again),
    # and how old MaxMind's may get before they're downloaded again. DB-IP's, used without a
    # license key, are replaced when each month's release comes out.
    geoip_dir: str = "/app/geoip"
    geoip_refresh_days: float = Field(default=7.0, ge=1)
    # How old a threat blocklist may get before it's downloaded again.
    blocklist_refresh_hours: float = Field(default=24.0, ge=1)
    # Days after a device's first DNS lookup that its baseline is learned for. Sites,
    # organizations, countries and networks first seen after that are recorded as new.
    baseline_learning_days: float = Field(default=7.0, ge=1)
    # An IoT device online for this many hours with fewer than dns_bypass_min_lookups DNS
    # lookups through Pi-hole probably uses its own DNS server. 0 lookups turns it off.
    dns_bypass_hours: float = Field(default=24.0, ge=1)
    dns_bypass_min_lookups: int = Field(default=10, ge=0)

    # Where alerts are sent: Apprise URLs (ntfy, Discord, email, ...), separated by spaces
    # or commas. Unset keeps alerts in the app only.
    apprise_urls: SecretStr | None = None
    # At most this many notifications an hour; alerts past it wait and go out together.
    notify_max_per_hour: int = Field(default=10, ge=1)
    # The app's address as seen from a phone, for links in notifications. Optional.
    public_url: str | None = None

    # `netmap backup`: a database dump into backup_dir every backup_interval_hours, keeping
    # the newest backup_keep. The server stack mounts <NETMAP_DATA_DIR>/backups there.
    backup_dir: str = "/backups"
    backup_interval_hours: float = Field(default=24.0, ge=1)
    backup_keep: int = Field(default=14, ge=1)
    # Where pg_dump and pg_restore are; the image installs PostgreSQL 16's.
    pg_bin_dir: str = "/usr/lib/postgresql/16/bin"

    # A device marked critical (a camera, a lock) unheard for this long raises a critical
    # alert, repeated every critical_remind_hours while it stays down (0: once).
    critical_grace_minutes: int = Field(default=5, ge=3)
    critical_remind_hours: float = Field(default=12.0, ge=0)

    # `netmap capture` (the opt-in capture service): flows from a SPAN mirror port with
    # nfstream, and/or NetFlow v5/v9 and IPFIX from a router. Either unset turns that off.
    capture_interface: str | None = None
    netflow_port: int | None = Field(default=None, ge=1, le=65535)
    netflow_bind: str = "0.0.0.0"
    # Flows still going are reported this often, so throughput is live within that.
    capture_report_seconds: int = Field(default=10, ge=5, le=60)
    # Packet captures of one device (needs capture_interface): where they're kept, their
    # largest size and length, and how many are kept.
    captures_dir: str = "/captures"
    pcap_max_mb: int = Field(default=100, ge=1, le=2000)
    pcap_max_minutes: int = Field(default=60, ge=1, le=1440)
    pcap_keep: int = Field(default=10, ge=1)

    # Traffic detections (collector/traffic.py). A device sending more than
    # upload_heavy_mb in an hour, and at least upload_heavy_ratio times what it received,
    # is upload-heavy.
    upload_heavy_mb: int = Field(default=500, ge=1)
    upload_heavy_ratio: float = Field(default=4.0, ge=1)

    # Fingerbank API key (fingerbank.org, free): names devices from their DHCP fingerprint.
    fingerbank_api_key: SecretStr | None = None

    # Wi-Fi access points to ask which devices are on which AP, and how strong their
    # signal is: a UniFi Network controller, and/or OpenWrt APs (comma-separated URLs,
    # sharing one login, with luci-mod-rpc / ubus over HTTP).
    unifi_url: str | None = None
    unifi_username: str | None = None
    unifi_password: SecretStr | None = None
    unifi_site: str = "default"
    unifi_verify_tls: bool = True
    openwrt_urls: str | None = None
    openwrt_username: str = "root"
    openwrt_password: SecretStr | None = None
    openwrt_verify_tls: bool = True
    wifi_poll_seconds: float = Field(default=60.0, ge=15)

    # Bearer token Prometheus sends for /metrics. Unset: /metrics needs a login like the
    # rest of the API (or is open when NETMAP_ADMIN_PASSWORD is unset too).
    metrics_token: SecretStr | None = None

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
    def openwrt_hosts(self) -> list[str]:
        return [u.strip() for u in (self.openwrt_urls or "").split(",") if u.strip()]

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
