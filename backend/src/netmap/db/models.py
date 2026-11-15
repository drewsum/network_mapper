"""ORM models. Hypertables, continuous aggregates and policies live in migrations/policies."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CIDR, INET, JSONB, MACADDR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DEVICE_CATEGORIES = ("iot", "phone", "computer", "infrastructure", "media", "unknown")
DNS_STATUSES = ("allowed", "blocked", "cached", "other")
BASELINE_KEY_TYPES = ("domain", "org", "country", "asn")
# Departures from a device's learned baseline (collector/baseline.py).
BASELINE_EVENT_KINDS = (*(f"new_{k}" for k in BASELINE_KEY_TYPES), "query_spike")
DEVICE_EVENT_KINDS = (
    "new_device", "online", "offline", "new_ip", "port_opened", "port_closed",
    *BASELINE_EVENT_KINDS,
)  # fmt: skip
# What the alert engine raises (collector/alerts.py), how loud each is, and what a rule
# can make of one.
ALERT_KINDS = (
    "new_device", "offline", "port_opened", *BASELINE_EVENT_KINDS, "blocklist_hit",
    "upnp_forward", "dns_bypass", "critical_offline", "critical_online", "lateral_traffic",
    "upload_heavy", "unencrypted",
)  # fmt: skip
ALERT_SEVERITIES = ("info", "warning", "critical")
ALERT_ACTIONS = ("notify", "record", "mute")
# An alert's notification: waiting to go out, sent, skipped as a repeat, or given up on.
NOTIFY_STATES = ("pending", "sent", "duplicate", "failed")
# Discovery protocols that can name a device (see collector/names.py).
NAME_SOURCES = ("dhcp", "mdns", "ssdp", "netbios", "rdns")
# Where a flow came from: the SPAN capture or a router's NetFlow/IPFIX export.
FLOW_SOURCES = ("nfstream", "netflow")
CAPTURE_STATES = ("pending", "running", "done", "stopped", "failed")
WIFI_SOURCES = ("unifi", "openwrt")


class Base(DeclarativeBase):
    pass


def _ts(**kw) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), **kw)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "category IN (" + ", ".join(f"'{c}'" for c in DEVICE_CATEGORIES) + ")",
            name="ck_devices_category",
        ),
    )

    mac: Mapped[str] = mapped_column(MACADDR, primary_key=True)
    label: Mapped[str | None] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(Text)
    hostname_source: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text, default="unknown", server_default="unknown")
    is_iot: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_randomized_mac: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    notes: Mapped[str | None] = mapped_column(Text)
    online: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    merged_into: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac"))
    # Last port scan (collector/ports.py); null until the first one.
    ports_scanned_at: Mapped[datetime | None] = _ts()
    # A camera, lock, ...: its going offline raises a critical alert after the grace
    # period (its own, or NETMAP_CRITICAL_GRACE_MINUTES).
    critical: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    offline_grace_minutes: Mapped[int | None] = mapped_column(Integer)
    # Fingerbank's verdict on its DHCP fingerprint (collector/fingerbank.py):
    # {"device", "parents", "score", "fingerprint", "checked_at"}.
    fingerbank: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class DeviceIP(Base):
    __tablename__ = "device_ips"
    __table_args__ = (Index("ix_device_ips_ip", "ip"),)

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class DeviceEvent(Base):
    """Device history: first sighting, online/offline transitions, new IPs, port changes,
    and departures from its baseline."""

    __tablename__ = "device_events"
    __table_args__ = (
        CheckConstraint(
            "kind IN (" + ", ".join(f"'{k}'" for k in DEVICE_EVENT_KINDS) + ")",
            name="ck_device_events_kind",
        ),
        Index("ix_device_events_mac_time", "mac", "time"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    time: Mapped[datetime] = _ts()
    mac: Mapped[str] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(INET)
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(Text)
    # Baseline departures: {"key", "label"} for new_*, {"lookups", "usual"} for query_spike.
    details: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))


class DeviceName(Base):
    """What one discovery protocol says a device is called, and when it last said so."""

    __tablename__ = "device_names"
    __table_args__ = (
        CheckConstraint(
            "source IN (" + ", ".join(f"'{s}'" for s in NAME_SOURCES) + ")",
            name="ck_device_names_source",
        ),
    )

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    source: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str | None] = mapped_column(Text)
    # Protocol extras: DHCP fingerprint and vendor class, UPnP model and manufacturer.
    details: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


HEALTH_STATUSES = ("ok", "warning", "unknown")


class HealthCheck(Base):
    """The latest result of a self-check the collector runs, shown in the UI if not ok."""

    __tablename__ = "health_checks"
    __table_args__ = (
        CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in HEALTH_STATUSES) + ")",
            name="ck_health_checks_status",
        ),
    )

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB(none_as_null=True))
    checked_at: Mapped[datetime] = _ts()


class AppSecret(Base):
    """Random secrets the app generates for itself, such as the session signing key."""

    __tablename__ = "app_secrets"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class OuiVendor(Base):
    """IEEE MAC block registry, refreshed weekly by the collector (see netmap.oui)."""

    __tablename__ = "oui_vendors"

    prefix: Mapped[str] = mapped_column(Text, primary_key=True)
    vendor: Mapped[str] = mapped_column(Text)
    # Null for rows loaded from the bundled snapshot, so they count as due for refresh.
    loaded_at: Mapped[datetime | None] = _ts()


class DnsQuery(Base):
    """One DNS query as seen by Pi-hole. TimescaleDB hypertable on ``time``."""

    __tablename__ = "dns_queries"
    __table_args__ = (
        CheckConstraint(
            "status IN (" + ", ".join(f"'{s}'" for s in DNS_STATUSES) + ")",
            name="ck_dns_queries_status",
        ),
        Index("ix_dns_queries_mac_time", "mac", "time"),
        Index("ix_dns_queries_domain_time", "domain", "time"),
        # Pi-hole query IDs are stored once, whatever the poller re-reads.
        Index(
            "uq_dns_queries_pihole",
            "pihole_id",
            "time",
            unique=True,
            postgresql_where=text("pihole_id IS NOT NULL"),
        ),
    )

    time: Mapped[datetime] = _ts(primary_key=True)
    # Pi-hole's query id, used to resume polling without duplicates. Null for seeded rows.
    pihole_id: Mapped[int | None] = mapped_column(BigInteger)
    # Surrogate part of the PK so rows without a pihole_id are still unique.
    seq: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    client_ip: Mapped[str] = mapped_column(INET)
    # Resolved from client_ip at ingest time; null if the client was unknown then.
    mac: Mapped[str | None] = mapped_column(MACADDR)
    domain: Mapped[str] = mapped_column(Text)
    query_type: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    reply_ips: Mapped[list[str] | None] = mapped_column(ARRAY(INET))


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        Index("ix_domains_organization", "organization"),
        Index("ix_domains_category", "category"),
    )

    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    organization: Mapped[str | None] = mapped_column(Text)
    # Kind of traffic (netmap/categories.py).
    category: Mapped[str | None] = mapped_column(Text)
    # Where the domain's most recently seen public IP is (see collector/geoip.py).
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_org: Mapped[str | None] = mapped_column(Text)
    # Whether Pi-hole blocked the domain's most recent query.
    pihole_blocked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Lists the domain, or an IP it resolved to, is on (netmap/blocklists.py), "pihole"
    # included; is_blocklisted is set for a threat list only, i.e. one other than Pi-hole.
    blocklists: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, server_default="{}")
    is_blocklisted: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())
    enriched_at: Mapped[datetime | None] = _ts()


class DomainIP(Base):
    """Passive DNS map: which IPs a domain resolved to, and when."""

    __tablename__ = "domain_ips"
    __table_args__ = (Index("ix_domain_ips_ip", "ip"),)

    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class IpInfo(Base):
    """Country, city and network (ASN) of an IP, from the GeoIP databases (netmap.geoip).
    All null for private and reserved addresses."""

    __tablename__ = "ip_info"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    country: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_org: Mapped[str | None] = mapped_column(Text)
    # Looked up again once the databases are newer than this.
    looked_up_at: Mapped[datetime] = _ts()


class Blocklist(Base):
    """A threat list's last successful download (netmap/blocklists.py)."""

    __tablename__ = "blocklists"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    entries: Mapped[int] = mapped_column(Integer)
    refreshed_at: Mapped[datetime] = _ts()


class BlocklistDomain(Base):
    __tablename__ = "blocklist_domains"

    list: Mapped[str] = mapped_column(Text, primary_key=True)
    domain: Mapped[str] = mapped_column(Text, primary_key=True)


class BlocklistNetwork(Base):
    __tablename__ = "blocklist_networks"
    # For matching IPs with ip <<= network.
    __table_args__ = (
        Index(
            "ix_blocklist_networks_network",
            "network",
            postgresql_using="gist",
            postgresql_ops={"network": "inet_ops"},
        ),
    )

    list: Mapped[str] = mapped_column(Text, primary_key=True)
    network: Mapped[str] = mapped_column(CIDR, primary_key=True)


class OrgRule(Base):
    """An organization rule added in the app; these take precedence over the bundled map
    (see netmap/orgs.py). ``value`` is a domain suffix, or an AS number for kind 'asn'."""

    __tablename__ = "org_rules"
    __table_args__ = (
        UniqueConstraint("kind", "value"),
        CheckConstraint("kind IN ('suffix', 'asn')", name="ck_org_rules_kind"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    organization: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class Port(Base):
    __tablename__ = "ports"

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    protocol: Mapped[str] = mapped_column(Text, primary_key=True)
    service: Mapped[str | None] = mapped_column(Text)
    banner: Mapped[str | None] = mapped_column(Text)
    # False once a scan no longer finds it; the row keeps its history.
    open: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class UpnpMapping(Base):
    """A port forward a LAN device asked the router for over UPnP (collector/upnp.py)."""

    __tablename__ = "upnp_mappings"
    __table_args__ = (UniqueConstraint("external_port", "protocol", name="uq_upnp_mappings_port"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    external_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(Text)
    internal_ip: Mapped[str] = mapped_column(INET)
    internal_port: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    mac: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="SET NULL"))
    # False once the router no longer lists it, or lists it as disabled.
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


def _one_of(column: str, values: tuple[str, ...], name: str) -> CheckConstraint:
    return CheckConstraint(f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")", name=name)


class Alert(Base):
    """Something worth knowing about, raised by the alert engine (collector/alerts.py)."""

    __tablename__ = "alerts"
    __table_args__ = (
        _one_of("kind", ALERT_KINDS, "ck_alerts_kind"),
        _one_of("severity", ALERT_SEVERITIES, "ck_alerts_severity"),
        _one_of("notify", NOTIFY_STATES, "ck_alerts_notify"),
        Index("ix_alerts_time", "time"),
        Index("ix_alerts_dedup_key_time", "dedup_key", "time"),
        Index("ix_alerts_pending", "time", postgresql_where=text("notify = 'pending'")),
        Index("ix_alerts_open", "time", postgresql_where=text("acknowledged_at IS NULL")),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    time: Mapped[datetime] = _ts(server_default=func.now())
    mac: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, default="info", server_default="info")
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    # The same thing happening again: repeats inside a window are skipped or not notified.
    dedup_key: Mapped[str] = mapped_column(Text)
    acknowledged_at: Mapped[datetime | None] = _ts()
    # Null when its rule said record only.
    notify: Mapped[str | None] = mapped_column(Text)
    notified_at: Mapped[datetime | None] = _ts()


class AlertRule(Base):
    """What to do with an alert kind: notify, record only, or mute. ``mac`` null applies to
    every device and ``kind`` null to every kind; the most specific rule wins. A rule with
    ``until`` (a snooze) lapses then."""

    __tablename__ = "alert_rules"
    __table_args__ = (
        _one_of("kind", ALERT_KINDS, "ck_alert_rules_kind"),
        _one_of("action", ALERT_ACTIONS, "ck_alert_rules_action"),
        UniqueConstraint("mac", "kind", name="uq_alert_rules", postgresql_nulls_not_distinct=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    mac: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"))
    kind: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    until: Mapped[datetime | None] = _ts()
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class CollectorCursor(Base):
    """How far a collector job has read another table, by ID."""

    __tablename__ = "collector_cursors"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[int] = mapped_column(BigInteger)


class DeviceBaseline(Base):
    """What is 'normal' for a device: the sites (registrable domains), organizations,
    countries and networks (AS numbers) it looks up (collector/baseline.py)."""

    __tablename__ = "device_baselines"
    __table_args__ = (
        CheckConstraint(
            "key_type IN (" + ", ".join(f"'{k}'" for k in BASELINE_KEY_TYPES) + ")",
            name="ck_device_baselines_key_type",
        ),
    )

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    key_type: Mapped[str] = mapped_column(Text, primary_key=True)  # domain | org | country | asn
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    # Days (UTC) the device looked it up on.
    hits: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    expected: Mapped[bool | None] = mapped_column(Boolean)  # user verdict; null = not reviewed
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class Flow(Base):
    """Traffic from the capture service (netmap/capture): 1-minute buckets per device and
    remote end. Hypertable on ``time``. ``remote_port`` is the server's port whichever side
    opened the connection, and ``outbound`` says whether the device did. Traffic between
    two LAN devices is a row for each, with the other as the remote end."""

    __tablename__ = "flows"
    __table_args__ = (Index("ix_flows_mac_time", "mac", "time"),)

    time: Mapped[datetime] = _ts(primary_key=True)
    mac: Mapped[str] = mapped_column(MACADDR, primary_key=True)
    remote_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    remote_port: Mapped[int] = mapped_column(Integer, primary_key=True)
    protocol: Mapped[str] = mapped_column(Text, primary_key=True)
    app: Mapped[str | None] = mapped_column(Text)
    sni: Mapped[str | None] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(Text)
    bytes_up: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_down: Mapped[int] = mapped_column(BigInteger, default=0)
    packets: Mapped[int] = mapped_column(BigInteger, default=0)
    outbound: Mapped[bool | None] = mapped_column(Boolean)
    source: Mapped[str | None] = mapped_column(Text)


class PacketCapture(Base):
    """A packet capture of one device, asked for in the UI and run by the capture service
    (capture/pcap.py) into a size- and time-bounded ring of files."""

    __tablename__ = "packet_captures"
    __table_args__ = (_one_of("status", CAPTURE_STATES, "ck_packet_captures_status"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    mac: Mapped[str] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(Text, default="pending", server_default="pending")
    max_seconds: Mapped[int] = mapped_column(Integer)
    max_bytes: Mapped[int] = mapped_column(BigInteger)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    packets: Mapped[int | None] = mapped_column(BigInteger)
    error: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = _ts(server_default=func.now())
    started_at: Mapped[datetime | None] = _ts()
    ended_at: Mapped[datetime | None] = _ts()


class WifiClient(Base):
    """A device on Wi-Fi, as an access point's controller reports it (collector/wifi.py).
    Not tied to ``devices``: an AP can report a client before discovery has seen it."""

    __tablename__ = "wifi_clients"
    __table_args__ = (_one_of("source", WIFI_SOURCES, "ck_wifi_clients_source"),)

    mac: Mapped[str] = mapped_column(MACADDR, primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    ap_name: Mapped[str | None] = mapped_column(Text)
    ap_mac: Mapped[str | None] = mapped_column(MACADDR)
    ssid: Mapped[str | None] = mapped_column(Text)
    band: Mapped[str | None] = mapped_column(Text)  # "2.4 GHz", "5 GHz", "6 GHz"
    channel: Mapped[int | None] = mapped_column(Integer)
    signal_dbm: Mapped[int | None] = mapped_column(Integer)
    rx_rate_kbps: Mapped[int | None] = mapped_column(BigInteger)
    tx_rate_kbps: Mapped[int | None] = mapped_column(BigInteger)
    connected: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    connected_since: Mapped[datetime | None] = _ts()
    last_seen: Mapped[datetime] = _ts(server_default=func.now())
