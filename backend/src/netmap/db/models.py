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
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, MACADDR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DEVICE_CATEGORIES = ("iot", "phone", "computer", "infrastructure", "media", "unknown")
DNS_STATUSES = ("allowed", "blocked", "cached", "other")
DEVICE_EVENT_KINDS = ("new_device", "online", "offline", "new_ip")
# Discovery protocols that can name a device (see collector/names.py).
NAME_SOURCES = ("dhcp", "mdns", "ssdp", "netbios", "rdns")


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
    """Device history: first sighting, online/offline transitions, new IPs."""

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
    details: Mapped[dict | None] = mapped_column(JSONB)
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


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

    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    organization: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(Text)
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_org: Mapped[str | None] = mapped_column(Text)
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


class Port(Base):
    __tablename__ = "ports"

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    protocol: Mapped[str] = mapped_column(Text, primary_key=True)
    service: Mapped[str | None] = mapped_column(Text)
    banner: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class UpnpMapping(Base):
    __tablename__ = "upnp_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    external_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(Text)
    internal_ip: Mapped[str] = mapped_column(INET)
    internal_port: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    mac: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="SET NULL"))
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_time", "time"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    time: Mapped[datetime] = _ts(server_default=func.now())
    mac: Mapped[str | None] = mapped_column(MACADDR, ForeignKey("devices.mac", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, default="info", server_default="info")
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class DeviceBaseline(Base):
    """What is 'normal' for a device: domains, orgs, countries it usually talks to."""

    __tablename__ = "device_baselines"

    mac: Mapped[str] = mapped_column(
        MACADDR, ForeignKey("devices.mac", ondelete="CASCADE"), primary_key=True
    )
    key_type: Mapped[str] = mapped_column(Text, primary_key=True)  # domain | org | country | asn
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    hits: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    expected: Mapped[bool | None] = mapped_column(Boolean)  # user verdict; null = not reviewed
    first_seen: Mapped[datetime] = _ts(server_default=func.now())
    last_seen: Mapped[datetime] = _ts(server_default=func.now())


class Flow(Base):
    """Reserved for the stretch SPAN capture (M7). 1-minute buckets. Hypertable on ``time``."""

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
