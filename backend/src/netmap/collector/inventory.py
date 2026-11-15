"""Device inventory updates: discovery sightings (MAC seen at IP, at a time), names, port
scans, UPnP mappings, and merging devices."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Text, case, cast, func, literal, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import ARRAY, MACADDR, distinct_on, insert
from sqlalchemy.orm import Session

from netmap.db.models import (
    NAME_SOURCES,
    Device,
    DeviceEvent,
    DeviceIP,
    DeviceName,
    OuiVendor,
    Port,
    UpnpMapping,
)

# The locally-administered bit: set on randomized (private) MACs, never on vendor-assigned ones.
_LOCAL_BIT = literal("02:00:00:00:00:00", MACADDR)
_NO_BITS = literal("00:00:00:00:00:00", MACADDR)


@dataclass(frozen=True)
class Sighting:
    ip: str
    seen_at: datetime


@dataclass(frozen=True)
class NameHint:
    """A name (and/or protocol details) one discovery source reported for a device."""

    mac: str
    source: str
    name: str | None
    details: dict | None
    seen_at: datetime


def canonical_macs(session: Session, macs: Iterable[str]) -> dict[str, str]:
    """Merged-away MACs among ``macs``, mapped to the device they were merged into."""
    return dict(
        session.execute(
            select(Device.mac, Device.merged_into).where(
                Device.mac.in_(set(macs)), Device.merged_into.is_not(None)
            )
        ).all()
    )


def _redirect_sightings(session: Session, sightings: Mapping[str, Sighting]) -> dict:
    """Sightings with merged-away MACs credited to their device (latest sighting wins)."""
    aliases = canonical_macs(session, sightings) if sightings else {}
    out: dict[str, Sighting] = {}
    for mac, s in sightings.items():
        mac = aliases.get(mac, mac)
        if mac not in out or s.seen_at > out[mac].seen_at:
            out[mac] = s
    return out


def known_addresses(session: Session) -> dict[str, str]:
    """Each device's most recently seen IP, as {mac: ip}."""
    rows = session.execute(
        select(DeviceIP.mac, DeviceIP.ip)
        .ext(distinct_on(DeviceIP.mac))
        .order_by(DeviceIP.mac, DeviceIP.last_seen.desc())
    )
    return {mac: str(ip) for mac, ip in rows}


def record_sightings(
    session: Session,
    sightings: Mapping[str, Sighting],
    now: datetime,
    offline_after: timedelta,
) -> None:
    """Upsert devices and their IPs, mark silent devices offline, and log the transitions.

    ``sightings`` maps MAC to its latest sighting. Commits.
    """
    sightings = _redirect_sightings(session, sightings)
    events: list[dict] = []
    if sightings:
        macs = list(sightings)
        was_online = dict(
            session.execute(select(Device.mac, Device.online).where(Device.mac.in_(macs))).all()
        )
        pairs = [(mac, s.ip) for mac, s in sightings.items()]
        # INET loads as an ipaddress object; sightings carry strings.
        known_pairs = {
            (mac, str(ip))
            for mac, ip in session.execute(
                select(DeviceIP.mac, DeviceIP.ip).where(
                    tuple_(DeviceIP.mac, DeviceIP.ip).in_(pairs)
                )
            )
        }

        rows = [
            {"mac": mac, "online": True, "first_seen": s.seen_at, "last_seen": s.seen_at}
            for mac, s in sightings.items()
        ]
        stmt = insert(Device).values(rows)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[Device.mac],
                set_={
                    "online": True,
                    "last_seen": func.greatest(Device.last_seen, stmt.excluded.last_seen),
                },
            )
        )
        ip_rows = [
            {"mac": mac, "ip": s.ip, "first_seen": s.seen_at, "last_seen": s.seen_at}
            for mac, s in sightings.items()
        ]
        ip_stmt = insert(DeviceIP).values(ip_rows)
        session.execute(
            ip_stmt.on_conflict_do_update(
                index_elements=[DeviceIP.mac, DeviceIP.ip],
                set_={"last_seen": func.greatest(DeviceIP.last_seen, ip_stmt.excluded.last_seen)},
            )
        )

        for mac, s in sightings.items():
            if mac not in was_online:
                events.append({"time": s.seen_at, "mac": mac, "kind": "new_device", "ip": s.ip})
            if not was_online.get(mac, False):
                events.append({"time": s.seen_at, "mac": mac, "kind": "online", "ip": s.ip})
            if (mac, s.ip) not in known_pairs:
                events.append({"time": s.seen_at, "mac": mac, "kind": "new_ip", "ip": s.ip})

    went_offline = session.scalars(
        update(Device)
        .where(Device.online, Device.last_seen < now - offline_after)
        .values(online=False)
        .returning(Device.mac)
    ).all()
    events += [{"time": now, "mac": mac, "kind": "offline", "ip": None} for mac in went_offline]

    if events:
        session.execute(insert(DeviceEvent).values(events))
    new_macs = [e["mac"] for e in events if e["kind"] == "new_device"]
    if new_macs:
        apply_vendors(session, new_macs)
    session.commit()


def apply_vendors(session: Session, macs: list[str] | None = None) -> None:
    """Set vendor and is_randomized_mac from the MAC, for ``macs`` or every device.

    Randomized MACs get no vendor: their prefix isn't an IEEE assignment. Doesn't commit.
    """
    randomized = Device.mac.op("&")(_LOCAL_BIT) != _NO_BITS
    digits = func.replace(cast(Device.mac, Text), ":", "")
    vendor = (
        select(OuiVendor.vendor)
        .where(OuiVendor.prefix.in_([func.left(digits, n) for n in (6, 7, 9)]))
        .order_by(func.length(OuiVendor.prefix).desc())
        .limit(1)
        .scalar_subquery()
    )
    stmt = update(Device).values(
        is_randomized_mac=randomized, vendor=case((randomized, None), else_=vendor)
    )
    if macs is not None:
        stmt = stmt.where(Device.mac.in_(macs))
    session.execute(stmt)


def record_names(
    session: Session, hints: Iterable[NameHint], precedence: Sequence[str]
) -> set[str]:
    """Store name hints and refresh the hostnames of the devices they name. Commits.

    A missing name or detail never erases a known one. Hints for MACs that aren't in the
    inventory yet are skipped; returns the MACs that were recorded.
    """
    hints = list(hints)
    aliases = canonical_macs(session, (h.mac for h in hints))
    if aliases:
        latest: dict[tuple[str, str], NameHint] = {}
        for h in hints:
            mac = aliases.get(h.mac, h.mac)
            h = NameHint(mac, h.source, h.name, h.details, h.seen_at)
            if (mac, h.source) not in latest or h.seen_at > latest[(mac, h.source)].seen_at:
                latest[(mac, h.source)] = h
        hints = list(latest.values())
    known = set(session.scalars(select(Device.mac).where(Device.mac.in_({h.mac for h in hints}))))
    rows = [
        {
            "mac": h.mac,
            "source": h.source,
            "name": h.name,
            "details": h.details,
            "first_seen": h.seen_at,
            "last_seen": h.seen_at,
        }
        for h in hints
        if h.mac in known
    ]
    if rows:
        stmt = insert(DeviceName).values(rows)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[DeviceName.mac, DeviceName.source],
                set_={
                    "name": func.coalesce(stmt.excluded.name, DeviceName.name),
                    # Merged when both are set (NULL || x is NULL), else whichever is.
                    "details": func.coalesce(
                        DeviceName.details.op("||")(stmt.excluded.details),
                        stmt.excluded.details,
                        DeviceName.details,
                    ),
                    "last_seen": func.greatest(DeviceName.last_seen, stmt.excluded.last_seen),
                },
            )
        )
        apply_hostnames(session, precedence, sorted({r["mac"] for r in rows}))
    session.commit()
    return {r["mac"] for r in rows}


def apply_hostnames(
    session: Session, precedence: Sequence[str], macs: list[str] | None = None
) -> None:
    """Set hostname and hostname_source from the best-ranked named source. Doesn't commit.

    Hostnames from elsewhere (the seeder) are left alone.
    """
    rank = func.array_position(literal(list(precedence), ARRAY(Text)), DeviceName.source)

    def best(column):
        return (
            select(column)
            .where(DeviceName.mac == Device.mac, DeviceName.name.is_not(None), rank.is_not(None))
            .order_by(rank)
            .limit(1)
            .scalar_subquery()
        )

    stmt = (
        update(Device)
        .values(hostname=best(DeviceName.name), hostname_source=best(DeviceName.source))
        .where(or_(Device.hostname_source.is_(None), Device.hostname_source.in_(NAME_SOURCES)))
    )
    if macs is not None:
        stmt = stmt.where(Device.mac.in_(macs))
    session.execute(stmt)


def record_scan(
    session: Session,
    mac: str,
    found: Mapping[tuple[int, str], tuple[str, str | None]],
    now: datetime,
) -> None:
    """Store one device's port scan, ``{(port, protocol): (service, banner)}``. Commits.

    Ports that opened or closed since the last scan become device events; the first scan
    only sets the baseline. A scan that finds nothing where ports were open is treated as
    inconclusive (the device most likely dropped off mid-scan) and closes nothing.
    """
    device = session.get(Device, mac)
    if device is None:
        return
    was_open = {
        (port, proto): is_open
        for port, proto, is_open in session.execute(
            select(Port.port, Port.protocol, Port.open).where(Port.mac == mac)
        )
    }
    events = []
    if found:
        stmt = insert(Port).values(
            [
                {
                    "mac": mac,
                    "port": port,
                    "protocol": proto,
                    "service": service,
                    "banner": banner,
                    "open": True,
                    "first_seen": now,
                    "last_seen": now,
                }
                for (port, proto), (service, banner) in found.items()
            ]
        )
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[Port.mac, Port.port, Port.protocol],
                set_={
                    "open": True,
                    "service": stmt.excluded.service,
                    "banner": func.coalesce(stmt.excluded.banner, Port.banner),
                    "last_seen": stmt.excluded.last_seen,
                },
            )
        )
        if device.ports_scanned_at is not None:
            events += [("port_opened", key) for key in found if not was_open.get(key)]
        closed = [key for key, is_open in was_open.items() if is_open and key not in found]
        if closed:
            session.execute(
                update(Port)
                .where(Port.mac == mac, tuple_(Port.port, Port.protocol).in_(closed))
                .values(open=False)
            )
            events += [("port_closed", key) for key in closed]
    if events:
        session.execute(
            insert(DeviceEvent).values(
                [
                    {"time": now, "mac": mac, "kind": kind, "port": port, "protocol": proto}
                    for kind, (port, proto) in events
                ]
            )
        )
    device.ports_scanned_at = now
    session.commit()


def record_upnp(session: Session, mappings: Iterable, now: datetime) -> None:
    """Store the router's current port mappings (``upnp.Mapping``s). Commits.

    Each is attributed to the device last seen at its internal IP. Mappings the router no
    longer lists are kept, marked inactive.
    """
    ip_to_mac = {ip: mac for mac, ip in known_addresses(session).items()}
    rows = {
        (m.external_port, m.protocol): {
            "external_port": m.external_port,
            "protocol": m.protocol,
            "internal_ip": m.internal_ip,
            "internal_port": m.internal_port,
            "description": m.description,
            "mac": ip_to_mac.get(m.internal_ip),
            "active": m.enabled,
            "first_seen": now,
            "last_seen": now,
        }
        for m in mappings
    }
    if rows:
        stmt = insert(UpnpMapping).values(list(rows.values()))
        session.execute(
            stmt.on_conflict_do_update(
                constraint="uq_upnp_mappings_port",
                set_={
                    col: stmt.excluded[col]
                    for col in (
                        "internal_ip",
                        "internal_port",
                        "description",
                        "mac",
                        "active",
                        "last_seen",
                    )
                },
            )
        )
    gone = update(UpnpMapping).where(UpnpMapping.active).values(active=False)
    if rows:
        gone = gone.where(
            tuple_(UpnpMapping.external_port, UpnpMapping.protocol).not_in(list(rows))
        )
    session.execute(gone)
    session.commit()


# Moves one device's rows onto another; where both have a row for the same key the two
# are combined. Order matters only in that devices goes last.
_MERGE_SQL = [
    """
    INSERT INTO device_ips (mac, ip, first_seen, last_seen)
    SELECT :target, ip, first_seen, last_seen FROM device_ips WHERE mac = :source
    ON CONFLICT (mac, ip) DO UPDATE SET
        first_seen = LEAST(device_ips.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(device_ips.last_seen, EXCLUDED.last_seen)
    """,
    "DELETE FROM device_ips WHERE mac = :source",
    """
    INSERT INTO device_names (mac, source, name, details, first_seen, last_seen)
    SELECT :target, source, name, details, first_seen, last_seen
    FROM device_names WHERE mac = :source
    ON CONFLICT (mac, source) DO UPDATE SET
        name = CASE WHEN EXCLUDED.last_seen > device_names.last_seen
            THEN COALESCE(EXCLUDED.name, device_names.name)
            ELSE COALESCE(device_names.name, EXCLUDED.name) END,
        details = COALESCE(device_names.details || EXCLUDED.details,
                           EXCLUDED.details, device_names.details),
        first_seen = LEAST(device_names.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(device_names.last_seen, EXCLUDED.last_seen)
    """,
    "DELETE FROM device_names WHERE mac = :source",
    """
    INSERT INTO ports (mac, port, protocol, service, banner, open, first_seen, last_seen)
    SELECT :target, port, protocol, service, banner, open, first_seen, last_seen
    FROM ports WHERE mac = :source
    ON CONFLICT (mac, port, protocol) DO UPDATE SET
        open = ports.open OR EXCLUDED.open,
        service = COALESCE(ports.service, EXCLUDED.service),
        banner = COALESCE(ports.banner, EXCLUDED.banner),
        first_seen = LEAST(ports.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(ports.last_seen, EXCLUDED.last_seen)
    """,
    "DELETE FROM ports WHERE mac = :source",
    """
    INSERT INTO device_baselines (mac, key_type, key, hits, expected, first_seen, last_seen)
    SELECT :target, key_type, key, hits, expected, first_seen, last_seen
    FROM device_baselines WHERE mac = :source
    ON CONFLICT (mac, key_type, key) DO UPDATE SET
        hits = device_baselines.hits + EXCLUDED.hits,
        expected = COALESCE(device_baselines.expected, EXCLUDED.expected),
        first_seen = LEAST(device_baselines.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(device_baselines.last_seen, EXCLUDED.last_seen)
    """,
    "DELETE FROM device_baselines WHERE mac = :source",
    "UPDATE device_events SET mac = :target WHERE mac = :source",
    "UPDATE dns_queries SET mac = :target WHERE mac = :source",
    "UPDATE upnp_mappings SET mac = :target WHERE mac = :source",
    "UPDATE alerts SET mac = :target WHERE mac = :source",
    """
    INSERT INTO alert_rules (mac, kind, action, until, created_at)
    SELECT :target, kind, action, until, created_at FROM alert_rules WHERE mac = :source
    ON CONFLICT DO NOTHING
    """,
    "DELETE FROM alert_rules WHERE mac = :source",
    # Earlier aliases of the source now point straight at the target: one hop, always.
    "UPDATE devices SET merged_into = :target WHERE merged_into = :source",
    """
    UPDATE devices t SET
        label = COALESCE(t.label, s.label),
        notes = COALESCE(t.notes, s.notes),
        category = CASE WHEN t.category = 'unknown' THEN s.category ELSE t.category END,
        is_iot = t.is_iot OR s.is_iot,
        online = t.online OR s.online,
        first_seen = LEAST(t.first_seen, s.first_seen),
        last_seen = GREATEST(t.last_seen, s.last_seen)
    FROM devices s WHERE t.mac = :target AND s.mac = :source
    """,
    "UPDATE devices SET merged_into = :target, online = false WHERE mac = :source",
]


def merge_devices(session: Session, source: str, target: str, precedence: Sequence[str]) -> None:
    """Fold device ``source`` into ``target``: its history, IPs, names and ports move over
    and later sightings of its MAC count for ``target`` (e.g. a phone that switched to a
    new private MAC). The source row stays as an alias. Commits.
    """
    params = {"source": source, "target": target}
    for sql in _MERGE_SQL:
        session.execute(text(sql), params)
    apply_hostnames(session, precedence, [target])
    session.commit()
