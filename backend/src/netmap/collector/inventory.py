"""Device inventory updates from discovery sightings (MAC seen at IP, at a time)."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Text, case, cast, func, literal, select, tuple_, update
from sqlalchemy.dialects.postgresql import MACADDR, distinct_on, insert
from sqlalchemy.orm import Session

from netmap.db.models import Device, DeviceEvent, DeviceIP, OuiVendor

# The locally-administered bit: set on randomized (private) MACs, never on vendor-assigned ones.
_LOCAL_BIT = literal("02:00:00:00:00:00", MACADDR)
_NO_BITS = literal("00:00:00:00:00:00", MACADDR)


@dataclass(frozen=True)
class Sighting:
    ip: str
    seen_at: datetime


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
