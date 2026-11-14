"""Device inventory updates from discovery sightings (MAC seen at IP, at a time)."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from netmap.db.models import Device, DeviceEvent, DeviceIP


@dataclass(frozen=True)
class Sighting:
    ip: str
    seen_at: datetime


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
    session.commit()
