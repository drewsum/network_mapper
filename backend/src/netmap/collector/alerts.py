"""The alert engine: turns what the collector records into alerts, and sends them out.

Alerts come from:
- device events: new devices, devices going offline, newly opened ports, and departures
  from a device's baseline (new sites, organizations, countries and networks, and spikes
  in lookups; see baseline.py);
- lookups of a domain on a threat blocklist, at most once a day per device and domain;
- port forwards opened on the router over UPnP;
- IoT devices that may skip Pi-hole (bypass.py), once each time one goes quiet;
- devices marked critical (cameras, locks) unheard for their grace period: a critical alert
  per outage, a reminder every NETMAP_CRITICAL_REMIND_HOURS, and word when one is back;
- captured traffic (traffic.py): DNS that skips Pi-hole, lateral traffic, upload-heavy
  hours, unencrypted protocols.

Each kind has a default action, which rules (alert_rules) override for every device or
one: "notify" keeps the alert and sends it (notify.py), "record" only keeps it, "mute"
drops it. The most specific rule wins: device and kind, then device, then kind, then the
default. Events from before the engine first ran raise nothing.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, insert, or_, select, text
from sqlalchemy.orm import Session

from netmap.blocklists import LABELS, PIHOLE
from netmap.collector import traffic
from netmap.collector.base import Source
from netmap.collector.baseline import UNWATCHED_CATEGORIES
from netmap.collector.bypass import dns_checks, unknown_reason
from netmap.collector.dns import CheckResult, record_check
from netmap.collector.notify import CHECK, Notifier, send_pending
from netmap.config import Settings
from netmap.db import get_sessionmaker
from netmap.db.models import (
    ALERT_KINDS,
    BASELINE_EVENT_KINDS,
    Alert,
    AlertRule,
    CollectorCursor,
    Device,
    DeviceEvent,
    UpnpMapping,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Kind:
    label: str
    severity: str  # info | warning | critical
    action: str  # the default: notify | record | mute


KINDS = {
    "new_device": Kind("New device", "warning", "notify"),
    "offline": Kind("Went offline", "info", "record"),
    "port_opened": Kind("Port opened", "info", "record"),
    "new_domain": Kind("New site", "info", "record"),
    "new_org": Kind("New organization", "info", "record"),
    "new_country": Kind("New country", "warning", "notify"),
    "new_asn": Kind("New network", "info", "mute"),
    "query_spike": Kind("Lookup spike", "warning", "notify"),
    "blocklist_hit": Kind("Threat blocklist hit", "critical", "notify"),
    "upnp_forward": Kind("UPnP port forward", "warning", "notify"),
    "dns_bypass": Kind("May skip Pi-hole", "warning", "notify"),
    "critical_offline": Kind("Critical device offline", "critical", "notify"),
    "critical_online": Kind("Critical device back", "info", "notify"),
    "lateral_traffic": Kind("Lateral traffic", "info", "record"),
    "upload_heavy": Kind("Heavy upload", "warning", "notify"),
    "unencrypted": Kind("Unencrypted traffic", "info", "record"),
}
assert tuple(KINDS) == ALERT_KINDS
LABELS_BY_KIND = {k: v.label for k, v in KINDS.items()}
# Phones and computers come and go all day: unless a rule says otherwise, their going
# offline is muted.
QUIET_OFFLINE = UNWATCHED_CATEGORIES
EVENT_KINDS = ("new_device", "offline", "port_opened", *BASELINE_EVENT_KINDS)
# A device's lookups of a blocklisted domain raise one alert a day at most.
THREAT_WINDOW = timedelta(hours=24)

_THREATS = text("""
    SELECT CAST(a.mac AS text) AS mac, a.domain, sum(a.queries) AS lookups,
           max(a.bucket) AS last, d.blocklists
    FROM dns_activity_1h a
    JOIN domains d ON d.domain = a.domain
    JOIN devices dv ON dv.mac = a.mac AND dv.merged_into IS NULL
    WHERE a.bucket >= :since AND d.is_blocklisted
    GROUP BY a.mac, a.domain, d.blocklists
""")


def device_name(label: str | None, hostname: str | None, vendor: str | None, mac: str) -> str:
    """What to call a device, as the UI does."""
    return label or hostname or (f"{vendor} device" if vendor else mac)


class Devices:
    """Names and categories of every device, loaded once a round."""

    def __init__(self, session: Session) -> None:
        rows = session.execute(
            select(Device.mac, Device.label, Device.hostname, Device.vendor, Device.category)
        ).all()
        self._rows = {str(r.mac): r for r in rows}

    def name(self, mac: str | None) -> str:
        r = self._rows.get(mac or "")
        return device_name(r.label, r.hostname, r.vendor, str(r.mac)) if r else mac or "?"

    def category(self, mac: str | None) -> str | None:
        r = self._rows.get(mac or "")
        return r.category if r else None


class Rules:
    """The rules in force: {(mac or None, kind or None): action}."""

    def __init__(self, rules: dict[tuple[str | None, str | None], str]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, session: Session, now: datetime) -> "Rules":
        rows = session.execute(
            select(AlertRule.mac, AlertRule.kind, AlertRule.action).where(
                or_(AlertRule.until.is_(None), AlertRule.until > now)
            )
        ).all()
        return cls({(str(m) if m else None, k): a for m, k, a in rows})

    def action(self, mac: str | None, kind: str, category: str | None) -> str:
        for key in ((mac, kind), (mac, None), (None, kind), (None, None)):
            if key in self.rules:
                return self.rules[key]
        return default_action(kind, category)


def default_action(kind: str, category: str | None) -> str:
    if kind == "offline" and category in QUIET_OFFLINE:
        return "mute"
    return KINDS[kind].action


@dataclass
class Found:
    time: datetime
    mac: str | None
    kind: str
    message: str
    details: dict
    dedup_key: str  # repeats share it


def _span(session: Session, name: str, column) -> tuple[int, int] | None:
    """IDs (after, up to) not yet read by cursor ``name``, moving it on. On first use the
    cursor starts at the newest row, so what came before raises nothing."""
    newest = session.scalar(select(func.max(column))) or 0
    cursor = session.get(CollectorCursor, name)
    if cursor is None:
        session.add(CollectorCursor(name=name, value=newest))
        return None
    after, cursor.value = cursor.value, max(cursor.value, newest)
    return (after, newest) if newest > after else None


def _latest(session: Session, keys: set[str]) -> dict[str, datetime]:
    """When each dedup key last raised an alert."""
    if not keys:
        return {}
    rows = session.execute(
        select(Alert.dedup_key, func.max(Alert.time))
        .where(Alert.dedup_key.in_(keys))
        .group_by(Alert.dedup_key)
    ).all()
    return dict(rows)


def _event_message(e: DeviceEvent, name: str) -> str:
    d = e.details or {}
    key = d.get("key")
    match e.kind:
        case "new_device":
            return f"New device on the network: {name}" + (f" at {e.ip}" if e.ip else "")
        case "offline":
            return f"{name} went offline"
        case "port_opened":
            return f"{name} opened port {e.port}/{e.protocol}"
        case "new_domain":
            return f"{name} looked up a new site: {key}"
        case "new_org":
            return f"{name} reached a new organization: {key}"
        case "new_country":
            return f"{name} reached a new country: {key}"
        case "new_asn":
            label = f" ({d['label']})" if d.get("label") else ""
            return f"{name} reached a new network: AS{key}{label}"
        case _:  # query_spike
            return (
                f"{name} made {d.get('lookups', 0):,} DNS lookups in an hour; "
                f"its usual busy hour has {d.get('usual', 0):,}"
            )


def from_events(session: Session, devices: Devices) -> list[Found]:
    span = _span(session, "alerts.device_events", DeviceEvent.id)
    if span is None:
        return []
    events = session.scalars(
        select(DeviceEvent)
        .where(
            DeviceEvent.id > span[0],
            DeviceEvent.id <= span[1],
            DeviceEvent.kind.in_(EVENT_KINDS),
        )
        .order_by(DeviceEvent.id)
    ).all()
    found = []
    for e in events:
        mac = str(e.mac)
        details = {**(e.details or {}), "event_id": e.id}
        if e.ip is not None:
            details["ip"] = str(e.ip)
        if e.port is not None:
            details |= {"port": e.port, "protocol": e.protocol}
        what = (e.details or {}).get("key") or (f"{e.port}/{e.protocol}" if e.port else "")
        message = _event_message(e, devices.name(mac))
        found.append(Found(e.time, mac, e.kind, message, details, f"{e.kind}:{mac}:{what}"))
    return found


def from_upnp(session: Session, devices: Devices) -> list[Found]:
    span = _span(session, "alerts.upnp_mappings", UpnpMapping.id)
    if span is None:
        return []
    mappings = session.scalars(
        select(UpnpMapping)
        .where(UpnpMapping.id > span[0], UpnpMapping.id <= span[1], UpnpMapping.active)
        .order_by(UpnpMapping.id)
    ).all()
    found = []
    for m in mappings:
        mac = str(m.mac) if m.mac else None
        who = devices.name(mac) if mac else str(m.internal_ip)
        port = f"{m.external_port}/{m.protocol}"
        what = f" for {m.description}" if m.description else ""
        found.append(
            Found(
                m.first_seen, mac, "upnp_forward",
                f"{who} opened port {port} on the router to the internet{what} (UPnP), "
                f"forwarded to {m.internal_ip}:{m.internal_port}",
                {"external_port": m.external_port, "protocol": m.protocol,
                 "internal_ip": str(m.internal_ip), "internal_port": m.internal_port,
                 "description": m.description},
                f"upnp_forward:{port}",
            )
        )  # fmt: skip
    return found


def threats(session: Session, devices: Devices, now: datetime) -> list[Found]:
    """Lookups of threat-listed domains in the last day, if the device looked one up since
    its last alert for it, and that was over a day ago."""
    rows = session.execute(_THREATS, {"since": now - THREAT_WINDOW}).all()
    latest = _latest(session, {f"blocklist_hit:{r.mac}:{r.domain}" for r in rows})
    found = []
    for r in rows:
        key = f"blocklist_hit:{r.mac}:{r.domain}"
        last = latest.get(key)
        if last is not None and (last > now - THREAT_WINDOW or r.last <= last):
            continue
        lists = [LABELS.get(b, b) for b in r.blocklists if b != PIHOLE]
        found.append(
            Found(
                now, r.mac, "blocklist_hit",
                f"{devices.name(r.mac)} looked up {r.domain}, which is on a threat blocklist "
                f"({', '.join(lists)})",
                {"domain": r.domain, "lookups": int(r.lookups), "blocklists": r.blocklists},
                key,
            )
        )  # fmt: skip
    return found


def bypassers(session: Session, devices: Devices, settings: Settings, now: datetime) -> list[Found]:
    """IoT devices gone quiet on Pi-hole: once each time, until one looks something up or
    goes offline and comes back."""
    if unknown_reason(session, settings, now):
        return []
    silent = {m: c for m, c in dns_checks(session, settings, now).items() if c.silent}
    latest = _latest(session, {f"dns_bypass:{m}" for m in silent})
    found = []
    for mac, c in silent.items():
        key = f"dns_bypass:{mac}"
        quiet_since = max(c.online_since, c.last_lookup or c.online_since)
        if key in latest and latest[key] > quiet_since:
            continue
        hours = f"{settings.dns_bypass_hours:g}"
        found.append(
            Found(
                now, mac, "dns_bypass",
                f"{devices.name(mac)} has been online for {hours} hours with only {c.lookups} "
                "DNS lookups through Pi-hole; it may use its own DNS server",
                {"lookups": c.lookups, "hours": settings.dns_bypass_hours,
                 "online_since": c.online_since.isoformat()},
                key,
            )
        )  # fmt: skip
    return found


_CRITICAL = text("""
    SELECT CAST(dv.mac AS text) AS mac, dv.last_seen, dv.offline_grace_minutes AS grace,
           (SELECT a.details FROM alerts a WHERE a.mac = dv.mac AND a.kind = 'critical_offline'
            ORDER BY a.time DESC LIMIT 1) AS last_alert
    FROM devices dv
    WHERE dv.critical AND dv.merged_into IS NULL
""")


def _minutes(delta: timedelta) -> str:
    m = int(delta.total_seconds() // 60)
    return f"{m} minutes" if m < 120 else f"{m / 60:.1f} hours"


def critical(session: Session, devices: Devices, settings: Settings, now: datetime) -> list[Found]:
    """Critical devices unheard for their grace period: once per outage (an outage is
    known by when the device was last heard), again every NETMAP_CRITICAL_REMIND_HOURS
    while it lasts; and once when the device is heard again."""
    found = []
    remind = timedelta(hours=settings.critical_remind_hours)
    for r in session.execute(_CRITICAL).mappings():
        mac, last_seen = r["mac"], r["last_seen"]
        grace = timedelta(minutes=r["grace"] or settings.critical_grace_minutes)
        name = devices.name(mac)
        outage = f"critical_offline:{mac}:{int(last_seen.timestamp())}"
        if now - last_seen >= grace:
            last = _latest(session, {outage}).get(outage)
            if last is None or (remind and last <= now - remind):
                again = " still" if last else ""
                found.append(Found(
                    now, mac, "critical_offline",
                    f"{name} is{again} offline: nothing heard from it for "
                    f"{_minutes(now - last_seen)}",
                    {"last_seen": last_seen.isoformat(), "reminder": last is not None,
                     "grace_minutes": int(grace.total_seconds() // 60)},
                    outage,
                ))  # fmt: skip
            continue
        alert = r["last_alert"] or {}
        if not alert.get("last_seen") or datetime.fromisoformat(alert["last_seen"]) >= last_seen:
            continue
        back = f"critical_online:{mac}:{alert['last_seen']}"
        if _latest(session, {back}):
            continue
        down = last_seen - datetime.fromisoformat(alert["last_seen"])
        found.append(Found(
            now, mac, "critical_online", f"{name} is back online after {_minutes(down)}",
            {"down_since": alert["last_seen"], "back_at": last_seen.isoformat()}, back,
        ))  # fmt: skip
    return found


def from_traffic(
    session: Session, devices: Devices, settings: Settings, now: datetime
) -> list[Found]:
    """Captured-traffic detections, each dedup key at most once in its window."""
    hits = traffic.detect(session, settings, now, devices.name)
    latest = _latest(session, {h.dedup_key for h in hits})
    found, seen = [], set()
    for h in hits:
        last = latest.get(h.dedup_key)
        if h.dedup_key in seen or (last is not None and last > now - h.window):
            continue
        seen.add(h.dedup_key)
        found.append(Found(h.time, h.mac, h.kind, h.message, h.details, h.dedup_key))
    return found


def raise_alerts(session: Session, settings: Settings, now: datetime) -> int:
    """Raise the alerts for whatever happened since the last round. Commits. Returns how
    many were kept."""
    devices = Devices(session)
    rules = Rules.load(session, now)
    found = [
        *from_events(session, devices),
        *from_upnp(session, devices),
        *threats(session, devices, now),
        *bypassers(session, devices, settings, now),
        *critical(session, devices, settings, now),
        *from_traffic(session, devices, settings, now),
    ]
    rows = []
    for f in found:
        action = rules.action(f.mac, f.kind, devices.category(f.mac))
        if action == "mute":
            continue
        rows.append(
            {"time": f.time, "mac": f.mac, "kind": f.kind, "severity": KINDS[f.kind].severity,
             "message": f.message, "details": f.details, "dedup_key": f.dedup_key,
             "notify": "pending" if action == "notify" else None}
        )  # fmt: skip
    if rows:
        session.execute(insert(Alert), rows)
    session.commit()
    return len(rows)


class AlertSource(Source):
    name = "alerts"
    interval_seconds = 60.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        urls = settings.apprise_urls.get_secret_value() if settings.apprise_urls else ""
        self.notifier = Notifier(urls, settings.public_url) if urls else None
        self._retry_at: datetime | None = None
        self._failures = 0
        self._check: str | None = None

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        now = datetime.now(UTC)
        with get_sessionmaker()() as session:
            kept = raise_alerts(session, self.settings, now)
            if kept:
                log.info("alerts: %d raised", kept)
            if self.notifier is None or (self._retry_at and now < self._retry_at):
                return
            try:
                sent = send_pending(
                    session, now, self.notifier, self.settings.notify_max_per_hour, LABELS_BY_KIND
                )
            except Exception as exc:  # any failure: retry later, keep going
                self._failures += 1
                pause = min(timedelta(minutes=2**self._failures), timedelta(minutes=30))
                self._retry_at = now + pause
                self._record(session, now, "warning", f"Couldn't send alert notifications: {exc}")
                log.warning("alerts: notifying failed (%s); retrying in %s", exc, pause)
                return
            self._failures, self._retry_at = 0, None
            if sent:
                log.info("alerts: notified %d", sent)
            self._record(session, now, "ok", "Alert notifications are being delivered.")

    def _record(self, session: Session, now: datetime, status: str, message: str) -> None:
        if status == self._check and status == "ok":
            return
        self._check = status
        record_check(session, CHECK, CheckResult(status, message, {}), now)
