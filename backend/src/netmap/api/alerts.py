"""Alerts (acknowledge them), alert rules (what each kind does, for every device or one),
notification settings with a test button, and each IoT device's DNS bypass check."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Body, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert

from netmap.api.deps import DB, MAC_PATTERN, Mac, get_device
from netmap.collector.alerts import KINDS, QUIET_OFFLINE, device_name
from netmap.collector.bypass import dns_checks, unknown_reason
from netmap.collector.notify import CHECK, Notifier, NotifyError
from netmap.config import get_settings
from netmap.db.models import (
    ALERT_ACTIONS,
    ALERT_KINDS,
    ALERT_SEVERITIES,
    Alert,
    AlertRule,
    Device,
    HealthCheck,
)

router = APIRouter()

AlertKind = Literal[ALERT_KINDS]  # type: ignore[valid-type]
Action = Literal[ALERT_ACTIONS]  # type: ignore[valid-type]
Severity = Literal[ALERT_SEVERITIES]  # type: ignore[valid-type]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    time: datetime
    mac: str | None
    device: str | None = None  # its name
    kind: AlertKind
    severity: Severity
    message: str
    details: dict | None
    acknowledged_at: datetime | None
    notify: str | None  # pending | sent | duplicate | failed; null if only recorded
    notified_at: datetime | None

    @field_validator("mac", mode="before")
    @classmethod
    def _str(cls, value) -> str | None:
        return str(value) if value is not None else None


class AlertPage(BaseModel):
    open: int  # unacknowledged, of all alerts
    items: list[AlertOut]


class AlertSummary(BaseModel):
    open: int
    critical: int  # open and critical


class AckRequest(BaseModel):
    acknowledged: bool


class AckAll(BaseModel):
    mac: str | None = Field(default=None, pattern=MAC_PATTERN)


class KindOut(BaseModel):
    kind: AlertKind
    label: str
    severity: Severity
    default_action: Action
    note: str | None  # an exception to the default


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mac: str | None
    kind: AlertKind | None
    action: Action
    until: datetime | None
    created_at: datetime

    @field_validator("mac", mode="before")
    @classmethod
    def _str(cls, value) -> str | None:
        return str(value) if value is not None else None


class RuleIn(BaseModel):
    """null mac: every device; null kind: every kind; until: a snooze that lapses then."""

    model_config = ConfigDict(extra="forbid")

    mac: str | None = Field(default=None, pattern=MAC_PATTERN)
    kind: AlertKind | None = None
    action: Action
    until: datetime | None = None


class Rules(BaseModel):
    kinds: list[KindOut]
    rules: list[RuleOut]


class Notifications(BaseModel):
    configured: bool  # NETMAP_APPRISE_URLS is set
    services: int  # URLs in it Apprise understands
    max_per_hour: int
    link: bool  # NETMAP_PUBLIC_URL is set, so notifications link here
    pending: int
    last_sent: datetime | None
    problem: str | None  # the delivery health check, if it's failing


class TestResult(BaseModel):
    sent: bool
    message: str


class DnsCheckOut(BaseModel):
    applies: bool  # an IoT device
    # too_soon: not online for the whole window yet
    status: Literal["ok", "silent", "too_soon", "offline", "unknown", "not_iot"]
    reason: str | None
    hours: float
    min_lookups: int
    lookups: int | None
    online_since: datetime | None


def _out(alerts: list[Alert], db) -> list[AlertOut]:
    macs = {a.mac for a in alerts if a.mac}
    names = {
        str(d.mac): device_name(d.label, d.hostname, d.vendor, str(d.mac))
        for d in (db.scalars(select(Device).where(Device.mac.in_(macs))) if macs else [])
    }
    return [
        AlertOut.model_validate(a).model_copy(update={"device": names.get(str(a.mac))})
        for a in alerts
    ]


@router.get("/api/alerts", response_model=AlertPage)
def list_alerts(
    db: DB,
    state: Literal["open", "all"] = "open",
    mac: Annotated[str | None, Query(pattern=MAC_PATTERN)] = None,
    before: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AlertPage:
    """Alerts, newest first; ``before`` (an alert ID) pages back."""
    stmt = select(Alert).order_by(Alert.id.desc()).limit(limit)
    if state == "open":
        stmt = stmt.where(Alert.acknowledged_at.is_(None))
    if mac:
        stmt = stmt.where(Alert.mac == mac.lower())
    if before is not None:
        stmt = stmt.where(Alert.id < before)
    alerts = list(db.scalars(stmt))
    total = db.scalar(select(func.count()).where(Alert.acknowledged_at.is_(None)))
    return AlertPage(open=total, items=_out(alerts, db))


@router.get("/api/alerts/summary", response_model=AlertSummary)
def alert_summary(db: DB) -> AlertSummary:
    row = db.execute(
        select(func.count(), func.count().filter(Alert.severity == "critical")).where(
            Alert.acknowledged_at.is_(None)
        )
    ).one()
    return AlertSummary(open=row[0], critical=row[1])


@router.patch("/api/alerts/{alert_id}", response_model=AlertOut)
def acknowledge(alert_id: int, body: Annotated[AckRequest, Body()], db: DB) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "unknown alert")
    alert.acknowledged_at = datetime.now(UTC) if body.acknowledged else None
    db.commit()
    return _out([alert], db)[0]


@router.post("/api/alerts/acknowledge")
def acknowledge_all(body: Annotated[AckAll, Body()], db: DB) -> dict[str, int]:
    """Acknowledge every open alert, or every one of a device's."""
    stmt = update(Alert).where(Alert.acknowledged_at.is_(None))
    if body.mac:
        stmt = stmt.where(Alert.mac == body.mac.lower())
    done = db.execute(stmt.values(acknowledged_at=datetime.now(UTC))).rowcount
    db.commit()
    return {"acknowledged": done}


def _kinds() -> list[KindOut]:
    quiet = " and ".join(f"{c}s" for c in QUIET_OFFLINE)
    return [
        KindOut(
            kind=kind,
            label=k.label,
            severity=k.severity,
            default_action=k.action,
            note=f"Muted for {quiet}" if kind == "offline" else None,
        )
        for kind, k in KINDS.items()
    ]


@router.get("/api/alert-rules", response_model=Rules)
def list_rules(db: DB, mac: Annotated[str | None, Query(pattern=MAC_PATTERN)] = None) -> Rules:
    """The alert kinds and their defaults, and the rules: those for every device, plus
    ``mac``'s if given."""
    mine = AlertRule.mac.is_(None)
    if mac:
        mine = or_(mine, AlertRule.mac == mac.lower())
    stmt = (
        select(AlertRule)
        .where(mine)
        .order_by(AlertRule.mac.nulls_first(), AlertRule.kind.nulls_first())
    )
    return Rules(kinds=_kinds(), rules=[RuleOut.model_validate(r) for r in db.scalars(stmt)])


@router.put("/api/alert-rules", response_model=RuleOut)
def save_rule(rule: Annotated[RuleIn, Body()], db: DB) -> AlertRule:
    """Add the rule for (mac, kind), or replace it."""
    mac = get_device(db, rule.mac).mac if rule.mac else None
    stmt = insert(AlertRule).values(mac=mac, kind=rule.kind, action=rule.action, until=rule.until)
    saved = db.scalar(
        stmt.on_conflict_do_update(
            constraint="uq_alert_rules",
            set_={"action": stmt.excluded.action, "until": stmt.excluded.until},
        ).returning(AlertRule)
    )
    db.commit()
    return saved


@router.delete("/api/alert-rules/{rule_id}", status_code=204)
def delete_rule(rule_id: Annotated[int, Path()], db: DB) -> None:
    """Remove a rule; that kind falls back to the next most specific rule or its default."""
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(404, "unknown rule")
    db.delete(rule)
    db.commit()


def _notifier() -> Notifier | None:
    settings = get_settings()
    if not settings.apprise_urls:
        return None
    return Notifier(settings.apprise_urls.get_secret_value(), settings.public_url)


@router.get("/api/notifications", response_model=Notifications)
def notifications(db: DB) -> Notifications:
    settings = get_settings()
    notifier = _notifier()
    check = db.get(HealthCheck, CHECK)
    return Notifications(
        configured=notifier is not None,
        services=notifier.services if notifier else 0,
        max_per_hour=settings.notify_max_per_hour,
        link=bool(settings.public_url),
        pending=db.scalar(select(func.count()).where(Alert.notify == "pending")),
        last_sent=db.scalar(select(func.max(Alert.notified_at)).where(Alert.notify == "sent")),
        problem=check.message if check is not None and check.status == "warning" else None,
    )


@router.post("/api/notifications/test", response_model=TestResult)
def test_notification() -> TestResult:
    """Send a test notification to every NETMAP_APPRISE_URLS service, now."""
    notifier = _notifier()
    if notifier is None:
        raise HTTPException(400, "Set NETMAP_APPRISE_URLS to send notifications.")
    try:
        notifier.send("netmap: test", "Notifications from netmap reach you here.")
    except NotifyError as exc:
        return TestResult(sent=False, message=str(exc))
    plural = "s" if notifier.services != 1 else ""
    return TestResult(sent=True, message=f"Sent to {notifier.services} service{plural}.")


@router.get("/api/devices/{mac}/dns-check", response_model=DnsCheckOut)
def dns_check(mac: Mac, db: DB) -> DnsCheckOut:
    """Whether an IoT device seems to skip Pi-hole: online a while with few lookups."""
    settings = get_settings()
    device = get_device(db, mac)
    base = {"hours": settings.dns_bypass_hours, "min_lookups": settings.dns_bypass_min_lookups,
            "lookups": None, "online_since": None, "reason": None}  # fmt: skip
    if not (device.is_iot or device.category == "iot"):
        return DnsCheckOut(applies=False, status="not_iot", **base)
    now = datetime.now(UTC)
    reason = unknown_reason(db, settings, now)
    if reason:
        return DnsCheckOut(applies=True, status="unknown", **base | {"reason": reason})
    check = dns_checks(db, settings, now, str(device.mac)).get(str(device.mac))
    if check is None:
        return DnsCheckOut(applies=True, status="offline", **base)
    base |= {"lookups": check.lookups, "online_since": check.online_since}
    if check.silent:
        return DnsCheckOut(applies=True, status="silent", **base)
    soon = check.lookups < settings.dns_bypass_min_lookups and (
        check.online_since > now - timedelta(hours=settings.dns_bypass_hours)
    )
    return DnsCheckOut(applies=True, status="too_soon" if soon else "ok", **base)
