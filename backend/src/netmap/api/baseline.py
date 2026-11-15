"""A device's learned baseline and its departures from it (collector/baseline.py)."""

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from netmap.api.deps import DB, Mac, get_device
from netmap.collector.baseline import UNWATCHED_CATEGORIES, learning_periods, usual_peak
from netmap.config import get_settings
from netmap.db.models import (
    BASELINE_EVENT_KINDS,
    BASELINE_KEY_TYPES,
    DeviceBaseline,
    DeviceEvent,
)

router = APIRouter()


class Departure(BaseModel):
    time: datetime
    kind: str
    details: dict | None


class Baseline(BaseModel):
    learning_days: float
    since: datetime | None  # first DNS lookup; null until there is one
    until: datetime | None  # learning ends
    learning: bool
    watched: bool  # false for phones and computers: no departures recorded
    counts: dict[str, int]  # sites, organizations, countries and networks it uses
    usual_peak: int  # lookups in a busy hour (95th percentile of the last week)
    departures: list[Departure]  # newest first


@router.get("/api/devices/{mac}/baseline", response_model=Baseline)
def device_baseline(mac: Mac, db: DB) -> Baseline:
    """What's normal for the device, and the latest departures from it."""
    device = get_device(db, mac)
    days = get_settings().baseline_learning_days
    now = datetime.now(UTC)
    period = learning_periods(db, days, [device.mac]).get(str(device.mac))
    counts = dict(
        db.execute(
            select(DeviceBaseline.key_type, func.count())
            .where(DeviceBaseline.mac == device.mac)
            .group_by(DeviceBaseline.key_type)
        ).all()
    )
    departures = db.scalars(
        select(DeviceEvent)
        .where(DeviceEvent.mac == device.mac, DeviceEvent.kind.in_(BASELINE_EVENT_KINDS))
        .order_by(DeviceEvent.time.desc(), DeviceEvent.id.desc())
        .limit(20)
    ).all()
    return Baseline(
        learning_days=days,
        since=period.since if period else None,
        until=period.until if period else None,
        learning=period is None or not period.done(now),
        watched=device.category not in UNWATCHED_CATEGORIES,
        counts={k: counts.get(k, 0) for k in BASELINE_KEY_TYPES},
        usual_peak=usual_peak(db, device.mac, now),
        departures=[Departure.model_validate(e, from_attributes=True) for e in departures],
    )
