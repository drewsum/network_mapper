"""Packet captures of one device: ask for one, stop it, download it as a .pcap (for
Wireshark). The capture service runs them (capture/pcap.py) and needs a SPAN port; the
API reads the files from the same volume, mounted read-only."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from netmap.api.deps import DB, Mac, get_device
from netmap.capture.main import CHECK
from netmap.capture.pcap import merged, ring_files
from netmap.config import get_settings
from netmap.db.models import HealthCheck, PacketCapture

router = APIRouter()

# The capture service reports every minute; older than this, it isn't running.
SERVICE_FRESH = timedelta(minutes=5)
MAX_RUNNING = 3


class CaptureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    max_seconds: int
    max_bytes: int
    bytes: int
    packets: int | None
    error: str | None
    requested_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    downloadable: bool = False


class CaptureRequest(BaseModel):
    minutes: int = Field(default=5, ge=1)
    megabytes: int = Field(default=20, ge=1)


class CaptureState(BaseModel):
    available: bool  # the capture service is running with a SPAN port
    reason: str | None
    max_minutes: int
    max_megabytes: int
    captures: list[CaptureOut]


def available(db) -> str | None:
    """Why captures can't run now, or None if they can."""
    check = db.get(HealthCheck, CHECK)
    if check is None or not (check.details or {}).get("span"):
        return (
            "Packet captures need the capture service with a SPAN port "
            "(NETMAP_CAPTURE_INTERFACE); see docs/span.md."
        )
    if check.checked_at < datetime.now(UTC) - SERVICE_FRESH:
        return "The capture service hasn't reported in the last few minutes."
    return None


def _out(c: PacketCapture, directory: Path) -> CaptureOut:
    out = CaptureOut.model_validate(c)
    out.downloadable = c.status != "pending" and bool(ring_files(directory, c.id))
    return out


@router.get("/api/devices/{mac}/captures", response_model=CaptureState)
def list_captures(mac: Mac, db: DB) -> CaptureState:
    settings = get_settings()
    device = get_device(db, mac)
    rows = db.scalars(
        select(PacketCapture)
        .where(PacketCapture.mac == device.mac)
        .order_by(PacketCapture.id.desc())
        .limit(20)
    ).all()
    reason = available(db)
    return CaptureState(
        available=reason is None,
        reason=reason,
        max_minutes=settings.pcap_max_minutes,
        max_megabytes=settings.pcap_max_mb,
        captures=[_out(c, Path(settings.captures_dir)) for c in rows],
    )


@router.post("/api/devices/{mac}/captures", response_model=CaptureOut, status_code=201)
def start_capture(mac: Mac, request: Annotated[CaptureRequest, Body()], db: DB) -> CaptureOut:
    """Capture a device's packets for up to ``minutes``, keeping the last ``megabytes``."""
    settings = get_settings()
    device = get_device(db, mac)
    if reason := available(db):
        raise HTTPException(409, reason)
    if request.minutes > settings.pcap_max_minutes or request.megabytes > settings.pcap_max_mb:
        raise HTTPException(
            422,
            f"at most {settings.pcap_max_minutes} minutes and {settings.pcap_max_mb} MB "
            "(NETMAP_PCAP_MAX_MINUTES, NETMAP_PCAP_MAX_MB)",
        )
    active = PacketCapture.status.in_(("pending", "running"))
    if db.scalar(select(PacketCapture.id).where(active, PacketCapture.mac == device.mac)):
        raise HTTPException(409, "a capture of this device is already running")
    if db.scalar(select(func.count()).where(active)) >= MAX_RUNNING:
        raise HTTPException(409, f"at most {MAX_RUNNING} captures can run at once")
    capture = PacketCapture(
        mac=device.mac,
        max_seconds=request.minutes * 60,
        max_bytes=request.megabytes * 1_000_000,
    )
    db.add(capture)
    db.commit()
    return _out(capture, Path(settings.captures_dir))


def _capture(db, mac: str, capture_id: int) -> PacketCapture:
    device = get_device(db, mac)
    capture = db.get(PacketCapture, capture_id)
    if capture is None or capture.mac != device.mac:
        raise HTTPException(404, "unknown capture")
    return capture


@router.post("/api/devices/{mac}/captures/{capture_id}/stop", response_model=CaptureOut)
def stop_capture(mac: Mac, capture_id: int, db: DB) -> CaptureOut:
    capture = _capture(db, mac, capture_id)
    if capture.status == "pending":
        capture.status = "stopped"
    if capture.status in ("pending", "running", "stopped") and capture.ended_at is None:
        capture.ended_at = datetime.now(UTC)  # the capture service sees this and stops it
    db.commit()
    return _out(capture, Path(get_settings().captures_dir))


@router.get("/api/devices/{mac}/captures/{capture_id}.pcap")
def download_capture(mac: Mac, capture_id: int, db: DB) -> StreamingResponse:
    capture = _capture(db, mac, capture_id)
    files = ring_files(Path(get_settings().captures_dir), capture.id)
    if not files:
        raise HTTPException(410, "this capture's files have been deleted")
    stamp = (capture.started_at or capture.requested_at).strftime("%Y%m%d-%H%M%S")
    name = f"netmap-{str(capture.mac).replace(':', '')}-{stamp}.pcap"
    return StreamingResponse(
        merged(files),
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
