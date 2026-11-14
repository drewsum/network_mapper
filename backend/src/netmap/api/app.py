from collections.abc import Iterator
from datetime import datetime
from pathlib import Path as FsPath
from typing import Annotated, Literal

from fastapi import Body, Depends, FastAPI, HTTPException, Path, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from netmap import __version__
from netmap.collector.inventory import known_addresses, merge_devices
from netmap.config import get_settings
from netmap.db import get_sessionmaker
from netmap.db.models import (
    DEVICE_CATEGORIES,
    Device,
    DeviceEvent,
    DeviceIP,
    DeviceName,
    Port,
    UpnpMapping,
)


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


DB = Annotated[Session, Depends(get_db)]
MAC_PATTERN = r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"
Mac = Annotated[str, Path(pattern=MAC_PATTERN)]
Category = Literal[DEVICE_CATEGORIES]  # type: ignore[valid-type]


class Health(BaseModel):
    status: str
    version: str
    database: bool


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    mac: str
    label: str | None
    hostname: str | None
    hostname_source: str | None
    vendor: str | None
    is_randomized_mac: bool
    category: str
    is_iot: bool
    notes: str | None
    online: bool
    first_seen: datetime
    last_seen: datetime
    ip: str | None = None  # most recently seen


class DeviceUpdate(BaseModel):
    """Fields the owner sets. Discovery never writes them, so they survive rediscovery.
    Omitted fields are left alone; label and notes can be cleared with null."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=200)
    category: Category | None = None
    is_iot: bool | None = None
    notes: str | None = Field(default=None, max_length=10_000)

    @field_validator("label", "notes")
    @classmethod
    def _blank_is_none(cls, value: str | None) -> str | None:
        return value.strip() or None if value is not None else None


class DeviceIPOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    first_seen: datetime
    last_seen: datetime

    @field_validator("ip", mode="before")
    @classmethod
    def _str(cls, value) -> str:
        return str(value)


class DeviceNameOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    name: str | None
    details: dict | None
    first_seen: datetime
    last_seen: datetime


class DeviceDetail(DeviceOut):
    merged_into: str | None
    aliases: list[str]  # MACs merged into this device
    ips: list[DeviceIPOut]
    names: list[DeviceNameOut]


class DeviceEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    time: datetime
    kind: str
    ip: str | None
    port: int | None
    protocol: str | None

    @field_validator("ip", mode="before")
    @classmethod
    def _str(cls, value) -> str | None:
        return None if value is None else str(value)


class MergeRequest(BaseModel):
    into: str = Field(pattern=MAC_PATTERN, description="MAC of the device to keep")


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    port: int
    protocol: str
    service: str | None
    banner: str | None
    open: bool
    first_seen: datetime
    last_seen: datetime


class UpnpMappingOut(BaseModel):
    external_port: int
    protocol: str
    internal_ip: str
    internal_port: int
    description: str | None
    mac: str | None
    device: str | None  # the device's label or hostname
    active: bool
    first_seen: datetime
    last_seen: datetime


def _device(db: Session, mac: str) -> Device:
    device = db.get(Device, mac.lower())
    if device is None:
        raise HTTPException(404, "unknown device")
    return device


def _detail(db: Session, device: Device) -> DeviceDetail:
    ips = db.scalars(
        select(DeviceIP).where(DeviceIP.mac == device.mac).order_by(DeviceIP.last_seen.desc())
    ).all()
    names = db.scalars(
        select(DeviceName).where(DeviceName.mac == device.mac).order_by(DeviceName.source)
    ).all()
    aliases = db.scalars(
        select(Device.mac).where(Device.merged_into == device.mac).order_by(Device.mac)
    ).all()
    return DeviceDetail.model_validate(
        {
            **DeviceOut.model_validate(device).model_dump(),
            "ip": str(ips[0].ip) if ips else None,
            "merged_into": device.merged_into,
            "aliases": list(aliases),
            "ips": ips,
            "names": names,
        }
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="netmap",
        version=__version__,
        description="Home network device inventory and activity history.",
    )

    @app.get("/api/health", response_model=Health)
    def health(db: DB) -> Health:
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(503, "database unavailable") from exc
        return Health(status="ok", version=__version__, database=True)

    @app.get("/api/devices", response_model=list[DeviceOut])
    def list_devices(db: DB) -> list[DeviceOut]:
        """Every device, except those merged into another."""
        devices = db.scalars(
            select(Device)
            .where(Device.merged_into.is_(None))
            .order_by(Device.category, Device.hostname)
        ).all()
        ips = known_addresses(db)
        return [
            DeviceOut.model_validate(d).model_copy(update={"ip": ips.get(d.mac)}) for d in devices
        ]

    @app.get("/api/devices/{mac}", response_model=DeviceDetail)
    def get_device(mac: Mac, db: DB) -> DeviceDetail:
        return _detail(db, _device(db, mac))

    @app.patch("/api/devices/{mac}", response_model=DeviceDetail)
    def update_device(mac: Mac, changes: DeviceUpdate, db: DB) -> DeviceDetail:
        device = _device(db, mac)
        if device.merged_into:
            raise HTTPException(409, f"merged into {device.merged_into}; edit that device")
        values = changes.model_dump(exclude_unset=True)
        if values.get("category", "") is None or values.get("is_iot", False) is None:
            raise HTTPException(422, "category and is_iot can't be null")
        for field, value in values.items():
            setattr(device, field, value)
        db.commit()
        return _detail(db, device)

    @app.post("/api/devices/{mac}/merge", response_model=DeviceDetail)
    def merge_device(mac: Mac, request: Annotated[MergeRequest, Body()], db: DB) -> DeviceDetail:
        """Fold device ``mac`` into ``into``: history, IPs, names and ports move over, and
        later sightings of ``mac`` count for ``into``. For one device seen under two MACs,
        such as a phone that switched to a new private address."""
        source = _device(db, mac)
        target = _device(db, request.into)
        if target.merged_into:
            target = _device(db, target.merged_into)
        if source.merged_into:
            raise HTTPException(409, f"already merged into {source.merged_into}")
        if source.mac == target.mac:
            raise HTTPException(400, "can't merge a device into itself")
        merge_devices(db, source.mac, target.mac, get_settings().hostname_sources)
        db.expire_all()
        return _detail(db, _device(db, target.mac))

    @app.get("/api/devices/{mac}/events", response_model=list[DeviceEventOut])
    def device_events(
        mac: Mac,
        db: DB,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        before: datetime | None = None,
    ) -> list[DeviceEvent]:
        """Device history, newest first. Page with ``before`` (the last event's time)."""
        device = _device(db, mac)
        stmt = select(DeviceEvent).where(DeviceEvent.mac == device.mac)
        if before is not None:
            stmt = stmt.where(DeviceEvent.time < before)
        return list(
            db.scalars(stmt.order_by(DeviceEvent.time.desc(), DeviceEvent.id.desc()).limit(limit))
        )

    @app.get("/api/devices/{mac}/ports", response_model=list[PortOut])
    def device_ports(mac: Mac, db: DB) -> list[Port]:
        """Ports found by the scanner, open ones first; closed ones keep their history."""
        device = _device(db, mac)
        return list(
            db.scalars(
                select(Port)
                .where(Port.mac == device.mac)
                .order_by(Port.open.desc(), Port.protocol, Port.port)
            )
        )

    @app.get("/api/upnp-mappings", response_model=list[UpnpMappingOut])
    def upnp_mappings(db: DB) -> list[UpnpMappingOut]:
        """Port forwards devices opened on the router over UPnP, active ones first."""
        rows = db.execute(
            select(UpnpMapping, func.coalesce(Device.label, Device.hostname))
            .outerjoin(Device, Device.mac == UpnpMapping.mac)
            .order_by(UpnpMapping.active.desc(), UpnpMapping.external_port)
        ).all()
        return [
            UpnpMappingOut(
                external_port=m.external_port,
                protocol=m.protocol,
                internal_ip=str(m.internal_ip),
                internal_port=m.internal_port,
                description=m.description,
                mac=m.mac,
                device=device,
                active=m.active,
                first_seen=m.first_seen,
                last_seen=m.last_seen,
            )
            for m, device in rows
        ]

    _mount_spa(app, get_settings().web_dist_dir)
    return app


def _mount_spa(app: FastAPI, dist_dir: str | None) -> None:
    """Serve the built React app (production image). In dev, Vite serves it instead."""
    if not dist_dir or not (FsPath(dist_dir) / "index.html").is_file():
        return
    dist = FsPath(dist_dir)
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
