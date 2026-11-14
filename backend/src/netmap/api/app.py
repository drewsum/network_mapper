from collections.abc import Iterator
from datetime import datetime
from pathlib import Path as FsPath
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from netmap import __version__
from netmap.config import get_settings
from netmap.db import get_sessionmaker
from netmap.db.models import Device, Port, UpnpMapping


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


DB = Annotated[Session, Depends(get_db)]
Mac = Annotated[str, Path(pattern=r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")]


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
    online: bool
    first_seen: datetime
    last_seen: datetime


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


def create_app() -> FastAPI:
    app = FastAPI(title="netmap", version=__version__)

    @app.get("/api/health", response_model=Health)
    def health(db: DB) -> Health:
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(503, "database unavailable") from exc
        return Health(status="ok", version=__version__, database=True)

    @app.get("/api/devices", response_model=list[DeviceOut])
    def list_devices(db: DB) -> list[Device]:
        return list(db.scalars(select(Device).order_by(Device.category, Device.hostname)))

    @app.get("/api/devices/{mac}/ports", response_model=list[PortOut])
    def device_ports(mac: Mac, db: DB) -> list[Port]:
        """Ports found by the scanner, open ones first; closed ones keep their history."""
        mac = mac.lower()
        if db.get(Device, mac) is None:
            raise HTTPException(404, "unknown device")
        return list(
            db.scalars(
                select(Port)
                .where(Port.mac == mac)
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
