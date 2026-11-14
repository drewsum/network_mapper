from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from netmap import __version__
from netmap.config import get_settings
from netmap.db import get_sessionmaker
from netmap.db.models import Device


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


DB = Annotated[Session, Depends(get_db)]


class Health(BaseModel):
    status: str
    version: str
    database: bool


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    mac: str
    label: str | None
    hostname: str | None
    vendor: str | None
    is_randomized_mac: bool
    category: str
    is_iot: bool
    online: bool
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

    _mount_spa(app, get_settings().web_dist_dir)
    return app


def _mount_spa(app: FastAPI, dist_dir: str | None) -> None:
    """Serve the built React app (production image). In dev, Vite serves it instead."""
    if not dist_dir or not (Path(dist_dir) / "index.html").is_file():
        return
    dist = Path(dist_dir)
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
