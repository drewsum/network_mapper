"""Shared API dependencies: the DB session and path parameters."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Path
from sqlalchemy.orm import Session

from netmap.db import get_sessionmaker
from netmap.db.models import Device


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


DB = Annotated[Session, Depends(get_db)]
MAC_PATTERN = r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"
Mac = Annotated[str, Path(pattern=MAC_PATTERN)]


def get_device(db: Session, mac: str) -> Device:
    device = db.get(Device, mac.lower())
    if device is None:
        raise HTTPException(404, "unknown device")
    return device
