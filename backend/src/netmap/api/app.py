import time
from datetime import datetime
from pathlib import Path as FsPath
from typing import Annotated, Literal

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from netmap import __version__
from netmap.api import (
    alerts,
    auth,
    baseline,
    captures,
    categories,
    dns,
    export,
    history,
    live,
    metrics,
    network,
    orgs,
    pihole,
    report,
    traffic,
)
from netmap.api.deps import DB, MAC_PATTERN, Mac, get_device
from netmap.collector.inventory import known_addresses, merge_devices
from netmap.config import get_settings
from netmap.db.models import (
    DEVICE_CATEGORIES,
    Device,
    DeviceEvent,
    DeviceIP,
    DeviceName,
    HealthCheck,
    Port,
    UpnpMapping,
    WifiClient,
)

Category = Literal[DEVICE_CATEGORIES]  # type: ignore[valid-type]


class Health(BaseModel):
    status: str
    version: str
    database: bool


class SessionOut(BaseModel):
    auth_enabled: bool  # false: no NETMAP_ADMIN_PASSWORD, so everything is open
    authenticated: bool


class LoginRequest(BaseModel):
    password: str = Field(max_length=1024)


# On every response: no framing by other sites, no MIME sniffing, no full URLs in referrers.
SECURITY_HEADERS = {
    "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}
# Reachable without logging in: the container healthcheck, the login flow, and the SPA's
# static files (the login page itself; they hold no data).
PUBLIC_API = {"/api/health", "/api/auth/session", "/api/auth/login", "/api/auth/logout"}
PROTECTED_PREFIXES = ("/api/", "/docs", "/redoc", "/openapi.json")


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
    critical: bool
    offline_grace_minutes: int | None
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
    critical: bool | None = None
    # null: NETMAP_CRITICAL_GRACE_MINUTES
    offline_grace_minutes: int | None = Field(default=None, ge=3, le=7 * 24 * 60)

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


class WifiOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    ap_name: str | None
    ssid: str | None
    band: str | None
    channel: int | None
    signal_dbm: int | None
    rx_rate_kbps: int | None
    tx_rate_kbps: int | None
    connected: bool
    connected_since: datetime | None
    last_seen: datetime


class DeviceDetail(DeviceOut):
    merged_into: str | None
    aliases: list[str]  # MACs merged into this device
    ips: list[DeviceIPOut]
    names: list[DeviceNameOut]
    fingerbank: dict | None  # Fingerbank's guess from the DHCP fingerprint
    wifi: WifiOut | None  # from the Wi-Fi controller, when one is set up
    critical_grace_default: int  # NETMAP_CRITICAL_GRACE_MINUTES


class DeviceEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    time: datetime
    kind: str
    ip: str | None
    port: int | None
    protocol: str | None
    details: dict | None

    @field_validator("ip", mode="before")
    @classmethod
    def _str(cls, value) -> str | None:
        return None if value is None else str(value)


class MergeRequest(BaseModel):
    into: str = Field(pattern=MAC_PATTERN, description="MAC of the device to keep")


class HealthCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str
    message: str
    details: dict | None
    checked_at: datetime


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
    # The device's own MAC, or failing that one merged into it (a phone's older address).
    wifi = db.scalars(
        select(WifiClient)
        .where(WifiClient.mac.in_([device.mac, *aliases]))
        .order_by(WifiClient.connected.desc(), WifiClient.last_seen.desc())
        .limit(1)
    ).first()
    return DeviceDetail.model_validate(
        {
            **DeviceOut.model_validate(device).model_dump(),
            "ip": str(ips[0].ip) if ips else None,
            "merged_into": device.merged_into,
            "aliases": list(aliases),
            "ips": ips,
            "names": names,
            "fingerbank": device.fingerbank,
            "wifi": wifi,
            "critical_grace_default": get_settings().critical_grace_minutes,
        }
    )


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="netmap",
        version=__version__,
        description="Home network device inventory and activity history.",
    )
    failures = auth.FailedLogins()

    def logged_in(request: Request) -> bool:
        if not auth.auth_enabled(settings):
            return True
        return auth.token_valid(auth.signing_key(settings), request.cookies.get(auth.COOKIE))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if (
            path.startswith(PROTECTED_PREFIXES)
            and path not in PUBLIC_API
            and not logged_in(request)
        ):
            return JSONResponse({"detail": "login required"}, status_code=401)
        return await call_next(request)

    @app.get("/api/auth/session", response_model=SessionOut)
    def session_state(request: Request) -> SessionOut:
        return SessionOut(
            auth_enabled=auth.auth_enabled(settings), authenticated=logged_in(request)
        )

    @app.post("/api/auth/login", response_model=SessionOut)
    def login(body: LoginRequest, request: Request, response: Response) -> SessionOut:
        if not auth.auth_enabled(settings):
            raise HTTPException(400, "no admin password is set (NETMAP_ADMIN_PASSWORD)")
        client = request.client.host if request.client else "?"
        if failures.locked(client):
            raise HTTPException(429, "too many failed logins; try again in a few minutes")
        if not auth.password_matches(settings, body.password):
            failures.record(client)
            raise HTTPException(401, "wrong password")
        failures.clear(client)
        max_age = int(settings.session_days * 86400)
        response.set_cookie(
            auth.COOKIE,
            auth.make_token(auth.signing_key(settings), int(time.time()) + max_age),
            max_age=max_age,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
        )
        return SessionOut(auth_enabled=True, authenticated=True)

    @app.post("/api/auth/logout", response_model=SessionOut)
    def logout(response: Response) -> SessionOut:
        response.delete_cookie(auth.COOKIE, httponly=True, samesite="strict")
        return SessionOut(auth_enabled=auth.auth_enabled(settings), authenticated=False)

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
    def read_device(mac: Mac, db: DB) -> DeviceDetail:
        return _detail(db, get_device(db, mac))

    @app.patch("/api/devices/{mac}", response_model=DeviceDetail)
    def update_device(mac: Mac, changes: DeviceUpdate, db: DB) -> DeviceDetail:
        device = get_device(db, mac)
        if device.merged_into:
            raise HTTPException(409, f"merged into {device.merged_into}; edit that device")
        values = changes.model_dump(exclude_unset=True)
        if any(values.get(k, "") is None for k in ("category", "is_iot", "critical")):
            raise HTTPException(422, "category, is_iot and critical can't be null")
        for field, value in values.items():
            setattr(device, field, value)
        db.commit()
        return _detail(db, device)

    @app.post("/api/devices/{mac}/merge", response_model=DeviceDetail)
    def merge_device(mac: Mac, request: Annotated[MergeRequest, Body()], db: DB) -> DeviceDetail:
        """Fold device ``mac`` into ``into``: history, IPs, names and ports move over, and
        later sightings of ``mac`` count for ``into``. For one device seen under two MACs,
        such as a phone that switched to a new private address."""
        source = get_device(db, mac)
        target = get_device(db, request.into)
        if target.merged_into:
            target = get_device(db, target.merged_into)
        if source.merged_into:
            raise HTTPException(409, f"already merged into {source.merged_into}")
        if source.mac == target.mac:
            raise HTTPException(400, "can't merge a device into itself")
        merge_devices(db, source.mac, target.mac, settings.hostname_sources)
        db.expire_all()
        return _detail(db, get_device(db, target.mac))

    @app.get("/api/devices/{mac}/events", response_model=list[DeviceEventOut])
    def device_events(
        mac: Mac,
        db: DB,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        before: datetime | None = None,
    ) -> list[DeviceEvent]:
        """Device history, newest first. Page with ``before`` (the last event's time)."""
        device = get_device(db, mac)
        stmt = select(DeviceEvent).where(DeviceEvent.mac == device.mac)
        if before is not None:
            stmt = stmt.where(DeviceEvent.time < before)
        return list(
            db.scalars(stmt.order_by(DeviceEvent.time.desc(), DeviceEvent.id.desc()).limit(limit))
        )

    @app.get("/api/devices/{mac}/ports", response_model=list[PortOut])
    def device_ports(mac: Mac, db: DB) -> list[Port]:
        """Ports found by the scanner, open ones first; closed ones keep their history."""
        device = get_device(db, mac)
        return list(
            db.scalars(
                select(Port)
                .where(Port.mac == device.mac)
                .order_by(Port.open.desc(), Port.protocol, Port.port)
            )
        )

    @app.get("/api/status", response_model=list[HealthCheckOut])
    def status(db: DB) -> list[HealthCheck]:
        """The collector's latest self-checks, such as whether Pi-hole sees devices by IP."""
        return list(db.scalars(select(HealthCheck).order_by(HealthCheck.name)))

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

    app.include_router(dns.router)
    app.include_router(orgs.router)
    app.include_router(categories.router)
    app.include_router(network.router)
    app.include_router(history.router)
    app.include_router(baseline.router)
    app.include_router(report.router)
    app.include_router(alerts.router)
    app.include_router(pihole.router)
    app.include_router(export.router)
    app.include_router(traffic.router)
    app.include_router(captures.router)
    app.include_router(live.router)
    app.include_router(metrics.router)
    _mount_spa(app, settings.web_dist_dir)
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
