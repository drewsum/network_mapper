"""Names devices from their DHCP fingerprint with the Fingerbank API (NETMAP_FINGERBANK_API_KEY,
free at fingerbank.org).

A device's DHCP request lists the options it wants in its own order (option 55), which
says a lot about its OS and make; Fingerbank matches that, with the vendor class (option
60) and MAC vendor, against its database and answers with a device ("Google Nest Cam",
"Apple iPhone") and its family ("Internet of Things (IoT)"). Only the MAC's vendor half is
sent, never the whole address.

Fingerprints are looked up when first seen or changed, and again after a month; at most
LOOKUPS_PER_ROUND an hour, well inside the free plan. A confident answer (score
MIN_SCORE or more) fills in the category of a device still "unknown"; categories set by
hand are never changed.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netmap.collector.base import Source
from netmap.collector.dns import CheckResult, record_check
from netmap.db import get_sessionmaker
from netmap.db.models import Device, DeviceName
from netmap.httpjson import HttpError, JsonClient

log = logging.getLogger(__name__)

API = "https://api.fingerbank.org"
CHECK = "fingerbank"
LOOKUPS_PER_ROUND = 25
RECHECK = timedelta(days=30)
MIN_SCORE = 50

# Words in Fingerbank's device name or its families -> netmap category, first match wins.
CATEGORY_WORDS = (
    ("phone", ("phone", "tablet", "wearable", "smartwatch", "ipad", "android os")),
    ("media", ("smart tv", "set-top", "television", "video game", "gaming console",
               "media player", "streaming", "chromecast", "roku", "apple tv", "fire tv",
               "audio", "speaker", "sonos")),
    ("iot", ("internet of things", "iot", "camera", "thermostat", "doorbell", "smart home",
             "light", "plug", "sensor", "hub", "lock", "appliance", "home automation")),
    ("infrastructure", ("router", "access point", "switch", "firewall", "storage", "nas",
                        "printer", "scanner", "network", "ups", "femtocell")),
    ("computer", ("computer", "windows", "macos", "mac os", "linux", "laptop", "desktop",
                  "workstation", "chrome os", "server")),
)  # fmt: skip


def category_for(names: list[str]) -> str | None:
    text = " / ".join(names).lower()
    for category, words in CATEGORY_WORDS:
        if any(w in text for w in words):
            return category
    return None


def vendor_mac(mac: str) -> str:
    """The MAC's vendor half (its OUI), the rest zeroed."""
    return mac.lower()[:8] + ":00:00:00"


def parse(answer: dict) -> dict:
    """What to keep of an interrogate answer."""
    device = answer.get("device") or {}
    parents = [p.get("name") for p in device.get("parents") or [] if p.get("name")]
    return {
        "device": device.get("name"),
        "parents": parents,
        "device_name": answer.get("device_name"),
        "score": answer.get("score"),
    }


def due(session: Session, now: datetime) -> list[tuple[str, str, str | None]]:
    """(mac, fingerprint, vendor class) for devices to look up, never-looked-up first."""
    rows = session.execute(
        select(Device.mac, Device.fingerbank, DeviceName.details)
        .join(DeviceName, (DeviceName.mac == Device.mac) & (DeviceName.source == "dhcp"))
        .where(Device.merged_into.is_(None))
    ).all()
    out = []
    for mac, known, details in rows:
        fingerprint = (details or {}).get("fingerprint")
        if not fingerprint:
            continue
        known = known or {}
        checked = known.get("checked_at")
        stale = not checked or datetime.fromisoformat(checked) < now - RECHECK
        if known.get("fingerprint") != fingerprint or stale:
            out.append((str(mac), fingerprint, (details or {}).get("vendor_class"), bool(checked)))
    out.sort(key=lambda r: r[3])
    return [r[:3] for r in out[:LOOKUPS_PER_ROUND]]


class AuthError(Exception):
    pass


def interrogate(client: JsonClient, key: str, mac: str, fingerprint: str, vendor: str | None):
    """Fingerbank's answer, or None when it knows nothing about this fingerprint."""
    params = {"key": key, "dhcp_fingerprint": fingerprint, "mac": vendor_mac(mac)}
    if vendor:
        params["dhcp_vendor"] = vendor
    status, body, _ = client.call("GET", "/api/v2/combinations/interrogate?" + urlencode(params))
    if status in (401, 403):
        raise AuthError("Fingerbank rejected the API key (NETMAP_FINGERBANK_API_KEY)")
    if status == 404:
        return None
    if status != 200 or not isinstance(body, dict):
        raise HttpError(f"Fingerbank answered HTTP {status}")
    return parse(body)


def store(session: Session, mac: str, fingerprint: str, result: dict | None, now: datetime):
    device = session.get(Device, mac)
    if device is None:
        return
    device.fingerbank = {**(result or {"device": None}), "fingerprint": fingerprint,
                         "checked_at": now.isoformat()}  # fmt: skip
    if result and (result.get("score") or 0) >= MIN_SCORE and device.category == "unknown":
        category = category_for([result.get("device") or "", *result.get("parents", []),
                                 result.get("device_name") or ""])  # fmt: skip
        if category:
            device.category = category
            device.is_iot = device.is_iot or category == "iot"


def lookup_round(session: Session, client: JsonClient, key: str, now: datetime) -> CheckResult:
    """Look up what's due. Commits after each device."""
    looked = 0
    for mac, fingerprint, vendor in due(session, now):
        try:
            result = interrogate(client, key, mac, fingerprint, vendor)
        except AuthError as exc:
            return CheckResult("warning", str(exc), {})
        except HttpError as exc:
            return CheckResult(
                "warning", f"Couldn't reach Fingerbank: {exc}", {"looked_up": looked}
            )
        store(session, mac, fingerprint, result, now)
        session.commit()
        looked += 1
    identified = session.scalar(
        select(func.count()).where(Device.fingerbank["device"].astext.isnot(None))
    )
    return CheckResult(
        "ok",
        f"Fingerbank has identified {identified} device{'s' if identified != 1 else ''} "
        "from their DHCP fingerprints.",
        {"identified": identified, "looked_up": looked},
    )


class FingerbankSource(Source):
    name = "fingerbank"
    interval_seconds = 3600.0

    def enabled(self) -> bool:
        return self.settings.fingerbank_api_key is not None

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        key = self.settings.require("fingerbank_api_key").get_secret_value()
        now = datetime.now(UTC)
        with get_sessionmaker()() as session:
            result = lookup_round(session, JsonClient(API), key, now)
            record_check(session, CHECK, result, now)
        log.info("fingerbank: %s", result.message)
