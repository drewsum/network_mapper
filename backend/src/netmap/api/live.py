"""Live throughput over a WebSocket (/api/live): passes on what the capture service publishes
on ``netmap_live`` (capture/live.py) every few seconds, starting with the last minute's
average so the page has numbers at once.

The HTTP login check doesn't cover WebSockets, so this checks the session cookie itself,
and refuses connections from pages on other sites.
"""

import asyncio
import contextlib
import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.engine import make_url

from netmap.api import auth
from netmap.capture.live import CHANNEL
from netmap.config import get_settings
from netmap.db import get_sessionmaker

log = logging.getLogger(__name__)
router = APIRouter()


def allowed(ws: WebSocket) -> bool:
    """Logged in (or no password set), and from a page on this site."""
    origin = ws.headers.get("origin")
    if origin and urlsplit(origin).netloc != ws.headers.get("host"):
        return False
    settings = get_settings()
    if not auth.auth_enabled(settings):
        return True
    return auth.token_valid(auth.signing_key(settings), ws.cookies.get(auth.COOKIE))


def snapshot() -> dict:
    """Bytes/second per device over the last whole minute of flows."""
    end = datetime.now(UTC).replace(second=0, microsecond=0)
    with get_sessionmaker()() as session:
        rows = session.execute(
            text("""
                SELECT mac::text, sum(bytes_up)::bigint, sum(bytes_down)::bigint FROM flows
                WHERE time >= :start AND time < :end GROUP BY 1
            """),
            {"start": end - timedelta(minutes=1), "end": end},
        ).all()
    return {
        "time": end.isoformat(),
        "seconds": 60,
        "devices": {mac: [round(up / 60), round(down / 60)] for mac, up, down in rows},
    }


def _conninfo() -> str:
    url = make_url(get_settings().database_url).set(drivername="postgresql")
    return url.render_as_string(hide_password=False)


class Listener:
    """LISTENs on its own blocking connection in a thread (portable: async psycopg can't run
    on Windows' default event loop), handing payloads to the event loop."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.queue: asyncio.Queue[str | None] = asyncio.Queue()
        self.ready = threading.Event()
        self.stopping = threading.Event()
        self.error: Exception | None = None
        self.thread = threading.Thread(target=self._run, name="live-listen", daemon=True)

    def _run(self) -> None:
        try:
            with psycopg.connect(_conninfo(), autocommit=True) as conn:
                conn.execute(f"LISTEN {CHANNEL}")
                self.ready.set()
                while not self.stopping.is_set():
                    for n in conn.notifies(timeout=1.0):
                        self.loop.call_soon_threadsafe(self.queue.put_nowait, n.payload)
        except psycopg.Error as exc:
            self.error = exc
        finally:
            self.ready.set()
            self.loop.call_soon_threadsafe(self.queue.put_nowait, None)

    async def start(self) -> None:
        self.thread.start()
        await asyncio.to_thread(self.ready.wait)
        if self.error:
            raise self.error


@router.websocket("/api/live")
async def live(ws: WebSocket) -> None:
    if not allowed(ws):
        await ws.close(code=4401)
        return
    await ws.accept()
    listener = Listener(asyncio.get_running_loop())
    closed = asyncio.create_task(_until_closed(ws))
    try:
        await listener.start()  # before the snapshot, so nothing published is missed
        await ws.send_text(json.dumps(await asyncio.to_thread(snapshot)))
        while not closed.done():
            nxt = asyncio.ensure_future(listener.queue.get())
            done, _ = await asyncio.wait({nxt, closed}, return_when=asyncio.FIRST_COMPLETED)
            if nxt not in done:
                nxt.cancel()
                break
            if nxt.result() is None:  # the listener's connection dropped
                raise listener.error or psycopg.OperationalError("connection closed")
            await ws.send_text(nxt.result())
    except (WebSocketDisconnect, RuntimeError):
        pass
    except psycopg.Error as exc:
        log.warning("live: database: %s", exc)
        with contextlib.suppress(RuntimeError):
            await ws.close(code=1011)
    finally:
        listener.stopping.set()
        closed.cancel()


async def _until_closed(ws: WebSocket) -> None:
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        while True:
            await ws.receive_text()
