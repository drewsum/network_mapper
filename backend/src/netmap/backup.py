"""Database backups: `netmap backup` keeps a pg_dump of the database in NETMAP_BACKUP_DIR,
and `netmap restore` puts one back.

A dump is due when the newest is older than NETMAP_BACKUP_INTERVAL_HOURS, so restarts don't
add extra ones. Each is pg_dump's custom format, named for when it started, and only the
newest NETMAP_BACKUP_KEEP are kept. Every run is recorded as the "backup" health check, so a
failure shows in the UI.

Restoring follows TimescaleDB's steps for a logical backup: a fresh database with the
extension, timescaledb_pre_restore(), pg_restore, timescaledb_post_restore(). The server must
run the TimescaleDB version that made the dump (the compose files pin it).
"""

import logging
import os
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from netmap.collector.dns import CheckResult, record_check
from netmap.config import Settings
from netmap.db import get_engine, get_sessionmaker

log = logging.getLogger(__name__)

CHECK = "backup"
PREFIX, SUFFIX, PARTIAL = "netmap-", ".dump", ".partial"
STAMP = "%Y%m%dT%H%M%SZ"
# The loop wakes at least this often, to touch its heartbeat file for the healthcheck.
WAKE_SECONDS = 300.0
HEARTBEAT = Path("/tmp/netmap-backup-heartbeat")

Runner = Callable[..., subprocess.CompletedProcess]


class BackupError(RuntimeError):
    pass


def dump_name(when: datetime) -> str:
    return f"{PREFIX}{when.astimezone(UTC).strftime(STAMP)}{SUFFIX}"


def dump_time(path: Path) -> datetime | None:
    """When a dump was started, from its name; None for files that aren't dumps."""
    if not (path.name.startswith(PREFIX) and path.name.endswith(SUFFIX)):
        return None
    try:
        return datetime.strptime(path.name[len(PREFIX) : -len(SUFFIX)], STAMP).replace(tzinfo=UTC)
    except ValueError:
        return None


def dumps(directory: Path) -> list[Path]:
    """The dumps in ``directory``, newest first."""
    found = [p for p in directory.iterdir() if p.is_file() and dump_time(p)]
    return sorted(found, key=lambda p: p.name, reverse=True)  # names sort by time


def seconds_until_due(directory: Path, now: datetime, interval: timedelta) -> float:
    """0 when a dump is due now, else how long until it is."""
    existing = dumps(directory)
    if not existing:
        return 0.0
    due = dump_time(existing[0]) + interval  # type: ignore[operator]
    return max(0.0, (due - now).total_seconds())


def prune(directory: Path, keep: int) -> list[Path]:
    """Delete all but the newest ``keep`` dumps, and dumps that never finished."""
    removed = dumps(directory)[keep:] + list(directory.glob(f"{PREFIX}*{PARTIAL}"))
    for path in removed:
        path.unlink(missing_ok=True)
    return removed


def _url(settings: Settings, database: str | None = None) -> URL:
    url = make_url(settings.database_url)
    return url.set(database=database) if database else url


def pg_connection(url: URL) -> tuple[list[str], dict[str, str]]:
    """Connection arguments for pg_dump/pg_restore, and the environment carrying the password."""
    args = ["--host", url.host or "localhost", "--port", str(url.port or 5432)]
    if url.username:
        args += ["--username", url.username]
    env = {**os.environ, "PGPASSWORD": url.password or ""} if url.password else dict(os.environ)
    return args, env


def _run(run: Runner, args: list[str], env: dict[str, str]) -> None:
    result = run(args, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()[-5:]
        raise BackupError(f"{Path(args[0]).name} failed: " + " / ".join(tail))


def make_dump(settings: Settings, now: datetime, run: Runner = subprocess.run) -> Path:
    """Dump the database into the backup directory. Written under a temporary name and
    renamed when complete, so a dump that's there is whole."""
    directory = Path(settings.backup_dir)
    final = directory / dump_name(now)
    partial = final.with_name(final.name + PARTIAL)
    url = _url(settings)
    conn, env = pg_connection(url)
    pg_dump = str(Path(settings.pg_bin_dir) / "pg_dump")
    try:
        _run(
            run,
            [pg_dump, "--format=custom", "--file", str(partial), *conn, url.database or ""],
            env,
        )
        partial.rename(final)
    finally:
        partial.unlink(missing_ok=True)
    return final


def _size(n: float) -> str:
    if n < 1024:
        return f"{n:.0f} bytes"
    for unit in ("KB", "MB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n / 1024:.1f} GB"


def backup_once(settings: Settings, now: datetime, run: Runner = subprocess.run) -> CheckResult:
    """One dump, then pruning; returns the health check result (and records it)."""
    directory = Path(settings.backup_dir)
    started = time.monotonic()
    try:
        if not os.access(directory, os.W_OK):
            raise BackupError(
                f"can't write to {directory}; it must belong to the netmap user (uid 10001)"
            )
        path = make_dump(settings, now, run)
        prune(directory, settings.backup_keep)
        kept = dumps(directory)
        result = CheckResult(
            "ok",
            f"Backed up the database ({_size(path.stat().st_size)}); {len(kept)} backups kept.",
            {
                "file": path.name,
                "bytes": path.stat().st_size,
                "seconds": round(time.monotonic() - started, 1),
                "kept": len(kept),
                "total_bytes": sum(p.stat().st_size for p in kept),
                "oldest": kept[-1].name,
                "next": (now + timedelta(hours=settings.backup_interval_hours)).isoformat(),
            },
        )
    except (BackupError, OSError) as exc:
        log.error("backup failed: %s", exc)
        result = CheckResult("warning", f"The database backup failed: {exc}", {"error": str(exc)})
    with get_sessionmaker()() as session:
        record_check(session, CHECK, result, now)
    # Hold no connection between runs, so `netmap restore` finds the database free.
    get_engine().dispose()
    return result


def run_backups(settings: Settings, once: bool = False) -> None:
    """Dump whenever one is due, forever (or once, now)."""
    os.umask(0o077)  # dumps hold everything: only the netmap user may read them
    directory = Path(settings.backup_dir)
    interval = timedelta(hours=settings.backup_interval_hours)
    if once:
        result = backup_once(settings, datetime.now(UTC))
        print(result.message)
        if result.status != "ok":
            raise SystemExit(1)
        return
    log.info("backups every %s to %s, keeping %d", interval, directory, settings.backup_keep)
    while True:
        HEARTBEAT.touch()
        try:
            wait = seconds_until_due(directory, datetime.now(UTC), interval)
        except OSError as exc:
            log.error("can't read %s: %s", directory, exc)
            wait = 0.0
        if wait == 0:
            result = backup_once(settings, datetime.now(UTC))
            log.info(result.message)
            # After a failure, try again in an hour rather than straight away.
            wait = WAKE_SECONDS if result.status == "ok" else 3600.0
        time.sleep(min(wait, WAKE_SECONDS))


def _admin_engine(settings: Settings, database: str):
    return create_engine(_url(settings, database), poolclass=NullPool, isolation_level="AUTOCOMMIT")


def restore(
    settings: Settings, dump: Path, database: str | None = None, run: Runner = subprocess.run
) -> str:
    """Replace ``database`` (by default the app's own) with the contents of ``dump``.
    Refuses while anything else is connected to it, such as the api or the collector."""
    if not dump.is_file():
        raise BackupError(f"no such file: {dump}")
    if not os.access(dump, os.R_OK):
        raise BackupError(f"can't read {dump}; run this as the netmap user (docker exec -u netmap)")
    target = database or _url(settings).database
    if not target or target == "postgres":
        raise BackupError("restore into a database other than postgres")
    admin = _admin_engine(settings, "postgres")
    try:
        with admin.connect() as conn:
            others = conn.scalar(
                text("SELECT count(*) FROM pg_stat_activity WHERE datname = :db"), {"db": target}
            )
            if others:
                raise BackupError(
                    f"{others} other connection(s) to {target}: stop the api and collector first"
                )
            quoted = conn.dialect.identifier_preparer.quote(target)
            conn.execute(text(f"DROP DATABASE IF EXISTS {quoted}"))
            conn.execute(text(f"CREATE DATABASE {quoted}"))
    finally:
        admin.dispose()

    db = _admin_engine(settings, target)
    try:
        with db.connect() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            conn.execute(text("SELECT timescaledb_pre_restore()"))
        conn_args, env = pg_connection(_url(settings, target))
        pg_restore = str(Path(settings.pg_bin_dir) / "pg_restore")
        try:
            _run(
                run, [pg_restore, "--exit-on-error", *conn_args, "--dbname", target, str(dump)], env
            )
        finally:
            with db.connect() as conn:
                conn.execute(text("SELECT timescaledb_post_restore()"))
    finally:
        db.dispose()
    return target
