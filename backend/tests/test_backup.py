"""Backups, restore, data export, and the hardening bits of the API."""

import csv
import io
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, insert, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from netmap import cli
from netmap.api.app import create_app
from netmap.backup import (
    BackupError,
    backup_once,
    dump_name,
    dump_time,
    dumps,
    make_dump,
    pg_connection,
    prune,
    restore,
    seconds_until_due,
)
from netmap.cli import main
from netmap.config import get_settings
from netmap.db import get_engine, get_sessionmaker
from netmap.db.models import Alert, Device, DeviceEvent, HealthCheck

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=UTC)


def touch_dumps(directory: Path, *hours_ago: int) -> list[Path]:
    paths = [directory / dump_name(NOW - timedelta(hours=h)) for h in hours_ago]
    for p in paths:
        p.write_bytes(b"dump")
    return paths


class FakePg:
    """Stands in for pg_dump/pg_restore: records calls, writes the --file it's given."""

    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.returncode, self.stderr = returncode, stderr

    def __call__(self, args, env, **_) -> subprocess.CompletedProcess:
        self.calls.append((args, env))
        if "--file" in args:
            Path(args[args.index("--file") + 1]).write_bytes(b"PGDMP fake")
        return subprocess.CompletedProcess(args, self.returncode, "", self.stderr)


def test_dump_names_carry_their_time():
    name = dump_name(NOW)
    assert name == "netmap-20261115T030000Z.dump"
    assert dump_time(Path(name)) == NOW
    assert dump_time(Path("notes.txt")) is None
    assert dump_time(Path("netmap-garbage.dump")) is None


def test_a_dump_is_due_when_the_newest_is_older_than_the_interval(tmp_path):
    day = timedelta(hours=24)
    assert seconds_until_due(tmp_path, NOW, day) == 0  # none yet
    touch_dumps(tmp_path, 30, 2)
    assert seconds_until_due(tmp_path, NOW, day) == 22 * 3600
    assert seconds_until_due(tmp_path, NOW + timedelta(hours=23), day) == 0


def test_prune_keeps_the_newest_and_drops_unfinished(tmp_path):
    newest, middle, oldest = touch_dumps(tmp_path, 1, 25, 49)
    partial = tmp_path / (dump_name(NOW) + ".partial")
    partial.write_bytes(b"half")
    (tmp_path / "keep-me.txt").write_text("not a dump")
    assert set(prune(tmp_path, keep=2)) == {oldest, partial}
    assert dumps(tmp_path) == [newest, middle]
    assert (tmp_path / "keep-me.txt").exists()


def test_password_goes_in_the_environment_not_the_arguments():
    args, env = pg_connection(make_url("postgresql+psycopg://netmap:s3cret@db:5432/netmap"))
    assert args == ["--host", "db", "--port", "5432", "--username", "netmap"]
    assert env["PGPASSWORD"] == "s3cret"
    assert "s3cret" not in " ".join(args)


def test_make_dump_renames_only_a_finished_dump(tmp_path, monkeypatch):
    monkeypatch.setenv("NETMAP_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("NETMAP_DATABASE_URL", "postgresql+psycopg://u:pw@db:5432/netmap")
    pg = FakePg()
    path = make_dump(get_settings(), NOW, pg)
    assert path == tmp_path / "netmap-20261115T030000Z.dump"
    assert path.read_bytes() == b"PGDMP fake"
    args, env = pg.calls[0]
    assert Path(args[0]).name == "pg_dump" and "--format=custom" in args and args[-1] == "netmap"
    assert env["PGPASSWORD"] == "pw"

    failing = FakePg(returncode=1, stderr="pg_dump: error: connection refused")
    with pytest.raises(BackupError, match="connection refused"):
        make_dump(get_settings(), NOW + timedelta(days=1), failing)
    assert dumps(tmp_path) == [path]
    assert not list(tmp_path.glob("*.partial"))


def test_backup_once_records_the_result(db_env, tmp_path, monkeypatch):
    main(["migrate"])
    monkeypatch.setenv("NETMAP_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("NETMAP_BACKUP_KEEP", "2")
    get_settings.cache_clear()
    touch_dumps(tmp_path, 48, 72)

    result = backup_once(get_settings(), NOW, FakePg())
    assert result.status == "ok"
    assert len(dumps(tmp_path)) == 2
    with get_sessionmaker()() as s:
        check = s.get(HealthCheck, "backup")
        assert check.status == "ok"
        assert check.details["file"] == dump_name(NOW)
        assert check.details["kept"] == 2

    result = backup_once(get_settings(), NOW, FakePg(returncode=1, stderr="disk full"))
    assert result.status == "warning" and "disk full" in result.message
    with get_sessionmaker()() as s:
        assert s.get(HealthCheck, "backup").status == "warning"


def test_restore_makes_a_fresh_timescale_database(db_env):
    main(["migrate"])
    target = "netmap_restore_test"
    pg = FakePg()
    dump = Path("x.dump")
    dump.write_bytes(b"PGDMP fake")
    assert restore(get_settings(), dump, target, pg) == target
    args, _ = pg.calls[0]
    assert Path(args[0]).name == "pg_restore" and args[-3:] == ["--dbname", target, "x.dump"]

    engine = create_engine(make_url(db_env.database_url).set(database=target), poolclass=NullPool)
    try:
        with engine.connect() as conn:
            assert conn.scalar(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))
            # post_restore turned restoring mode back off.
            assert conn.scalar(text("SHOW timescaledb.restoring")) == "off"
    finally:
        engine.dispose()
        admin = create_engine(
            make_url(db_env.database_url).set(database="postgres"),
            poolclass=NullPool,
            isolation_level="AUTOCOMMIT",
        )
        with admin.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {target}"))
        admin.dispose()


def test_restore_refuses_while_the_app_is_connected(db_env):
    main(["migrate"])
    dump = Path("x.dump")
    dump.write_bytes(b"PGDMP fake")
    with get_engine().connect() as conn:  # stands in for the api
        conn.execute(text("SELECT 1"))
        with pytest.raises(BackupError, match="stop the api and collector"):
            restore(get_settings(), dump, None, FakePg())
        assert conn.scalar(text("SELECT count(*) FROM alembic_version")) == 1


def test_restore_of_the_live_database_needs_yes(db_env):
    with pytest.raises(SystemExit, match="--yes"):
        main(["restore", "x.dump"])


def test_api_trusts_only_the_configured_proxies(monkeypatch):
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: seen.update(kw))
    cli.cmd_api(None)
    assert seen["forwarded_allow_ips"] is None  # uvicorn's default: loopback only
    monkeypatch.setenv("NETMAP_TRUSTED_PROXIES", "172.16.0.0/12")
    get_settings.cache_clear()
    cli.cmd_api(None)
    assert seen["forwarded_allow_ips"] == "172.16.0.0/12"


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE devices, alerts, device_events CASCADE"))
    old = datetime.now(UTC) - timedelta(days=10)
    with get_sessionmaker()() as s:
        s.execute(
            insert(Device),
            [
                {"mac": "00:ee:00:00:00:01", "label": "Thermostat, upstairs", "is_iot": True},
                {"mac": "00:ee:00:00:00:02", "hostname": "laptop", "category": "computer"},
            ],
        )
        s.execute(
            insert(DeviceEvent),
            [
                {"time": old, "mac": "00:ee:00:00:00:01", "kind": "new_device"},
                {
                    "time": datetime.now(UTC),
                    "mac": "00:ee:00:00:00:01",
                    "kind": "online",
                    "ip": "192.0.2.7",
                },
            ],
        )
        s.execute(
            insert(Alert),
            [
                {
                    "mac": "00:ee:00:00:00:02",
                    "kind": "new_device",
                    "severity": "warning",
                    "message": "New device: laptop",
                    "details": {"why": "first seen"},
                    "dedup_key": "new_device:00:ee:00:00:00:02",
                }
            ],
        )
        s.commit()
    with TestClient(create_app()) as c:
        yield c


def test_export_lists_datasets(client):
    names = {d["name"]: d["by_time"] for d in client.get("/api/export").json()}
    assert names["devices"] is False and names["events"] is True and "dns_daily" in names


def test_export_devices_as_csv(client):
    r = client.get("/api/export/devices.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert 'filename="netmap-devices-' in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [row["mac"] for row in rows] == ["00:ee:00:00:00:01", "00:ee:00:00:00:02"]
    assert rows[0]["label"] == "Thermostat, upstairs"  # quoted, not split
    assert rows[0]["is_iot"] == "True" and rows[1]["label"] == ""


def test_export_json_and_days(client):
    events = client.get("/api/export/events.json").json()
    assert [e["kind"] for e in events] == ["new_device", "online"]
    assert events[1]["ip"] == "192.0.2.7"
    recent = client.get("/api/export/events.json", params={"days": 3}).json()
    assert [e["kind"] for e in recent] == ["online"]
    alerts = list(csv.DictReader(io.StringIO(client.get("/api/export/alerts.csv").text)))
    assert alerts[0]["details"] == '{"why":"first seen"}'
    assert client.get("/api/export/dns_daily.csv").status_code == 200
    assert client.get("/api/export/secrets.csv").status_code == 422
    assert client.get("/api/export/devices.xml").status_code == 422


def test_responses_carry_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
