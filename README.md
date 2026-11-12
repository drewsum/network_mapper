# network_mapper

Self-hosted map of every device on the home LAN/WLAN, plus a 30-day history of what each
device talks to. Built mainly to see whether IoT devices phone home anywhere beyond their
companion apps' clouds. It runs in Docker and will be deployed on TrueNAS.

**v1 data sources:** Pi-hole's DNS query log and active LAN discovery. No network changes
are needed. Byte-level traffic (switch port mirroring) is a stretch goal (milestone M7).

## Layout

```
backend/            Python package `netmap` (uv project)
  src/netmap/
    config.py       all settings, from NETMAP_* env vars
    db/             SQLAlchemy models, session, TimescaleDB policies
    api/            FastAPI app (also serves the built UI in production)
    collector/      discovery / Pi-hole sources (M1, M2)
    seed/           synthetic data for local development
  migrations/       Alembic migrations (hypertables, continuous aggregates)
  tests/
web/                React + TypeScript + Vite UI
scripts/            check_hardcoded_ips.py, test.sh
Dockerfile          one image; compose picks the role (api / collector / migrate / seed)
docker-compose.yml  dev stack
```

## Configuration

Every network-specific value (LAN subnet, Pi-hole URL/password, ports, credentials) comes
from environment variables in `.env`. Nothing network-specific is hardcoded, and
`scripts/check_hardcoded_ips.py` enforces this. Copy `.env.example` to `.env` and fill it in.

## Run locally

Requires Docker Desktop.

```sh
cp .env.example .env        # then edit
docker compose up -d --build
docker compose run --rm seed            # 30 days of fake devices + DNS activity
docker compose run --rm seed --reset    # wipe and reseed
```

- UI (Vite dev server, hot reload): http://localhost:5173
- API: http://localhost:8000/api/health, OpenAPI docs at http://localhost:8000/docs
- The API container also serves the built UI at http://localhost:8000

On Windows, Docker Desktop runs containers in a VM and can't see the real LAN at layer 2.
Pi-hole polling works locally. ARP, mDNS and DHCP discovery has to be tested on TrueNAS or
another Linux host on the LAN.

## Tests and lint (local only)

Tests run locally, not in GitHub Actions.

```sh
uvx pre-commit install      # once: lint, IP check, unit tests on each commit
bash scripts/test.sh        # everything, incl. DB integration tests
```

`scripts/test.sh` runs the DB tests against a separate `netmap_test` database in the
compose `db` container, so your dev data isn't touched.

Backend only: `cd backend && uv run pytest`. DB tests are skipped unless
`NETMAP_TEST_DATABASE_URL` is set.

## Data retention

Raw DNS queries are kept for `NETMAP_RAW_RETENTION_DAYS` (default 30). Hourly and daily
aggregates are kept for 90 and 365 days. These policies are re-applied from env on every
`netmap migrate`, which runs automatically on startup.

## Images and CI

There's no CI. Images are built on the machine that runs them (`docker compose up -d --build`):
this PC for development, and the TrueNAS host for deployment, from a git checkout. Nothing is
published to a registry, and the repo stays private.
