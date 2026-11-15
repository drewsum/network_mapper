# network_mapper

Self-hosted map of every device on the home LAN/WLAN, plus a 30-day history of what each
device talks to. Built mainly to see whether IoT devices phone home anywhere beyond their
companion apps' clouds. It runs in Docker and will be deployed on TrueNAS.

**v1 data sources:** Pi-hole's DNS query log and active LAN discovery. No network changes
are needed. Byte-level traffic (switch port mirroring) is a stretch goal (milestone M7).
See [what netmap can and can't see](docs/visibility.md): it counts lookups, not bytes,
and misses devices that bypass Pi-hole.

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
scripts/            check_hardcoded_ips.py, test.sh, build-on-host.sh
Dockerfile          one image; compose picks the role (api / collector / migrate / seed)
docker-compose.yml  dev stack
deploy/             portainer-compose.yml: the TrueNAS server stack
docs/               deploy-portainer.md
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

## IP locations (GeoIP)

The collector looks up the country, city and network (ASN) of the IPs that domains resolve
to. It gets those IPs from Pi-hole's answers and doesn't resolve anything itself. With a free
MaxMind license key in `NETMAP_MAXMIND_LICENSE_KEY` it uses the GeoLite2 databases and
re-downloads them every `NETMAP_GEOIP_REFRESH_DAYS`. Without a key it uses
[DB-IP](https://db-ip.com)'s free Lite databases (CC BY 4.0), which are updated monthly.
The collector keeps the databases (about 140 MB) in the `geoip` volume. The status bar
shows a warning if the download fails.

## Organizations

Each domain is grouped under an organization such as Google, AWS, Tuya or Apple, so you can
see which companies a device talks to. The grouping comes from a curated map in
`backend/src/netmap/data/organizations.yaml`. The domain's longest matching suffix decides
first. If no suffix matches, the network (ASN) its IP is in decides, so a Tuya domain hosted
on AWS still counts as Tuya. Domains that match neither are grouped as "Other". Rules you
add on the Domains page take precedence over the map, and saving one regroups every domain
right away.

## Categories and blocklists

Each domain also gets a category: ads and trackers, telemetry and analytics, vendor cloud,
CDN and hosting, internet infrastructure (connectivity checks, time, certificate status), or
unknown. Ad and analytics services come from `backend/src/netmap/data/categories.yaml` and
from words in the name (`ads.`, `telemetry.`, `metrics.`). Domains Pi-hole blocks count as
ads and trackers. Everything else takes its organization's category.

Domains are also matched against threat blocklists, downloaded every
`NETMAP_BLOCKLIST_REFRESH_HOURS` (24 by default). A domain is flagged when its name, or any
IP it has resolved to, is on a list:

- FireHOL level1 and abuse.ch Feodo Tracker need no account.
- abuse.ch URLhaus and ThreatFox need a free Auth-Key from https://auth.abuse.ch/ in
  `NETMAP_ABUSECH_AUTH_KEY`. Without one they're skipped.

Flagged domains carry a red "threat" tag in a device's DNS table and are listed on the
Domains page. Download problems show on the status bar as the "blocklists" check.

## Baselines

Each device learns what's normal for it: the sites (registrable domains), organizations,
countries and networks (AS numbers) it looks up, and how many lookups it makes in a busy
hour. Learning starts with the device's first DNS lookup and lasts
`NETMAP_BASELINE_LEARNING_DAYS` (7 by default). After that, anything seen for the first
time is recorded in the device's History, as is an hour with at least 200 lookups and four
times its usual busy hour. A device page's "Normal behavior" card shows the baseline and
the latest changes. Phones and computers get a baseline but no changes recorded, since new
sites are everyday for them. Changing the learning period applies to past data too.

## IoT report

The IoT report page lists, for each IoT device (category IoT, or ticked IoT), the sites it
looked up and sorts each one: its maker's own cloud (the MAC vendor or UPnP manufacturer
matches the site's organization), infrastructure (CDNs, hosting, time, DNS), trackers and
telemetry, threats, or other third parties. Mark a site expected or unexpected for a device
and the report remembers it. Lookups between midnight and 6 am in your time zone are counted
separately. "Download CSV" exports the report as shown.

## Images and CI

There's no CI. Images are built on the machine that runs them (`docker compose up -d --build`):
this PC for development, and the TrueNAS host for deployment. Nothing is published to a
registry, and the repo stays private.

## Deploying on TrueNAS

The server runs `deploy/portainer-compose.yml` as a Portainer Git-repository stack. See
[docs/deploy-portainer.md](docs/deploy-portainer.md).
