# Deploying on TrueNAS SCALE

netmap runs on TrueNAS SCALE 24.10 or later (the Docker-based releases) as a compose stack
of five containers. The image is built on the TrueNAS host from a git checkout, so nothing is
published to a registry and the repo can stay private.

There are two ways to run the stack, both from the same `deploy/portainer-compose.yml`:

- **Plain `docker compose` from a checkout** on the host, over SSH. Described here.
- **A Portainer Git-repository stack**, if you run Portainer. See
  [deploy-portainer.md](deploy-portainer.md). Portainer can't build images on TrueNAS, so the
  image is still built on the host (`scripts/build-on-host.sh`).

| Service | Network | Purpose |
|---|---|---|
| `db` | bridge; DB port on `127.0.0.1` only | TimescaleDB, data in `<data dir>/db` |
| `migrate` | bridge | One-off: migrations and retention policies, then exits |
| `api` | bridge; `NETMAP_API_PUBLISH_PORT` published | API and web UI |
| `collector` | **host**, `NET_RAW` | LAN discovery, Pi-hole log, port scans, UPnP, downloads |
| `backup` | bridge | Daily `pg_dump` into `<data dir>/backups` (see [backups.md](backups.md)) |
| `capture` | **host**, `NET_RAW` | Opt-in (`COMPOSE_PROFILES=capture`): traffic from a SPAN port or NetFlow ([span.md](span.md)) |

## What it needs from the host

- **A dataset** for the data, e.g. `/mnt/<pool>/apps/network_mapper` (Generic preset). The
  stack creates `db/` (owned by uid 70, Postgres) and `backups/` (owned by uid 10001, netmap)
  inside it. Snapshot and replicate it like any other dataset.
- **Host networking for the collector.** ARP sweeps, DHCP, mDNS and SSDP only work on the real
  LAN, not on a Docker bridge. The collector publishes no ports and listens without binding
  any; it only sends ARP requests, discovery queries, and a gentle port scan of each device
  every 6 hours.
- **One capability, `NET_RAW`**, for the collector's raw ARP socket. Every other container
  capability is dropped (see [security.md](security.md)).
- **SSH access with docker rights**, to clone, build and run. On TrueNAS, give a user
  *Allowed sudo commands with no password* for `/usr/bin/docker` (docker access is
  effectively root, so keep that user's key safe), and run the commands below with
  `sudo docker`.
- **A free host port** for the UI (default 8000).

## First deploy

1. **Clone the repo** into the dataset. For a private repo, add a read-only deploy key on
   GitHub (repo *Settings → Deploy keys*, without write access) and clone over SSH with it:

   ```sh
   cd /mnt/<pool>/apps/network_mapper
   git clone git@github.com:<you>/network_mapper.git src
   cd src
   ```

2. **Write `.env`** in the checkout from `.env.example`, and add these lines at the top so a
   bare `docker compose` uses the server stack and builds the image:

   ```sh
   COMPOSE_PROJECT_NAME=netmap
   COMPOSE_FILE=deploy/portainer-compose.yml:deploy/compose.build.yml
   NETMAP_DATA_DIR=/mnt/<pool>/apps/network_mapper
   ```

   Fill in `POSTGRES_PASSWORD` (a long random one), `NETMAP_LAN_CIDR`, `NETMAP_PIHOLE_URL`,
   `NETMAP_PIHOLE_PASSWORD` and `NETMAP_ADMIN_PASSWORD`. Then `chmod 600 .env`: it holds the
   secrets. The dev-only `NETMAP_WEB_PUBLISH_PORT` isn't used.

3. **Start it:**

   ```sh
   sudo docker compose up -d --build --wait
   ```

   The first start takes a few minutes: the image builds, and Postgres initialises its data
   directory (slow on ZFS; the DB healthcheck allows 5 minutes for it). `--wait` returns once
   `db`, `api`, `collector` and `backup` are healthy and `migrate` has exited.

4. Open `http://<truenas-host>:8000` and log in. The **System** page shows the self-checks,
   and the first backup within a minute.

## Updating

```sh
cd /mnt/<pool>/apps/network_mapper/src
git pull && sudo docker compose up -d --build
```

The image is rebuilt, `migrate` brings the database up to date, and the other containers are
recreated from the new image. Everything that matters lives outside the containers, so it
survives updates and rebuilds: the database in `<data dir>/db`, backups in
`<data dir>/backups`, and the downloaded GeoIP databases in the `netmap_geoip` volume. To be
safe before a big update, take a backup first:
`sudo docker compose exec -u netmap backup netmap backup --once`.

## Running 24/7

- **Restarts.** Every long-running container has `restart: unless-stopped`, so Docker starts
  them again after a crash, a Docker restart or a TrueNAS reboot. At boot they start in no
  particular order, and that's fine: the API reports the database as down (`/api/health`
  answers 503) until Postgres is up, and the collector and backup service retry. `migrate`
  isn't rerun at boot; it only runs on `up`.
- **Healthchecks.** `db`: `pg_isready` over TCP. `api`: `GET /api/health`, which also checks
  the database. `collector`: a heartbeat file it touches every tick. `backup`: a heartbeat file
  it touches at least every 5 minutes. `docker ps` and Portainer show them.
- **Logs** rotate at 10 MB, three files per container (`json-file` driver), so they can't fill
  the pool. Read them with `sudo docker compose logs -f collector` (or `api`, `backup`, ...).
- **Memory limits.** 1 GB per app container and 2 GB for the database; the stack uses about
  400 MB in all. Change them with `NETMAP_APP_MEMORY_LIMIT` and `NETMAP_DB_MEMORY_LIMIT`
  (e.g. `512m`, `4g`).
- **Problems the app can see itself** (Pi-hole unreachable, a failed backup, blocklists that
  won't download) show as a banner in the UI and on the System page.

## Environment variables for the server stack

Everything in `.env.example`, plus:

| Variable | Purpose |
|---|---|
| `NETMAP_DATA_DIR` | Host path of the dataset. Required. |
| `NETMAP_API_PUBLISH_PORT` | Host port for the UI and API (default 8000). Use `127.0.0.1:8000` to reach it only through a reverse proxy on the host. |
| `NETMAP_DB_PUBLISH_PORT` | Loopback-only DB port (default 5433); the collector connects through it. |
| `NETMAP_APP_MEMORY_LIMIT` / `NETMAP_DB_MEMORY_LIMIT` | Memory limits (default `1g` / `2g`). |
| `NETMAP_IMAGE` | Image name (default `netmap:local`). |
| `COMPOSE_PROFILES` | `capture` to run the traffic capture service ([span.md](span.md)). |

## Removing it

`sudo docker compose down` stops and removes the containers; add `-v` to drop the GeoIP
volume too. The database and backups stay in the dataset until you delete them.
