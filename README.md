# Network Mapper (netmap)

A self-hosted map of every device on your home network, and a record of who each one talks
to. netmap was built to answer one question: **are my IoT devices phoning home anywhere
beyond their makers' clouds?** It finds every device on the LAN, names it, and reads your
Pi-hole's DNS log to show which companies, countries and networks each device reaches. It
learns what's normal for each device, and alerts you when something changes.

It runs as a small Docker Compose stack on any always-on Linux box on your LAN (it was built
for TrueNAS SCALE), next to an existing [Pi-hole](https://pi-hole.net). The core features
need no changes to your network. Traffic capture is optional: a switch's mirror port, or a
router's NetFlow, adds bytes, applications and live throughput.

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [What you need](#what-you-need)
- [Step-by-step deployment](#step-by-step-deployment)
- [Configuration reference](#configuration-reference)
- [Third-party services](#third-party-services)
- [Privacy and security](#privacy-and-security)
- [Features in detail](#features-in-detail)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## What it does

| Page | What you get |
|---|---|
| **Devices** (home) | Every device netmap has seen: name, category, vendor, IP, online status. Search, filter, rename, recategorize, mark as IoT. |
| **Device page** | What the device calls itself (DHCP, mDNS, SSDP, NetBIOS, reverse DNS), its IP history, open ports and services, the router port forwards it asked for (UPnP), its normal behavior and recent changes, every DNS lookup with organization, country and threat flags, Wi-Fi details, traffic, and per-device alert rules. |
| **Map** | Devices around the router, grouped by category. With traffic capture, a live line to each device sized by its throughput. |
| **History** | Lookups over time for the whole network or one device, with breakdowns by organization, category, country and network. |
| **Flows** | Where lookups go (device → organization → country) and when (hour-of-day heatmap). |
| **Domains** | Every domain grouped by organization and category, your own grouping rules, and threat-blocklist matches. |
| **IoT report** | For each IoT device: maker's cloud vs. infrastructure vs. trackers vs. third parties, overnight lookups, and your expected/unexpected marks. Exports CSV. |
| **Alerts** | New devices, offline devices, new ports, new countries/networks/sites, lookup spikes, threats, new port forwards, DNS that skips Pi-hole, and (with capture) traffic detections. Each alert kind can notify, record only, or be muted. Notifications go out through [Apprise](https://github.com/caronc/apprise/wiki) (ntfy, Discord, email, and many more). |
| **System** | Self-checks (Pi-hole, discovery, downloads, backups, capture), the latest backup, and CSV/JSON export. |

Also: optional login, daily database backups, Prometheus metrics with a Grafana dashboard,
blocking a domain in Pi-hole from an alert, critical-device alerts for cameras and locks,
device identification from DHCP fingerprints (Fingerbank), and Wi-Fi details from UniFi or
OpenWrt access points.

## How it works

```
   devices on the LAN ──DNS──▶ Pi-hole v6 ──query log (API)──┐
         ▲      │                                            ▼
         │      └── ARP, DHCP, mDNS, SSDP ──▶  collector ──▶ TimescaleDB ◀── api + web UI ◀── you
         └──── ARP sweep, name queries, ─────  (host network)    ▲             (port 8000)
               gentle port scan                                  │
                                         optional: capture ──────┘
                                         (SPAN port or NetFlow/IPFIX)
```

One Docker image runs every role:

| Service | Network | Does |
|---|---|---|
| `db` | bridge; port on `127.0.0.1` only | TimescaleDB (PostgreSQL 16) holding everything. |
| `migrate` | bridge | Runs once on each start: database migrations and retention policies, then exits. |
| `api` | bridge; publishes port 8000 | The REST API and the web UI. |
| `collector` | **host network**, `NET_RAW` | Discovery (ARP sweeps, passive DHCP/mDNS/SSDP listening, name queries), a gentle port scan of each device every 6 hours, the router's UPnP mappings, Pi-hole's query log, enrichment (GeoIP, organizations, blocklists), baselines and alerts. |
| `backup` | bridge | A `pg_dump` every 24 hours into your data directory, keeping 14. |
| `capture` | **host network**, `NET_RAW` | Optional (`COMPOSE_PROFILES=capture`): flows from a mirror port (nfstream) or NetFlow/IPFIX. |

The collector needs the host network because ARP, DHCP, mDNS and SSDP only work on the real
LAN, not behind Docker's NAT. It publishes no ports. Every other capability is dropped, and
the app containers run as an unprivileged user on read-only filesystems
([docs/security.md](docs/security.md)).

**What netmap can't see on its own:** it counts DNS lookups, not bytes, and it misses
devices that skip Pi-hole (hardcoded or encrypted DNS). It detects and flags the second case.
Details and workarounds: [docs/visibility.md](docs/visibility.md).

## What you need

**Required**

| Thing | Notes |
|---|---|
| An always-on Linux host on the LAN | TrueNAS SCALE 24.10+ (the Docker-based releases), Debian, Ubuntu, a mini PC, etc. It must be on the **same layer-2 network** as your devices (not behind a router or a VPN), with a wired connection preferred. Only tested on x86_64. |
| Docker Engine with Compose v2 | `docker compose version` should print v2.x. Docker Desktop on Windows or macOS can't see the LAN at layer 2, so it's only for development. |
| Resources | About 450 MB of RAM in use for the whole stack (limits default to 1 GB per app container and 2 GB for the database). Disk grows with the number of DNS lookups: a home with 23 devices used 62 MB after two days. Raw lookups are kept 30 days and summaries a year, and the database is compressed, so a few GB is plenty for most homes. |
| [Pi-hole v6](https://pi-hole.net) | Must be the DNS server your devices actually use (see [step 1](#1-set-up-pi-hole)). Without Pi-hole, netmap still discovers and names devices, but it can't see what they look up. |
| A browser | Any modern one; the UI works on phones too. |

**Optional**

| Thing | Adds |
|---|---|
| Free [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) license key | More accurate country and network lookups (DB-IP's free databases are used without it). |
| Free [abuse.ch](https://auth.abuse.ch/) Auth-Key | Two more threat blocklists (URLhaus, ThreatFox). |
| Free [Fingerbank](https://fingerbank.org) API key | Device types from DHCP fingerprints. |
| A notification service Apprise supports | Alerts on your phone or in chat: [ntfy](https://ntfy.sh), Discord, Telegram, email, Pushover, and more. |
| A managed switch with port mirroring, or a router that exports NetFlow/IPFIX | Bytes per device, applications, live throughput, packet captures ([docs/span.md](docs/span.md)). |
| A UniFi controller or OpenWrt access points | Which AP each device is on and its signal strength. |
| Prometheus and Grafana | Long-term metrics and a ready-made dashboard. |
| Portainer | Run the stack as a Portainer Git stack instead of from a checkout. |

## Step-by-step deployment

The commands below use `sudo docker`. Drop `sudo` if your user is in the `docker` group.
`<host>` is your server's hostname or IP, and `/srv/netmap` stands for wherever you keep the
data (on TrueNAS, a dataset such as `/mnt/<pool>/apps/network_mapper`).

### 1. Set up Pi-hole

netmap credits each DNS lookup to the device that made it, using the client address Pi-hole
records. Two things have to be true:

1. **Pi-hole is v6.** Upgrade with `pihole -up` if needed.
2. **Devices ask Pi-hole directly, not the router.** If the router forwards lookups to
   Pi-hole, every lookup looks like it came from the router. Fix it in one of two ways:
   - In the router's **LAN / DHCP settings**, set the DNS server handed to devices to
     Pi-hole's IP address, and leave the secondary empty. (A "WAN DNS" setting isn't the same
     thing: it only changes what the router itself uses.)
   - Or turn off the router's DHCP and enable **Pi-hole's DHCP server** (Settings → DHCP).

   Devices switch over when they renew their lease; reconnecting Wi-Fi does it right away.
   In Pi-hole's Query Log, the Client column should now show many addresses.
3. **Create an app password for netmap.** In Pi-hole's web interface:
   **Settings → Web interface / API → Configure app password**. Copy it for step 4.

More, including IPv6 and troubleshooting: [docs/pihole.md](docs/pihole.md).

### 2. Prepare the host

```sh
sudo mkdir -p /srv/netmap        # on TrueNAS: create a dataset (Generic preset) instead
cd /srv/netmap
```

The stack creates `db/` (owned by uid 70, Postgres) and `backups/` (owned by uid 10001)
inside it. Include this directory in your snapshots or backups.

Pick a free port for the UI (8000 by default), and find the subnet your devices are on,
e.g. `192.0.2.0/24`: `ip -4 addr` shows the host's address and prefix length.

### 3. Get the code

```sh
git clone https://github.com/drewsum/network_mapper.git src
cd src
```

### 4. Configure

```sh
cp .env.example .env
chmod 600 .env                   # it will hold passwords
```

Add these three lines at the top of `.env`, so a plain `docker compose` uses the server
stack and builds the image locally:

```sh
COMPOSE_PROJECT_NAME=netmap
COMPOSE_FILE=deploy/portainer-compose.yml:deploy/compose.build.yml
NETMAP_DATA_DIR=/srv/netmap
```

Then set at least these in `.env`:

| Variable | Set it to |
|---|---|
| `POSTGRES_PASSWORD` | A long random string, e.g. the output of `openssl rand -hex 24`. |
| `NETMAP_LAN_CIDR` | Your LAN subnet, e.g. `192.0.2.0/24`. |
| `NETMAP_PIHOLE_URL` | Pi-hole's address, e.g. `http://192.0.2.53` (without `/admin`). |
| `NETMAP_PIHOLE_PASSWORD` | The app password from step 1. |
| `NETMAP_ADMIN_PASSWORD` | A password for netmap's UI. If it's blank, anyone on your network can open and change netmap. |

Everything else has a sensible default; see the [configuration reference](#configuration-reference).
Leave `NETMAP_LAN_IFACE` blank unless the host has several interfaces on that subnet.

### 5. Start it

```sh
sudo docker compose up -d --build --wait
```

The first start takes a few minutes: the image builds (web UI and Python), then Postgres
creates its database. `--wait` returns once everything is healthy.

### 6. Check it

Open `http://<host>:8000` and log in. Within a few minutes:

- **Devices** fills up as ARP sweeps find devices (every 2 minutes), and names arrive from
  DHCP, mDNS, SSDP, NetBIOS and reverse DNS over the next rounds.
- **System → Self-checks** should be green. The Pi-hole check warns if most lookups come
  from the router (see step 1). Problems also show as a banner on every page.
- The first backup appears on the System page within a minute.

Then give it time. Each device's normal behavior is learned over its first 7 days, so
"new site / country / network" alerts start after that.

### 7. Optional extras

Add any of these to `.env` and run `sudo docker compose up -d` again:

- **Notifications:** `NETMAP_APPRISE_URLS=ntfy://my-topic` (any [Apprise URL](https://github.com/caronc/apprise/wiki)),
  and `NETMAP_PUBLIC_URL=http://<host>:8000` so notifications link back. Test it from the
  Alerts page.
- **Better GeoIP:** `NETMAP_MAXMIND_LICENSE_KEY` (free account at maxmind.com).
- **More blocklists:** `NETMAP_ABUSECH_AUTH_KEY` (free at auth.abuse.ch).
- **Device fingerprinting:** `NETMAP_FINGERBANK_API_KEY` (free at fingerbank.org).
- **Wi-Fi details:** the `NETMAP_UNIFI_*` or `NETMAP_OPENWRT_*` settings ([docs/integrations.md](docs/integrations.md#wi-fi-access-points)).
- **Prometheus/Grafana:** `NETMAP_METRICS_TOKEN`, a scrape job like
  [deploy/prometheus.example.yml](deploy/prometheus.example.yml), and the dashboard in
  [deploy/grafana/](deploy/grafana/) ([docs/integrations.md](docs/integrations.md#prometheus-and-grafana)).
- **Traffic capture:** a mirror port or NetFlow, then `COMPOSE_PROFILES=capture` and
  `NETMAP_CAPTURE_INTERFACE` or `NETMAP_NETFLOW_PORT` ([docs/span.md](docs/span.md)).
- **HTTPS:** put it behind Caddy or nginx and set `NETMAP_TRUSTED_PROXIES`
  ([docs/security.md](docs/security.md#https-through-a-reverse-proxy)).

### Updating

```sh
cd /srv/netmap/src
git pull && sudo docker compose up -d --build
```

The image is rebuilt, `migrate` updates the database, and the containers are recreated. Data
lives outside the containers (`db/`, `backups/`, and the `netmap_geoip` volume), so it
survives. To take a backup first:
`sudo docker compose exec -u netmap backup netmap backup --once`.

### Other ways to deploy

- **TrueNAS SCALE specifics** (datasets, SSH and sudo rules, restarts, logs, memory limits):
  [docs/deploy-truenas.md](docs/deploy-truenas.md).
- **Portainer Git stack**, with the image built on the host:
  [docs/deploy-portainer.md](docs/deploy-portainer.md).
- **Backups, restoring and exporting:** [docs/backups.md](docs/backups.md).

### Removing it

`sudo docker compose down` stops and removes the containers (add `-v` to also drop the GeoIP
volume). The database and backups stay in your data directory until you delete them.

## Configuration reference

All settings are environment variables: in `.env` for plain compose, or in the stack's
environment variables in Portainer. Blank means "use the default". Network-specific values
(subnets, addresses, URLs) have no defaults and are never hardcoded.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_DB` | `netmap` | Database user and name. |
| `POSTGRES_PASSWORD` | **required** | Database password. |
| `NETMAP_DATA_DIR` | **required** (server stack) | Host directory for `db/` and `backups/`. |
| `NETMAP_LAN_CIDR` | **required** | The subnet to discover devices in. |
| `NETMAP_LAN_IFACE` | automatic | Host interface on that subnet. |
| `NETMAP_ADMIN_PASSWORD` | unset (no login) | Password for the UI and API. Changing it logs everyone out. |
| `NETMAP_SESSION_DAYS` | `30` | How long a login lasts. |
| `NETMAP_API_PUBLISH_PORT` | `8000` | Host port for the UI. `127.0.0.1:8000` limits it to a reverse proxy on the host. |
| `NETMAP_DB_PUBLISH_PORT` | `5433` | Loopback-only database port; the collector connects through it. |
| `NETMAP_PUBLIC_URL` | unset | The UI's address as seen from your phone, for links in notifications. |
| `NETMAP_TRUSTED_PROXIES` | unset | Reverse proxies (IPs/CIDRs, comma-separated, or `*`) whose `X-Forwarded-*` headers to trust. |
| `NETMAP_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |
| `NETMAP_APP_MEMORY_LIMIT` / `NETMAP_DB_MEMORY_LIMIT` | `1g` / `2g` | Memory limits per container. |
| `NETMAP_IMAGE` | `netmap:local` | Image the server stack runs. |
| `COMPOSE_PROFILES` | unset | `capture` to run the traffic capture service. |

### Pi-hole

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_PIHOLE_URL` | unset (Pi-hole off) | Pi-hole v6's web address. |
| `NETMAP_PIHOLE_PASSWORD` | unset | A Pi-hole app password. Also used to block domains from netmap. |
| `NETMAP_PIHOLE_VERIFY_TLS` | `true` | `false` for an `https://` URL with Pi-hole's self-signed certificate. |
| `NETMAP_PIHOLE_POLL_SECONDS` | `15` | How often the query log is read (minimum 5). |
| `NETMAP_RDNS_SERVER` | Pi-hole's host | DNS server for reverse lookups of device IPs. |

### Discovery

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_ARP_SWEEP_INTERVAL_SECONDS` | `120` | Time between ARP sweeps of the subnet. |
| `NETMAP_DEVICE_OFFLINE_AFTER_SECONDS` | `600` | Silence before a device counts as offline. |
| `NETMAP_NAMES_INTERVAL_SECONDS` | `300` | Time between name discovery rounds (mDNS, SSDP, NetBIOS, reverse DNS). |
| `NETMAP_HOSTNAME_PRECEDENCE` | `ssdp,mdns,dhcp,netbios,rdns` | Which source names a device when several do, best first. |
| `NETMAP_PORT_SCAN_INTERVAL_SECONDS` | `21600` | Time before a device's ports are scanned again; `0` turns scanning off. |
| `NETMAP_UPNP_POLL_INTERVAL_SECONDS` | `300` | Time between reads of the router's UPnP port mappings. |
| `NETMAP_OUI_REFRESH_DAYS` | `7` | Age before the IEEE MAC vendor list is downloaded again (a copy ships in the image). |

### Enrichment

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_MAXMIND_LICENSE_KEY` | unset (DB-IP Lite) | GeoLite2 license key. |
| `NETMAP_GEOIP_REFRESH_DAYS` | `7` | Age before MaxMind's databases are downloaded again. |
| `NETMAP_ABUSECH_AUTH_KEY` | unset | Adds the URLhaus and ThreatFox blocklists. |
| `NETMAP_BLOCKLIST_REFRESH_HOURS` | `24` | Age before each blocklist is downloaded again. |
| `NETMAP_FINGERBANK_API_KEY` | unset | Device types from DHCP fingerprints. |

### Baselines and alerts

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_BASELINE_LEARNING_DAYS` | `7` | How long each device's normal behavior is learned. |
| `NETMAP_DNS_BYPASS_HOURS` / `NETMAP_DNS_BYPASS_MIN_LOOKUPS` | `24` / `10` | An IoT device online this long with fewer lookups probably skips Pi-hole. `0` lookups turns it off. |
| `NETMAP_APPRISE_URLS` | unset (in-app only) | Where notifications go: Apprise URLs, space- or comma-separated. |
| `NETMAP_NOTIFY_MAX_PER_HOUR` | `10` | Notification cap; alerts past it wait and go out together. |
| `NETMAP_CRITICAL_GRACE_MINUTES` | `5` | Silence before a critical device alerts (minimum 3; per device on its page). |
| `NETMAP_CRITICAL_REMIND_HOURS` | `12` | Reminders while a critical device stays down; `0` for once. |
| `NETMAP_UPLOAD_HEAVY_MB` / `NETMAP_UPLOAD_HEAVY_RATIO` | `500` / `4` | With capture: an hour's upload over this many MB, and this many times the download, alerts. |

### Data retention and backups

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_RAW_RETENTION_DAYS` | `30` | Days individual DNS lookups and flows are kept. |
| `NETMAP_AGG_1H_RETENTION_DAYS` | `90` | Days hourly summaries are kept. |
| `NETMAP_AGG_1D_RETENTION_DAYS` | `365` | Days daily summaries are kept. |
| `NETMAP_COMPRESS_AFTER_DAYS` | `2` | Age at which raw data is compressed. |
| `NETMAP_BACKUP_INTERVAL_HOURS` | `24` | Time between database dumps. |
| `NETMAP_BACKUP_KEEP` | `14` | Dumps kept; older ones are deleted. |

Retention is re-applied on every start, so changing it takes effect after `docker compose up -d`.

### Traffic capture (optional)

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_CAPTURE_INTERFACE` | unset | Host NIC receiving a switch's mirror port (no IP address on it). |
| `NETMAP_NETFLOW_PORT` | unset | UDP port for NetFlow v5/v9 and IPFIX, e.g. `2055`. |
| `NETMAP_NETFLOW_BIND` | `0.0.0.0` | Address to receive flows on. |
| `NETMAP_CAPTURE_REPORT_SECONDS` | `10` | How often flows are written and live throughput refreshed. |
| `NETMAP_PCAP_MAX_MB` / `NETMAP_PCAP_MAX_MINUTES` / `NETMAP_PCAP_KEEP` | `100` / `60` / `10` | Packet capture limits. |

### Wi-Fi access points (optional)

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_UNIFI_URL` / `NETMAP_UNIFI_USERNAME` / `NETMAP_UNIFI_PASSWORD` | unset | A UniFi controller and a local *View Only* account. |
| `NETMAP_UNIFI_SITE` | `default` | The UniFi site. |
| `NETMAP_UNIFI_VERIFY_TLS` | `true` | `false` for a self-signed certificate. |
| `NETMAP_OPENWRT_URLS` | unset | OpenWrt APs, comma-separated (need `uhttpd-mod-ubus`). |
| `NETMAP_OPENWRT_USERNAME` / `NETMAP_OPENWRT_PASSWORD` | `root` / unset | Their shared login. |
| `NETMAP_OPENWRT_VERIFY_TLS` | `true` | `false` for self-signed certificates. |
| `NETMAP_WIFI_POLL_SECONDS` | `60` | How often the APs are asked. |

### Metrics (optional)

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_METRICS_TOKEN` | unset | Bearer token Prometheus sends for `/metrics`. Without it, `/metrics` needs a login. |

### Development only

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_WEB_PUBLISH_PORT` | `5173` | Vite dev server port (dev stack only). |

## Third-party services

netmap runs entirely on your network. These are the only outside services it contacts, and
what each one receives:

| Service | Used for | Account | What netmap sends |
|---|---|---|---|
| Your Pi-hole | DNS query log; blocking domains you choose | App password | Nothing leaves your network. |
| [IEEE](https://standards-oui.ieee.org/) | MAC vendor registry, weekly | No | A plain download. |
| [DB-IP](https://db-ip.com) Lite (CC BY 4.0) | Country and network of IPs, when no MaxMind key is set | No | A plain monthly download. |
| [MaxMind GeoLite2](https://www.maxmind.com) | Country and network of IPs | Free, optional | Your license key, to download the databases. Lookups happen locally. |
| [FireHOL level1](https://iplists.firehol.org/), [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Threat blocklists | No | A plain daily download. |
| [abuse.ch URLhaus, ThreatFox](https://abuse.ch) | Threat blocklists | Free, optional | Your Auth-Key, to download the lists. |
| [Fingerbank](https://fingerbank.org) | Device types | Free, optional | Each fingerprinted device's DHCP fingerprint, DHCP vendor class, and the vendor half of its MAC (`aa:bb:cc:00:00:00`). No full MACs, IPs or names. |
| [Apprise](https://github.com/caronc/apprise) targets | Notifications | Whatever you configure | The alert text (device names, domains) to the services you choose. |
| Your UniFi controller / OpenWrt APs | Wi-Fi details | Read-only login | Nothing leaves your network. |

Threat matching and GeoIP lookups are done locally against the downloaded lists. netmap never
sends your DNS history anywhere.

## Privacy and security

- **Only run netmap on a network you own or administer.** It sweeps the subnet with ARP,
  queries devices for their names, and port-scans each device gently (a TCP connect scan of
  69 ports common on home networks, every 6 hours). Set `NETMAP_PORT_SCAN_INTERVAL_SECONDS=0` to turn scanning off.
- **Set `NETMAP_ADMIN_PASSWORD`.** Without it the UI and API are open to anyone on the LAN,
  and the UI says so. Repeated failed logins are rate-limited.
- **Don't expose it to the internet.** For remote access use a VPN, or an HTTPS reverse proxy
  with its own authentication ([docs/security.md](docs/security.md)).
- **Secrets** live only in `.env` (`chmod 600`) or Portainer's stack variables, never in the
  repo.
- **Containers:** every capability dropped except `NET_RAW` for the collector (and capture),
  read-only root filesystems, a non-root user, memory limits, rotated logs.
- **Data:** DNS history reveals a lot about a household. It stays in your database and your
  backups; protect those like any other personal data.

Found a security problem? Please report it privately through GitHub's
[security advisories](https://github.com/drewsum/network_mapper/security/advisories/new) rather than a public issue.

## Features in detail

### Discovery and names

Devices are found by ARP sweeps (unicast re-checks for known devices that ignore broadcasts),
plus passive listening to DHCP, mDNS and SSDP. Each is named from the best available source
(`NETMAP_HOSTNAME_PRECEDENCE`), and the vendor comes from the IEEE registry. Randomized
("private") MACs are flagged and merged when a device reappears under a new one. You can
rename and recategorize any device.

### IP locations (GeoIP)

The collector looks up the country, city and network (ASN) of the IPs that domains resolve
to. It takes those IPs from Pi-hole's answers and doesn't resolve anything itself. With a
MaxMind key it uses GeoLite2; without one it uses DB-IP's free Lite databases. They're kept in
the `geoip` volume (about 140 MB).

### Organizations

Each domain is grouped under an organization such as Google, AWS, Tuya or Apple, from a
curated map in `backend/src/netmap/data/organizations.yaml`. The domain's longest matching
suffix decides first; if none matches, the network (ASN) its IP is in decides, so a Tuya
domain hosted on AWS still counts as Tuya. Rules you add on the Domains page take precedence.

### Categories and blocklists

Each domain gets a category: ads and trackers, telemetry and analytics, vendor cloud, CDN and
hosting, internet infrastructure, or unknown. Domains are also matched by name and by
resolved IP against threat blocklists (FireHOL level1, Feodo Tracker, and with a key URLhaus
and ThreatFox). Flagged domains carry a red "threat" tag and raise an alert.

### Baselines

Each device learns what's normal for it over `NETMAP_BASELINE_LEARNING_DAYS`: the sites,
organizations, countries and networks it uses, and its busiest hour. After that, anything new
is recorded in its History, as is an hour with at least 200 lookups and four times its usual
busy hour. Phones and computers get a baseline but no change alerts, since new sites are
everyday for them.

### IoT report

For each IoT device, every site it looked up, sorted into: its maker's own cloud,
infrastructure, trackers and telemetry, threats, or other third parties. Lookups between
midnight and 6 am are counted separately. Mark sites expected or unexpected, and export CSV.

### Alerts and notifications

| Default | Alert kinds |
|---|---|
| **Notify** | Threats, new devices, new countries, lookup spikes, new port forwards, DNS that skips Pi-hole, critical devices down. |
| **Record only** | Offline (muted for phones and computers), new ports, new sites and organizations, and with capture: lateral traffic, unencrypted protocols. |
| **Mute** | New networks. |

Change them for the whole network on the Alerts page, or for one device on its page. Alerts
can be acknowledged or snoozed. Each minute's alerts go out as one message, repeats within an
hour are skipped, and failed sends are retried for a day.

### Devices that skip Pi-hole

An IoT device online for a day with fewer than 10 lookups through Pi-hole probably has its
own DNS server built in, or uses encrypted DNS. Its page says so and it raises an alert. With
traffic capture, netmap also sees DNS to other servers and DNS-over-HTTPS to known resolvers.

### Blocking a domain

"Block…" next to a domain, or on a threat alert, shows where the domain stands in Pi-hole and
adds it to Pi-hole's exact deny list on confirmation (for every device). It can be unblocked
the same way.

### Traffic capture

With a switch's mirror port or a router's NetFlow/IPFIX, netmap adds bytes per device and per
destination, applications (nDPI), server names (TLS SNI), live throughput on the map,
packet captures you can download for Wireshark, and traffic alerts. Hardware, wiring and
setup: [docs/span.md](docs/span.md).

### Integrations

Critical-device alerts, Prometheus and the Grafana dashboard, Fingerbank, and UniFi/OpenWrt
Wi-Fi: [docs/integrations.md](docs/integrations.md).

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| No devices appear | The collector isn't on the LAN: it must run on a Linux host on the same subnet (not Docker Desktop). Check `NETMAP_LAN_CIDR`, and `NETMAP_LAN_IFACE` if the host has several NICs. `sudo docker compose logs collector`. |
| Devices but no DNS lookups | Pi-hole isn't connected (System page, collector log), or devices don't use Pi-hole. See [docs/pihole.md](docs/pihole.md#troubleshooting). |
| Every lookup belongs to the router | The router forwards DNS to Pi-hole. Hand out Pi-hole as the DNS server via DHCP ([step 1](#1-set-up-pi-hole)). |
| A device has no lookups at all | Hardcoded or encrypted DNS, or IPv6 DNS from the router: [docs/visibility.md](docs/visibility.md). |
| `db` stays "starting" on first run | Postgres initialization on ZFS is slow; the healthcheck allows 5 minutes. |
| Port 8000 in use | Set `NETMAP_API_PUBLISH_PORT` to a free port. |
| "API unreachable" in the UI | `sudo docker compose ps`; the `api` container's logs say why. |
| Notifications don't arrive | Use the test button on the Alerts page; check the Apprise URL format. |

Logs: `sudo docker compose logs -f collector` (or `api`, `backup`, `migrate`, `capture`).

## Development

```
backend/            Python package `netmap` (uv project)
  src/netmap/
    config.py       all settings, from NETMAP_* env vars
    db/             SQLAlchemy models, session, TimescaleDB policies
    api/            FastAPI app (also serves the built UI in production)
    collector/      discovery, Pi-hole, enrichment, alerts, Fingerbank, Wi-Fi APs
    capture/        traffic capture service: nfstream (SPAN), NetFlow/IPFIX, pcaps
    seed/           synthetic data for local development
  migrations/       Alembic migrations (hypertables, continuous aggregates)
  tests/
web/                React + TypeScript + Vite UI
scripts/            check_hardcoded_ips.py, test.sh, build-on-host.sh, update_oui_bundle.py
Dockerfile          one image; compose picks the role (api / collector / migrate / seed / ...)
docker-compose.yml  dev stack
deploy/             server stack (portainer-compose.yml), Grafana dashboard, Prometheus example
docs/               deployment, Pi-hole, backups, security, traffic capture, integrations
```

### Run locally

Requires Docker Desktop (or Docker Engine) and, for running tests outside Docker,
[uv](https://docs.astral.sh/uv/) and Node 24.

```sh
cp .env.example .env                    # the defaults work for development
docker compose up -d --build
docker compose run --rm seed            # 30 days of fake devices and DNS activity
docker compose run --rm seed --reset    # wipe and reseed
```

- UI with hot reload: http://localhost:5173
- API: http://localhost:8000/api/health; OpenAPI docs at http://localhost:8000/docs

On Windows and macOS, Docker Desktop can't see the LAN at layer 2, so discovery doesn't work
there; Pi-hole polling does.

### Tests and lint

```sh
uvx pre-commit install      # once: lint, the hardcoded-IP check and unit tests on each commit
bash scripts/test.sh        # everything, including database integration tests
```

`scripts/test.sh` runs the database tests against a separate `netmap_test` database in the
dev `db` container, so your dev data isn't touched. Backend only: `cd backend && uv run pytest`
(database tests are skipped unless `NETMAP_TEST_DATABASE_URL` is set).

Rules of the codebase:

- **No network-specific values in code.** Every subnet, address and URL comes from `NETMAP_*`
  settings; `scripts/check_hardcoded_ips.py` fails the commit otherwise. Tests and docs use the
  documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Images are built where they run.** Nothing is published to a registry, and there's no CI;
  tests run locally through pre-commit and `scripts/test.sh`.
- A new `NETMAP_*` setting goes in `config.py`, `.env.example`, and the `x-netmap-env` block of
  `deploy/portainer-compose.yml`.

## License

[MIT](LICENSE). The DB-IP Lite databases netmap downloads are licensed CC BY 4.0 by
[DB-IP.com](https://db-ip.com); MaxMind's GeoLite2 data is subject to MaxMind's license.
