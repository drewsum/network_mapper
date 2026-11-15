# Security

netmap sees every device on the network and every name they look up, so the server stack is
locked down by default. This is what it does, and how to put HTTPS in front of it.

## Containers

| Container | Runs as | Capabilities | Filesystem |
|---|---|---|---|
| `api` | netmap (uid 10001) | none | read-only, `/tmp` in memory |
| `migrate` | netmap | none | read-only, `/tmp` in memory |
| `collector` | netmap | `NET_RAW` only | read-only, `/tmp` in memory, GeoIP volume |
| `capture` (opt-in) | netmap | `NET_RAW` only | read-only, `/tmp` in memory, `captures` volume |
| `backup` | root at start, then netmap | `CHOWN`, `SETUID`, `SETGID` at start; none after | read-only, `/tmp` in memory, `backups/` |
| `db` | root at start, then postgres | Docker's defaults | the data directory |

- **The collector** needs `NET_RAW` for its raw ARP socket. Docker grants `cap_add`
  capabilities only to root, so the image carries `NET_RAW` as a file capability on a copy of
  the Python interpreter (`python-netraw`) that only the collector runs. Its capability
  bounding set is `NET_RAW` alone, so nothing it runs can gain anything else. It doesn't need
  `NET_ADMIN`: it changes no network settings, and listens for DHCP, mDNS and SSDP without
  binding their ports.
- **The capture service** (only with the `capture` profile, see [span.md](span.md)) is set up
  like the collector: host networking, `NET_RAW` through `python-netraw` and a copy of the
  capability on `tcpdump` for packet captures. The API reads the packet captures read-only.
- **The backup service** starts as root only to hand its `backups/` directory to the netmap
  user, then switches to it with `setpriv`. The dump process has no capabilities, and the
  dumps are readable by uid 10001 only.
- **The database** uses the TimescaleDB image's defaults: its entrypoint needs root to set up
  the data directory, then Postgres runs as the postgres user. Its port is published on the
  host's loopback only (for the host-networked collector), never on the LAN.
- `no-new-privileges` isn't set. It would stop the collector's file capability from
  working, and Portainer can be set to refuse `security_opt` from non-admin users.

## Secrets

All secrets come from environment variables: the Portainer stack's env vars, or a
`chmod 600` `.env` file in the checkout. None are in the image or the repo, and the app never
logs them.

| Secret | What it's for |
|---|---|
| `POSTGRES_PASSWORD` | The database. Only containers in the stack can reach it. |
| `NETMAP_ADMIN_PASSWORD` | The web UI and API. Set it: without it, anyone on the LAN can use both, and the UI says so. |
| `NETMAP_PIHOLE_PASSWORD` | A Pi-hole **app password** (Pi-hole *Settings → Web interface / API*), not the admin password. It can read the query log and change the deny list. |
| `NETMAP_MAXMIND_LICENSE_KEY`, `NETMAP_ABUSECH_AUTH_KEY` | Downloads (GeoIP, threat lists). Optional. |
| `NETMAP_APPRISE_URLS` | Notification services; the URLs usually embed tokens. |
| `NETMAP_METRICS_TOKEN` | What Prometheus sends for `/metrics`. Read-only, but the metrics name every device. |
| `NETMAP_FINGERBANK_API_KEY`, `NETMAP_UNIFI_PASSWORD`, `NETMAP_OPENWRT_PASSWORD` | Optional integrations ([integrations.md](integrations.md)). Give UniFi a *View Only* account. |

`pg_dump` and `pg_restore` get the database password through `PGPASSWORD` in their
environment, never on the command line.

## Logging in

- One admin password. A login gets a session cookie that is `HttpOnly`, `SameSite=Strict`, and
  `Secure` when the request came over HTTPS. It's signed with a key that combines a random
  secret in the database with the password, so changing the password logs everyone out.
- Five failed logins from one address within five minutes lock that address out for a few
  minutes.
- The API only takes JSON bodies, which browsers won't send to another site without CORS
  (and netmap allows none), so other sites can't act with your session.
- The live throughput WebSocket (`/api/live`) checks the session cookie itself and refuses
  connections from pages on other sites.
- Every response says the page may not be framed (`X-Frame-Options: DENY`,
  `frame-ancestors 'none'`), must not be MIME-sniffed, and sends no referrer to other sites.

## HTTPS through a reverse proxy

netmap serves plain HTTP on its port. To use HTTPS, put a reverse proxy in front of it, then
tell netmap to trust that proxy's `X-Forwarded-For` and `X-Forwarded-Proto` headers:

```sh
NETMAP_TRUSTED_PROXIES=<the proxy's address, as the api container sees it>
NETMAP_PUBLIC_URL=https://netmap.home.example   # for links in notifications
```

With that set, login cookies get the `Secure` flag and the login lockout counts the real
client addresses instead of the proxy's. The value is a comma-separated list of addresses or
CIDRs (or `*` to trust anyone, which only makes sense if nothing but the proxy can reach the
port). The api's log shows the address each request came from, so the proxy's appears there.
Unset, only the container itself is trusted.

Give the name an address on your LAN DNS: in Pi-hole, *Local DNS → DNS Records*, point
`netmap.home.example` at the proxy's host.

### Caddy

Caddy sends the forwarded headers by itself. `tls internal` makes certificates with Caddy's
own CA for a LAN-only name (install its root certificate on your devices); with a real domain,
use Caddy's DNS challenge instead.

```caddyfile
netmap.home.example {
    tls internal
    reverse_proxy <truenas-host>:8000
}
```

### nginx

```nginx
server {
    listen 443 ssl;
    server_name netmap.home.example;
    ssl_certificate     /etc/nginx/certs/netmap.crt;
    ssl_certificate_key /etc/nginx/certs/netmap.key;

    location / {
        proxy_pass http://<truenas-host>:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Closing the plain-HTTP port

If the proxy runs on the TrueNAS host itself, publish netmap's port on loopback only, so the
LAN can reach it through the proxy alone: `NETMAP_API_PUBLISH_PORT=127.0.0.1:8000`, with the
proxy pointing at `127.0.0.1:8000`. A proxy on another machine needs the port open on the LAN;
limit who can reach it with your firewall if that matters to you.
