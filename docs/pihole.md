# Pi-hole

netmap reads every DNS query from Pi-hole's query log and credits it to the device that
asked, by the client IP Pi-hole recorded. Two things have to be true for that to work:
netmap can talk to Pi-hole's API, and Pi-hole sees each device's own IP address.

## Connecting netmap to Pi-hole

netmap needs **Pi-hole v6**. v5's API is different and no longer maintained; upgrade with
`pihole -up` on the Pi-hole host (settings migrate automatically). On v5, the collector
logs that the URL "isn't the Pi-hole v6 API".

1. In Pi-hole's web interface, open **Settings → Web interface / API** and use
   **Configure app password** to create one. An app password works even with two-factor
   login on, and can be revoked without changing your own password.
2. Set these, on the server in **Portainer → stack → Environment variables** and for local
   development in the repo's `.env`:

   | Variable | Value |
   |---|---|
   | `NETMAP_PIHOLE_URL` | Pi-hole's web address, e.g. `http://<pihole-host>` (no `/admin`). |
   | `NETMAP_PIHOLE_PASSWORD` | The app password. |
   | `NETMAP_PIHOLE_VERIFY_TLS` | `false` only for an `https://` URL with Pi-hole's default self-signed certificate. |
   | `NETMAP_PIHOLE_POLL_SECONDS` | How often to read new queries (default 15). |

3. Redeploy. The collector log shows `source pihole: enabled`, then
   `pihole: stored N queries`. The first poll takes everything Pi-hole still has in memory
   (the last 24 hours by default).

netmap logs in once and reuses the session, and logs out when the collector stops.
Pi-hole allows only a few API sessions at a time (`webserver.api.max_sessions`), so
anything else that logs in with the same app password shares that budget.

## Making sure Pi-hole sees each device

If devices send their DNS queries to the router, and the router forwards them to Pi-hole,
then Pi-hole sees every query coming from the router. Blocking still works, but netmap
(and Pi-hole's own per-client stats) can't tell devices apart.

netmap checks this every 10 minutes. If at least half of the last hour's queries arrive
from the router, or Pi-hole sees fewer than two clients, the collector logs a warning and
the web UI shows a banner. The latest result is at `GET /api/status`.

To fix it, devices need to ask Pi-hole directly. Pick one of these; each is a settings
change only:

- **Router DHCP hands out Pi-hole as the DNS server (usually easiest).** In the router's
  LAN or DHCP settings, set the primary DNS server to Pi-hole's IP address and leave the
  secondary empty (a public secondary lets devices skip Pi-hole). Some ISP routers only
  have a "WAN DNS" setting, which makes the router itself use Pi-hole, but devices still
  query the router. That's exactly the case this check catches; use the next option.
- **Pi-hole as the DHCP server.** Turn off the router's DHCP server, then enable Pi-hole's
  in **Settings → DHCP**, with the router as the gateway. Pi-hole then tells devices to
  use it for DNS and also learns their hostnames.

Devices pick up the change when they renew their lease. Reconnecting Wi-Fi or rebooting a
device makes it happen right away.

### Checking it yourself

- In Pi-hole's **Query Log**, the **Client** column should show many different
  addresses, not just the router's.
- In netmap, open a device's page: the **DNS lookups** section lists what it looked up.
  A device that shows none is probably using another DNS server, such as one hardcoded in
  its firmware (common for Google and Amazon devices) or one learned over IPv6.

### IPv6

If the router advertises its own IPv6 DNS server (RDNSS in router advertisements, or
DHCPv6), dual-stack devices may send some queries there instead of to Pi-hole. If you see
devices missing lookups, turn off IPv6 DNS advertisement on the router, or point it at
Pi-hole's IPv6 address.

## Troubleshooting

| Collector log | Meaning |
|---|---|
| `isn't the Pi-hole v6 API (HTTP 404)` | Pi-hole v5, or the URL points somewhere else. Upgrade, or fix `NETMAP_PIHOLE_URL`. |
| `Pi-hole login failed (HTTP 401): password incorrect` | Wrong app password. Create a new one and update `NETMAP_PIHOLE_PASSWORD`. |
| `Pi-hole login failed (HTTP 429)` | Too many API sessions or failed logins. Wait a few minutes; restart other API clients. |
| `can't reach Pi-hole at ...` | Network or TLS problem. For `https://` with a self-signed certificate, set `NETMAP_PIHOLE_VERIFY_TLS=false`. |
| `source pihole: disabled` | `NETMAP_PIHOLE_URL` or `NETMAP_PIHOLE_PASSWORD` is not set. |

Queries from `127.0.0.1` are Pi-hole's own host looking things up. netmap credits them to
that host's device.
