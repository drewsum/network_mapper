# Integrations

Optional extras, each off until its setting is set. Put the settings in the Portainer
stack's environment variables (or the checkout's `.env` with plain compose) and redeploy.

## Critical devices

For cameras, locks, alarm panels, a freezer sensor: mark the device **Critical** on its page.
When netmap hears nothing from it for the grace period (5 minutes by default; set per device
on its page, or `NETMAP_CRITICAL_GRACE_MINUTES`), it raises a **critical** alert, which is
notified by default, unlike ordinary offline alerts. While the device stays down the alert is
repeated every `NETMAP_CRITICAL_REMIND_HOURS` (12; 0 for once), and when it's back an
"is back online" alert says how long it was gone.

The grace period can't be under 3 minutes: discovery hears from each device about every 2
minutes, so shorter would cry wolf.

## Prometheus and Grafana

netmap serves Prometheus metrics at `/metrics`: devices online, DNS lookups and blocks, bytes
per device (with traffic capture), open alerts, self-checks, the last backup, capture drops
and Wi-Fi signal.

1. Set `NETMAP_METRICS_TOKEN` to a long random value. Prometheus sends it as a bearer token;
   without it, `/metrics` needs a login like the rest of the API.
2. Add a scrape job like [deploy/prometheus.example.yml](../deploy/prometheus.example.yml),
   with the token in the file it names.
3. In Grafana, *Dashboards → New → Import*, upload
   [deploy/grafana/netmap-dashboard.json](../deploy/grafana/netmap-dashboard.json), and pick
   the Prometheus data source.

Values ending in `_5m` cover the last 5 minutes and are gauges: the database keeps a rolling
window, so there are no ever-growing counters to `rate()`.

## Fingerbank: device types from DHCP fingerprints

When a device asks for an address, the list of DHCP options it requests (and in what order)
says a lot about its make and OS; netmap records it (*What it calls itself → dhcp*).
[Fingerbank](https://fingerbank.org) matches that against its database.

1. Create a free account at fingerbank.org and copy the API key.
2. Set `NETMAP_FINGERBANK_API_KEY`.

Within the hour each device with a DHCP fingerprint gets Fingerbank's verdict on its page
("Google Nest Cam (87% sure)"), and devices still in the *Unknown* category get one when
Fingerbank is at least 50% sure. Categories you set are never changed. netmap sends the
fingerprint, the DHCP vendor class and only the vendor half of the MAC (`aa:bb:cc:00:00:00`).
Fingerprints are looked up again when they change, or after a month, at most 25 an hour.

## Wi-Fi access points

With a UniFi or OpenWrt access point, a device's page shows which AP it's on, the network,
band and channel, its signal strength and link rate, and when it connected.

**UniFi** (a UniFi OS console such as a UDM or Cloud Key, UniFi OS Server, or the older
self-hosted Network application):

1. Create a local admin with the *View Only* role (*Settings → Admins & Users*), not tied to
   a UI.com account.
2. Set `NETMAP_UNIFI_URL` (e.g. `https://unifi.home.example`), `NETMAP_UNIFI_USERNAME`,
   `NETMAP_UNIFI_PASSWORD`, and `NETMAP_UNIFI_SITE` if it isn't `default`. Consoles use a
   self-signed certificate: `NETMAP_UNIFI_VERIFY_TLS=false`.

**OpenWrt** (one or more APs):

1. The APs need ubus over HTTP, which LuCI includes (`uhttpd-mod-ubus`).
2. Set `NETMAP_OPENWRT_URLS` (comma-separated, e.g. `https://ap-attic.home.example`),
   `NETMAP_OPENWRT_USERNAME` (`root`, or a user with read access to `iwinfo`) and
   `NETMAP_OPENWRT_PASSWORD`; `NETMAP_OPENWRT_VERIFY_TLS=false` for self-signed certificates.

Polled every `NETMAP_WIFI_POLL_SECONDS` (60). The System page shows how it's going.
