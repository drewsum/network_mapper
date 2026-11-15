# Traffic capture: a SPAN port (or NetFlow)

Out of the box netmap sees DNS lookups (through Pi-hole) and what devices announce about
themselves. It doesn't see **bytes**: how much a device sends, where to, and over what. For
that, the TrueNAS host has to see the traffic itself. There are two ways:

| | SPAN mirror port | NetFlow / IPFIX from the router |
|---|---|---|
| Hardware | A managed switch (about $30-60) and a spare NIC on TrueNAS | A router that exports flows (OPNsense, pfSense, OpenWrt + softflowd) |
| What netmap gets | Every packet: bytes, application (nDPI), server names (TLS SNI), packet captures | Byte and packet counts per connection, no application names or packet captures |
| Works with the ISP router | Yes | No: replace or bridge it |

Both write to the same `flows` table, so the map, History's Traffic section, the device
pages, the traffic alerts and the Grafana dashboard work the same with either.

## SPAN: what to buy

Any "easy smart" managed switch with **port mirroring**:

- TP-Link TL-SG105E / TL-SG108E, Netgear GS305E / GS308E (5-8 ports, about $30-60).
- Gigabit on every port. The mirror port carries both directions of the mirrored link, so a
  link at full speed both ways can briefly outrun it; for home traffic it's fine.

And on the TrueNAS host, **a second network port** for the mirror: a spare onboard port or a
USB 3 / PCIe gigabit adapter. It must not be the port TrueNAS itself uses.

## SPAN: wiring

```
ISP router (LAN port) ──── switch port 1  (mirrored: the uplink)
                           switch port 2 ──── TrueNAS main NIC (its normal address)
                           switch port 3 ──── TrueNAS mirror NIC (no address)
                           switch port 4.. ── wired devices, a Wi-Fi access point
```

1. Put the switch between the router and everything else: the router's LAN port goes to
   switch port 1, and every wired device moves to the switch.
2. In the switch's web UI, under *Port Mirroring* (TP-Link: *Monitoring → Port Mirror*;
   Netgear: *System → Monitoring → Mirroring*), mirror **port 1** (ingress and egress) to
   **port 3**.
3. Plug the TrueNAS mirror NIC into port 3.

Mirroring the uplink shows everything that goes to or from the internet. Traffic between
two devices on the switch (one camera to the NAS, say) doesn't cross the uplink; to see it,
mirror those ports too (most of these switches allow several sources to one mirror port).

### Wi-Fi: the router's built-in Wi-Fi bypasses the switch

Devices on the **ISP router's own Wi-Fi** talk to the internet inside the router: their
traffic never reaches the switch, so the mirror can't see it. To capture them:

1. Turn off the router's Wi-Fi.
2. Plug a separate access point into the switch (any AP in access-point / bridge mode, e.g.
   a TP-Link EAP, a UniFi U6, or an old router in AP mode), with the same network name and
   password so devices reconnect by themselves.

A UniFi or OpenWrt AP can also tell netmap which AP each device is on and how strong its
signal is (see [integrations.md](integrations.md)).

## SPAN: the TrueNAS side

1. **No address on the mirror NIC.** In *Network → Interfaces*, edit the mirror NIC and turn
   DHCP and IPv6 auto-configuration off, with no aliases. It only listens.
2. **Promiscuous mode.** The capture service asks for it when it starts, but setting it on
   the host makes sure: in *System → Advanced → Init/Shutdown Scripts*, add a *Post Init*
   command `ip link set <mirror NIC> promisc on`.
3. Find the NIC's name (e.g. `enp3s0`, `eno2`): *Network → Interfaces*, or `ip link` over SSH.
   Check traffic arrives on it: `sudo tcpdump -i <mirror NIC> -c 20 -n`.

## Turning on the capture service

The `capture` service is in the server stack but starts only with the `capture` compose
profile. It runs on the host network (to see the NIC) with `NET_RAW`, like the collector.

```sh
NETMAP_CAPTURE_INTERFACE=<mirror NIC>
COMPOSE_PROFILES=capture
```

- **Plain compose:** add both lines to the checkout's `.env`, then `sudo docker compose up -d`.
- **Portainer:** add both as environment variables of the stack, then redeploy.

Within a minute the **System** page shows a *Traffic capture* check ("packets on ... (0
dropped)"), the map draws a line from the router to every device moving data, and the device
pages and History get Traffic sections. Then check the numbers: run a speed test on a phone
and compare its download with the phone's *Down* on its page. They match to within a few
percent: netmap counts whole Ethernet frames, as switch counters do, and speed tests count
the payload.

### Drops

The *Traffic capture* check counts packets the host couldn't keep up with: the kernel's
(nfstream's buffer was full) and the NIC's (its own ring overflowed). If it warns about
drops, the host is too busy or the link too fast. `/metrics` exports both counters, and the
Grafana dashboard graphs them.

### Packet captures

With a SPAN port, a device's page has a **Packet capture** card: capture everything to and
from it for up to `NETMAP_PCAP_MAX_MINUTES`, keeping the newest `NETMAP_PCAP_MAX_MB`, then
download it as a `.pcap` for Wireshark. The files are in the `captures` volume; only the
newest `NETMAP_PCAP_KEEP` are kept.

## NetFlow / IPFIX instead

If you replace the ISP router with OPNsense (or another router that exports flows):

1. Point its NetFlow export at the TrueNAS host's address, on a UDP port of your choice
   (2055 is usual). OPNsense: *Reporting → NetFlow*, listening interfaces **LAN** (not WAN:
   behind NAT, WAN flows carry the router's address, not the devices'), version **v9**.
2. Set `NETMAP_NETFLOW_PORT=2055` and `COMPOSE_PROFILES=capture` as above.

The capture service listens on the host network, so nothing needs publishing. Flows carry no
application names or server names, so those columns stay empty; domains come from Pi-hole's
answers (passive DNS). NetFlow records don't say who opened a connection, so netmap takes the
lower port for the server's.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `NETMAP_CAPTURE_INTERFACE` | unset | The mirror NIC. |
| `NETMAP_NETFLOW_PORT` | unset | UDP port for NetFlow v5/v9 and IPFIX. |
| `NETMAP_NETFLOW_BIND` | `0.0.0.0` | Address to listen on. |
| `NETMAP_CAPTURE_REPORT_SECONDS` | `10` | How often flows are written and throughput refreshed. |
| `NETMAP_PCAP_MAX_MB` / `_MAX_MINUTES` / `_KEEP` | `100` / `60` / `10` | Packet capture limits. |
| `NETMAP_UPLOAD_HEAVY_MB` / `_RATIO` | `500` / `4` | When an hour's upload raises an alert. |

## What captured traffic adds

- **Map:** a line from the router to each device moving data, wider for more (live).
- **History → Traffic:** bytes over time, by device, remote end or application.
- **Device page:** its throughput now, its bytes over time, and where they went.
- **Alerts:** DNS that skips Pi-hole (plain DNS or DNS-over-TLS to another server, DNS over
  HTTPS to known resolvers), lateral traffic (an IoT device connecting to another LAN
  device), upload-heavy hours, and unencrypted protocols to the internet (HTTP, Telnet, FTP,
  POP3, IMAP, SMTP, MQTT). Lateral traffic and unencrypted protocols are recorded, not
  notified, by default; change that on the Alerts page.
