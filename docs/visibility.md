# What netmap can and can't see

netmap v1 learns about traffic from two places: Pi-hole's query log (which device looked
up which name, and whether Pi-hole blocked it) and ARP/neighbor scans (which devices are
on the network). It doesn't sit in the path of the traffic itself, so some things are out
of view.

## No byte counts

A DNS lookup says a device was about to talk to a service, not how much it sent or
received. A single lookup can be followed by one tiny request or by an hour of video, and
apps cache answers and reuse connections, so lookup counts are a rough measure of how
chatty a device is, not of bandwidth. Without traffic capture, every chart and table in
netmap counts lookups.

Seeing bytes needs a flow source: a mirrored switch port, or NetFlow/IPFIX from a router
that exports it. Both need changes to the network, so they're optional; see
[span.md](span.md). With one, netmap also sees devices that skip Pi-hole.

## Devices that bypass Pi-hole

netmap only sees lookups that reach Pi-hole. These don't:

- **Hardcoded DNS servers.** Some devices ignore the DNS server DHCP hands out and ask a
  public one directly (often Google's or Cloudflare's). Many Google and Amazon devices,
  and some smart TVs, do this.
- **Encrypted DNS (DNS over HTTPS or TLS).** Browsers and phones can send lookups inside
  HTTPS to a public resolver. Firefox, Chrome and iOS/Android "private DNS" settings can
  all do this, sometimes automatically.
- **IPv6 DNS from the router.** If the router advertises its own IPv6 DNS server,
  dual-stack devices may send some lookups there. See [Pi-hole → IPv6](pihole.md#ipv6).
- **Devices that ask the router.** If the router forwards lookups to Pi-hole, they all
  look like they come from the router. netmap detects this and shows a warning; see
  [Pi-hole → Making sure Pi-hole sees each device](pihole.md#making-sure-pi-hole-sees-each-device).
- **Connections by IP address.** Traffic to an address that was never looked up (common
  for peer-to-peer, some games and some malware) has no lookup to record.

Such a device still appears in the device list, from ARP scans, but shows few or no DNS
lookups. A device that's online with no lookups at all is the usual sign.

## Narrowing the gap

All of these are optional and change the network, not netmap:

- Block outbound DNS (port 53, and 853 for DNS over TLS) to anything but Pi-hole on the
  router, if it supports firewall rules. Hardcoded-DNS devices then usually fall back to
  the DHCP-provided server.
- Add a blocklist of well-known DNS-over-HTTPS resolver names to Pi-hole, and keep its
  default block on Firefox's canary domain (`use-application-dns.net`), so browsers stay
  on the network's DNS.
- Turn off IPv6 DNS advertisement on the router, or point it at Pi-hole's IPv6 address.
