import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";
import { ActivityCard, SummaryCards } from "./Activity";
import { AlertList, RulesTable } from "./Alerts";
import { BlockButton } from "./Pihole";
import { CapturesCard, DeviceTrafficCard } from "./Traffic";

// ECharts loads only when a device page is opened.
const HeatmapCard = lazy(() => import("./Insights").then((m) => ({ default: m.HeatmapCard })));
import {
  api,
  type DeviceDetail as Detail,
  type DeviceEvent,
  deviceName,
  DOMAIN_CATEGORY_LABELS,
  type DomainSort,
} from "./api";
import { ago, CategorySelect, countryName, dateTime, EditableText, Status, ThreatTag, useUpdateDevice } from "./ui";

const DETAIL_LABELS: Record<string, string> = {
  friendly_name: "Friendly name",
  manufacturer: "Manufacturer",
  model: "Model",
  model_number: "Model number",
  device_type: "UPnP type",
  fingerprint: "DHCP fingerprint",
  vendor_class: "DHCP vendor class",
};

export function DeviceDetailPage({ mac }: { mac: string }) {
  const device = useQuery({ queryKey: ["device", mac], queryFn: () => api.device(mac) });
  // One time range for the activity chart, the top lists and the DNS lookups.
  const [hours, setHours] = useState(24);
  const [start, setStart] = useState(() => rangeStart(24));
  const pick = (h: number) => {
    setHours(h);
    setStart(rangeStart(h));
  };

  if (device.error) {
    return (
      <p className="error">
        Couldn't load {mac}: {device.error.message}. <a href="#/">Back to devices</a>
      </p>
    );
  }
  if (!device.data) return <p className="muted">Loading…</p>;
  const d = device.data;
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      {d.merged_into && (
        <p className="notice">
          This MAC was merged into <a href={`#/devices/${d.merged_into}`}>{d.merged_into}</a>; its
          history lives there now.
        </p>
      )}
      <Header device={d} />
      <div className="grid">
        <Facts device={d} />
        <Notes device={d} />
      </div>
      <div className="range-bar">
        <RangePicker hours={hours} onPick={pick} />
        <span className="muted small">Activity, top lists and DNS lookups</span>
      </div>
      <ActivityCard mac={d.mac} start={start} />
      <DeviceTrafficCard mac={d.mac} start={start} />
      <SummaryCards mac={d.mac} start={start} countryName={countryName} />
      <Suspense fallback={null}>
        <HeatmapCard mac={d.mac} />
      </Suspense>
      <DnsCheckCard mac={d.mac} />
      <BaselineCard mac={d.mac} />
      <Domains mac={d.mac} start={start} />
      <Names device={d} />
      <Wifi device={d} />
      <Addresses device={d} />
      <Ports mac={d.mac} />
      <Forwards mac={d.mac} />
      {!d.merged_into && <CapturesCard mac={d.mac} />}
      <History mac={d.mac} />
      {!d.merged_into && <DeviceAlerts mac={d.mac} />}
      {!d.merged_into && <Merge device={d} />}
    </article>
  );
}

function Header({ device: d }: { device: Detail }) {
  const update = useUpdateDevice(d.mac);
  const editable = !d.merged_into;
  return (
    <header className="detail-head">
      <div>
        <h1>
          {editable ? (
            <EditableText
              value={d.label}
              placeholder={deviceName({ ...d, label: null })}
              onSave={(label) => update.mutate({ label })}
              className="title"
            />
          ) : (
            deviceName(d)
          )}
        </h1>
        {d.label && d.hostname && <div className="sub">calls itself {d.hostname}</div>}
      </div>
      <div className="head-controls">
        <Status online={d.online} lastSeen={d.last_seen} />
        {editable && (
          <>
            <CategorySelect value={d.category} onChange={(category) => update.mutate({ category })} />
            <label className="check">
              <input
                type="checkbox"
                checked={d.is_iot}
                onChange={(e) => update.mutate({ is_iot: e.target.checked })}
              />
              IoT
            </label>
            <label className="check" title="Alert loudly when it goes offline (cameras, locks, alarms)">
              <input
                type="checkbox"
                checked={d.critical}
                onChange={(e) => update.mutate({ critical: e.target.checked })}
              />
              Critical
            </label>
          </>
        )}
      </div>
      {editable && d.critical && <CriticalGrace device={d} />}
      {update.error && <p className="error">{update.error.message}</p>}
    </header>
  );
}

/** How long a critical device may go unheard before its alert. */
function CriticalGrace({ device: d }: { device: Detail }) {
  const update = useUpdateDevice(d.mac);
  const [draft, setDraft] = useState<string | null>(null);
  const current = d.offline_grace_minutes ?? d.critical_grace_default;
  const value = draft ?? String(current);
  const save = () => {
    const n = Number(value);
    if (!Number.isInteger(n) || n < 3) return;
    update.mutate(
      { offline_grace_minutes: n === d.critical_grace_default ? null : n },
      { onSuccess: () => setDraft(null) },
    );
  };
  return (
    <form
      className="sub inline-field"
      onSubmit={(e) => {
        e.preventDefault();
        save();
      }}
    >
      Critical alert after
      <input
        type="number"
        min={3}
        value={value}
        aria-label="Minutes offline before the critical alert"
        onChange={(e) => setDraft(e.target.value)}
        onBlur={save}
      />
      minutes unheard{d.offline_grace_minutes === null && " (the default)"}
    </form>
  );
}

function Facts({ device: d }: { device: Detail }) {
  const rows: [string, React.ReactNode][] = [
    ["MAC", <span className="mono">{d.mac}</span>],
    ["IP", <span className="mono">{d.ip ?? "—"}</span>],
    ["Vendor", d.is_randomized_mac ? "randomized (private) MAC" : (d.vendor ?? "unknown")],
    ["Hostname", d.hostname ? `${d.hostname} (from ${d.hostname_source})` : "—"],
    ["First seen", dateTime(d.first_seen)],
    ["Last seen", `${dateTime(d.last_seen)} (${ago(d.last_seen)})`],
  ];
  if (d.aliases.length) rows.push(["Also seen as", <span className="mono">{d.aliases.join(", ")}</span>]);
  if (d.fingerbank?.device) {
    const sure = d.fingerbank.score != null ? ` (${d.fingerbank.score}% sure)` : "";
    rows.push(["Fingerbank", `${d.fingerbank.device}${sure}`]);
  }
  return (
    <section className="card">
      <h2>Device</h2>
      <dl className="facts">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function Notes({ device: d }: { device: Detail }) {
  const update = useUpdateDevice(d.mac);
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? d.notes ?? "";
  return (
    <section className="card">
      <h2>Notes</h2>
      <textarea
        value={value}
        rows={5}
        placeholder="Where it is, what it's for…"
        disabled={!!d.merged_into}
        onChange={(e) => setDraft(e.target.value)}
      />
      {draft !== null && draft !== (d.notes ?? "") && (
        <div className="row">
          <button
            type="button"
            disabled={update.isPending}
            onClick={() => update.mutate({ notes: draft }, { onSuccess: () => setDraft(null) })}
          >
            Save notes
          </button>
          <button type="button" className="plain" onClick={() => setDraft(null)}>
            Cancel
          </button>
        </div>
      )}
      {update.error && <p className="error">{update.error.message}</p>}
    </section>
  );
}

function Names({ device: d }: { device: Detail }) {
  if (!d.names.length) return null;
  return (
    <section className="card">
      <h2>What it calls itself</h2>
      <table className="stack">
        <thead>
          <tr>
            <th>Source</th>
            <th>Name</th>
            <th>Details</th>
            <th>Last heard</th>
          </tr>
        </thead>
        <tbody>
          {d.names.map((n) => (
            <tr key={n.source} className={n.source === d.hostname_source ? "chosen" : ""}>
              <td>
                {n.source}
                {n.source === d.hostname_source && <span className="tag">shown</span>}
              </td>
              <td data-label="Name">{n.name ?? "—"}</td>
              <td className="small">
                {Object.entries(n.details ?? {})
                  .filter(([k]) => k !== "friendly_name")
                  .map(([k, v]) => (
                    <div key={k}>
                      <span className="muted">{DETAIL_LABELS[k] ?? k}:</span> {v}
                    </div>
                  ))}
              </td>
              <td data-label="Heard" title={dateTime(n.last_seen)}>
                {ago(n.last_seen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function signal(dbm: number): string {
  if (dbm >= -60) return "strong";
  if (dbm >= -70) return "fair";
  return "weak";
}

/** Which access point it's on, from the Wi-Fi controller. */
function Wifi({ device: d }: { device: Detail }) {
  const w = d.wifi;
  if (!w) return null;
  const radio = [w.band, w.channel != null ? `channel ${w.channel}` : null].filter(Boolean).join(", ");
  const rows: [string, React.ReactNode][] = [
    ["Access point", w.ap_name ?? "—"],
    ["Network", w.ssid ?? "—"],
    ["Radio", radio || "—"],
    ["Signal", w.signal_dbm != null ? `${w.signal_dbm} dBm (${signal(w.signal_dbm)})` : "—"],
  ];
  if (w.rx_rate_kbps || w.tx_rate_kbps) {
    const mbit = (k: number | null) => (k ? `${(k / 1000).toFixed(0)} Mbit/s` : "—");
    rows.push(["Link rate", `${mbit(w.rx_rate_kbps)} down, ${mbit(w.tx_rate_kbps)} up`]);
  }
  rows.push(
    w.connected
      ? ["Connected", w.connected_since ? `since ${dateTime(w.connected_since)}` : "yes"]
      : ["Last connected", `${dateTime(w.last_seen)} (${ago(w.last_seen)})`],
  );
  return (
    <section className="card">
      <h2>Wi-Fi</h2>
      <dl className="facts">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <p className="muted small">From {w.source === "unifi" ? "the UniFi controller" : "OpenWrt"}.</p>
    </section>
  );
}

function Addresses({ device: d }: { device: Detail }) {
  return (
    <section className="card">
      <h2>IP addresses</h2>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>First seen</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {d.ips.map((ip) => (
            <tr key={ip.ip}>
              <td className="mono">{ip.ip}</td>
              <td>{dateTime(ip.first_seen)}</td>
              <td title={dateTime(ip.last_seen)}>{ago(ip.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Ports({ mac }: { mac: string }) {
  const ports = useQuery({ queryKey: ["ports", mac], queryFn: () => api.ports(mac) });
  return (
    <section className="card">
      <h2>Open ports</h2>
      {ports.data?.length === 0 && <p className="muted">No open ports found (or not scanned yet).</p>}
      {!!ports.data?.length && (
        <table className="stack">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Banner</th>
              <th>Since</th>
            </tr>
          </thead>
          <tbody>
            {ports.data.map((p) => (
              <tr key={`${p.port}/${p.protocol}`} className={p.open ? "" : "offline"}>
                <td className="mono">
                  {p.port}/{p.protocol}
                  {!p.open && <span className="tag">closed</span>}
                </td>
                <td>{p.service ?? "—"}</td>
                <td className="mono small">{p.banner ?? ""}</td>
                <td data-label="Since" title={dateTime(p.first_seen)}>
                  {ago(p.first_seen)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Forwards({ mac }: { mac: string }) {
  const mappings = useQuery({ queryKey: ["upnp"], queryFn: api.upnpMappings });
  const mine = mappings.data?.filter((m) => m.mac === mac) ?? [];
  if (!mine.length) return null;
  return (
    <section className="card">
      <h2>Router port forwards (UPnP)</h2>
      <table className="stack">
        <thead>
          <tr>
            <th>External</th>
            <th>To</th>
            <th>Description</th>
            <th>Since</th>
          </tr>
        </thead>
        <tbody>
          {mine.map((m) => (
            <tr key={`${m.external_port}/${m.protocol}`} className={m.active ? "" : "offline"}>
              <td className="mono">
                {m.external_port}/{m.protocol}
                {!m.active && <span className="tag">gone</span>}
              </td>
              <td className="mono" data-label="To">
                {m.internal_ip}:{m.internal_port}
              </td>
              <td>{m.description ?? "—"}</td>
              <td data-label="Since" title={dateTime(m.first_seen)}>
                {ago(m.first_seen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function describe(e: Pick<DeviceEvent, "kind" | "ip" | "port" | "protocol" | "details">): string {
  const key = e.details?.key ?? "";
  switch (e.kind) {
    case "new_device":
      return `First seen${e.ip ? ` at ${e.ip}` : ""}`;
    case "online":
      return `Came online${e.ip ? ` at ${e.ip}` : ""}`;
    case "offline":
      return "Went offline";
    case "new_ip":
      return `New IP address ${e.ip}`;
    case "port_opened":
      return `Port ${e.port}/${e.protocol} opened`;
    case "port_closed":
      return `Port ${e.port}/${e.protocol} closed`;
    case "new_domain":
      return `New site: ${key}`;
    case "new_org":
      return `New organization: ${key}`;
    case "new_country":
      return `New country: ${countryName(key)}`;
    case "new_asn":
      return `New network: AS${key}${e.details?.label ? ` (${e.details.label})` : ""}`;
    case "query_spike":
      return `Lookup spike: ${(e.details?.lookups ?? 0).toLocaleString()} in an hour (usually up to ${(e.details?.usual ?? 0).toLocaleString()})`;
  }
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

function dateOnly(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/** What the device normally looks up, and what's new since it was learned. */
function BaselineCard({ mac }: { mac: string }) {
  const baseline = useQuery({ queryKey: ["baseline", mac], queryFn: () => api.baseline(mac) });
  const b = baseline.data;
  if (baseline.error) {
    return (
      <section className="card">
        <h2>Normal behavior</h2>
        <p className="error">{baseline.error.message}</p>
      </section>
    );
  }
  if (!b) return null;
  const c = b.counts;
  return (
    <section className="card">
      <h2>Normal behavior</h2>
      {!b.since ? (
        <p className="muted">Learning starts with the device's first DNS lookup.</p>
      ) : (
        <>
          <p className="muted small">
            {b.learning
              ? `Learning for ${plural(b.learning_days, "day", "days")}, until ${dateOnly(b.until!)}.`
              : `Learned over ${plural(b.learning_days, "day", "days")} from ${dateOnly(b.since)}.`}{" "}
            {b.watched
              ? "Sites, organizations, countries and networks first seen after that are listed here and in History, as are hours with far more lookups than usual."
              : "Changes aren't recorded for phones and computers, which visit new sites all the time."}
          </p>
          <p className="baseline-counts">
            {plural(c.domain, "site", "sites")} · {plural(c.org, "organization", "organizations")} ·{" "}
            {plural(c.country, "country", "countries")} · {plural(c.asn, "network", "networks")} · up to{" "}
            {plural(b.usual_peak, "lookup", "lookups")} in a busy hour
          </p>
        </>
      )}
      {b.departures.length > 0 && (
        <ol className="timeline">
          {b.departures.map((e, i) => (
            <li key={`${e.time}-${e.kind}-${i}`} className={`ev ${e.kind}`}>
              <time dateTime={e.time} title={dateTime(e.time)}>
                {ago(e.time)}
              </time>{" "}
              {describe({ ...e, ip: null, port: null, protocol: null })}
            </li>
          ))}
        </ol>
      )}
      {b.watched && !b.learning && b.departures.length === 0 && <p className="muted small">Nothing new since.</p>}
    </section>
  );
}

/** For IoT devices: does it look things up through Pi-hole at all, or might it use its own DNS server? */
function DnsCheckCard({ mac }: { mac: string }) {
  const check = useQuery({ queryKey: ["dnsCheck", mac], queryFn: () => api.dnsCheck(mac) });
  const c = check.data;
  if (!c?.applies) return null;
  const span = `${c.hours} hours`;
  let text;
  if (c.status === "silent")
    text = (
      <p className="warning">
        Online for {span} with only {plural(c.lookups ?? 0, "DNS lookup", "DNS lookups")} through Pi-hole (fewer
        than {c.min_lookups}). It probably uses its own DNS server (like Google's) or encrypted DNS, so netmap can't see
        where it goes. Blocking outbound DNS (port 53) on your router, except to Pi-hole, would force it through.
      </p>
    );
  else if (c.status === "ok")
    text = (
      <p className="muted">
        {plural(c.lookups ?? 0, "lookup", "lookups")} through Pi-hole in the last {span}: it uses Pi-hole.
      </p>
    );
  else if (c.status === "too_soon")
    text = <p className="muted">Online since {dateTime(c.online_since!)}; it's judged after {span} online.</p>;
  else if (c.status === "offline") text = <p className="muted">Offline; checked while it's online.</p>;
  else text = <p className="muted">Can't tell right now: {c.reason}</p>;
  return (
    <section className="card">
      <h2>DNS through Pi-hole</h2>
      {text}
    </section>
  );
}

/** This device's alerts, and its own alert rules. */
function DeviceAlerts({ mac }: { mac: string }) {
  const [rules, setRules] = useState(false);
  return (
    <>
      <AlertList mac={mac} />
      <section className="card">
        <h2>Alert rules for this device</h2>
        {rules ? (
          <RulesTable mac={mac} />
        ) : (
          <button type="button" onClick={() => setRules(true)}>
            Show rules
          </button>
        )}
      </section>
    </>
  );
}

function History({ mac }: { mac: string }) {
  const events = useInfiniteQuery({
    queryKey: ["events", mac],
    queryFn: ({ pageParam }) => api.events(mac, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => (last.length === 50 ? last[last.length - 1].time : undefined),
  });
  const all = events.data?.pages.flat() ?? [];
  return (
    <section className="card">
      <h2>History</h2>
      <ol className="timeline">
        {all.map((e, i) => (
          <li key={`${e.time}-${e.kind}-${i}`} className={`ev ${e.kind}`}>
            <time dateTime={e.time}>{dateTime(e.time)}</time> {describe(e)}
          </li>
        ))}
      </ol>
      {events.hasNextPage && (
        <button type="button" disabled={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()}>
          Load older
        </button>
      )}
    </section>
  );
}

function Merge({ device: d }: { device: Detail }) {
  const client = useQueryClient();
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.devices });
  const [into, setInto] = useState("");
  const [confirming, setConfirming] = useState(false);
  const merge = useMutation({
    mutationFn: () => api.mergeDevice(d.mac, into),
    onSuccess: (target) => {
      void client.invalidateQueries();
      window.location.hash = `#/devices/${target.mac}`;
    },
  });
  const others = (devices.data ?? [])
    .filter((o) => o.mac !== d.mac)
    .sort((a, b) => deviceName(a).localeCompare(deviceName(b)));
  return (
    <section className="card">
      <h2>Same device as…</h2>
      <p className="muted">
        If this is a device you already know under another MAC (phones and laptops switch to new
        private addresses), merge it: its history moves over and this MAC counts as that device
        from now on.
      </p>
      <div className="row">
        <select
          value={into}
          onChange={(e) => {
            setInto(e.target.value);
            setConfirming(false);
          }}
          aria-label="Device to merge into"
        >
          <option value="">Choose a device…</option>
          {others.map((o) => (
            <option key={o.mac} value={o.mac}>
              {deviceName(o)} ({o.mac})
            </option>
          ))}
        </select>
        {!confirming ? (
          <button type="button" disabled={!into} onClick={() => setConfirming(true)}>
            Merge into it
          </button>
        ) : (
          <button type="button" className="danger" disabled={merge.isPending} onClick={() => merge.mutate()}>
            Yes, merge {deviceName(d)} into it
          </button>
        )}
      </div>
      {merge.error && <p className="error">{merge.error.message}</p>}
    </section>
  );
}

/** The network a domain's IP is in, for a tooltip: "Network: Amazon.com, Inc. (AS16509)". */
function network(asn: number | null, org: string | null): string | undefined {
  if (asn === null) return undefined;
  return org ? `Network: ${org} (AS${asn})` : `Network: AS${asn}`;
}

/** Where IP locations come from; DB-IP's free databases ask for a credit where shown. */
function GeoipCredit() {
  const checks = useQuery({ queryKey: ["status"], queryFn: api.status });
  const source = checks.data?.find((c) => c.name === "geoip")?.details?.source;
  if (source === "dbip")
    return (
      <p className="muted small">
        Country and network: <a href="https://db-ip.com">IP Geolocation by DB-IP</a>.
      </p>
    );
  if (source === "maxmind")
    return <p className="muted small">Country and network: MaxMind GeoLite2.</p>;
  return null;
}

const RANGES = [
  { label: "1 hour", hours: 1 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

/** Start of a range ending now, fixed when the range is picked so pages line up. */
function rangeStart(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

function RangePicker({ hours, onPick }: { hours: number; onPick: (hours: number) => void }) {
  return (
    <div className="segmented" role="group" aria-label="Time range">
      {RANGES.map((r) => (
        <button
          key={r.hours}
          type="button"
          className={r.hours === hours ? "on" : ""}
          aria-pressed={r.hours === hours}
          onClick={() => onPick(r.hours)}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

function Domains({ mac, start }: { mac: string; start: string }) {
  const [sort, setSort] = useState<DomainSort>("queries");
  const pages = useInfiniteQuery({
    queryKey: ["domains", mac, start, sort],
    queryFn: ({ pageParam }) => api.domains(mac, start, sort, pageParam),
    initialPageParam: 0,
    getNextPageParam: (last, all) => {
      const loaded = all.reduce((n, p) => n + p.items.length, 0);
      return loaded < last.total ? loaded : undefined;
    },
    refetchInterval: false,
  });
  const first = pages.data?.pages[0];
  const items = pages.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <section className="card">
      <h2>DNS lookups</h2>
      <div className="row toolbar-row">
        <select value={sort} onChange={(e) => setSort(e.target.value as DomainSort)} aria-label="Sort domains">
          <option value="queries">Most looked up</option>
          <option value="last_seen">Most recent</option>
          <option value="domain">Name</option>
        </select>
      </div>
      {pages.error && <p className="error">{pages.error.message}</p>}
      {first && (
        <p className="muted small">
          {first.total} domains, {first.queries.toLocaleString()} lookups
          {first.blocked ? `, ${first.blocked.toLocaleString()} blocked` : ""}
        </p>
      )}
      {first && first.total === 0 && <p className="muted">No DNS lookups in this range.</p>}
      {items.length > 0 && (
        <table className="stack">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Lookups</th>
              <th>Blocked</th>
              <th>Country</th>
              <th>Organization</th>
              <th>Category</th>
              <th>First seen</th>
              <th>Last</th>
              <th>
                <span className="visually-hidden">Pi-hole</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((d) => (
              <tr key={d.domain}>
                <td className="domain">
                  {d.domain}
                  {d.new && <span className="tag">new</span>}
                  <ThreatTag lists={d.blocklists} />
                </td>
                <td data-label="Lookups">{d.queries.toLocaleString()}</td>
                <td data-label="Blocked" className={d.blocked ? "blocked" : "muted hide-narrow"}>
                  {d.blocked ? d.blocked.toLocaleString() : "—"}
                </td>
                {/* Unknowns read as a bare dash once stacked on a phone; leave them out there. */}
                <td title={d.country ? countryName(d.country) : undefined} className={d.country ? undefined : "hide-narrow"}>
                  {d.country ?? "—"}
                </td>
                <td title={network(d.asn, d.asn_org)} className={d.organization ? undefined : "hide-narrow"}>
                  {d.organization ?? "—"}
                </td>
                <td className={d.category ? undefined : "hide-narrow"}>
                  {d.category ? (DOMAIN_CATEGORY_LABELS[d.category] ?? d.category) : "—"}
                </td>
                <td data-label="First" title={dateTime(d.first_seen)}>
                  {ago(d.first_seen)}
                </td>
                <td data-label="Last" title={dateTime(d.last_seen)}>
                  {ago(d.last_seen)}
                </td>
                <td>
                  <BlockButton domain={d.domain} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {pages.hasNextPage && (
        <button type="button" disabled={pages.isFetchingNextPage} onClick={() => void pages.fetchNextPage()}>
          Show more
        </button>
      )}
      <GeoipCredit />
    </section>
  );
}
