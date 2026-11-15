export interface Health {
  status: string;
  version: string;
  database: boolean;
}

export interface Session {
  auth_enabled: boolean;
  authenticated: boolean;
}

export interface ExportDataset {
  name: string;
  label: string;
  by_time: boolean;
}

export interface HealthCheck {
  name: string;
  status: "ok" | "warning" | "unknown";
  message: string;
  details: Record<string, unknown> | null;
  checked_at: string;
}

/** Fired when the API answers 401, so the app can show the login page. */
export const UNAUTHORIZED_EVENT = "netmap:unauthorized";

export const CATEGORIES = ["iot", "phone", "computer", "infrastructure", "media", "unknown"] as const;
export type Category = (typeof CATEGORIES)[number];

export interface Device {
  mac: string;
  label: string | null;
  hostname: string | null;
  hostname_source: string | null;
  vendor: string | null;
  is_randomized_mac: boolean;
  category: Category;
  is_iot: boolean;
  notes: string | null;
  online: boolean;
  /** Its going offline raises a critical alert after offline_grace_minutes. */
  critical: boolean;
  offline_grace_minutes: number | null;
  first_seen: string;
  last_seen: string;
  ip: string | null;
}

export interface MapDevice {
  mac: string;
  label: string | null;
  hostname: string | null;
  vendor: string | null;
  category: Category;
  online: boolean;
  ip: string | null;
  queries: number;
  blocked: number;
  bytes_up: number;
  bytes_down: number;
}

export interface NetworkMap {
  since: string;
  router: string | null;
  /** Traffic capture is on: some traffic was captured in the window. */
  captured: boolean;
  devices: MapDevice[];
}

export interface DeviceIP {
  ip: string;
  first_seen: string;
  last_seen: string;
}

export interface DeviceName {
  source: string;
  name: string | null;
  details: Record<string, string> | null;
  first_seen: string;
  last_seen: string;
}

export interface WifiClient {
  source: "unifi" | "openwrt";
  ap_name: string | null;
  ssid: string | null;
  band: string | null;
  channel: number | null;
  signal_dbm: number | null;
  rx_rate_kbps: number | null;
  tx_rate_kbps: number | null;
  connected: boolean;
  connected_since: string | null;
  last_seen: string;
}

export interface Fingerbank {
  device: string | null;
  parents?: string[];
  device_name?: string | null;
  score?: number | null;
  checked_at: string;
}

export interface DeviceDetail extends Device {
  merged_into: string | null;
  aliases: string[];
  ips: DeviceIP[];
  names: DeviceName[];
  fingerbank: Fingerbank | null;
  wifi: WifiClient | null;
  critical_grace_default: number;
}

export interface TrafficPoint {
  time: string;
  bytes_up: number;
  bytes_down: number;
}

export type TrafficDimension = "device" | "remote" | "app";

export interface TrafficRow {
  key: string;
  label: string;
  bytes_up: number;
  bytes_down: number;
  flows: number;
}

export interface Traffic {
  start: string;
  end: string;
  bucket_seconds: number;
  source: string;
  captured: boolean;
  bytes_up: number;
  bytes_down: number;
  points: TrafficPoint[];
  by: TrafficDimension;
  rows: TrafficRow[];
}

export interface TrafficRemote {
  remote: string;
  ip: string;
  port: number;
  protocol: string;
  app: string | null;
  outbound: boolean | null;
  bytes_up: number;
  bytes_down: number;
  last: string;
}

export interface DeviceTraffic {
  hours: number;
  bytes_up: number;
  bytes_down: number;
  remotes: TrafficRemote[];
}

export interface PacketCapture {
  id: number;
  status: "pending" | "running" | "done" | "stopped" | "failed";
  max_seconds: number;
  max_bytes: number;
  bytes: number;
  packets: number | null;
  error: string | null;
  requested_at: string;
  started_at: string | null;
  ended_at: string | null;
  downloadable: boolean;
}

export interface CaptureState {
  available: boolean;
  reason: string | null;
  max_minutes: number;
  max_megabytes: number;
  captures: PacketCapture[];
}

/** Live throughput: bytes/second [up, down] per device, from /api/live. */
export interface LiveReport {
  time: string;
  seconds: number;
  devices: Record<string, [number, number]>;
}

/** Departures from a device's learned baseline. */
export type DepartureKind = "new_domain" | "new_org" | "new_country" | "new_asn" | "query_spike";

export interface DeviceEvent {
  time: string;
  kind: "new_device" | "online" | "offline" | "new_ip" | "port_opened" | "port_closed" | DepartureKind;
  ip: string | null;
  port: number | null;
  protocol: string | null;
  /** {key, label?} for new_*, {lookups, usual} for query_spike. */
  details: { key?: string; label?: string; lookups?: number; usual?: number } | null;
}

export type SiteStatus = "threat" | "expected" | "unexpected" | "tracker" | "maker" | "infrastructure" | "third_party";

export interface ReportSite {
  site: string;
  status: SiteStatus;
  expected: boolean | null;
  organization: string | null;
  category: string | null;
  lookups: number;
  night: number;
  blocked: number;
  domains: string[];
}

export interface ReportDevice {
  mac: string;
  label: string | null;
  hostname: string | null;
  vendor: string | null;
  lookups: number;
  night: number;
  flagged: number;
  sites: ReportSite[];
}

export interface IotReport {
  start: string;
  tz: string;
  devices: ReportDevice[];
}

export interface Baseline {
  learning_days: number;
  since: string | null;
  until: string | null;
  learning: boolean;
  watched: boolean;
  counts: { domain: number; org: number; country: number; asn: number };
  usual_peak: number;
  departures: Pick<DeviceEvent, "time" | "kind" | "details">[];
}

export type AlertKind =
  | "new_device"
  | "offline"
  | "port_opened"
  | DepartureKind
  | "blocklist_hit"
  | "upnp_forward"
  | "dns_bypass"
  | "critical_offline"
  | "critical_online"
  | "lateral_traffic"
  | "upload_heavy"
  | "unencrypted";
export type AlertAction = "notify" | "record" | "mute";
export type Severity = "info" | "warning" | "critical";

export interface Alert {
  id: number;
  time: string;
  mac: string | null;
  device: string | null;
  kind: AlertKind;
  severity: Severity;
  message: string;
  /** blocklist_hit: {domain, lookups, blocklists}; others vary by kind. */
  details: { domain?: string } & Record<string, unknown>;
  acknowledged_at: string | null;
  notify: "pending" | "sent" | "duplicate" | "failed" | null;
  notified_at: string | null;
}

export interface AlertPage {
  open: number;
  items: Alert[];
}

export interface AlertKindInfo {
  kind: AlertKind;
  label: string;
  severity: Severity;
  default_action: AlertAction;
  note: string | null;
}

export interface AlertRule {
  id: number;
  mac: string | null;
  kind: AlertKind | null;
  action: AlertAction;
  until: string | null;
  created_at: string;
}

export interface AlertRules {
  kinds: AlertKindInfo[];
  rules: AlertRule[];
}

export interface Notifications {
  configured: boolean;
  services: number;
  max_per_hour: number;
  link: boolean;
  pending: number;
  last_sent: string | null;
  problem: string | null;
}

export interface DnsCheck {
  applies: boolean;
  status: "ok" | "silent" | "too_soon" | "offline" | "unknown" | "not_iot";
  reason: string | null;
  hours: number;
  min_lookups: number;
  lookups: number | null;
  online_since: string | null;
}

export interface PiholeState {
  configured: boolean;
  domain: string;
  denied: boolean;
  deny_rules: string[];
  allowed: boolean;
  lists: string[];
  blocked: boolean;
  last_blocked: boolean | null;
}

export interface Port {
  port: number;
  protocol: string;
  service: string | null;
  banner: string | null;
  open: boolean;
  first_seen: string;
  last_seen: string;
}

export interface UpnpMapping {
  external_port: number;
  protocol: string;
  internal_ip: string;
  internal_port: number;
  description: string | null;
  mac: string | null;
  device: string | null;
  active: boolean;
  first_seen: string;
  last_seen: string;
}

export interface DeviceDomain {
  domain: string;
  queries: number;
  blocked: number;
  first_seen: string;
  last_seen: string;
  new: boolean;
  organization: string | null;
  category: string | null;
  blocklists: string[];
  country: string | null;
  asn: number | null;
  asn_org: string | null;
}

export interface DeviceDomainPage {
  start: string;
  end: string;
  total: number;
  queries: number;
  blocked: number;
  items: DeviceDomain[];
}

export interface ActivityPoint {
  time: string;
  queries: number;
  blocked: number;
}

export interface DeviceActivity {
  start: string;
  end: string;
  bucket_seconds: number;
  points: ActivityPoint[];
}

export interface Share {
  key: string;
  label: string;
  domains: number;
  queries: number;
}

export interface DeviceSummary {
  start: string;
  end: string;
  organizations: Share[];
  countries: Share[];
  categories: Share[];
}

export type HistoryDimension = "device" | "domain" | "organization" | "country" | "asn" | "category" | "status";

export interface HistoryFilters {
  mac?: string;
  domain?: string;
  organization?: string;
  country?: string;
  asn?: string;
  category?: string;
}

export interface HistoryRow {
  key: string;
  label: string;
  queries: number;
  blocked: number;
  domains: number;
}

export interface History {
  start: string;
  end: string;
  bucket_seconds: number;
  source: string;
  queries: number;
  blocked: number;
  domains: number;
  devices: number;
  points: ActivityPoint[];
  by: HistoryDimension;
  rows: HistoryRow[];
}

export interface FlowNode {
  id: string;
  label: string;
  layer: "device" | "organization" | "country";
  queries: number;
}

export interface Flows {
  start: string;
  end: string;
  source: string;
  iot_only: boolean;
  nodes: FlowNode[];
  links: { source: string; target: string; queries: number }[];
}

export interface Heatmap {
  start: string;
  end: string;
  tz: string;
  days: string[];
  cells: [number, number, number][];
  max: number;
}

export type DomainSort = "queries" | "last_seen" | "domain";

export interface Organization {
  name: string;
  domains: number;
}

export interface DomainCategory {
  category: string;
  label: string;
  domains: number;
}

export interface BlocklistInfo {
  name: string;
  label: string;
  url: string;
  entries: number | null;
  refreshed_at: string | null;
  needs_key: boolean;
}

export interface FlaggedDomain {
  domain: string;
  organization: string | null;
  category: string | null;
  blocklists: string[];
  last_seen: string;
}

export interface Blocklists {
  lists: BlocklistInfo[];
  labels: Record<string, string>;
  flagged: FlaggedDomain[];
}

/** Display names for domain categories (backend netmap/categories.py). */
export const DOMAIN_CATEGORY_LABELS: Record<string, string> = {
  ads: "Ads & trackers",
  analytics: "Telemetry & analytics",
  vendor: "Vendor cloud",
  cdn: "CDN & hosting",
  infrastructure: "Internet infrastructure",
  unknown: "Unknown",
};

/** Display names for blocklists (backend netmap/blocklists.py). */
export const BLOCKLIST_LABELS: Record<string, string> = {
  pihole: "Pi-hole",
  firehol_level1: "FireHOL level1",
  feodo: "abuse.ch Feodo Tracker",
  urlhaus: "abuse.ch URLhaus",
  threatfox: "abuse.ch ThreatFox",
};

/** Threat lists a domain is on: every hit but Pi-hole's own blocking. */
export function threats(lists: string[]): string[] {
  return lists.filter((l) => l !== "pihole");
}

export type OrgRuleKind = "suffix" | "asn";

export interface OrgRule {
  id: number;
  kind: OrgRuleKind;
  value: string;
  organization: string;
  created_at: string;
}

export interface OrgRuleSaved extends OrgRule {
  regrouped: number;
}

export type DeviceUpdate = Partial<
  Pick<Device, "label" | "category" | "is_iot" | "notes" | "critical" | "offline_grace_minutes">
>;

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) {
    const detail = await res
      .json()
      .then((j: { detail?: unknown }) => (typeof j.detail === "string" ? j.detail : ""))
      .catch(() => "");
    throw new Error(detail || `${method} ${path}: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const get = <T>(path: string) => request<T>("GET", path);

export const api = {
  health: () => get<Health>("/api/health"),
  session: () => get<Session>("/api/auth/session"),
  status: () => get<HealthCheck[]>("/api/status"),
  exportDatasets: () => get<ExportDataset[]>("/api/export"),
  exportUrl: (name: string, format: "csv" | "json", days?: number) =>
    `/api/export/${name}.${format}${days ? `?days=${days}` : ""}`,
  login: (password: string) => request<Session>("POST", "/api/auth/login", { password }),
  logout: () => request<Session>("POST", "/api/auth/logout"),
  devices: () => get<Device[]>("/api/devices"),
  device: (mac: string) => get<DeviceDetail>(`/api/devices/${mac}`),
  events: (mac: string, before?: string) =>
    get<DeviceEvent[]>(
      `/api/devices/${mac}/events?limit=50${before ? `&before=${encodeURIComponent(before)}` : ""}`,
    ),
  domains: (mac: string, start: string, sort: DomainSort, offset: number) =>
    get<DeviceDomainPage>(
      `/api/devices/${mac}/domains?${new URLSearchParams({ start, sort, offset: String(offset), limit: "50" })}`,
    ),
  activity: (mac: string, start: string) =>
    get<DeviceActivity>(`/api/devices/${mac}/activity?${new URLSearchParams({ start })}`),
  summary: (mac: string, start: string) =>
    get<DeviceSummary>(`/api/devices/${mac}/summary?${new URLSearchParams({ start })}`),
  ports: (mac: string) => get<Port[]>(`/api/devices/${mac}/ports`),
  baseline: (mac: string) => get<Baseline>(`/api/devices/${mac}/baseline`),
  iotReport: (start: string, tz: string) =>
    get<IotReport>(`/api/reports/iot?start=${encodeURIComponent(start)}&tz=${encodeURIComponent(tz)}`),
  iotReportCsv: (start: string, tz: string) =>
    `/api/reports/iot.csv?start=${encodeURIComponent(start)}&tz=${encodeURIComponent(tz)}`,
  setExpected: (mac: string, site: string, expected: boolean | null) =>
    request<{ expected: boolean | null }>("PUT", `/api/devices/${mac}/sites/${encodeURIComponent(site)}/expected`, {
      expected,
    }),
  alerts: (state: "open" | "all", mac?: string, before?: number) =>
    get<AlertPage>(
      `/api/alerts?${new URLSearchParams({ state, limit: "50", ...(mac ? { mac } : {}), ...(before ? { before: String(before) } : {}) })}`,
    ),
  alertSummary: () => get<{ open: number; critical: number }>("/api/alerts/summary"),
  acknowledge: (id: number, acknowledged: boolean) =>
    request<Alert>("PATCH", `/api/alerts/${id}`, { acknowledged }),
  acknowledgeAll: (mac?: string) =>
    request<{ acknowledged: number }>("POST", "/api/alerts/acknowledge", { mac: mac ?? null }),
  alertRules: (mac?: string) => get<AlertRules>(`/api/alert-rules${mac ? `?mac=${mac}` : ""}`),
  saveAlertRule: (rule: Pick<AlertRule, "mac" | "kind" | "action" | "until">) =>
    request<AlertRule>("PUT", "/api/alert-rules", rule),
  deleteAlertRule: (id: number) => request<void>("DELETE", `/api/alert-rules/${id}`),
  notifications: () => get<Notifications>("/api/notifications"),
  testNotification: () => request<{ sent: boolean; message: string }>("POST", "/api/notifications/test"),
  dnsCheck: (mac: string) => get<DnsCheck>(`/api/devices/${mac}/dns-check`),
  piholeState: (domain: string) => get<PiholeState>(`/api/pihole/domains/${encodeURIComponent(domain)}`),
  block: (domain: string) => request<PiholeState>("PUT", `/api/pihole/deny/${encodeURIComponent(domain)}`),
  unblock: (domain: string) => request<PiholeState>("DELETE", `/api/pihole/deny/${encodeURIComponent(domain)}`),
  history: (start: string, end: string | undefined, by: HistoryDimension, filters: HistoryFilters) =>
    get<History>(
      `/api/history?${new URLSearchParams({ start, ...(end ? { end } : {}), by, ...(filters as Record<string, string>) })}`,
    ),
  flows: (start: string, iotOnly: boolean) =>
    get<Flows>(`/api/flows?${new URLSearchParams({ start, iot_only: String(iotOnly) })}`),
  heatmap: (start: string, tz: string, mac?: string) =>
    get<Heatmap>(`/api/heatmap?${new URLSearchParams({ start, tz, ...(mac ? { mac } : {}) })}`),
  map: (minutes: number) => get<NetworkMap>(`/api/map?minutes=${minutes}`),
  upnpMappings: () => get<UpnpMapping[]>("/api/upnp-mappings"),
  updateDevice: (mac: string, changes: DeviceUpdate) =>
    request<DeviceDetail>("PATCH", `/api/devices/${mac}`, changes),
  mergeDevice: (mac: string, into: string) =>
    request<DeviceDetail>("POST", `/api/devices/${mac}/merge`, { into }),
  organizations: () => get<Organization[]>("/api/organizations"),
  orgRules: () => get<OrgRule[]>("/api/org-rules"),
  saveOrgRule: (rule: Pick<OrgRule, "kind" | "value" | "organization">) =>
    request<OrgRuleSaved>("POST", "/api/org-rules", rule),
  deleteOrgRule: (id: number) => request<OrgRuleSaved>("DELETE", `/api/org-rules/${id}`),
  domainCategories: () => get<DomainCategory[]>("/api/categories"),
  blocklists: () => get<Blocklists>("/api/blocklists"),
  traffic: (start: string, end: string | undefined, by: TrafficDimension, mac?: string) =>
    get<Traffic>(
      `/api/traffic?${new URLSearchParams({ start, ...(end ? { end } : {}), by, ...(mac ? { mac } : {}) })}`,
    ),
  deviceTraffic: (mac: string, hours: number) => get<DeviceTraffic>(`/api/devices/${mac}/traffic?hours=${hours}`),
  captures: (mac: string) => get<CaptureState>(`/api/devices/${mac}/captures`),
  startCapture: (mac: string, minutes: number, megabytes: number) =>
    request<PacketCapture>("POST", `/api/devices/${mac}/captures`, { minutes, megabytes }),
  stopCapture: (mac: string, id: number) => request<PacketCapture>("POST", `/api/devices/${mac}/captures/${id}/stop`),
  captureUrl: (mac: string, id: number) => `/api/devices/${mac}/captures/${id}.pcap`,
};

/** Bytes as KB, MB, GB (powers of 1000, as network speeds are). */
export function bytes(n: number): string {
  if (n < 1000) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n;
  let i = -1;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** Bytes per second as a bit rate: kbit/s, Mbit/s, ... */
export function rate(bytesPerSecond: number): string {
  const bits = bytesPerSecond * 8;
  if (bits < 1000) return `${Math.round(bits)} bit/s`;
  const units = ["kbit/s", "Mbit/s", "Gbit/s"];
  let v = bits;
  let i = -1;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** What to call a device: the owner's label, else what it calls itself, else its maker. */
export function deviceName(d: Pick<Device, "label" | "hostname" | "vendor" | "mac">): string {
  return d.label ?? d.hostname ?? (d.vendor ? `${d.vendor} device` : d.mac);
}
