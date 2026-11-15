export interface Health {
  status: string;
  version: string;
  database: boolean;
}

export interface Session {
  auth_enabled: boolean;
  authenticated: boolean;
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
  first_seen: string;
  last_seen: string;
  ip: string | null;
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

export interface DeviceDetail extends Device {
  merged_into: string | null;
  aliases: string[];
  ips: DeviceIP[];
  names: DeviceName[];
}

export interface DeviceEvent {
  time: string;
  kind: "new_device" | "online" | "offline" | "new_ip" | "port_opened" | "port_closed";
  ip: string | null;
  port: number | null;
  protocol: string | null;
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

export type DeviceUpdate = Partial<Pick<Device, "label" | "category" | "is_iot" | "notes">>;

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
  return res.json() as Promise<T>;
}

const get = <T>(path: string) => request<T>("GET", path);

export const api = {
  health: () => get<Health>("/api/health"),
  session: () => get<Session>("/api/auth/session"),
  status: () => get<HealthCheck[]>("/api/status"),
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
};

/** What to call a device: the owner's label, else what it calls itself, else its maker. */
export function deviceName(d: Pick<Device, "label" | "hostname" | "vendor" | "mac">): string {
  return d.label ?? d.hostname ?? (d.vendor ? `${d.vendor} device` : d.mac);
}
