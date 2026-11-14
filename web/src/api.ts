export interface Health {
  status: string;
  version: string;
  database: boolean;
}

export interface Session {
  auth_enabled: boolean;
  authenticated: boolean;
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
  login: (password: string) => request<Session>("POST", "/api/auth/login", { password }),
  logout: () => request<Session>("POST", "/api/auth/logout"),
  devices: () => get<Device[]>("/api/devices"),
  device: (mac: string) => get<DeviceDetail>(`/api/devices/${mac}`),
  events: (mac: string, before?: string) =>
    get<DeviceEvent[]>(
      `/api/devices/${mac}/events?limit=50${before ? `&before=${encodeURIComponent(before)}` : ""}`,
    ),
  ports: (mac: string) => get<Port[]>(`/api/devices/${mac}/ports`),
  upnpMappings: () => get<UpnpMapping[]>("/api/upnp-mappings"),
  updateDevice: (mac: string, changes: DeviceUpdate) =>
    request<DeviceDetail>("PATCH", `/api/devices/${mac}`, changes),
  mergeDevice: (mac: string, into: string) =>
    request<DeviceDetail>("POST", `/api/devices/${mac}/merge`, { into }),
};

/** What to call a device: the owner's label, else what it calls itself, else its maker. */
export function deviceName(d: Pick<Device, "label" | "hostname" | "vendor" | "mac">): string {
  return d.label ?? d.hostname ?? (d.vendor ? `${d.vendor} device` : d.mac);
}
