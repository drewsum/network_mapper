export interface Health {
  status: string;
  version: string;
  database: boolean;
}

export interface Device {
  mac: string;
  label: string | null;
  hostname: string | null;
  vendor: string | null;
  is_randomized_mac: boolean;
  category: string;
  is_iot: boolean;
  online: boolean;
  first_seen: string;
  last_seen: string;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<Health>("/api/health"),
  devices: () => get<Device[]>("/api/devices"),
};
