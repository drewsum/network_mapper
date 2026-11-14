import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, CATEGORIES, type Device, deviceName } from "./api";
import { CategorySelect, EditableText, ipKey, Status, useUpdateDevice } from "./ui";

type SortKey = "name" | "category" | "vendor" | "ip" | "status";

const SORTS: Record<SortKey, (d: Device) => string> = {
  name: (d) => deviceName(d).toLowerCase(),
  category: (d) => d.category,
  vendor: (d) => (d.is_randomized_mac ? "~randomized" : (d.vendor ?? "~").toLowerCase()),
  ip: (d) => ipKey(d.ip),
  // Online first, then the most recently seen.
  status: (d) => `${d.online ? 0 : 1}${String(1e13 - new Date(d.last_seen).getTime())}`,
};

function matches(d: Device, words: string[]): boolean {
  const haystack = [d.label, d.hostname, d.vendor, d.ip, d.mac, d.mac.replaceAll(":", "")]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return words.every((w) => haystack.includes(w));
}

export function DeviceTable() {
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.devices });
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [iotOnly, setIotOnly] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "status", desc: false });

  const rows = useMemo(() => {
    const words = search.toLowerCase().split(/\s+/).filter(Boolean);
    const key = SORTS[sort.key];
    return (devices.data ?? [])
      .filter(
        (d) =>
          matches(d, words) &&
          (!category || d.category === category) &&
          (!onlineOnly || d.online) &&
          (!iotOnly || d.is_iot || d.category === "iot"),
      )
      .sort((a, b) => key(a).localeCompare(key(b)) * (sort.desc ? -1 : 1));
  }, [devices.data, search, category, onlineOnly, iotOnly, sort]);

  const header = (key: SortKey, label: string) => (
    <th aria-sort={sort.key === key ? (sort.desc ? "descending" : "ascending") : "none"}>
      <button
        type="button"
        className="sort"
        onClick={() => setSort((s) => ({ key, desc: s.key === key ? !s.desc : false }))}
      >
        {label}
        {sort.key === key ? (sort.desc ? " ▾" : " ▴") : ""}
      </button>
    </th>
  );

  if (devices.error) return <p className="error">Couldn't load devices: {devices.error.message}</p>;
  if (!devices.data) return <p className="muted">Loading devices…</p>;

  const online = devices.data.filter((d) => d.online).length;
  return (
    <>
      <div className="toolbar">
        <input
          type="search"
          className="search"
          placeholder="Search name, IP, MAC or vendor"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search devices"
        />
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category filter">
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <label className="check">
          <input type="checkbox" checked={onlineOnly} onChange={(e) => setOnlineOnly(e.target.checked)} />
          Online
        </label>
        <label className="check">
          <input type="checkbox" checked={iotOnly} onChange={(e) => setIotOnly(e.target.checked)} />
          IoT
        </label>
        <span className="muted count">
          {rows.length === devices.data.length
            ? `${devices.data.length} devices, ${online} online`
            : `${rows.length} of ${devices.data.length}`}
        </span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {header("name", "Name")}
              {header("category", "Category")}
              {header("vendor", "Vendor")}
              {header("ip", "IP")}
              <th>MAC</th>
              {header("status", "Status")}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <Row key={d.mac} device={d} />
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="muted empty">No devices match.</p>}
      </div>
    </>
  );
}

function Row({ device: d }: { device: Device }) {
  const update = useUpdateDevice(d.mac);
  return (
    <tr className={d.online ? "" : "offline"}>
      <td>
        <div className="name-cell">
          <EditableText
            value={d.label}
            placeholder={d.hostname ?? (d.vendor ? `${d.vendor} device` : "unnamed")}
            onSave={(label) => update.mutate({ label })}
          />
          <a href={`#/devices/${d.mac}`} className="open" title="Details">
            details →
          </a>
        </div>
        {d.label && d.hostname && (
          <div className="sub" title={d.hostname_source ? `from ${d.hostname_source}` : undefined}>
            {d.hostname}
          </div>
        )}
        {update.error && <div className="error sub">{update.error.message}</div>}
      </td>
      <td>
        <CategorySelect value={d.category} onChange={(category) => update.mutate({ category })} />
        {d.is_iot && d.category !== "iot" ? <span className="tag">IoT</span> : null}
      </td>
      <td>{d.is_randomized_mac ? <span className="muted">randomized MAC</span> : (d.vendor ?? "—")}</td>
      <td className="mono">{d.ip ?? "—"}</td>
      <td className="mono">{d.mac}</td>
      <td>
        <Status online={d.online} lastSeen={d.last_seen} />
      </td>
    </tr>
  );
}
