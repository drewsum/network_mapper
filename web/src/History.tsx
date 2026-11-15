import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { bucketName, Chart } from "./Activity";
import { api, type HistoryDimension, type HistoryFilters, type HistoryRow } from "./api";
import { TrafficCard } from "./Traffic";
import { countryName } from "./ui";

const RANGES = [
  { label: "1 hour", hours: 1 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

const DIMENSIONS: { by: HistoryDimension; label: string; filter?: keyof HistoryFilters }[] = [
  { by: "device", label: "Device", filter: "mac" },
  { by: "domain", label: "Domain", filter: "domain" },
  { by: "organization", label: "Organization", filter: "organization" },
  { by: "country", label: "Country", filter: "country" },
  { by: "asn", label: "Network", filter: "asn" },
  { by: "category", label: "Category", filter: "category" },
  { by: "status", label: "Allowed / blocked" },
];

const SOURCES: Record<string, string> = {
  dns_activity_1m: "per-minute",
  dns_activity_1h: "hourly",
  dns_activity_1d: "daily",
};

interface Range {
  hours: number | null; // null: custom
  start: string;
  end?: string;
}

/** Start of a range ending now. */
function rangeStart(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

/** An <input type="datetime-local"> value for a time, in local time. */
function localInput(d: Date): string {
  const shifted = new Date(d.getTime() - d.getTimezoneOffset() * 60_000);
  return shifted.toISOString().slice(0, 16);
}

function rowLabel(by: HistoryDimension, r: HistoryRow): string {
  if (by === "country") return r.key ? countryName(r.key) : "Unknown";
  return r.label;
}

export function HistoryPage() {
  const [range, setRange] = useState<Range>(() => ({ hours: 24, start: rangeStart(24) }));
  const [by, setBy] = useState<HistoryDimension>("device");
  // Each filter remembers the label it was picked from, for its chip.
  const [filters, setFilters] = useState<Partial<Record<keyof HistoryFilters, { value: string; label: string }>>>({});
  const [custom, setCustom] = useState(() => ({
    start: localInput(new Date(Date.now() - 7 * 86400_000)),
    end: localInput(new Date()),
  }));

  const params: HistoryFilters = Object.fromEntries(Object.entries(filters).map(([k, f]) => [k, f!.value]));
  const history = useQuery({
    queryKey: ["history", range.start, range.end, by, params],
    queryFn: () => api.history(range.start, range.end, by, params),
    placeholderData: keepPreviousData,
    refetchInterval: range.end ? false : 60_000,
  });
  const data = history.data;
  const dimension = DIMENSIONS.find((d) => d.by === by)!;
  const max = Math.max(1, ...(data?.rows.map((r) => r.queries) ?? []));

  const pick = (hours: number) => setRange({ hours, start: rangeStart(hours) });
  const applyCustom = (e: FormEvent) => {
    e.preventDefault();
    const start = new Date(custom.start);
    const end = new Date(custom.end);
    if (!(start < end)) return;
    setRange({ hours: null, start: start.toISOString(), end: end.toISOString() });
  };
  const narrow = (r: HistoryRow) => {
    if (!dimension.filter || !r.key) return;
    setFilters((f) => ({ ...f, [dimension.filter!]: { value: r.key, label: rowLabel(by, r) } }));
    // Drill down: from a device to what it looked up, from anything else to the devices.
    setBy(by === "device" ? "domain" : "device");
  };
  const clear = (k: keyof HistoryFilters) =>
    setFilters((f) => {
      const next = { ...f };
      delete next[k];
      return next;
    });

  return (
    <article className="detail">
      <h1 className="title">History</h1>
      <div className="range-bar">
        <div className="segmented" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              type="button"
              className={r.hours === range.hours ? "on" : ""}
              aria-pressed={r.hours === range.hours}
              onClick={() => pick(r.hours)}
            >
              {r.label}
            </button>
          ))}
        </div>
        <form className="custom-range" onSubmit={applyCustom}>
          <input
            type="datetime-local"
            value={custom.start}
            onChange={(e) => setCustom((c) => ({ ...c, start: e.target.value }))}
            aria-label="From"
          />
          <span className="muted">to</span>
          <input
            type="datetime-local"
            value={custom.end}
            onChange={(e) => setCustom((c) => ({ ...c, end: e.target.value }))}
            aria-label="To"
          />
          <button type="submit" className={range.hours === null ? "on" : ""}>
            Custom
          </button>
        </form>
      </div>
      {Object.keys(filters).length > 0 && (
        <div className="chips filters">
          {Object.entries(filters).map(([k, f]) => (
            <button key={k} type="button" className="chip on" onClick={() => clear(k as keyof HistoryFilters)}>
              {DIMENSIONS.find((d) => d.filter === k)?.label}: {f!.label} ✕
            </button>
          ))}
        </div>
      )}
      {history.error && <p className="error">{history.error.message}</p>}
      <section className="card">
        <h2>DNS lookups</h2>
        {data && (
          <>
            <div className="legend">
              <span>
                <span className="swatch allowed" />
                Allowed {(data.queries - data.blocked).toLocaleString()}
              </span>
              <span>
                <span className="swatch blocked" />
                Blocked {data.blocked.toLocaleString()}
              </span>
              <span>
                {data.domains.toLocaleString()} domain{data.domains === 1 ? "" : "s"}, {data.devices.toLocaleString()}{" "}
                device{data.devices === 1 ? "" : "s"} · per{" "}
                {bucketName(data.bucket_seconds)}, from the {SOURCES[data.source] ?? data.source} aggregate
              </span>
            </div>
            {data.queries === 0 ? <p className="muted">No DNS lookups in this range.</p> : <Chart data={data} />}
          </>
        )}
      </section>
      <section className="card">
        <div className="row toolbar-row">
          <h2>Breakdown</h2>
          <select
            className="narrow-only"
            value={by}
            onChange={(e) => setBy(e.target.value as HistoryDimension)}
            aria-label="Break down by"
          >
            {DIMENSIONS.map((d) => (
              <option key={d.by} value={d.by}>
                By {d.label.toLowerCase()}
              </option>
            ))}
          </select>
          <div className="segmented hide-narrow" role="group" aria-label="Break down by">
            {DIMENSIONS.map((d) => (
              <button
                key={d.by}
                type="button"
                className={d.by === by ? "on" : ""}
                aria-pressed={d.by === by}
                onClick={() => setBy(d.by)}
              >
                {d.label}
              </button>
            ))}
          </div>
        </div>
        {dimension.filter && <p className="muted small">Click a row to narrow everything to it.</p>}
        {data && data.rows.length > 0 && (
          <table className="breakdown">
            <thead>
              <tr>
                <th>{dimension.label}</th>
                <th>Lookups</th>
                <th>Blocked</th>
                {by !== "status" && <th>Domains</th>}
              </tr>
            </thead>
            <tbody>
              {data.rows.map((r) => (
                <tr
                  key={r.key || "unknown"}
                  className={dimension.filter && r.key ? "clickable" : undefined}
                  onClick={() => narrow(r)}
                >
                  <td>
                    {rowLabel(by, r)}
                    {by === "device" && r.key && (
                      <a className="open" href={`#/devices/${r.key}`} onClick={(e) => e.stopPropagation()}>
                        open
                      </a>
                    )}
                  </td>
                  <td className="share">
                    <span className="bar" style={{ width: `${(r.queries / max) * 100}%` }} />
                    <span>{r.queries.toLocaleString()}</span>
                  </td>
                  <td className={r.blocked ? "blocked" : "muted"}>{r.blocked ? r.blocked.toLocaleString() : "—"}</td>
                  {by !== "status" && <td>{r.domains.toLocaleString()}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <TrafficCard start={range.start} end={range.end} />
    </article>
  );
}
