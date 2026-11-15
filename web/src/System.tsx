import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, type HealthCheck } from "./api";
import { ago, dateTime } from "./ui";

const CHECK_LABELS: Record<string, string> = {
  backup: "Backups",
  blocklists: "Threat blocklists",
  capture: "Traffic capture",
  fingerbank: "Fingerbank",
  geoip: "IP locations",
  notifications: "Notifications",
  pihole_client_visibility: "Pi-hole sees devices",
  wifi: "Wi-Fi access points",
};

const STATUS_TAGS: Record<HealthCheck["status"], string> = {
  ok: "tag quiet",
  warning: "tag warn",
  unknown: "tag quiet",
};

const EXPORT_RANGES = [
  { label: "All time", days: 0 },
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
  { label: "1 year", days: 365 },
];

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

/** How netmap itself is doing: its self-checks, backups, and data export. */
export function SystemPage() {
  const checks = useQuery({ queryKey: ["status"], queryFn: api.status });
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      <h1 className="title">System</h1>
      <Backups
        check={checks.data?.find((c) => c.name === "backup")}
        loading={!checks.data}
      />
      <ExportCard />
      <section className="card">
        <h2>Self-checks</h2>
        {checks.error && <p className="error">{checks.error.message}</p>}
        {checks.data?.length === 0 && (
          <p className="muted">The collector hasn't run any checks yet.</p>
        )}
        {!!checks.data?.length && (
          <div className="table-wrap">
            <table className="stack">
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Status</th>
                  <th>Result</th>
                  <th>Checked</th>
                </tr>
              </thead>
              <tbody>
                {checks.data.map((c) => (
                  <tr key={c.name}>
                    <td>{CHECK_LABELS[c.name] ?? c.name}</td>
                    <td data-label="Status">
                      <span className={STATUS_TAGS[c.status]}>{c.status}</span>
                    </td>
                    <td data-label="Result">{c.message}</td>
                    <td data-label="Checked">
                      <time title={dateTime(c.checked_at)}>
                        {ago(c.checked_at)}
                      </time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </article>
  );
}

function Backups({
  check,
  loading,
}: {
  check?: HealthCheck;
  loading: boolean;
}) {
  const d = (check?.details ?? {}) as {
    file?: string;
    bytes?: number;
    kept?: number;
    total_bytes?: number;
    oldest?: string;
    next?: string;
  };
  return (
    <section className="card">
      <h2>Backups</h2>
      {loading && <p className="muted">Loading…</p>}
      {!loading && !check && (
        <p className="muted">
          No backup yet. The server stack's backup service dumps the database
          into the data directory's <span className="mono">backups</span> folder
          once a day; the dev stack doesn't run it.
        </p>
      )}
      {check?.status === "warning" && <p className="error">{check.message}</p>}
      {d.file && (
        <dl className="facts">
          <div>
            <dt>Latest</dt>
            <dd>
            <span className="mono">{d.file}</span>
            {d.bytes !== undefined && `, ${size(d.bytes)}`}
            {check?.status === "ok" && (
              <>
                {" "}
                (
                <time title={dateTime(check.checked_at)}>
                  {ago(check.checked_at)}
                </time>
                )
              </>
            )}
            </dd>
          </div>
          <div>
            <dt>Kept</dt>
            <dd>
            {d.kept} backup{d.kept === 1 ? "" : "s"}
            {d.total_bytes !== undefined && `, ${size(d.total_bytes)} in all`}
            {d.oldest && (
              <>
                ; oldest <span className="mono">{d.oldest}</span>
              </>
            )}
            </dd>
          </div>
          {d.next && (
            <div>
              <dt>Next</dt>
              <dd>{new Date(d.next).toLocaleString()}</dd>
            </div>
          )}
        </dl>
      )}
      <p className="muted small">
        To restore one, see <span className="mono">docs/backups.md</span> in the
        repo.
      </p>
    </section>
  );
}

function ExportCard() {
  const datasets = useQuery({
    queryKey: ["exportDatasets"],
    queryFn: api.exportDatasets,
  });
  const [days, setDays] = useState(0);
  return (
    <section className="card">
      <h2>Export data</h2>
      <div className="row toolbar-row">
        <div
          className="segmented"
          role="group"
          aria-label="Time range for events, alerts and DNS"
        >
          {EXPORT_RANGES.map((r) => (
            <button
              key={r.days}
              type="button"
              className={days === r.days ? "on" : ""}
              aria-pressed={days === r.days}
              onClick={() => setDays(r.days)}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {datasets.error && <p className="error">{datasets.error.message}</p>}
      {datasets.data && (
        <ul className="exports">
          {datasets.data.map((d) => (
            <li key={d.name}>
              <span>
                {d.label}
                {!d.by_time && days > 0 && (
                  <span className="muted small"> (always everything)</span>
                )}
              </span>
              <span className="exports-links">
                <a
                  href={api.exportUrl(
                    d.name,
                    "csv",
                    d.by_time ? days : undefined,
                  )}
                  download
                >
                  CSV
                </a>
                <a
                  href={api.exportUrl(
                    d.name,
                    "json",
                    d.by_time ? days : undefined,
                  )}
                  download
                >
                  JSON
                </a>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
