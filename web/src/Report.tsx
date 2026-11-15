import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, DOMAIN_CATEGORY_LABELS, deviceName, type ReportDevice, type ReportSite, type SiteStatus } from "./api";

const STATUS: Record<SiteStatus, { label: string; tag: string; hint: string }> = {
  threat: { label: "Threat", tag: "tag bad", hint: "On a threat blocklist" },
  unexpected: { label: "Unexpected", tag: "tag bad", hint: "You marked it unexpected" },
  tracker: { label: "Tracker", tag: "tag warn", hint: "Ads, analytics or telemetry" },
  third_party: { label: "Third party", tag: "tag warn", hint: "Not the device's maker, and not marked expected" },
  expected: { label: "Expected", tag: "tag quiet", hint: "You marked it expected" },
  maker: { label: "Maker", tag: "tag quiet", hint: "The device maker's own cloud" },
  infrastructure: { label: "Infrastructure", tag: "tag quiet", hint: "CDN, hosting, time or DNS" },
};

const RANGES = [
  { label: "24 hours", days: 1 },
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
];

function startOf(days: number): string {
  return new Date(Date.now() - days * 86400_000).toISOString();
}

/** Per IoT device: where it phones home, what's expected, and what deserves a look. */
export function ReportPage() {
  const [days, setDays] = useState(7);
  const [start, setStart] = useState(() => startOf(7));
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const report = useQuery({ queryKey: ["iotReport", start, tz], queryFn: () => api.iotReport(start, tz) });
  const devices = report.data?.devices;
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      <h1 className="title">IoT report</h1>
      <div className="range-bar">
        <div className="segmented" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.days}
              type="button"
              className={r.days === days ? "on" : ""}
              aria-pressed={r.days === days}
              onClick={() => {
                setDays(r.days);
                setStart(startOf(r.days));
              }}
            >
              {r.label}
            </button>
          ))}
        </div>
        <a href={api.iotReportCsv(start, tz)} download>
          Download CSV
        </a>
      </div>
      <p className="muted small">
        Sites each IoT device looked up, by registrable domain. Threats, trackers, third parties and sites
        you marked unexpected come first. Mark a site expected and it stops being flagged for that device.
        Night is midnight to 6 am in your time zone ({tz}).
      </p>
      {report.error && <p className="error">{report.error.message}</p>}
      {!report.data && !report.error && <p className="muted">Loading…</p>}
      {devices && devices.length === 0 && (
        <p className="muted">No IoT devices. Set a device's category to IoT, or tick IoT on its page.</p>
      )}
      {devices?.map((d) => (
        <DeviceCard key={d.mac} device={d} start={start} tz={tz} />
      ))}
    </article>
  );
}

function DeviceCard({ device: d, start, tz }: { device: ReportDevice; start: string; tz: string }) {
  return (
    <section className="card">
      <h2>
        <a href={`#/devices/${d.mac}`}>{deviceName(d)}</a>
      </h2>
      <p className="muted small">
        {[
          d.vendor,
          `${d.lookups.toLocaleString()} lookups`,
          `${d.night.toLocaleString()} at night`,
          d.flagged ? `${d.flagged} to review` : "nothing to review",
        ]
          .filter(Boolean)
          .join(" · ")}
      </p>
      {d.sites.length === 0 ? (
        <p className="muted">No lookups in this range.</p>
      ) : (
        <div className="table-wrap">
          <table className="stack">
            <thead>
              <tr>
                <th>Site</th>
                <th>Status</th>
                <th>Organization</th>
                <th>Lookups</th>
                <th>At night</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {d.sites.map((s) => (
                <SiteRow key={s.site} mac={d.mac} site={s} start={start} tz={tz} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function SiteRow({ mac, site: s, start, tz }: { mac: string; site: ReportSite; start: string; tz: string }) {
  const client = useQueryClient();
  const mark = useMutation({
    mutationFn: (expected: boolean | null) => api.setExpected(mac, s.site, expected),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["iotReport", start, tz] }),
  });
  const status = STATUS[s.status];
  const names = s.domains.length;
  return (
    <tr>
      <td>
        <span className="mono">{s.site}</span>
        {names > 1 || s.domains[0] !== s.site ? (
          <div className="sub" title={s.domains.join("\n")}>
            {names === 1 ? s.domains[0] : `${names} names, mostly ${s.domains[0]}`}
          </div>
        ) : null}
        {mark.error && <div className="error sub">{mark.error.message}</div>}
      </td>
      <td data-label="Status">
        <span className={status.tag} title={status.hint}>
          {status.label}
        </span>
      </td>
      <td data-label="Organization" className={s.organization ? "" : "hide-narrow"}>
        {s.organization ?? "—"}
        {s.category && <div className="sub">{DOMAIN_CATEGORY_LABELS[s.category] ?? s.category}</div>}
      </td>
      <td data-label="Lookups">
        {s.lookups.toLocaleString()}
        {s.blocked > 0 && <span className="muted small"> ({s.blocked.toLocaleString()} blocked)</span>}
      </td>
      <td data-label="At night" className={s.night ? "" : "muted"}>
        {s.night.toLocaleString()}
      </td>
      <td data-label="Verdict">
        <select
          value={s.expected === null ? "" : String(s.expected)}
          disabled={mark.isPending}
          onChange={(e) => mark.mutate(e.target.value === "" ? null : e.target.value === "true")}
          aria-label={`Verdict for ${s.site}`}
        >
          <option value="">Not reviewed</option>
          <option value="true">Expected</option>
          <option value="false">Unexpected</option>
        </select>
      </td>
    </tr>
  );
}
