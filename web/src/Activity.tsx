import { useQuery } from "@tanstack/react-query";
import { useLayoutEffect, useRef, useState } from "react";
import { type ActivityPoint, api, type DeviceActivity, type Share } from "./api";

const HEIGHT = 180;
const PAD = { top: 8, right: 8, bottom: 22, left: 40 };
const MAX_BAR = 24;
const GAP = 2; // surface gap between bars and between stacked segments

/** The element's width, kept current as the page resizes. */
function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(el);
    setWidth(el.getBoundingClientRect().width);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

/** A round axis maximum and its tick step: 0 / 5 / 10, 0 / 200 / 400, ... */
function niceScale(max: number): { top: number; step: number } {
  if (max <= 0) return { top: 4, step: 2 };
  const rough = max / 3;
  const pow = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 5, 10].map((m) => m * pow).find((s) => s >= rough) ?? 10 * pow;
  return { top: Math.ceil(max / step) * step, step };
}

function compact(n: number): string {
  return n >= 1000 ? `${+(n / 1000).toFixed(1)}K` : String(n);
}

function tickLabel(iso: string, bucketSeconds: number): string {
  const d = new Date(iso);
  if (bucketSeconds >= 86400) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  if (bucketSeconds >= 3600)
    return d.toLocaleString(undefined, { weekday: "short", hour: "numeric" });
  return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

export function bucketLabel(p: ActivityPoint, bucketSeconds: number): string {
  const from = new Date(p.time);
  const to = new Date(from.getTime() + bucketSeconds * 1000);
  if (bucketSeconds >= 86400) return from.toLocaleDateString(undefined, { dateStyle: "medium" });
  const time = (d: Date) => d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  return `${from.toLocaleDateString(undefined, { month: "short", day: "numeric" })}, ${time(from)}–${time(to)}`;
}

/** A bar segment with its top corners rounded (the data end), square at the bottom. */
function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

/** Allowed and blocked lookups per bucket, stacked, with a hover tooltip. */
export function Chart({ data }: { data: Pick<DeviceActivity, "bucket_seconds" | "points"> }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const points = data.points;
  const plotW = Math.max(0, width - PAD.left - PAD.right);
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const { top, step } = niceScale(Math.max(0, ...points.map((p) => p.queries)));
  const slot = points.length ? plotW / points.length : 0;
  const barW = Math.max(1, Math.min(MAX_BAR, slot - GAP));
  const y = (v: number) => PAD.top + plotH - (v / top) * plotH;
  const ticks = Array.from({ length: Math.round(top / step) + 1 }, (_, i) => i * step);
  const every = Math.max(1, Math.ceil(points.length / Math.max(1, Math.floor(plotW / 90))));
  const shown = hover !== null ? points[hover] : null;

  return (
    <div className="chart" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 && (
        <svg height={HEIGHT} role="img" aria-label="DNS lookups over time, allowed and blocked">
          {ticks.map((t) => (
            <g key={t}>
              <line className="grid-line" x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
              <text className="axis" x={PAD.left - 6} y={y(t) + 4} textAnchor="end">
                {compact(t)}
              </text>
            </g>
          ))}
          {/* Hit targets: the whole column, wider than the bar; drawn first so the hover
              highlight sits behind the bars. */}
          {points.map((p, i) => (
            <rect
              key={`hit-${p.time}`}
              className={`hit${hover === i ? " on" : ""}`}
              x={PAD.left + i * slot}
              y={PAD.top}
              width={slot}
              height={plotH}
              onMouseEnter={() => setHover(i)}
            />
          ))}
          <g className="bars">
            {points.map((p, i) => {
              const x = PAD.left + i * slot + (slot - barW) / 2;
              const allowed = p.queries - p.blocked;
              const hAllowed = (allowed / top) * plotH;
              const hBlocked = (p.blocked / top) * plotH;
              const base = PAD.top + plotH;
              // The gap sits between the segments, taken from the upper one.
              const gap = allowed > 0 && p.blocked > 0 ? Math.min(GAP, hBlocked / 2) : 0;
              return (
                <g key={p.time}>
                  {allowed > 0 && (
                    <path
                      className="allowed"
                      d={
                        p.blocked > 0
                          ? `M${x},${base}V${base - hAllowed}H${x + barW}V${base}Z`
                          : topRounded(x, base - hAllowed, barW, hAllowed, 4)
                      }
                    />
                  )}
                  {p.blocked > 0 && (
                    <path
                      className="blocked"
                      d={topRounded(x, base - hAllowed - hBlocked, barW, hBlocked - gap, 4)}
                    />
                  )}
                  {i % every === 0 && (
                    <text className="axis" x={PAD.left + i * slot + slot / 2} y={HEIGHT - 6} textAnchor="middle">
                      {tickLabel(p.time, data.bucket_seconds)}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      )}
      {shown && hover !== null && (
        <div
          className="tooltip"
          style={{
            left: Math.min(Math.max(0, PAD.left + hover * slot + slot / 2 - 80), Math.max(0, width - 170)),
          }}
        >
          <div>{bucketLabel(shown, data.bucket_seconds)}</div>
          <div>
            <span className="swatch allowed" />
            {(shown.queries - shown.blocked).toLocaleString()} allowed
          </div>
          <div>
            <span className="swatch blocked" />
            {shown.blocked.toLocaleString()} blocked
          </div>
        </div>
      )}
    </div>
  );
}

export function bucketName(seconds: number): string {
  if (seconds >= 86400) return "day";
  if (seconds >= 3600) return "hour";
  return seconds >= 900 ? "15 minutes" : "minute";
}

/** DNS lookups over the range, allowed and blocked, with a table view of the same data. */
export function ActivityCard({ mac, start }: { mac: string; start: string }) {
  const activity = useQuery({
    queryKey: ["activity", mac, start],
    queryFn: () => api.activity(mac, start),
  });
  const data = activity.data;
  const total = data?.points.reduce((n, p) => n + p.queries, 0) ?? 0;
  const blocked = data?.points.reduce((n, p) => n + p.blocked, 0) ?? 0;
  return (
    <section className="card">
      <h2>Activity</h2>
      {activity.error && <p className="error">{activity.error.message}</p>}
      {data && (
        <>
          <div className="legend">
            <span>
              <span className="swatch allowed" />
              Allowed {(total - blocked).toLocaleString()}
            </span>
            <span>
              <span className="swatch blocked" />
              Blocked {blocked.toLocaleString()}
            </span>
            <span>DNS lookups per {bucketName(data.bucket_seconds)}</span>
          </div>
          {total === 0 ? <p className="muted">No DNS lookups in this range.</p> : <Chart data={data} />}
          {total > 0 && (
            <details>
              <summary className="muted small">Table</summary>
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Allowed</th>
                    <th>Blocked</th>
                  </tr>
                </thead>
                <tbody>
                  {data.points
                    .filter((p) => p.queries > 0)
                    .map((p) => (
                      <tr key={p.time}>
                        <td>{bucketLabel(p, data.bucket_seconds)}</td>
                        <td>{(p.queries - p.blocked).toLocaleString()}</td>
                        <td>{p.blocked.toLocaleString()}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </details>
          )}
        </>
      )}
    </section>
  );
}

function Shares({ title, items, label }: { title: string; items: Share[]; label?: (s: Share) => string }) {
  const max = Math.max(1, ...items.map((s) => s.queries));
  return (
    <section className="card">
      <h2>{title}</h2>
      {items.length === 0 && <p className="muted">Nothing in this range.</p>}
      <ul className="shares">
        {items.map((s) => (
          <li key={s.key} title={`${s.domains} domain${s.domains === 1 ? "" : "s"}`}>
            <span className="name">{label ? label(s) : s.label}</span>
            <span className="value">{s.queries.toLocaleString()}</span>
            <span className="bar" style={{ width: `${(s.queries / max) * 100}%` }} />
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Where the range's lookups went: top organizations, countries and categories. */
export function SummaryCards({
  mac,
  start,
  countryName,
}: {
  mac: string;
  start: string;
  countryName: (code: string) => string;
}) {
  const summary = useQuery({ queryKey: ["summary", mac, start], queryFn: () => api.summary(mac, start) });
  if (summary.error) return <p className="error">{summary.error.message}</p>;
  const data = summary.data;
  if (!data) return null;
  return (
    <div className="grid">
      <Shares title="Top organizations" items={data.organizations} />
      <Shares title="Top countries" items={data.countries} label={(s) => (s.key ? countryName(s.key) : s.label)} />
      <Shares title="Kinds of service" items={data.categories} />
    </div>
  );
}
