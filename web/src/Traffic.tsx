import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { bucketName, Chart, type Series } from "./Activity";
import { api, bytes, type PacketCapture, rate, type TrafficDimension, type TrafficPoint } from "./api";
import { useLive } from "./live";
import { ago, dateTime } from "./ui";

export const TRAFFIC_SERIES: Series<TrafficPoint> = {
  split: (p) => [p.bytes_down, p.bytes_up],
  classes: ["down", "up"],
  labels: ["down", "up"],
  format: bytes,
  axis: (n) => (n === 0 ? "0" : bytes(n).replace(" ", "")),
  aria: "Traffic over time, download and upload",
};

const DIMENSIONS: { by: TrafficDimension; label: string }[] = [
  { by: "device", label: "Device" },
  { by: "remote", label: "Remote end" },
  { by: "app", label: "Application" },
];

/** Shown where traffic would be, when nothing has ever been captured. */
function NotCaptured() {
  return (
    <p className="muted">
      No traffic captured. Byte counts need the capture service with a mirror (SPAN) port or a router that exports
      NetFlow/IPFIX; see <span className="mono">docs/span.md</span>. DNS lookups above work without it.
    </p>
  );
}

function Legend({ up, down, note }: { up: number; down: number; note?: string }) {
  return (
    <div className="legend">
      <span>
        <span className="swatch down" />
        Down {bytes(down)}
      </span>
      <span>
        <span className="swatch up" />
        Up {bytes(up)}
      </span>
      {note && <span>{note}</span>}
    </div>
  );
}

/** Network-wide traffic over a range, broken down by device, remote end or application. */
export function TrafficCard({ start, end }: { start: string; end?: string }) {
  const [by, setBy] = useState<TrafficDimension>("device");
  const traffic = useQuery({
    queryKey: ["traffic", start, end, by],
    queryFn: () => api.traffic(start, end, by),
    placeholderData: keepPreviousData,
    refetchInterval: end ? false : 60_000,
  });
  const data = traffic.data;
  const max = Math.max(1, ...(data?.rows.map((r) => r.bytes_up + r.bytes_down) ?? []));
  return (
    <section className="card">
      <div className="row toolbar-row">
        <h2>Traffic</h2>
        {data?.captured && (
          <div className="segmented" role="group" aria-label="Break traffic down by">
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
        )}
      </div>
      {traffic.error && <p className="error">{traffic.error.message}</p>}
      {data && !data.captured && <NotCaptured />}
      {data?.captured && (
        <>
          <Legend up={data.bytes_up} down={data.bytes_down} note={`per ${bucketName(data.bucket_seconds)}`} />
          {data.bytes_up + data.bytes_down === 0 ? (
            <p className="muted">No traffic in this range.</p>
          ) : (
            <Chart data={data} series={TRAFFIC_SERIES} />
          )}
          {data.rows.length > 0 && (
            <table className="breakdown">
              <thead>
                <tr>
                  <th>{DIMENSIONS.find((d) => d.by === by)?.label}</th>
                  <th>Total</th>
                  <th>Down</th>
                  <th>Up</th>
                </tr>
              </thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.key || "unknown"}>
                    <td>
                      {r.label}
                      {by === "device" && (
                        <a className="open" href={`#/devices/${r.key}`}>
                          open
                        </a>
                      )}
                    </td>
                    <td className="share">
                      <span className="bar" style={{ width: `${((r.bytes_up + r.bytes_down) / max) * 100}%` }} />
                      <span>{bytes(r.bytes_up + r.bytes_down)}</span>
                    </td>
                    <td>{bytes(r.bytes_down)}</td>
                    <td>{bytes(r.bytes_up)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {by !== "device" && (
            <p className="muted small">Remote ends and applications reach back as far as raw flows are kept (30 days).</p>
          )}
        </>
      )}
    </section>
  );
}

/** One device's traffic: right now, over the range, and where it went. */
export function DeviceTrafficCard({ mac, start }: { mac: string; start: string }) {
  const traffic = useQuery({
    queryKey: ["traffic", start, undefined, "remote", mac],
    queryFn: () => api.traffic(start, undefined, "remote", mac),
    refetchInterval: 60_000,
  });
  const remotes = useQuery({
    queryKey: ["deviceTraffic", mac],
    queryFn: () => api.deviceTraffic(mac, 24),
    enabled: !!traffic.data?.captured,
  });
  const live = useLive(!!traffic.data?.captured);
  const data = traffic.data;
  if (!data) return null;
  if (!data.captured) return null; // the History page explains how to set capture up
  const now = live?.devices[mac];
  return (
    <section className="card">
      <h2>Traffic</h2>
      <p className="live-rate">
        Now: {now ? `↓ ${rate(now[1])}  ↑ ${rate(now[0])}` : "idle"}
        {live && <span className="muted small"> · updated {ago(live.time)}</span>}
      </p>
      <Legend up={data.bytes_up} down={data.bytes_down} note={`per ${bucketName(data.bucket_seconds)}`} />
      {data.bytes_up + data.bytes_down > 0 && <Chart data={data} series={TRAFFIC_SERIES} />}
      {remotes.data && remotes.data.remotes.length > 0 && (
        <>
          <h3>Where it went, last 24 hours</h3>
          <div className="table-wrap">
            <table className="stack">
              <thead>
                <tr>
                  <th>Remote end</th>
                  <th>Port</th>
                  <th>Application</th>
                  <th>Down</th>
                  <th>Up</th>
                  <th>Last</th>
                </tr>
              </thead>
              <tbody>
                {remotes.data.remotes.map((r) => (
                  <tr key={`${r.ip}-${r.port}-${r.protocol}`}>
                    <td>
                      {r.remote}
                      {r.remote !== r.ip && <div className="sub mono">{r.ip}</div>}
                      {r.outbound === false && <div className="sub">connected to this device</div>}
                    </td>
                    <td data-label="Port">
                      {r.port}/{r.protocol}
                    </td>
                    <td data-label="Application">{r.app ?? "—"}</td>
                    <td data-label="Down">{bytes(r.bytes_down)}</td>
                    <td data-label="Up">{bytes(r.bytes_up)}</td>
                    <td data-label="Last">
                      <time title={dateTime(r.last)}>{ago(r.last)}</time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

const CAPTURE_STATUS: Record<PacketCapture["status"], string> = {
  pending: "starting",
  running: "capturing",
  done: "finished",
  stopped: "stopped",
  failed: "failed",
};

/** Packet captures of the device: start one (time- and size-bounded), stop it, download it. */
export function CapturesCard({ mac }: { mac: string }) {
  const client = useQueryClient();
  const state = useQuery({
    queryKey: ["captures", mac],
    queryFn: () => api.captures(mac),
    refetchInterval: (q) => (q.state.data?.captures.some((c) => c.status === "pending" || c.status === "running") ? 3000 : 30_000),
  });
  const [minutes, setMinutes] = useState(5);
  const [megabytes, setMegabytes] = useState(20);
  const refresh = () => client.invalidateQueries({ queryKey: ["captures", mac] });
  const start = useMutation({ mutationFn: () => api.startCapture(mac, minutes, megabytes), onSuccess: refresh });
  const stop = useMutation({ mutationFn: (id: number) => api.stopCapture(mac, id), onSuccess: refresh });
  const data = state.data;
  if (!data || (!data.available && data.captures.length === 0)) return null;
  const running = data.captures.find((c) => c.status === "pending" || c.status === "running");
  return (
    <section className="card">
      <h2>Packet capture</h2>
      {!data.available && <p className="muted">{data.reason}</p>}
      {data.available && !running && (
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            start.mutate();
          }}
        >
          <label className="inline-field">
            Up to
            <input
              type="number"
              min={1}
              max={data.max_minutes}
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
            />
            minutes,
          </label>
          <label className="inline-field">
            keeping the last
            <input
              type="number"
              min={1}
              max={data.max_megabytes}
              value={megabytes}
              onChange={(e) => setMegabytes(Number(e.target.value))}
            />
            MB
          </label>
          <button type="submit" disabled={start.isPending}>
            Start capture
          </button>
        </form>
      )}
      {start.error && <p className="error">{start.error.message}</p>}
      <p className="muted small">
        Every packet to and from this device, as a .pcap file for Wireshark. Captures hold the newest packets once full,
        and the oldest captures' files are deleted.
      </p>
      {data.captures.length > 0 && (
        <ul className="captures">
          {data.captures.map((c) => (
            <li key={c.id}>
              <span>
                <time title={dateTime(c.requested_at)}>{ago(c.requested_at)}</time> · {CAPTURE_STATUS[c.status]}
                {c.bytes > 0 && ` · ${bytes(c.bytes)}`}
                {c.packets !== null && ` · ${c.packets.toLocaleString()} packets`}
                {c.error && <span className="muted"> · {c.error}</span>}
              </span>
              <span className="exports-links">
                {(c.status === "pending" || c.status === "running") && (
                  <button type="button" className="plain" onClick={() => stop.mutate(c.id)}>
                    Stop
                  </button>
                )}
                {c.downloadable && (
                  <a href={api.captureUrl(mac, c.id)} download>
                    Download
                  </a>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
