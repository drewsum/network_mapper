import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type DeviceDetail as Detail, type DeviceEvent, deviceName } from "./api";
import { ago, CategorySelect, dateTime, EditableText, Status, useUpdateDevice } from "./ui";

const DETAIL_LABELS: Record<string, string> = {
  friendly_name: "Friendly name",
  manufacturer: "Manufacturer",
  model: "Model",
  model_number: "Model number",
  device_type: "UPnP type",
  fingerprint: "DHCP fingerprint",
  vendor_class: "DHCP vendor class",
};

export function DeviceDetailPage({ mac }: { mac: string }) {
  const device = useQuery({ queryKey: ["device", mac], queryFn: () => api.device(mac) });

  if (device.error) {
    return (
      <p className="error">
        Couldn't load {mac}: {device.error.message}. <a href="#/">Back to devices</a>
      </p>
    );
  }
  if (!device.data) return <p className="muted">Loading…</p>;
  const d = device.data;
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      {d.merged_into && (
        <p className="notice">
          This MAC was merged into <a href={`#/devices/${d.merged_into}`}>{d.merged_into}</a>; its
          history lives there now.
        </p>
      )}
      <Header device={d} />
      <div className="grid">
        <Facts device={d} />
        <Notes device={d} />
      </div>
      <Names device={d} />
      <Addresses device={d} />
      <Ports mac={d.mac} />
      <Forwards mac={d.mac} />
      <History mac={d.mac} />
      <section className="card muted">
        <h2>DNS activity</h2>
        <p>
          Domains contacted, top organizations and countries, and the activity chart arrive with
          the Pi-hole integration (M2) and enrichment (M3).
        </p>
      </section>
      {!d.merged_into && <Merge device={d} />}
    </article>
  );
}

function Header({ device: d }: { device: Detail }) {
  const update = useUpdateDevice(d.mac);
  const editable = !d.merged_into;
  return (
    <header className="detail-head">
      <div>
        <h1>
          {editable ? (
            <EditableText
              value={d.label}
              placeholder={deviceName({ ...d, label: null })}
              onSave={(label) => update.mutate({ label })}
              className="title"
            />
          ) : (
            deviceName(d)
          )}
        </h1>
        {d.label && d.hostname && <div className="sub">calls itself {d.hostname}</div>}
      </div>
      <div className="head-controls">
        <Status online={d.online} lastSeen={d.last_seen} />
        {editable && (
          <>
            <CategorySelect value={d.category} onChange={(category) => update.mutate({ category })} />
            <label className="check">
              <input
                type="checkbox"
                checked={d.is_iot}
                onChange={(e) => update.mutate({ is_iot: e.target.checked })}
              />
              IoT
            </label>
          </>
        )}
      </div>
      {update.error && <p className="error">{update.error.message}</p>}
    </header>
  );
}

function Facts({ device: d }: { device: Detail }) {
  const rows: [string, React.ReactNode][] = [
    ["MAC", <span className="mono">{d.mac}</span>],
    ["IP", <span className="mono">{d.ip ?? "—"}</span>],
    ["Vendor", d.is_randomized_mac ? "randomized (private) MAC" : (d.vendor ?? "unknown")],
    ["Hostname", d.hostname ? `${d.hostname} (from ${d.hostname_source})` : "—"],
    ["First seen", dateTime(d.first_seen)],
    ["Last seen", `${dateTime(d.last_seen)} (${ago(d.last_seen)})`],
  ];
  if (d.aliases.length) rows.push(["Also seen as", <span className="mono">{d.aliases.join(", ")}</span>]);
  return (
    <section className="card">
      <h2>Device</h2>
      <dl className="facts">
        {rows.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function Notes({ device: d }: { device: Detail }) {
  const update = useUpdateDevice(d.mac);
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? d.notes ?? "";
  return (
    <section className="card">
      <h2>Notes</h2>
      <textarea
        value={value}
        rows={5}
        placeholder="Where it is, what it's for…"
        disabled={!!d.merged_into}
        onChange={(e) => setDraft(e.target.value)}
      />
      {draft !== null && draft !== (d.notes ?? "") && (
        <div className="row">
          <button
            type="button"
            disabled={update.isPending}
            onClick={() => update.mutate({ notes: draft }, { onSuccess: () => setDraft(null) })}
          >
            Save notes
          </button>
          <button type="button" className="plain" onClick={() => setDraft(null)}>
            Cancel
          </button>
        </div>
      )}
      {update.error && <p className="error">{update.error.message}</p>}
    </section>
  );
}

function Names({ device: d }: { device: Detail }) {
  if (!d.names.length) return null;
  return (
    <section className="card">
      <h2>What it calls itself</h2>
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Name</th>
            <th>Details</th>
            <th>Last heard</th>
          </tr>
        </thead>
        <tbody>
          {d.names.map((n) => (
            <tr key={n.source} className={n.source === d.hostname_source ? "chosen" : ""}>
              <td>
                {n.source}
                {n.source === d.hostname_source && <span className="tag">shown</span>}
              </td>
              <td>{n.name ?? "—"}</td>
              <td className="small">
                {Object.entries(n.details ?? {})
                  .filter(([k]) => k !== "friendly_name")
                  .map(([k, v]) => (
                    <div key={k}>
                      <span className="muted">{DETAIL_LABELS[k] ?? k}:</span> {v}
                    </div>
                  ))}
              </td>
              <td title={dateTime(n.last_seen)}>{ago(n.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Addresses({ device: d }: { device: Detail }) {
  return (
    <section className="card">
      <h2>IP addresses</h2>
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>First seen</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {d.ips.map((ip) => (
            <tr key={ip.ip}>
              <td className="mono">{ip.ip}</td>
              <td>{dateTime(ip.first_seen)}</td>
              <td title={dateTime(ip.last_seen)}>{ago(ip.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Ports({ mac }: { mac: string }) {
  const ports = useQuery({ queryKey: ["ports", mac], queryFn: () => api.ports(mac) });
  return (
    <section className="card">
      <h2>Open ports</h2>
      {ports.data?.length === 0 && <p className="muted">No open ports found (or not scanned yet).</p>}
      {!!ports.data?.length && (
        <table>
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Banner</th>
              <th>Since</th>
            </tr>
          </thead>
          <tbody>
            {ports.data.map((p) => (
              <tr key={`${p.port}/${p.protocol}`} className={p.open ? "" : "offline"}>
                <td className="mono">
                  {p.port}/{p.protocol}
                  {!p.open && <span className="tag">closed</span>}
                </td>
                <td>{p.service ?? "—"}</td>
                <td className="mono small">{p.banner ?? ""}</td>
                <td title={dateTime(p.first_seen)}>{ago(p.first_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Forwards({ mac }: { mac: string }) {
  const mappings = useQuery({ queryKey: ["upnp"], queryFn: api.upnpMappings });
  const mine = mappings.data?.filter((m) => m.mac === mac) ?? [];
  if (!mine.length) return null;
  return (
    <section className="card">
      <h2>Router port forwards (UPnP)</h2>
      <table>
        <thead>
          <tr>
            <th>External</th>
            <th>To</th>
            <th>Description</th>
            <th>Since</th>
          </tr>
        </thead>
        <tbody>
          {mine.map((m) => (
            <tr key={`${m.external_port}/${m.protocol}`} className={m.active ? "" : "offline"}>
              <td className="mono">
                {m.external_port}/{m.protocol}
                {!m.active && <span className="tag">gone</span>}
              </td>
              <td className="mono">
                {m.internal_ip}:{m.internal_port}
              </td>
              <td>{m.description ?? "—"}</td>
              <td title={dateTime(m.first_seen)}>{ago(m.first_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function describe(e: DeviceEvent): string {
  switch (e.kind) {
    case "new_device":
      return `First seen${e.ip ? ` at ${e.ip}` : ""}`;
    case "online":
      return `Came online${e.ip ? ` at ${e.ip}` : ""}`;
    case "offline":
      return "Went offline";
    case "new_ip":
      return `New IP address ${e.ip}`;
    case "port_opened":
      return `Port ${e.port}/${e.protocol} opened`;
    case "port_closed":
      return `Port ${e.port}/${e.protocol} closed`;
  }
}

function History({ mac }: { mac: string }) {
  const events = useInfiniteQuery({
    queryKey: ["events", mac],
    queryFn: ({ pageParam }) => api.events(mac, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => (last.length === 50 ? last[last.length - 1].time : undefined),
  });
  const all = events.data?.pages.flat() ?? [];
  return (
    <section className="card">
      <h2>History</h2>
      <ol className="timeline">
        {all.map((e, i) => (
          <li key={`${e.time}-${e.kind}-${i}`} className={`ev ${e.kind}`}>
            <time dateTime={e.time}>{dateTime(e.time)}</time> {describe(e)}
          </li>
        ))}
      </ol>
      {events.hasNextPage && (
        <button type="button" disabled={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()}>
          Load older
        </button>
      )}
    </section>
  );
}

function Merge({ device: d }: { device: Detail }) {
  const client = useQueryClient();
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.devices });
  const [into, setInto] = useState("");
  const [confirming, setConfirming] = useState(false);
  const merge = useMutation({
    mutationFn: () => api.mergeDevice(d.mac, into),
    onSuccess: (target) => {
      void client.invalidateQueries();
      window.location.hash = `#/devices/${target.mac}`;
    },
  });
  const others = (devices.data ?? [])
    .filter((o) => o.mac !== d.mac)
    .sort((a, b) => deviceName(a).localeCompare(deviceName(b)));
  return (
    <section className="card">
      <h2>Same device as…</h2>
      <p className="muted">
        If this is a device you already know under another MAC (phones and laptops switch to new
        private addresses), merge it: its history moves over and this MAC counts as that device
        from now on.
      </p>
      <div className="row">
        <select
          value={into}
          onChange={(e) => {
            setInto(e.target.value);
            setConfirming(false);
          }}
          aria-label="Device to merge into"
        >
          <option value="">Choose a device…</option>
          {others.map((o) => (
            <option key={o.mac} value={o.mac}>
              {deviceName(o)} ({o.mac})
            </option>
          ))}
        </select>
        {!confirming ? (
          <button type="button" disabled={!into} onClick={() => setConfirming(true)}>
            Merge into it
          </button>
        ) : (
          <button type="button" className="danger" disabled={merge.isPending} onClick={() => merge.mutate()}>
            Yes, merge {deviceName(d)} into it
          </button>
        )}
      </div>
      {merge.error && <p className="error">{merge.error.message}</p>}
    </section>
  );
}
