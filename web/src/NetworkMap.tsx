import { useQuery } from "@tanstack/react-query";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, CATEGORIES, type Category, deviceName, type MapDevice } from "./api";

const GROUP_LABELS: Record<Category, string> = {
  iot: "IoT",
  phone: "Phones",
  computer: "Computers",
  infrastructure: "Infrastructure",
  media: "Media",
  unknown: "Unknown",
};
const SPACING = 104; // between devices in a group, wide enough for their labels
const HUB = "hub";
const REFRESH_MS = 15_000;

/** Node diameter from lookups in the last hour: idle devices stay small, busy ones grow. */
function size(queries: number): number {
  return Math.min(56, 18 + 4 * Math.sqrt(queries));
}

/** Groups around the hub, each a grid of its devices sorted by name, so a refresh or a new
 * device moves as little as possible. */
function layout(devices: MapDevice[], router: string | null): ElementDefinition[] {
  const groups = CATEGORIES.map((c) => ({
    category: c,
    members: devices
      .filter((d) => d.category === c && d.mac !== router)
      .sort((a, b) => deviceName(a).localeCompare(deviceName(b))),
  })).filter((g) => g.members.length > 0);
  // A group's diagonal bounds it at any angle around the hub, so the ring of groups is
  // sized from those: long enough to fit them all, and far enough out to clear the hub.
  const diagonals = groups.map((g) => {
    const cols = Math.ceil(Math.sqrt(g.members.length));
    return Math.hypot(cols, Math.ceil(g.members.length / cols)) * SPACING;
  });
  const radius = Math.max(
    260,
    (diagonals.reduce((a, b) => a + b, 0) + groups.length * 40) / (2 * Math.PI),
    Math.max(0, ...diagonals) / 2 + 120,
  );
  const hub = devices.find((d) => d.mac === router);
  const elements: ElementDefinition[] = [
    {
      group: "nodes",
      data: hub
        ? { id: HUB, label: deviceName(hub), mac: hub.mac, size: 64, online: hub.online ? 1 : 0, kind: "hub" }
        : { id: HUB, label: "Network", size: 64, online: 1, kind: "hub" },
      position: { x: 0, y: 0 },
    },
  ];
  groups.forEach((g, i) => {
    const angle = (2 * Math.PI * i) / groups.length - Math.PI / 2;
    const cols = Math.ceil(Math.sqrt(g.members.length));
    const rows = Math.ceil(g.members.length / cols);
    const cx = radius * Math.cos(angle);
    const cy = radius * Math.sin(angle);
    const online = g.members.filter((d) => d.online).length;
    elements.push({
      group: "nodes",
      data: { id: `group-${g.category}`, label: `${GROUP_LABELS[g.category]} · ${online}/${g.members.length} online`, kind: "group" },
    });
    elements.push({
      group: "edges",
      data: { id: `edge-${g.category}`, source: HUB, target: `group-${g.category}` },
    });
    g.members.forEach((d, j) => {
      elements.push({
        group: "nodes",
        data: {
          id: d.mac,
          mac: d.mac,
          parent: `group-${g.category}`,
          label: deviceName(d),
          size: size(d.queries),
          online: d.online ? 1 : 0,
          blocked: d.blocked > 0 ? 1 : 0,
          kind: "device",
        },
        position: {
          x: cx + ((j % cols) - (cols - 1) / 2) * SPACING,
          y: cy + (Math.floor(j / cols) - (rows - 1) / 2) * SPACING,
        },
      });
    });
  });
  return elements;
}

function css(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function stylesheet(): cytoscape.StylesheetJson {
  const [fg, muted, line, card, accent, blocked] = [
    css("--fg"), css("--muted"), css("--line"), css("--card"), css("--chart-allowed"), css("--chart-blocked"),
  ];
  return [
    {
      selector: "node",
      style: {
        width: "data(size)",
        height: "data(size)",
        label: "data(label)",
        "font-size": 10,
        color: fg,
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-max-width": "92px",
        "text-wrap": "ellipsis",
        "background-color": accent,
        "border-width": 2,
        "border-color": card,
      },
    },
    { selector: "node[online = 0]", style: { "background-color": line, "border-color": muted, "border-style": "dashed", color: muted } },
    // A red ring: Pi-hole blocked some of its lookups in the last hour.
    { selector: "node[blocked = 1][online = 1]", style: { "border-color": blocked, "border-width": 3 } },
    { selector: 'node[kind = "hub"]', style: { "font-size": 12, "font-weight": 600, shape: "round-rectangle" } },
    {
      selector: 'node[kind = "group"]',
      style: {
        "background-color": card,
        "background-opacity": 0.6,
        "border-color": line,
        "border-width": 1,
        "border-style": "solid",
        shape: "round-rectangle",
        padding: "18px",
        label: "data(label)",
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-y": -4,
        "text-max-width": "1000px",
        "text-wrap": "none",
        "font-size": 12,
        color: muted,
      },
    },
    { selector: "edge", style: { width: 1, "line-color": line, "curve-style": "straight" } },
    { selector: "node:selected", style: { "overlay-opacity": 0 } },
  ];
}

interface Hover {
  device: MapDevice;
  x: number;
  y: number;
  width: number; // of the map, to keep the tooltip inside it
}

export default function NetworkMapPage() {
  const map = useQuery({ queryKey: ["map"], queryFn: () => api.map(60), refetchInterval: REFRESH_MS });
  const [hidden, setHidden] = useState<Set<Category>>(new Set());
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [hover, setHover] = useState<Hover | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const fitted = useRef("");

  const data = map.data;
  const shown = useMemo(
    () => (data?.devices ?? []).filter((d) => !hidden.has(d.category) && (!onlineOnly || d.online || d.mac === data?.router)),
    [data, hidden, onlineOnly],
  );
  const byMac = useMemo(() => new Map((data?.devices ?? []).map((d) => [d.mac, d])), [data]);
  // The tooltip handler is bound once; it reads the latest devices through this ref.
  const byMacRef = useRef(byMac);
  useEffect(() => {
    byMacRef.current = byMac;
  }, [byMac]);

  useEffect(() => {
    if (!box.current) return;
    const instance = cytoscape({
      container: box.current,
      style: stylesheet(),
      layout: { name: "preset" },
      minZoom: 0.2,
      maxZoom: 3,
      autoungrabify: true,
      boxSelectionEnabled: false,
    });
    instance.on("tap", "node", (e) => {
      const mac = e.target.data("mac");
      if (mac) location.hash = `#/devices/${mac}`;
    });
    instance.on("mouseover", 'node[kind != "group"]', (e) => {
      const mac = e.target.data("mac");
      const p = e.target.renderedPosition();
      const width = box.current?.clientWidth ?? 0;
      setHover(mac ? { device: byMacRef.current.get(mac)!, x: p.x, y: p.y, width } : null);
      if (box.current) box.current.style.cursor = mac ? "pointer" : "";
    });
    instance.on("mouseout", "node", () => {
      setHover(null);
      if (box.current) box.current.style.cursor = "";
    });
    instance.on("viewport", () => setHover(null));
    const scheme = matchMedia("(prefers-color-scheme: dark)");
    const restyle = () => instance.style(stylesheet());
    scheme.addEventListener("change", restyle);
    cy.current = instance;
    return () => {
      scheme.removeEventListener("change", restyle);
      instance.destroy();
      cy.current = null;
    };
  }, []);

  // Live refresh: update nodes in place, keeping zoom and pan. Refit when the filter changes
  // or devices come or go, so none end up off screen.
  useEffect(() => {
    const instance = cy.current;
    if (!instance || !data) return;
    const elements = layout(shown, data.router);
    const ids = new Set(elements.map((e) => e.data.id));
    instance.batch(() => {
      instance.elements().filter((e) => !ids.has(e.id())).remove();
      for (const el of elements) {
        const existing = instance.getElementById(el.data.id!);
        if (existing.nonempty()) {
          existing.data(el.data);
          if (el.position) existing.position(el.position);
        } else {
          instance.add(el);
        }
      }
    });
    const key = `${[...hidden].sort().join(",")}|${onlineOnly}|${shown.length}`;
    if (fitted.current !== key) {
      instance.fit(undefined, 30);
      fitted.current = key;
    }
  }, [data, shown, hidden, onlineOnly]);

  const counts = useMemo(() => {
    const out = new Map<Category, number>();
    for (const d of data?.devices ?? []) out.set(d.category, (out.get(d.category) ?? 0) + 1);
    return out;
  }, [data]);
  const toggle = (c: Category) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });

  return (
    <article className="detail">
      <h1 className="title">Network map</h1>
      <div className="range-bar">
        <div className="chips" role="group" aria-label="Show categories">
          {CATEGORIES.filter((c) => counts.get(c)).map((c) => (
            <button
              key={c}
              type="button"
              className={hidden.has(c) ? "chip" : "chip on"}
              aria-pressed={!hidden.has(c)}
              onClick={() => toggle(c)}
            >
              {GROUP_LABELS[c]} {counts.get(c)}
            </button>
          ))}
        </div>
        <label className="muted small">
          <input type="checkbox" checked={onlineOnly} onChange={(e) => setOnlineOnly(e.target.checked)} /> Online only
        </label>
        <button type="button" className="plain" onClick={() => cy.current?.fit(undefined, 30)}>
          Fit
        </button>
      </div>
      <p className="legend">
        <span>
          <span className="swatch allowed" />
          Online
        </span>
        <span>
          <span className="swatch offline" />
          Offline
        </span>
        <span>
          <span className="swatch ring" />
          Pi-hole blocked some lookups
        </span>
        <span>Size: DNS lookups in the last hour. Updates every 15 seconds; click a device to open it.</span>
      </p>
      {map.error && <p className="error">{map.error.message}</p>}
      <div className="network-map card">
        <div ref={box} className="cy" role="img" aria-label="Map of devices around the router, grouped by category" />
        {hover?.device && (
          <div
            className="tooltip"
            style={{
              top: hover.y + 14,
              // Left of the pointer when there's no room to its right.
              ...(hover.x + 280 > hover.width
                ? { right: hover.width - hover.x + 14 }
                : { left: hover.x + 14 }),
            }}
          >
            <div>
              <strong>{deviceName(hover.device)}</strong>
            </div>
            <div className="muted">{hover.device.ip ?? "no IP"} · {hover.device.online ? "online" : "offline"}</div>
            <div>
              {hover.device.queries.toLocaleString()} lookups in the last hour
              {hover.device.blocked ? `, ${hover.device.blocked.toLocaleString()} blocked` : ""}
            </div>
          </div>
        )}
      </div>
    </article>
  );
}
