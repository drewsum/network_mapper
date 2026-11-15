import { useQuery } from "@tanstack/react-query";
import { HeatmapChart, SankeyChart } from "echarts/charts";
import { GridComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef, useState } from "react";
import { api, type Flows } from "./api";
import { countryName } from "./ui";

echarts.use([SankeyChart, HeatmapChart, TooltipComponent, VisualMapComponent, GridComponent, CanvasRenderer]);

const DARK = matchMedia("(prefers-color-scheme: dark)");

/** Chart colors, checked for colorblind separation and contrast on --card in each mode. */
function colors() {
  const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const dark = DARK.matches;
  return {
    fg: css("--fg"),
    muted: css("--muted"),
    line: css("--line"),
    card: css("--card"),
    // Sankey columns: devices, organizations, countries.
    layers: dark
      ? { device: "#3987e5", organization: "#199e70", country: "#d95926" }
      : { device: "#2a78d6", organization: "#1baf7a", country: "#eb6834" },
    // Heatmap: one hue, faint to strong.
    ramp: dark ? ["#1d3557", "#3987e5", "#b7d3f6"] : ["#cde2fb", "#2a78d6", "#104281"],
  };
}

type Colors = ReturnType<typeof colors>;

/** An ECharts instance on a div, resized with it, redrawn when ``data`` changes or the
 * color scheme flips. */
function useChart<T>(data: T | undefined, build: (data: T, c: Colors) => echarts.EChartsCoreOption) {
  const ref = useRef<HTMLDivElement>(null);
  const builder = useRef(build);
  useEffect(() => {
    builder.current = build;
  });
  const [scheme, setScheme] = useState(DARK.matches);
  useEffect(() => {
    const flip = () => setScheme(DARK.matches);
    DARK.addEventListener("change", flip);
    return () => DARK.removeEventListener("change", flip);
  }, []);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const chart = echarts.init(el);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(el);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, []);
  useEffect(() => {
    const el = ref.current;
    const chart = el && echarts.getInstanceByDom(el);
    if (chart && data !== undefined) chart.setOption(builder.current(data, colors()), { notMerge: true });
  }, [data, scheme]);
  return ref;
}

function sankeyOption(data: Flows, c: Colors): echarts.EChartsCoreOption {
  const label = (layer: string, text: string) =>
    layer === "country" && text.length === 2 ? countryName(text) : text;
  return {
    tooltip: {
      trigger: "item",
      backgroundColor: c.card,
      borderColor: c.line,
      textStyle: { color: c.fg, fontSize: 12 },
      formatter: (p: { dataType: string; data: { label?: string; layer?: string; value: number; sourceLabel?: string; targetLabel?: string } }) =>
        p.dataType === "edge"
          ? `${p.data.sourceLabel} → ${p.data.targetLabel}<br/>${p.data.value.toLocaleString()} lookups`
          : `${label(p.data.layer!, p.data.label!)}<br/>${p.data.value.toLocaleString()} lookups`,
    },
    series: [
      {
        type: "sankey",
        left: 8,
        right: 140,
        top: 8,
        bottom: 8,
        // Wide enough for a label even beside a node too thin to see.
        nodeGap: 18,
        nodeWidth: 12,
        layoutIterations: 32,
        draggable: false,
        emphasis: { focus: "adjacency" },
        label: { color: c.fg, fontSize: 12, formatter: (p: { data: { label: string; layer: string } }) => label(p.data.layer, p.data.label) },
        lineStyle: { color: "source", opacity: 0.25, curveness: 0.5 },
        itemStyle: { borderWidth: 0 },
        data: data.nodes.map((n) => ({
          name: n.id,
          label: n.label,
          layer: n.layer,
          value: n.queries,
          depth: { device: 0, organization: 1, country: 2 }[n.layer],
          itemStyle: { color: c.layers[n.layer] },
        })),
        links: data.links.map((l) => ({
          source: l.source,
          target: l.target,
          value: l.queries,
          sourceLabel: data.nodes.find((n) => n.id === l.source)?.label,
          targetLabel: data.nodes.find((n) => n.id === l.target)?.label,
        })),
      },
    ],
  };
}

/** Device -> organization -> country lookups over the range. */
export function FlowsCard({ start }: { start: string }) {
  const [iotOnly, setIotOnly] = useState(true);
  const flows = useQuery({
    queryKey: ["flows", start, iotOnly],
    queryFn: () => api.flows(start, iotOnly),
  });
  const data = flows.data;
  const empty = data && data.nodes.length === 0;
  // Tall enough for the longest column's labels.
  const tallest = Math.max(
    0,
    ...(["device", "organization", "country"] as const).map((l) => data?.nodes.filter((n) => n.layer === l).length ?? 0),
  );
  const height = Math.max(320, Math.min(1000, tallest * 40));
  const ref = useChart(empty ? undefined : data, sankeyOption);
  return (
    <section className="card">
      <div className="row toolbar-row">
        <h2>Where lookups go</h2>
        <label className="muted small">
          <input type="checkbox" checked={iotOnly} onChange={(e) => setIotOnly(e.target.checked)} /> IoT devices only
        </label>
      </div>
      <div className="legend">
        <span>
          <span className="swatch layer-device" />
          Devices
        </span>
        <span>
          <span className="swatch layer-org" />
          Organizations
        </span>
        <span>
          <span className="swatch layer-country" />
          Countries
        </span>
        <span>Width: DNS lookups. Hover a band to follow it.</span>
      </div>
      {flows.error && <p className="error">{flows.error.message}</p>}
      {empty && (
        <p className="muted">
          No lookups {iotOnly ? "from IoT devices " : ""}in this range.
          {iotOnly ? " Mark devices as IoT on their pages, or show all devices." : ""}
        </p>
      )}
      <div ref={ref} style={{ height: empty ? 0 : height }} role="img" aria-label="Sankey diagram of DNS lookups from devices to organizations to countries" />
    </section>
  );
}

const DAY_RANGES = [7, 14, 30];

function hourLabel(h: number): string {
  const d = new Date(2000, 0, 1, h);
  return d.toLocaleTimeString(undefined, { hour: "numeric" });
}

/** Lookups per day and hour of day, in the viewer's time zone. The whole network, or one
 * device with ``mac``. */
export function HeatmapCard({ mac }: { mac?: string }) {
  const [days, setDays] = useState(7);
  const [start, setStart] = useState(() => daysAgo(7));
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const heat = useQuery({
    queryKey: ["heatmap", mac ?? "all", start, tz],
    queryFn: () => api.heatmap(start, tz, mac),
  });
  const data = heat.data;
  const ref = useChart(data, (data, c) => {
    const dayLabels = data.days.map((d) =>
      new Date(`${d}T12:00:00`).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }),
    );
    return {
      tooltip: {
        backgroundColor: c.card,
        borderColor: c.line,
        textStyle: { color: c.fg, fontSize: 12 },
        formatter: (p: { value: [number, number, number] }) =>
          `${dayLabels[p.value[1]]}, ${hourLabel(p.value[0])}–${hourLabel((p.value[0] + 1) % 24)}<br/>${p.value[2].toLocaleString()} lookups`,
      },
      grid: { left: 96, right: 16, top: 8, bottom: 64 },
      xAxis: {
        type: "category",
        data: Array.from({ length: 24 }, (_, h) => hourLabel(h)),
        axisLabel: { color: c.muted, fontSize: 11, interval: 2 },
        axisLine: { show: false },
        axisTick: { show: false },
        splitArea: { show: false },
      },
      yAxis: {
        type: "category",
        data: dayLabels,
        inverse: true,
        axisLabel: { color: c.muted, fontSize: 11 },
        axisLine: { show: false },
        axisTick: { show: false },
      },
      visualMap: {
        min: 0,
        max: Math.max(1, data.max),
        calculable: false,
        orient: "horizontal",
        left: "center",
        bottom: 4,
        itemHeight: 160,
        itemWidth: 10,
        text: ["More", "Fewer"],
        textStyle: { color: c.muted, fontSize: 11 },
        inRange: { color: c.ramp },
      },
      series: [
        {
          type: "heatmap",
          // x = hour, y = day; empty cells are left out, so the card shows through.
          data: data.cells.map(([day, hour, n]) => [hour, day, n]),
          itemStyle: { borderColor: c.card, borderWidth: 2, borderRadius: 3 },
          emphasis: { itemStyle: { borderColor: c.fg, borderWidth: 1 } },
        },
      ],
    };
  });
  const pick = (d: number) => {
    setDays(d);
    setStart(daysAgo(d));
  };
  return (
    <section className="card">
      <div className="row toolbar-row">
        <h2>When</h2>
        <div className="segmented" role="group" aria-label="Heatmap range">
          {DAY_RANGES.map((d) => (
            <button key={d} type="button" className={d === days ? "on" : ""} aria-pressed={d === days} onClick={() => pick(d)}>
              {d} days
            </button>
          ))}
        </div>
      </div>
      <p className="muted small">
        DNS lookups per hour{mac ? "" : " across the network"}, in your time zone ({tz}).
      </p>
      {heat.error && <p className="error">{heat.error.message}</p>}
      <div ref={ref} style={{ height: 80 + (data?.days.length ?? days) * 22 }} role="img" aria-label="Heatmap of DNS lookups by day and hour" />
    </section>
  );
}

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86400_000).toISOString();
}

const RANGES = [
  { label: "1 hour", hours: 1 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 24 * 7 },
  { label: "30 days", hours: 24 * 30 },
];

function rangeStart(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

/** The Flows page: the Sankey for a range, and the network-wide heatmap. */
export default function FlowsPage() {
  const [hours, setHours] = useState(24);
  const [start, setStart] = useState(() => rangeStart(24));
  return (
    <article className="detail">
      <h1 className="title">Flows</h1>
      <div className="range-bar">
        <div className="segmented" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              type="button"
              className={r.hours === hours ? "on" : ""}
              aria-pressed={r.hours === hours}
              onClick={() => {
                setHours(r.hours);
                setStart(rangeStart(r.hours));
              }}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>
      <FlowsCard start={start} />
      <HeatmapCard />
    </article>
  );
}
