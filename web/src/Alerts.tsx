import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  type Alert,
  type AlertAction,
  type AlertKind,
  type AlertKindInfo,
  type AlertRule,
  api,
  type Severity,
} from "./api";
import { BlockButton } from "./Pihole";
import { ago, dateTime } from "./ui";

export const ACTION_LABELS: Record<AlertAction, string> = {
  notify: "Notify",
  record: "Record only",
  mute: "Mute",
};

const SEVERITY_TAGS: Record<Severity, string> = {
  critical: "tag bad",
  warning: "tag warn",
  info: "tag quiet",
};

const NOTIFY_LABELS: Record<NonNullable<Alert["notify"]>, string> = {
  pending: "notification waiting",
  sent: "notified",
  duplicate: "repeat, not notified",
  failed: "notification failed",
};

const SNOOZES = [
  { label: "for a day", days: 1 },
  { label: "for a week", days: 7 },
  { label: "always", days: 0 },
];

/** Every alert, newest first, with what each kind does by default and where notifications go. */
export function AlertsPage() {
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      <h1 className="title">Alerts</h1>
      <AlertList />
      <RulesCard />
      <NotificationsCard />
    </article>
  );
}

function invalidateAlerts(client: ReturnType<typeof useQueryClient>) {
  void client.invalidateQueries({ queryKey: ["alerts"] });
  void client.invalidateQueries({ queryKey: ["alertSummary"] });
}

/** Alerts, all or one device's, open or all, with acknowledge and mute. */
export function AlertList({ mac }: { mac?: string }) {
  const client = useQueryClient();
  const [state, setState] = useState<"open" | "all">("open");
  const pages = useInfiniteQuery({
    queryKey: ["alerts", state, mac],
    queryFn: ({ pageParam }) => api.alerts(state, mac, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.items.length === 50 ? last.items[last.items.length - 1].id : undefined),
  });
  const ackAll = useMutation({
    mutationFn: () => api.acknowledgeAll(mac),
    onSuccess: () => invalidateAlerts(client),
  });
  const items = pages.data?.pages.flatMap((p) => p.items) ?? [];
  const open = mac ? items.filter((a) => !a.acknowledged_at).length : (pages.data?.pages[0].open ?? 0);
  return (
    <section className="card">
      <div className="row toolbar-row">
        <h2>{mac ? "Alerts" : open ? `${open} open` : "Nothing open"}</h2>
        <div className="segmented" role="group" aria-label="Which alerts">
          {(["open", "all"] as const).map((s) => (
            <button key={s} type="button" className={state === s ? "on" : ""} aria-pressed={state === s} onClick={() => setState(s)}>
              {s === "open" ? "Open" : "All"}
            </button>
          ))}
        </div>
        {open > 0 && (
          <button type="button" disabled={ackAll.isPending} onClick={() => ackAll.mutate()}>
            Acknowledge all
          </button>
        )}
      </div>
      {pages.error && <p className="error">{pages.error.message}</p>}
      {!pages.data && !pages.error && <p className="muted">Loading…</p>}
      {pages.data && items.length === 0 && (
        <p className="muted">{state === "open" ? "No open alerts." : "No alerts yet."}</p>
      )}
      {items.length > 0 && (
        <ul className="alerts">
          {items.map((a) => (
            <AlertRow key={a.id} alert={a} showDevice={!mac} />
          ))}
        </ul>
      )}
      {pages.hasNextPage && (
        <button type="button" disabled={pages.isFetchingNextPage} onClick={() => void pages.fetchNextPage()}>
          Show more
        </button>
      )}
    </section>
  );
}

function AlertRow({ alert: a, showDevice }: { alert: Alert; showDevice: boolean }) {
  const client = useQueryClient();
  const ack = useMutation({
    mutationFn: () => api.acknowledge(a.id, !a.acknowledged_at),
    onSuccess: () => invalidateAlerts(client),
  });
  const mute = useMutation({
    mutationFn: (days: number) =>
      api.saveAlertRule({
        mac: a.mac,
        kind: a.kind,
        action: "mute",
        until: days ? new Date(Date.now() + days * 86400_000).toISOString() : null,
      }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["alertRules"] }),
  });
  return (
    <li className={a.acknowledged_at ? "alert done" : "alert"}>
      <div className="alert-main">
        <span className={SEVERITY_TAGS[a.severity]}>{a.severity}</span>
        <span className="alert-message">{a.message}</span>
      </div>
      <div className="alert-meta small muted">
        <time title={dateTime(a.time)}>{ago(a.time)}</time>
        {showDevice && a.mac && (
          <a href={`#/devices/${a.mac}`}>{a.device ?? a.mac}</a>
        )}
        {a.notify && <span>{NOTIFY_LABELS[a.notify]}</span>}
        {a.acknowledged_at && <span>acknowledged {ago(a.acknowledged_at)}</span>}
      </div>
      <div className="alert-actions">
        <button type="button" className="plain small link-button" disabled={ack.isPending} onClick={() => ack.mutate()}>
          {a.acknowledged_at ? "Reopen" : "Acknowledge"}
        </button>
        <select
          className="small"
          value=""
          disabled={mute.isPending}
          onChange={(e) => e.target.value && mute.mutate(Number(e.target.value))}
          aria-label={`Mute alerts like this${a.device ? ` for ${a.device}` : ""}`}
        >
          <option value="">{mute.isSuccess ? "Muted" : a.mac ? "Mute for this device…" : "Mute…"}</option>
          {SNOOZES.map((s) => (
            <option key={s.days} value={s.days || "0"}>
              {s.label}
            </option>
          ))}
        </select>
        {a.kind === "blocklist_hit" && a.details.domain && <BlockButton domain={a.details.domain} />}
      </div>
      {(ack.error || mute.error) && <p className="error small">{(ack.error ?? mute.error)?.message}</p>}
    </li>
  );
}

function ruleFor(rules: AlertRule[], mac: string | null, kind: AlertKind | null): AlertRule | undefined {
  return rules.find((r) => r.mac === mac && r.kind === kind);
}

/** What a kind does without the rule being edited: the next most specific rule, or its default. */
function inherited(kind: AlertKindInfo, rules: AlertRule[], mac: string | null): string {
  if (mac) {
    const device = ruleFor(rules, mac, null);
    if (device) return `${ACTION_LABELS[device.action]}, as all this device's alerts`;
  }
  const global = mac ? ruleFor(rules, null, kind.kind) : undefined;
  if (global) return `${ACTION_LABELS[global.action]}, as every device`;
  return ACTION_LABELS[kind.default_action] + (kind.note ? `; ${kind.note.toLowerCase()}` : "");
}

/** What each alert kind does: for every device, or (with ``mac``) for one. */
export function RulesTable({ mac }: { mac?: string }) {
  const client = useQueryClient();
  const rules = useQuery({ queryKey: ["alertRules", mac], queryFn: () => api.alertRules(mac) });
  const save = useMutation({
    mutationFn: async ({ kind, action, existing }: { kind: AlertKind | null; action: string; existing?: AlertRule }) => {
      if (action) await api.saveAlertRule({ mac: mac ?? null, kind, action: action as AlertAction, until: null });
      else if (existing) await api.deleteAlertRule(existing.id);
    },
    onSuccess: () => void client.invalidateQueries({ queryKey: ["alertRules"] }),
  });
  if (rules.error) return <p className="error">{rules.error.message}</p>;
  if (!rules.data) return <p className="muted">Loading…</p>;
  const { kinds, rules: all } = rules.data;
  const me = mac ?? null;
  const select = (kind: AlertKind | null, fallback: string, label: string) => {
    const existing = ruleFor(all, me, kind);
    const snoozed = existing?.until && new Date(existing.until);
    return (
      <>
        <select
          value={existing?.action ?? ""}
          disabled={save.isPending}
          onChange={(e) => save.mutate({ kind, action: e.target.value, existing })}
          aria-label={label}
        >
          <option value="">Default ({fallback})</option>
          {(Object.keys(ACTION_LABELS) as AlertAction[]).map((a) => (
            <option key={a} value={a}>
              {ACTION_LABELS[a]}
            </option>
          ))}
        </select>
        {snoozed && <div className="sub">until {snoozed.toLocaleString()}</div>}
      </>
    );
  };
  return (
    <>
      {mac && (
        <div className="row toolbar-row">
          <span>All alerts for this device:</span>
          {select(null, "per kind, below", "All alerts for this device")}
        </div>
      )}
      <div className="table-wrap">
        <table className="stack">
          <thead>
            <tr>
              <th>Alert</th>
              <th>Severity</th>
              <th>{mac ? "For this device" : "For every device"}</th>
            </tr>
          </thead>
          <tbody>
            {kinds.map((k) => (
              <tr key={k.kind}>
                <td>{k.label}</td>
                <td data-label="Severity">
                  <span className={SEVERITY_TAGS[k.severity]}>{k.severity}</span>
                </td>
                <td data-label={mac ? "This device" : "Every device"}>
                  {select(k.kind, inherited(k, all, me), `${k.label}: what to do`)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {save.error && <p className="error">{save.error.message}</p>}
    </>
  );
}

function RulesCard() {
  return (
    <section className="card">
      <h2>What each alert does</h2>
      <p className="muted small">
        Notify sends it to your notification services, record only keeps it here, mute drops it. A device's own
        rules (on its page) win over these.
      </p>
      <RulesTable />
    </section>
  );
}

function NotificationsCard() {
  const n = useQuery({ queryKey: ["notifications"], queryFn: api.notifications });
  const test = useMutation({ mutationFn: api.testNotification });
  const d = n.data;
  return (
    <section className="card">
      <h2>Notifications</h2>
      {n.error && <p className="error">{n.error.message}</p>}
      {d && !d.configured && (
        <p className="muted">
          Not set up. Set NETMAP_APPRISE_URLS to one or more{" "}
          <a href="https://github.com/caronc/apprise/wiki" target="_blank" rel="noreferrer">
            Apprise URLs
          </a>{" "}
          (like ntfy://your-topic, discord://…, or mailtos://…) to get alerts on your phone.
        </p>
      )}
      {d?.configured && (
        <>
          <p>
            Sending to {d.services} service{d.services === 1 ? "" : "s"}, at most {d.max_per_hour} notifications an
            hour; repeats within an hour are skipped.
            {d.last_sent ? ` Last sent ${ago(d.last_sent)}.` : " Nothing sent yet."}
            {d.pending ? ` ${d.pending} waiting.` : ""}
          </p>
          {d.services === 0 && <p className="error">None of NETMAP_APPRISE_URLS is a URL Apprise understands.</p>}
          {d.problem && <p className="error">{d.problem}</p>}
          {!d.link && (
            <p className="muted small">Set NETMAP_PUBLIC_URL to put a link back to this page in each notification.</p>
          )}
          <div className="row">
            <button type="button" disabled={test.isPending} onClick={() => test.mutate()}>
              {test.isPending ? "Sending…" : "Send a test notification"}
            </button>
            {test.data && <span className={test.data.sent ? "muted" : "error"}>{test.data.message}</span>}
            {test.error && <span className="error">{test.error.message}</span>}
          </div>
        </>
      )}
    </section>
  );
}
