import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useEffect, useState } from "react";
import { AlertsPage } from "./Alerts";
import { api, UNAUTHORIZED_EVENT } from "./api";
import { DeviceDetailPage } from "./DeviceDetail";
import { DeviceTable } from "./DeviceTable";
import { HistoryPage } from "./History";
import { Login } from "./Login";
import { OrganizationsPage } from "./Organizations";
import { ReportPage } from "./Report";
import { SystemPage } from "./System";

// Cytoscape is big; load it only when the map is opened.
const NetworkMapPage = lazy(() => import("./NetworkMap"));
// So is ECharts, for the Flows page.
const FlowsPage = lazy(() => import("./Insights"));

const DOCS_URL = "https://github.com/drewsum/network_mapper/blob/main/docs/visibility.md";
const BANNER_KEY = "netmap.limitsBannerDismissed";

/** Per-browser memory of the dismissed banner; storage can be blocked, so never rely on it. */
function bannerDismissed(): boolean {
  try {
    return localStorage.getItem(BANNER_KEY) === "1";
  } catch {
    return false;
  }
}

/** What v1 can't see: bytes, and lookups that skip Pi-hole. Dismissible, per browser; gone
 * once the capture service reports, since then netmap sees both. */
function LimitsBanner() {
  const [dismissed, setDismissed] = useState(bannerDismissed);
  const checks = useQuery({ queryKey: ["status"], queryFn: api.status });
  if (dismissed || checks.data?.some((c) => c.name === "capture")) return null;
  const dismiss = () => {
    try {
      localStorage.setItem(BANNER_KEY, "1");
    } catch {
      // Hidden for this visit only.
    }
    setDismissed(true);
  };
  return (
    <div className="notice banner" role="note">
      <p>
        netmap counts DNS lookups, not bytes, and it can't see devices that skip Pi-hole (hardcoded
        or encrypted DNS). <a href={DOCS_URL} target="_blank" rel="noreferrer">What it can and can't see</a>
      </p>
      <button type="button" className="plain" onClick={dismiss} aria-label="Dismiss">
        ✕
      </button>
    </div>
  );
}

const NAV = [
  ["#/map", "Map"],
  ["#/history", "History"],
  ["#/flows", "Flows"],
  ["#/domains", "Domains"],
  ["#/report", "IoT report"],
  ["#/alerts", "Alerts"],
  ["#/system", "System"],
];

const DEVICE_ROUTE = /^#\/devices\/([0-9a-f]{2}(?::[0-9a-f]{2}){5})$/i;

function useHash(): string {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const onChange = () => {
      setHash(window.location.hash);
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash;
}

export function App() {
  const client = useQueryClient();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const session = useQuery({ queryKey: ["session"], queryFn: api.session });
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: (s) => {
      client.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
      client.setQueryData(["session"], s);
    },
  });
  const hash = useHash();
  const device = DEVICE_ROUTE.exec(hash);
  const signedIn = !!session.data && (!session.data.auth_enabled || session.data.authenticated);
  const checks = useQuery({
    queryKey: ["status"],
    queryFn: api.status,
    enabled: signedIn,
    refetchInterval: 5 * 60_000,
  });
  const alerts = useQuery({
    queryKey: ["alertSummary"],
    queryFn: api.alertSummary,
    enabled: signedIn,
    refetchInterval: 60_000,
  });

  // Any 401 (an expired session, or a password change) means: show the login page.
  useEffect(() => {
    const onUnauthorized = () => void client.invalidateQueries({ queryKey: ["session"] });
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [client]);

  const s = session.data;
  const needsLogin = !!s && s.auth_enabled && !s.authenticated;
  let page;
  if (!s) page = session.error ? <p className="error">API unreachable.</p> : null;
  else if (needsLogin) page = <Login />;
  else if (device) page = <DeviceDetailPage key={device[1]} mac={device[1].toLowerCase()} />;
  else if (hash === "#/domains" || hash === "#/organizations") page = <OrganizationsPage />;
  else if (hash === "#/history") page = <HistoryPage />;
  else if (hash === "#/report") page = <ReportPage />;
  else if (hash === "#/alerts") page = <AlertsPage />;
  else if (hash === "#/system") page = <SystemPage />;
  else if (hash === "#/flows")
    page = (
      <Suspense fallback={<p className="muted">Loading…</p>}>
        <FlowsPage />
      </Suspense>
    );
  else if (hash === "#/map")
    page = (
      <Suspense fallback={<p className="muted">Loading…</p>}>
        <NetworkMapPage />
      </Suspense>
    );
  else page = <DeviceTable />;

  return (
    <main>
      <header className="app-head">
        <a href="#/" className="brand">
          Network Mapper
        </a>
        {signedIn && (
          <nav className="nav">
            {NAV.map(([href, label]) => (
              <a key={href} href={href} aria-current={hash === href ? "page" : undefined}>
                {label}
                {href === "#/alerts" && !!alerts.data?.open && (
                  <span className={alerts.data.critical ? "badge bad" : "badge"} aria-label={`${alerts.data.open} open`}>
                    {alerts.data.open}
                  </span>
                )}
              </a>
            ))}
          </nav>
        )}
        <span className={health.data?.status === "ok" ? "pill ok" : "pill bad"}>
          {health.isPending ? "checking…" : health.data ? `API ${health.data.version}` : "API down"}
        </span>
        {s?.auth_enabled && s.authenticated && (
          <button type="button" className="plain logout" onClick={() => logout.mutate()}>
            Log out
          </button>
        )}
      </header>
      {s && !s.auth_enabled && (
        <p className="warning">
          No admin password is set, so anyone on your network can view and edit this. Set
          NETMAP_ADMIN_PASSWORD to require a login.
        </p>
      )}
      {signedIn &&
        checks.data
          ?.filter((c) => c.status === "warning")
          .map((c) => (
            <p key={c.name} className="warning" title={`checked ${new Date(c.checked_at).toLocaleString()}`}>
              {c.message}
            </p>
          ))}
      {signedIn && <LimitsBanner />}
      {page}
    </main>
  );
}
