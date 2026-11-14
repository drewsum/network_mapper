import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, UNAUTHORIZED_EVENT } from "./api";
import { DeviceDetailPage } from "./DeviceDetail";
import { DeviceTable } from "./DeviceTable";
import { Login } from "./Login";
import { OrganizationsPage } from "./Organizations";

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
  else page = <DeviceTable />;

  return (
    <main>
      <header className="app-head">
        <div className="left">
          <a href="#/" className="brand">
            Network Mapper
          </a>
          {signedIn && <a href="#/domains">Domains</a>}
          <span className={health.data?.status === "ok" ? "pill ok" : "pill bad"}>
            {health.isPending ? "checking…" : health.data ? `API ${health.data.version}` : "API down"}
          </span>
        </div>
        {s?.auth_enabled && s.authenticated && (
          <button type="button" className="plain" onClick={() => logout.mutate()}>
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
      {page}
    </main>
  );
}
