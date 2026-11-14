import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export function App() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.devices });

  return (
    <main>
      <header>
        <h1>Network Mapper</h1>
        <span className={health.data?.status === "ok" ? "pill ok" : "pill bad"}>
          {health.isPending ? "checking…" : health.data ? `API ${health.data.version}` : "API down"}
        </span>
      </header>

      {devices.error && <p className="error">Couldn't load devices: {devices.error.message}</p>}
      {devices.data && (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Category</th>
              <th>Vendor</th>
              <th>MAC</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {devices.data.map((d) => (
              <tr key={d.mac}>
                <td title={!d.label && d.hostname_source ? `from ${d.hostname_source}` : undefined}>
                  {d.label ?? d.hostname ?? "—"}
                </td>
                <td>
                  {d.category}
                  {d.is_iot && d.category !== "iot" ? " · IoT" : ""}
                </td>
                <td>{d.is_randomized_mac ? "randomized MAC" : (d.vendor ?? "—")}</td>
                <td className="mono">{d.mac}</td>
                <td>{d.online ? "online" : `offline since ${new Date(d.last_seen).toLocaleDateString()}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
