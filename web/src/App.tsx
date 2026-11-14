import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "./api";
import { DeviceDetailPage } from "./DeviceDetail";
import { DeviceTable } from "./DeviceTable";

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
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const device = DEVICE_ROUTE.exec(useHash());

  return (
    <main>
      <header className="app-head">
        <a href="#/" className="brand">
          Network Mapper
        </a>
        <span className={health.data?.status === "ok" ? "pill ok" : "pill bad"}>
          {health.isPending ? "checking…" : health.data ? `API ${health.data.version}` : "API down"}
        </span>
      </header>
      {device ? <DeviceDetailPage key={device[1]} mac={device[1].toLowerCase()} /> : <DeviceTable />}
    </main>
  );
}
