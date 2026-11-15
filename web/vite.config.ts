import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In dev, Vite serves the UI and proxies /api to the backend. The target comes from the
// environment (docker-compose sets it to the api service) so nothing is hardcoded here.
const apiTarget = process.env.NETMAP_API_PROXY ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  // The chart libraries (Cytoscape, ECharts) are lazy chunks of up to ~550 kB, loaded only
  // by the pages that draw them; the main bundle stays well under this.
  build: { chunkSizeWarningLimit: 600 },
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, ws: true }, // ws: the live throughput socket
      "/docs": apiTarget,
      "/openapi.json": apiTarget,
      "/metrics": apiTarget,
    },
    // Bind-mounted sources on Windows don't emit file events into the container.
    watch: process.env.VITE_POLL ? { usePolling: true, interval: 300 } : undefined,
  },
});
