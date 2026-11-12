import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In dev, Vite serves the UI and proxies /api to the backend. The target comes from the
// environment (docker-compose sets it to the api service) so nothing is hardcoded here.
const apiTarget = process.env.NETMAP_API_PROXY ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: { "/api": apiTarget, "/docs": apiTarget, "/openapi.json": apiTarget },
    // Bind-mounted sources on Windows don't emit file events into the container.
    watch: process.env.VITE_POLL ? { usePolling: true, interval: 300 } : undefined,
  },
});
