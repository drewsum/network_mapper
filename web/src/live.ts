import { useEffect, useState } from "react";
import type { LiveReport } from "./api";

/** Live throughput from /api/live while the calling page is open; null until the first
 * report, or when the capture service isn't running. Reconnects, backing off, if dropped. */
export function useLive(enabled = true): LiveReport | null {
  const [report, setReport] = useState<LiveReport | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let delay = 2000;
    let stopped = false;
    const connect = () => {
      const scheme = location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${scheme}//${location.host}/api/live`);
      socket.onmessage = (e) => {
        delay = 2000;
        try {
          setReport(JSON.parse(e.data) as LiveReport);
        } catch {
          // not a report; ignore
        }
      };
      socket.onclose = () => {
        if (stopped) return;
        retry = window.setTimeout(connect, delay);
        delay = Math.min(delay * 2, 60_000);
      };
    };
    connect();
    return () => {
      stopped = true;
      window.clearTimeout(retry);
      socket?.close();
    };
  }, [enabled]);
  return report;
}
