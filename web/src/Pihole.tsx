import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, type PiholeState } from "./api";

/** "Block…": opens a dialog that shows where the domain stands in Pi-hole and asks before changing it. */
export function BlockButton({ domain }: { domain: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="plain small link-button" onClick={() => setOpen(true)}>
        Block…
      </button>
      {open && <BlockDialog domain={domain} onClose={() => setOpen(false)} />}
    </>
  );
}

function describe(s: PiholeState): string {
  if (s.allowed) return "On your Pi-hole allow list, so Pi-hole answers for it whatever else says.";
  if (s.denied) return "On your Pi-hole deny list: Pi-hole blocks it for every device.";
  if (s.deny_rules.length) return `Blocked by your Pi-hole rule ${s.deny_rules.join(", ")}.`;
  if (s.lists.length) return `On ${s.lists.length === 1 ? "a Pi-hole blocklist" : `${s.lists.length} Pi-hole blocklists`}, so it's blocked already.`;
  return "Pi-hole doesn't block it.";
}

function BlockDialog({ domain, onClose }: { domain: string; onClose: () => void }) {
  const client = useQueryClient();
  const state = useQuery({ queryKey: ["pihole", domain], queryFn: () => api.piholeState(domain), refetchInterval: false });
  const change = useMutation({
    mutationFn: (block: boolean) => (block ? api.block(domain) : api.unblock(domain)),
    onSuccess: (s) => client.setQueryData(["pihole", domain], s),
  });
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const s = state.data;
  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div
        className="dialog card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="block-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="block-title">
          Block <span className="mono">{domain}</span> in Pi-hole?
        </h2>
        {state.error && <p className="error">{state.error.message}</p>}
        {!s && !state.error && <p className="muted">Asking Pi-hole…</p>}
        {s && !s.configured && (
          <p className="muted">Pi-hole isn't set up: set NETMAP_PIHOLE_URL and NETMAP_PIHOLE_PASSWORD.</p>
        )}
        {s?.configured && (
          <>
            <p>
              <strong>Now:</strong> {describe(s)}
            </p>
            {s.lists.length > 0 && (
              <ul className="small muted dialog-lists">
                {s.lists.map((l) => (
                  <li key={l} className="mono">
                    {l}
                  </li>
                ))}
              </ul>
            )}
            {!s.denied && (
              <p className="small muted">
                Adds it to Pi-hole's deny list. Every device on your network then gets no answer for{" "}
                {domain} (other names under it aren't affected). Some devices stop working without the
                sites they expect.
              </p>
            )}
            {s.denied && (
              <p className="small muted">Unblocking takes it off the deny list; Pi-hole's blocklists still apply.</p>
            )}
          </>
        )}
        {change.error && <p className="error">{change.error.message}</p>}
        <div className="row dialog-actions">
          {s?.configured && !s.denied && (
            <button type="button" className="danger" disabled={change.isPending} onClick={() => change.mutate(true)}>
              {change.isPending ? "Blocking…" : "Block for every device"}
            </button>
          )}
          {s?.configured && s.denied && (
            <button type="button" disabled={change.isPending} onClick={() => change.mutate(false)}>
              {change.isPending ? "Unblocking…" : "Unblock"}
            </button>
          )}
          <button type="button" onClick={onClose}>
            {change.isSuccess ? "Done" : "Cancel"}
          </button>
        </div>
      </div>
    </div>
  );
}
