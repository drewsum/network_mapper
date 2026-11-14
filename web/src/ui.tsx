import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, BLOCKLIST_LABELS, CATEGORIES, type Category, type DeviceUpdate, threats } from "./api";

export function ago(iso: string): string {
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
  if (seconds < 90) return "just now";
  if (seconds < 3600 * 1.5) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400 * 1.5) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Sortable form of a dotted IPv4 address. */
export function ipKey(ip: string | null): string {
  return ip ? ip.split(".").map((n) => n.padStart(3, "0")).join(".") : "~";
}

/** Saves owner edits and refreshes every view of the device. */
export function useUpdateDevice(mac: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (changes: DeviceUpdate) => api.updateDevice(mac, changes),
    onSuccess: (device) => {
      client.setQueryData(["device", mac], device);
      void client.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

/** Text that turns into an input on click; Enter or leaving the field saves, Esc cancels. */
export function EditableText({
  value,
  placeholder,
  onSave,
  className,
}: {
  value: string | null;
  placeholder: string;
  onSave: (value: string | null) => void;
  className?: string;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  if (draft === null) {
    return (
      <button
        type="button"
        className={`editable ${className ?? ""}`}
        title="Click to edit"
        onClick={() => setDraft(value ?? "")}
      >
        {value ?? <span className="muted">{placeholder}</span>}
      </button>
    );
  }
  const finish = (save: boolean) => {
    const next = draft.trim() || null;
    setDraft(null);
    if (save && next !== value) onSave(next);
  };
  return (
    <input
      autoFocus
      className={`edit-input ${className ?? ""}`}
      value={draft}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => finish(true)}
      onKeyDown={(e) => {
        if (e.key === "Enter") finish(true);
        if (e.key === "Escape") finish(false);
      }}
    />
  );
}

export function CategorySelect({
  value,
  onChange,
}: {
  value: Category;
  onChange: (value: Category) => void;
}) {
  return (
    <select
      className="category"
      value={value}
      aria-label="Category"
      onChange={(e) => onChange(e.target.value as Category)}
    >
      {CATEGORIES.map((c) => (
        <option key={c} value={c}>
          {c}
        </option>
      ))}
    </select>
  );
}

export function Status({ online, lastSeen }: { online: boolean; lastSeen: string }) {
  return online ? (
    <span className="status on">online</span>
  ) : (
    <span className="status off" title={dateTime(lastSeen)}>
      offline · {ago(lastSeen)}
    </span>
  );
}

/** A red "threat" tag when a domain is on a threat blocklist, naming the lists. */
export function ThreatTag({ lists }: { lists: string[] }) {
  const hits = threats(lists);
  if (hits.length === 0) return null;
  return (
    <span className="tag bad" title={`On ${hits.map((l) => BLOCKLIST_LABELS[l] ?? l).join(", ")}`}>
      threat
    </span>
  );
}
