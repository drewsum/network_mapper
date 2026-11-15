import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import {
  api,
  BLOCKLIST_LABELS,
  DOMAIN_CATEGORY_LABELS,
  type OrgRuleKind,
  type OrgRuleSaved,
  threats,
} from "./api";
import { ago, dateTime } from "./ui";

export function OrganizationsPage() {
  return (
    <article className="detail">
      <a href="#/" className="back">
        ← All devices
      </a>
      <h1 className="title">Domains</h1>
      <Blocklists />
      <Categories />
      <Rules />
      <Groups />
    </article>
  );
}

function useRegroup() {
  const client = useQueryClient();
  return (saved: OrgRuleSaved) => {
    void client.invalidateQueries({ queryKey: ["orgRules"] });
    void client.invalidateQueries({ queryKey: ["organizations"] });
    void client.invalidateQueries({ queryKey: ["domains"] });
    void client.invalidateQueries({ queryKey: ["domainCategories"] });
    return saved.regrouped;
  };
}

function Rules() {
  const rules = useQuery({ queryKey: ["orgRules"], queryFn: api.orgRules });
  const names = useQuery({ queryKey: ["organizations"], queryFn: api.organizations });
  const regroup = useRegroup();
  const [kind, setKind] = useState<OrgRuleKind>("suffix");
  const [value, setValue] = useState("");
  const [organization, setOrganization] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => api.saveOrgRule({ kind, value, organization }),
    onSuccess: (saved) => {
      const n = regroup(saved);
      setResult(`Saved. ${n} domain${n === 1 ? "" : "s"} regrouped.`);
      setValue("");
    },
  });
  const remove = useMutation({
    mutationFn: api.deleteOrgRule,
    onSuccess: (saved) => {
      const n = regroup(saved);
      setResult(`Removed. ${n} domain${n === 1 ? "" : "s"} regrouped.`);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setResult(null);
    save.mutate();
  };
  return (
    <section className="card">
      <h2>Organization rules</h2>
      <p className="muted">
        A domain's organization comes from the built-in map: its longest matching domain suffix,
        else the network (AS number) its IP is in. Anything unmatched is grouped as Other. Rules
        here take precedence over the map. A suffix rule covers the domain and all its
        subdomains.
      </p>
      <form className="row rule-form" onSubmit={submit}>
        <select value={kind} onChange={(e) => setKind(e.target.value as OrgRuleKind)} aria-label="Rule type">
          <option value="suffix">Domain suffix</option>
          <option value="asn">Network (AS number)</option>
        </select>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={kind === "suffix" ? "example.com" : "AS64500"}
          aria-label={kind === "suffix" ? "Domain suffix" : "AS number"}
          required
        />
        <input
          value={organization}
          onChange={(e) => setOrganization(e.target.value)}
          placeholder="Organization"
          aria-label="Organization"
          list="org-names"
          required
        />
        <datalist id="org-names">
          {names.data?.map((o) => <option key={o.name} value={o.name} />)}
        </datalist>
        <button type="submit" disabled={save.isPending}>
          Save rule
        </button>
      </form>
      {(save.error ?? remove.error) && <p className="error">{(save.error ?? remove.error)?.message}</p>}
      {result && <p className="muted small">{result}</p>}
      {rules.data && rules.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Matches</th>
              <th>Organization</th>
              <th>Added</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rules.data.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.kind === "asn" ? `AS${r.value}` : `*.${r.value}`}</td>
                <td>{r.organization}</td>
                <td>{dateTime(r.created_at)}</td>
                <td>
                  <button type="button" className="plain" disabled={remove.isPending} onClick={() => remove.mutate(r.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rules.data?.length === 0 && <p className="muted small">No rules yet.</p>}
    </section>
  );
}

function Groups() {
  const orgs = useQuery({ queryKey: ["organizations"], queryFn: api.organizations });
  const seen = orgs.data?.filter((o) => o.domains > 0) ?? [];
  return (
    <section className="card">
      <h2>Domains by organization</h2>
      {orgs.error && <p className="error">{orgs.error.message}</p>}
      {orgs.data && seen.length === 0 && <p className="muted">No domains grouped yet.</p>}
      {seen.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Organization</th>
              <th>Domains</th>
            </tr>
          </thead>
          <tbody>
            {seen.map((o) => (
              <tr key={o.name}>
                <td>{o.name}</td>
                <td>{o.domains.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Categories() {
  const cats = useQuery({ queryKey: ["domainCategories"], queryFn: api.domainCategories });
  return (
    <section className="card">
      <h2>Domains by category</h2>
      <p className="muted">
        Ad and analytics services come from a built-in list and from words in the name (ads.,
        telemetry., metrics.). Domains Pi-hole blocks count as ads and trackers. The rest take their
        organization's kind: a vendor's cloud, a CDN or hosting network, or Unknown for Other.
      </p>
      {cats.error && <p className="error">{cats.error.message}</p>}
      {cats.data && (
        <table>
          <thead>
            <tr>
              <th>Category</th>
              <th>Domains</th>
            </tr>
          </thead>
          <tbody>
            {cats.data.map((c) => (
              <tr key={c.category}>
                <td>{c.label}</td>
                <td>{c.domains.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Blocklists() {
  const bl = useQuery({ queryKey: ["blocklists"], queryFn: api.blocklists });
  const data = bl.data;
  return (
    <section className="card">
      <h2>Threat blocklists</h2>
      <p className="muted">
        A domain is flagged when it, or an IP it resolved to, is on one of these lists. Each is
        downloaded again daily.
      </p>
      {bl.error && <p className="error">{bl.error.message}</p>}
      {data && (
        <table>
          <thead>
            <tr>
              <th>List</th>
              <th>Entries</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {data.lists.map((l) => (
              <tr key={l.name}>
                <td>
                  <a href={l.url} target="_blank" rel="noreferrer">
                    {l.label}
                  </a>
                </td>
                <td>{l.entries?.toLocaleString() ?? "—"}</td>
                <td className="muted">
                  {l.needs_key ? (
                    "Needs NETMAP_ABUSECH_AUTH_KEY"
                  ) : l.refreshed_at ? (
                    <span title={dateTime(l.refreshed_at)}>{ago(l.refreshed_at)}</span>
                  ) : (
                    "Not downloaded yet"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data?.flagged.length === 0 && <p className="muted small">No domains on a threat list.</p>}
      {data && data.flagged.length > 0 && (
        <table className="stack">
          <thead>
            <tr>
              <th>Flagged domain</th>
              <th>Lists</th>
              <th>Organization</th>
              <th>Category</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {data.flagged.map((d) => (
              <tr key={d.domain}>
                <td className="domain">{d.domain}</td>
                <td>{threats(d.blocklists).map((l) => BLOCKLIST_LABELS[l] ?? l).join(", ")}</td>
                <td>{d.organization ?? "—"}</td>
                <td>{d.category ? (DOMAIN_CATEGORY_LABELS[d.category] ?? d.category) : "—"}</td>
                <td data-label="Seen" title={dateTime(d.last_seen)}>
                  {ago(d.last_seen)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
