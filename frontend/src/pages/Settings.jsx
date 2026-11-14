import { useEffect, useState } from "react";
import { api, fmt, useApi } from "../api.js";
import { Card, Empty, ErrorBanner, PageHead, Sev } from "../components.jsx";

const KINDS = [
  ["domain", "Domain", "acme.com"],
  ["keyword", "Keyword", "Acme Corp"],
  ["email_domain", "Email domain", "acme.com"],
  ["ip_range", "IP range", "198.51.100.0/24"],
  ["bin", "Card BIN", "457173"],
];

const COLLECTOR_INFO = {
  demo: "Synthetic dataset — no network access",
  ransomware: "ransomware.live public leak-site dataset",
  leaksites: "Crawl ransomware leak sites directly over Tor (front pages only)",
  ransomwhere: "Import known ransomware payment wallets (ransomwhe.re)",
  tor: "Allowlisted .onion seeds (requires Tor)",
  ahmia: "Ahmia onion search for watchlist terms",
  telegram: "Public Telegram channels (requires API keys)",
  clearnet: "Configured public paste / feed URLs",
  wallets: "Check BTC payment wallets against the public blockchain",
};

function TorCard() {
  const { data: t, reload, loading } = useApi("/api/tor");
  const [busy, setBusy] = useState(false);
  const recheck = async () => {
    setBusy(true);
    try {
      await api("/api/tor", { params: { refresh: 1 } });
    } finally {
      setBusy(false);
      reload();
    }
  };
  return (
    <Card
      title="Tor connection"
      sub="Needed only for crawling .onion sites directly"
      actions={<button className="btn small" onClick={recheck} disabled={busy || loading}>{busy ? "Checking…" : "Re-check"}</button>}
    >
      {!t ? (
        <Empty>Checking…</Empty>
      ) : t.available ? (
        <dl className="kv">
          <dt>Status</dt>
          <dd><span className="status-dot up"><i />Connected</span></dd>
          <dt>Proxy</dt>
          <dd className="mono">{t.proxy}</dd>
          <dt>Tor exit IP</dt>
          <dd className="mono">{t.exit_ip}</dd>
          <dt>Onion seeds</dt>
          <dd>{t.seeds_configured} configured in config/seeds.yaml</dd>
        </dl>
      ) : (
        <>
          <dl className="kv">
            <dt>Status</dt>
            <dd><span className="status-dot down"><i />Not reachable</span></dd>
            <dt>Tried</dt>
            <dd className="mono">{t.tried.join(", ")}</dd>
            <dt>Onion seeds</dt>
            <dd>{t.seeds_configured} configured</dd>
          </dl>
          <ol className="secondary" style={{ fontSize: 13, paddingLeft: 18, marginBottom: 0 }}>
            <li>Install and open <b>Tor Browser</b> (torproject.org) and keep it running. OnionLens finds it on port 9150 automatically.</li>
            <li>Add the .onion sites you are authorised to monitor to <span className="mono">config/seeds.yaml</span>.</li>
            <li>Click Re-check, then run the <b>tor</b> collection.</li>
          </ol>
        </>
      )}
    </Card>
  );
}

export default function Settings({ onAlertsChanged }) {
  const { data: items, error, reload } = useApi("/api/watchlist");
  const { data: sources, reload: reloadSources } = useApi("/api/sources");
  const { data: jobs, reload: reloadJobs } = useApi("/api/jobs");
  const [form, setForm] = useState({ kind: "domain", value: "", severity: "high" });
  const [msg, setMsg] = useState(null);

  const running = jobs?.some((j) => j.status === "running");
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => {
      reloadJobs();
      reloadSources();
    }, 3000);
    return () => clearInterval(t);
  }, [running, reloadJobs, reloadSources]);

  useEffect(() => {
    if (!msg) return;
    const t = setTimeout(() => setMsg(null), 3500);
    return () => clearTimeout(t);
  }, [msg]);

  const add = async (e) => {
    e.preventDefault();
    try {
      await api("/api/watchlist", { method: "POST", body: form });
      setForm((f) => ({ ...f, value: "" }));
      setMsg("Added. New matches will alert on the next collection run.");
      reload();
    } catch (err) {
      setMsg(err.message);
    }
  };
  const remove = async (id) => {
    await api(`/api/watchlist/${id}`, { method: "DELETE" });
    reload();
  };
  const run = async (src) => {
    try {
      await api(`/api/collect/${src}`, { method: "POST" });
      setMsg(`Started ${src} collection`);
      reloadJobs();
      onAlertsChanged?.();
    } catch (err) {
      setMsg(err.message);
    }
  };

  return (
    <>
      <PageHead title="Watchlist & sources" sub="What to look for, and where it is collected from" />
      <ErrorBanner error={error} />
      <div className="grid cols-2e" style={{ marginBottom: 16 }}>
        <Card title="Watchlist" sub="Your organization's assets. Matches raise alerts; leaked credentials are escalated.">
          <form className="filters" onSubmit={add}>
            <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })} aria-label="Kind">
              {KINDS.map(([k, l]) => (
                <option key={k} value={k}>{l}</option>
              ))}
            </select>
            <input
              className="input"
              style={{ flex: 1, minWidth: 160 }}
              placeholder={KINDS.find(([k]) => k === form.kind)[2]}
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
              aria-label="Value"
              required
            />
            <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} aria-label="Severity">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button className="btn primary" type="submit">Add</button>
          </form>
          {!items ? (
            <Empty>Loading…</Empty>
          ) : items.length === 0 ? (
            <Empty>Watchlist is empty.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Value</th>
                    <th>Severity</th>
                    <th className="num">Alerts</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {items.map((w) => (
                    <tr key={w.id}>
                      <td><span className="tag">{w.kind.replace("_", " ")}</span></td>
                      <td className="mono">{w.value}</td>
                      <td><Sev level={w.severity} /></td>
                      <td className="num">{w.alerts}</td>
                      <td style={{ textAlign: "right" }}>
                        <button className="btn small" onClick={() => remove(w.id)}>Remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Run a collection" sub="Runs in the background on the API server. Scheduled runs use Celery beat.">
          {Object.entries(COLLECTOR_INFO).map(([k, info]) => (
            <div key={k} className="list-item" style={{ cursor: "default", display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div className="title">{k}</div>
                <div className="meta">{info}</div>
              </div>
              <button className="btn small" onClick={() => run(k)} disabled={jobs?.some((j) => j.source === k && j.status === "running")}>
                Run
              </button>
            </div>
          ))}
          {jobs?.length > 0 && (
            <>
              <h3 className="secondary" style={{ fontSize: 12.5, margin: "16px 0 6px" }}>RECENT JOBS</h3>
              {jobs.slice(0, 6).map((j) => (
                <div key={j.id} style={{ fontSize: 12.5, padding: "3px 0" }} className="secondary">
                  <b style={{ color: "var(--text-primary)" }}>{j.source}</b> · {j.status} · {fmt.ago(j.started_at)}
                  {j.result && !j.result.error && ` · ${j.result.new_documents} new docs, ${j.result.alerts} alerts`}
                  {j.result?.error && <span style={{ color: "var(--status-critical)" }}> · {j.result.error}</span>}
                </div>
              ))}
            </>
          )}
        </Card>
      </div>
      <div style={{ marginBottom: 16 }}>
        <TorCard />
      </div>
      <Card title="Sources" sub="Availability over the last 30 checks — onion services go up and down often">
        {!sources ? (
          <Empty>Loading…</Empty>
        ) : sources.length === 0 ? (
          <Empty>No sources yet — run a collection.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th className="num">Uptime</th>
                  <th className="num">Latency</th>
                  <th className="num">Docs</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{s.name}</div>
                      <div className="muted mono" style={{ fontSize: 11.5, maxWidth: 300 }}>{s.url}</div>
                    </td>
                    <td><span className="tag">{s.kind}</span></td>
                    <td>
                      <span className={`status-dot ${s.status}`}>
                        <i />
                        {s.status}
                      </span>
                    </td>
                    <td className="num">{s.uptime != null ? `${s.uptime}%` : "—"}</td>
                    <td className="num secondary">{s.avg_latency_ms != null ? `${fmt.n(s.avg_latency_ms)} ms` : "—"}</td>
                    <td className="num">{fmt.n(s.documents)}</td>
                    <td className="secondary" style={{ whiteSpace: "nowrap" }}>{fmt.ago(s.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {msg && <div className="toast">{msg}</div>}
    </>
  );
}
