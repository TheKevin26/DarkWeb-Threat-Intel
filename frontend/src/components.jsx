import { useEffect } from "react";
import { IOC_LABELS, fmt, useApi } from "./api.js";

export function PageHead({ title, sub, children }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {children && <div className="actions">{children}</div>}
    </div>
  );
}

export function Card({ title, sub, actions, children, style }) {
  return (
    <section className="card" style={style}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <p className="sub" style={{ marginBottom: 0 }}>{sub}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Kpi({ label, value, delta, deltaClass }) {
  return (
    <div className="card kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {delta && <div className={`delta ${deltaClass || ""}`}>{delta}</div>}
    </div>
  );
}

export function Seg({ options, value, onChange }) {
  return (
    <div className="seg" role="group">
      {options.map(([v, label]) => (
        <button key={String(v)} className={v === value ? "on" : ""} onClick={() => onChange(v)} aria-pressed={v === value}>
          {label}
        </button>
      ))}
    </div>
  );
}

export function Sev({ level }) {
  const label = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }[level] || level;
  return (
    <span className={`sev ${level}`}>
      <i aria-hidden="true" />
      {label}
    </span>
  );
}

export function Score({ value }) {
  const cls = value >= 60 ? "hi" : value >= 35 ? "mid" : "";
  const label = value >= 60 ? "High risk" : value >= 35 ? "Medium" : "Low";
  return (
    <span className={`score ${cls}`} title={`Threat score ${value} / 100`}>
      {Math.round(value)} · {label}
    </span>
  );
}

export function Empty({ children = "Nothing here yet." }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return (
    <div className="error-banner">
      Couldn't reach the API ({error.message}). Is the backend running on port 8000?
    </div>
  );
}

/** Plain table of label -> count with share of total. Rows are clickable when onClick is given. */
export function CountTable({ rows, name = "Name", unit = "Count", onClick, format = fmt.n, share = true }) {
  if (!rows.length) return <Empty />;
  const total = rows.reduce((a, r) => a + r.value, 0) || 1;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{name}</th>
            <th className="num">{unit}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key ?? r.label} className={onClick ? "clickable" : ""} onClick={onClick ? () => onClick(r) : undefined}>
              <td>{r.label}</td>
              <td className="num">
                {format(r.value)}
                {share && <span className="share">{Math.round((100 * r.value) / total)}%</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Drawer({ onClose, children }) {
  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <button className="btn small close" onClick={onClose} aria-label="Close">
          ✕ Close
        </button>
        {children}
      </aside>
    </>
  );
}

export function DocDrawer({ id, onClose, onIndicator }) {
  const { data: d, error } = useApi(id ? `/api/documents/${id}` : null);
  return (
    <Drawer onClose={onClose}>
      {error && <ErrorBanner error={error} />}
      {!d ? (
        <Empty>Loading…</Empty>
      ) : (
        <>
          <div className="secondary" style={{ fontSize: 12.5 }}>
            {d.source} · {d.source_kind} · {fmt.datetime(d.published_at || d.collected_at)}
          </div>
          <h2>{d.title || "(untitled)"}</h2>
          <div className="chips" style={{ margin: "8px 0 4px" }}>
            <span className="tag">{d.category_label}</span>
            <Score value={d.threat_score} />
            {d.language && <span className="tag">lang: {d.language}</span>}
          </div>
          {d.alerts.length > 0 && (
            <>
              <h3>Watchlist hits</h3>
              {d.alerts.map((a) => (
                <div key={a.id} style={{ display: "flex", gap: 10, padding: "3px 0" }}>
                  <Sev level={a.severity} /> <span>{a.watch_value}</span> <span className="mono muted">{a.matched}</span>
                </div>
              ))}
            </>
          )}
          <h3>Content (redacted)</h3>
          <pre>{d.text}</pre>
          {d.translated_text && (
            <>
              <h3>Translation</h3>
              <pre>{d.translated_text}</pre>
            </>
          )}
          <h3>Classification</h3>
          <CountTable
            name="Category"
            unit="Confidence"
            share={false}
            rows={Object.entries(d.category_scores)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 4)
              .map(([k, v]) => ({ key: k, label: k.replace("_", " "), value: v }))}
            format={(v) => `${Math.round(v * 100)}%`}
          />
          {d.evidence.length > 0 && (
            <p className="secondary" style={{ fontSize: 12.5 }}>
              Evidence terms: {d.evidence.map((e) => `“${e}”`).join(", ")}
            </p>
          )}
          <h3>Indicators ({d.indicators.length})</h3>
          {d.indicators.length === 0 ? (
            <span className="muted">None extracted.</span>
          ) : (
            <div className="table-wrap">
              <table>
                <tbody>
                  {d.indicators.map((i) => (
                    <tr key={i.id} className="clickable" onClick={() => onIndicator?.(i.id)}>
                      <td style={{ width: 110 }}>
                        <span className="tag">{IOC_LABELS[i.type] || i.type}</span>
                      </td>
                      <td className="mono">{i.value}</td>
                      <td className="num muted">{i.sightings}×</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {d.attack.length > 0 && (
            <>
              <h3>MITRE ATT&CK</h3>
              {d.attack.map((t) => (
                <div key={t.id} style={{ padding: "2px 0" }}>
                  <a href={t.url} target="_blank" rel="noreferrer" className="mono">
                    {t.id}
                  </a>{" "}
                  {t.name} <span className="muted">· {t.tactic}</span>
                </div>
              ))}
            </>
          )}
          {d.entities.length > 0 && (
            <>
              <h3>Entities</h3>
              <div className="chips">
                {d.entities.map((e) => (
                  <span key={e.label + e.text} className="tag">
                    {e.label}: {e.text}
                  </span>
                ))}
              </div>
            </>
          )}
          <h3>Provenance</h3>
          <dl className="kv">
            <dt>URL</dt>
            <dd className="mono">{d.url}</dd>
            <dt>Collected</dt>
            <dd>{fmt.datetime(d.collected_at)}</dd>
            <dt>Document ID</dt>
            <dd>{d.id}</dd>
          </dl>
        </>
      )}
    </Drawer>
  );
}

export function IndicatorDrawer({ id, onClose, onDoc, onIndicator }) {
  const { data: i, error } = useApi(id ? `/api/indicators/${id}` : null);
  return (
    <Drawer onClose={onClose}>
      {error && <ErrorBanner error={error} />}
      {!i ? (
        <Empty>Loading…</Empty>
      ) : (
        <>
          <span className="tag">{IOC_LABELS[i.type] || i.type}</span>
          <h2 className="mono" style={{ fontSize: 16, marginTop: 8 }}>
            {i.value}
          </h2>
          <dl className="kv">
            <dt>Sightings</dt>
            <dd>{i.sightings}</dd>
            <dt>First seen</dt>
            <dd>{fmt.datetime(i.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{fmt.datetime(i.last_seen)}</dd>
            {i.context && (
              <>
                <dt>Context</dt>
                <dd>{i.context}</dd>
              </>
            )}
          </dl>
          {i.type === "btc_address" && (
            <>
              <h3>On-chain activity (public blockchain)</h3>
              {i.on_chain.length === 0 ? (
                <span className="muted">Not checked yet. Runs hourly, or use the wallets job on Watchlist and sources.</span>
              ) : (
                <>
                  <dl className="kv">
                    <dt>Transactions</dt>
                    <dd>{fmt.n(i.on_chain[0].tx_count)}{i.on_chain[0].pending_tx ? ` (+${i.on_chain[0].pending_tx} pending)` : ""}</dd>
                    <dt>Total received</dt>
                    <dd>{i.on_chain[0].received_btc.toFixed(8)} BTC</dd>
                    <dt>Balance</dt>
                    <dd>{i.on_chain[0].balance_btc.toFixed(8)} BTC</dd>
                    <dt>Last transaction</dt>
                    <dd>{fmt.datetime(i.on_chain[0].last_tx_at)}</dd>
                    <dt>Checked</dt>
                    <dd>{fmt.ago(i.on_chain[0].checked_at)}</dd>
                  </dl>
                  <p style={{ fontSize: 12.5, marginBottom: 0 }}>
                    <a href={`https://mempool.space/address/${i.value}`} target="_blank" rel="noreferrer">View on mempool.space ↗</a>
                  </p>
                </>
              )}
            </>
          )}
          <h3>Seen in ({i.documents.length})</h3>
          {i.documents.map((d) => (
            <div key={d.id} className="list-item" onClick={() => onDoc?.(d.id)}>
              <div className="title">{d.title || "(untitled)"}</div>
              <div className="meta">
                <span>{d.source}</span>
                <span className="tag">{d.category}</span>
              </div>
            </div>
          ))}
          <h3>Pivot: co-occurring indicators ({i.related.length})</h3>
          <div className="table-wrap">
            <table>
              <tbody>
                {i.related.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => onIndicator?.(r.id)}>
                    <td style={{ width: 110 }}>
                      <span className="tag">{IOC_LABELS[r.type] || r.type}</span>
                    </td>
                    <td className="mono">{r.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Drawer>
  );
}
