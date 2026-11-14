import { useEffect, useState } from "react";
import { fmt, useApi } from "../api.js";
import { Card, Empty, ErrorBanner, PageHead, Score, Seg } from "../components.jsx";

const CATS = [
  ["", "All"],
  ["credential_leak", "Credential leak"],
  ["ransomware", "Ransomware"],
  ["access_broker", "Access broker"],
  ["exploit", "Exploits"],
  ["malware", "Malware"],
  ["fraud", "Fraud"],
  ["hacking_services", "Hacking services"],
  ["drugs", "Drugs"],
  ["other", "Other"],
];

function hashParam(name) {
  const q = window.location.hash.split("?")[1];
  return q ? new URLSearchParams(q).get(name) || "" : "";
}

export default function Investigate({ openDoc }) {
  const [input, setInput] = useState("");
  const [q, setQ] = useState("");
  const [category, setCategory] = useState(hashParam("category"));
  const [minScore, setMinScore] = useState(0);
  const [sort, setSort] = useState("recent");
  const [page, setPage] = useState(0);
  const limit = 25;

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(input);
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [input]);

  const { data, error } = useApi("/api/documents", { q, category, min_score: minScore, sort, limit, offset: page * limit });

  return (
    <>
      <PageHead title="Investigate" sub="Full-text search across every collected document" />
      <ErrorBanner error={error} />
      <div className="filters">
        <input
          className="input"
          type="search"
          placeholder="Search text, e.g. RDP, combolist, CVE-2024-3400, a handle or wallet…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          aria-label="Search"
        />
        <select className="input" value={minScore} onChange={(e) => { setMinScore(+e.target.value); setPage(0); }} aria-label="Minimum score">
          <option value={0}>Any score</option>
          <option value={35}>Score ≥ 35</option>
          <option value={60}>Score ≥ 60</option>
          <option value={80}>Score ≥ 80</option>
        </select>
        <Seg options={[["recent", "Newest"], ["score", "Highest risk"]]} value={sort} onChange={(v) => { setSort(v); setPage(0); }} />
      </div>
      <div className="chips" style={{ marginBottom: 14 }}>
        {CATS.map(([id, label]) => (
          <button key={id} className={`chip ${category === id ? "on" : ""}`} onClick={() => { setCategory(id); setPage(0); }}>
            {label}
          </button>
        ))}
      </div>
      <Card>
        {!data ? (
          <Empty>Loading…</Empty>
        ) : data.items.length === 0 ? (
          <Empty>No documents match.</Empty>
        ) : (
          <>
            <div className="secondary" style={{ fontSize: 12.5, marginBottom: 4 }}>{fmt.n(data.total)} results</div>
            {data.items.map((d) => (
              <div key={d.id} className="list-item" onClick={() => openDoc(d.id)}>
                <div style={{ display: "flex", gap: 12, alignItems: "baseline" }}>
                  <span className="title" style={{ flex: 1, minWidth: 0 }}>{d.title || "(untitled)"}</span>
                  <Score value={d.threat_score} />
                </div>
                <div className="meta">
                  <span className="tag">{d.category_label}</span>
                  <span>{d.source}</span>
                  <span>{fmt.date(d.published_at || d.collected_at)}</span>
                  {d.indicator_count > 0 && <span>{d.indicator_count} indicators</span>}
                  {d.alert_count > 0 && <span style={{ color: "var(--status-critical)", fontWeight: 600 }}>▲ {d.alert_count} watchlist hit{d.alert_count > 1 ? "s" : ""}</span>}
                  {d.language && d.language !== "en" && <span className="tag">{d.language}</span>}
                </div>
                <div className="snippet">{d.snippet}</div>
              </div>
            ))}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12, alignItems: "center" }}>
              <span className="secondary" style={{ fontSize: 12.5 }}>
                Page {page + 1} of {Math.max(1, Math.ceil(data.total / limit))}
              </span>
              <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <button className="btn small" disabled={(page + 1) * limit >= data.total} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
