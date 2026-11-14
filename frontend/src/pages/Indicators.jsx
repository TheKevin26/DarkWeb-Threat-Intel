import { useEffect, useState } from "react";
import { IOC_LABELS, exportUrl, fmt, useApi } from "../api.js";
import { Card, Empty, ErrorBanner, PageHead, Seg } from "../components.jsx";

function hashParam(name) {
  const q = window.location.hash.split("?")[1];
  return q ? new URLSearchParams(q).get(name) || "" : "";
}

export default function Indicators({ openInd }) {
  const [type, setType] = useState(hashParam("type"));
  const [input, setInput] = useState("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("sightings");
  const [page, setPage] = useState(0);
  const limit = 50;
  const { data: stats } = useApi("/api/stats", { days: 0 });
  const { data, error } = useApi("/api/indicators", { type, q, sort, limit, offset: page * limit });

  useEffect(() => {
    const t = setTimeout(() => {
      setQ(input);
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [input]);

  const counts = stats?.indicator_types || {};
  const types = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);

  return (
    <>
      <PageHead title="Indicators of compromise" sub="Validated, de-duplicated and enriched with sightings">
        <a className="btn" href={exportUrl("stix", type)} download>Export STIX 2.1</a>
        <a className="btn" href={exportUrl("misp", type)} download>Export MISP</a>
        <a className="btn" href={exportUrl("csv", type)} download>Export CSV</a>
      </PageHead>
      <ErrorBanner error={error} />
      <div className="banner-safe">
        Emails, credentials and card numbers are stored masked — only the fact of the leak and its domain/BIN are kept,
        and masked values are never included in STIX or MISP exports.
      </div>
      <div className="chips" style={{ marginBottom: 12 }}>
        <button className={`chip ${type === "" ? "on" : ""}`} onClick={() => { setType(""); setPage(0); }}>All</button>
        {types.map((t) => (
          <button key={t} className={`chip ${type === t ? "on" : ""}`} onClick={() => { setType(t); setPage(0); }}>
            {IOC_LABELS[t] || t}
            <span className="n">{fmt.n(counts[t])}</span>
          </button>
        ))}
      </div>
      <div className="filters">
        <input className="input" type="search" placeholder="Filter by value or context (domain, BIN)…" value={input} onChange={(e) => setInput(e.target.value)} aria-label="Filter indicators" />
        <Seg options={[["sightings", "Most seen"], ["recent", "Most recent"]]} value={sort} onChange={setSort} />
      </div>
      <Card>
        {!data ? (
          <Empty>Loading…</Empty>
        ) : data.items.length === 0 ? (
          <Empty>No indicators.</Empty>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Context</th>
                    <th className="num">Sightings</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((i) => (
                    <tr key={i.id} className="clickable" onClick={() => openInd(i.id)}>
                      <td><span className="tag">{IOC_LABELS[i.type] || i.type}</span></td>
                      <td className="mono" style={{ maxWidth: 420 }}>{i.value}</td>
                      <td className="secondary">{i.context || ""}</td>
                      <td className="num">{i.sightings}</td>
                      <td className="secondary" style={{ whiteSpace: "nowrap" }}>{fmt.date(i.first_seen)}</td>
                      <td className="secondary" style={{ whiteSpace: "nowrap" }}>{fmt.date(i.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12, alignItems: "center" }}>
              <span className="secondary" style={{ fontSize: 12.5 }}>{fmt.n(data.total)} indicators</span>
              <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <button className="btn small" disabled={(page + 1) * limit >= data.total} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </>
        )}
      </Card>
    </>
  );
}
