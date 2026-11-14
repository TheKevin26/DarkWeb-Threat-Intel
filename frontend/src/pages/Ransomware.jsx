import { useState } from "react";
import { fmt, useApi } from "../api.js";
import { Card, CountTable, Empty, ErrorBanner, Kpi, PageHead, Seg } from "../components.jsx";

const STATE_LABEL = {
  parsed: "Parsed",
  "no victims parsed": "No victims parsed",
  "javascript-only page": "JavaScript-only (skipped)",
  unreachable: "Unreachable",
};

function Coverage() {
  const [days, setDays] = useState(14);
  const { data } = useApi("/api/coverage", { days });
  const t = data?.totals || {};
  return (
    <Card
      title="Source coverage: our Tor crawl vs ransomware.live"
      sub={
        data
          ? `${data.groups_parsed} of ${data.groups_crawled} crawled leak sites parsed · last ${days} days · ` +
            `ours ${fmt.n(t.ours)} · ransomware.live ${fmt.n(t.theirs)} · both ${fmt.n(t.both)} · ` +
            `only ours ${fmt.n(t.only_ours)} · only ransomware.live ${fmt.n(t.only_theirs)}`
          : ""
      }
      actions={<Seg options={[[7, "7d"], [14, "14d"], [30, "30d"]]} value={days} onChange={setDays} />}
      style={{ marginBottom: 16 }}
    >
      {!data ? (
        <Empty>Loading…</Empty>
      ) : data.groups.length === 0 ? (
        <Empty>No leak sites crawled yet. Run the leaksites collection.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Our crawl</th>
                <th className="num">Seen by us</th>
                <th className="num">Seen by ransomware.live</th>
                <th className="num">Both</th>
                <th className="num">Only us</th>
                <th className="num">Only ransomware.live</th>
                <th>Last crawled</th>
              </tr>
            </thead>
            <tbody>
              {data.groups.map((g) => (
                <tr key={g.group}>
                  <td style={{ fontWeight: 600 }}>{g.group}</td>
                  <td>
                    <span className={`status-dot ${g.state === "parsed" ? "up" : g.state === "unreachable" ? "down" : ""}`}>
                      <i />
                      {STATE_LABEL[g.state] || g.state}
                    </span>
                  </td>
                  <td className="num">{fmt.n(g.ours)}</td>
                  <td className="num">{fmt.n(g.theirs)}</td>
                  <td className="num">{fmt.n(g.both)}</td>
                  <td className="num" style={{ color: g.only_ours ? "var(--success-text)" : undefined, fontWeight: g.only_ours ? 600 : 400 }}>
                    {fmt.n(g.only_ours)}
                  </td>
                  <td className="num">{fmt.n(g.only_theirs)}</td>
                  <td className="secondary">{fmt.ago(g.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function Ransomware({ openDoc }) {
  const [days, setDays] = useState(0);
  const [filter, setFilter] = useState({ group: "", country: "", sector: "" });
  const [q, setQ] = useState("");
  const { data: st, error } = useApi("/api/victims/stats", { days });
  const { data: victims } = useApi("/api/victims", { days, q, ...filter, limit: 300 });

  const set = (k, v) => setFilter((f) => ({ ...f, [k]: f[k] === v ? "" : v }));
  const active = Object.entries(filter).filter(([, v]) => v);

  return (
    <>
      <PageHead title="Ransomware & extortion" sub="Victims posted on leak sites, by group, country and sector">
        <Seg options={[[30, "30d"], [90, "90d"], [0, "All"]]} value={days} onChange={setDays} />
      </PageHead>
      <ErrorBanner error={error} />
      {st && (
        <>
          <div className="grid kpis">
            <Kpi label="Victims" value={fmt.n(st.total)} />
            <Kpi label="Active groups" value={fmt.n(st.groups_total)} />
            <Kpi label="Countries" value={fmt.n(st.by_country.length)} />
            <Kpi label="Most targeted sector" value={<span style={{ fontSize: 18 }}>{st.by_sector[0]?.sector || "—"}</span>} />
          </div>
          <div className="grid cols-3" style={{ marginBottom: 16 }}>
            <Card title="Most active groups" sub={`Top ${st.by_group.length} of ${st.groups_total} · click to filter`}>
              <CountTable name="Group" unit="Victims" rows={st.by_group.map((g) => ({ key: g.group, label: g.group, value: g.count }))} onClick={(r) => set("group", r.key)} />
            </Card>
            <Card title="Countries" sub="Click to filter">
              <CountTable
                name="Country"
                unit="Victims"
                rows={st.by_country.slice(0, 15).map((c) => ({ key: c.code, label: c.name || c.code, value: c.count }))}
                onClick={(r) => set("country", r.key)}
              />
            </Card>
            <Card title="Sectors" sub="Click to filter">
              <CountTable name="Sector" unit="Victims" rows={st.by_sector.map((s) => ({ key: s.sector, label: s.sector, value: s.count }))} onClick={(r) => set("sector", r.key)} />
            </Card>
          </div>
        </>
      )}
      <Coverage />
      <Card
        title="Victim postings"
        sub={victims ? `${fmt.n(victims.total)} matching` : ""}
        actions={
          <div className="filters" style={{ margin: 0 }}>
            {active.map(([k, v]) => (
              <button key={k} className="chip on" onClick={() => set(k, v)} title="Remove filter">
                {k}: {v} ✕
              </button>
            ))}
            <input className="input" type="search" placeholder="Search victim or domain" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search victims" />
          </div>
        }
      >
        {!victims ? (
          <Empty>Loading…</Empty>
        ) : victims.items.length === 0 ? (
          <Empty>No victims match.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Victim</th>
                  <th>Group</th>
                  <th>Country</th>
                  <th>Sector</th>
                  <th>Discovered</th>
                </tr>
              </thead>
              <tbody>
                {victims.items.map((v) => (
                  <tr key={v.id} className="clickable" onClick={() => v.document_id && openDoc(v.document_id)}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{v.name}</div>
                      {v.domain && <div className="muted mono" style={{ fontSize: 12 }}>{v.domain}</div>}
                    </td>
                    <td>{v.group}</td>
                    <td>{v.country_name || "—"}</td>
                    <td className="secondary">{v.sector || "—"}</td>
                    <td className="secondary" style={{ whiteSpace: "nowrap" }}>{fmt.date(v.discovered_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
