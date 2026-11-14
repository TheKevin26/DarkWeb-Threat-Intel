import { useEffect, useRef, useState } from "react";
import { IOC_LABELS, fmt, useApi } from "../api.js";
import { Card, CountTable, Empty, ErrorBanner, Kpi, PageHead, Seg, Sev } from "../components.jsx";
import WorldMap from "../WorldMap.jsx";

const RANGES = [
  [7, "7d"],
  [30, "30d"],
  [90, "90d"],
  [0, "All"],
];
const REFRESH_MS = 30_000;
const WALLET = { btc_address: "BTC", xmr_address: "XMR", eth_address: "ETH" };

function useStoredBool(key, initial) {
  const [v, setV] = useState(() => {
    try {
      const s = localStorage.getItem(key);
      return s === null ? initial : s === "1";
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, v ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [key, v]);
  return [v, setV];
}

function LiveFeed({ data, fresh, openDoc, openInd }) {
  if (!data) return <Empty>Loading…</Empty>;
  if (!data.items.length) return <Empty>No activity yet. Run a collection from Watchlist & sources.</Empty>;
  return (
    <div className="feed">
      {data.items.map((e) => (
        <div
          key={e.key}
          className={`feed-item k-${e.kind} ${fresh.has(e.key) ? "fresh" : ""}`}
          onClick={() => (e.kind === "transaction" ? openInd(e.indicator_id) : e.document_id && openDoc(e.document_id))}
        >
          <span className="rail" aria-hidden="true" />
          <div style={{ minWidth: 0 }}>
            <div className="fl">{e.label}</div>
            <div className="ft">{e.title}</div>
            <div className="fm">
              {e.country_name && <span>{e.country_name}</span>}
              {e.sector && <span>{e.sector}</span>}
              {e.payment_wallets.length > 0 && e.kind !== "transaction" && (
                <span className="wallet">{e.payment_wallets.map((w) => WALLET[w]).join(" / ")} payment address</span>
              )}
              <span>{e.source}</span>
            </div>
          </div>
          <span className="fa">{fmt.ago(e.at)}</span>
        </div>
      ))}
    </div>
  );
}

export default function Overview({ openDoc, openInd, go }) {
  const [days, setDays] = useState(30);
  const [realOnly, setRealOnly] = useStoredBool("ol-real-only", true);
  const [tick, setTick] = useState(0);
  const [fresh, setFresh] = useState(new Set());
  const seenKeys = useRef(null);

  // poll everything on the page every 30 s
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), REFRESH_MS);
    return () => clearInterval(t);
  }, []);

  const scope = { real_only: realOnly };
  const { data: s, error } = useApi("/api/stats", { days, ...scope }, [tick]);
  const { data: geo } = useApi("/api/victims/stats", { days, ...scope }, [tick]);
  const { data: feed } = useApi("/api/activity", { limit: 40, ...scope }, [tick]);
  const { data: alerts } = useApi("/api/alerts", { status: "new", limit: 6 }, [tick]);

  // highlight events that arrived since the previous poll
  useEffect(() => {
    if (!feed) return;
    const keys = feed.items.map((i) => i.key);
    if (seenKeys.current) setFresh(new Set(keys.filter((k) => !seenKeys.current.has(k))));
    seenKeys.current = new Set([...(seenKeys.current || []), ...keys]);
  }, [feed]);

  const openAlerts = s ? Object.values(s.alerts_open).reduce((a, b) => a + b, 0) : 0;
  const delta = s && days ? s.documents - s.documents_prev : null;
  const ac = feed?.auto_collect?.ransomware;
  const pulses = (feed?.items || []).filter((i) => i.country_numeric).slice(0, 15).map((i) => ({ numeric: i.country_numeric, title: i.title, at: i.at }));

  return (
    <>
      <PageHead title="Threat overview" sub="Attacks, leaks and illicit trade surfacing across monitored dark web sources">
        <label className="toggle" title="Hide the synthetic [demo] dataset">
          <input type="checkbox" checked={realOnly} onChange={(e) => setRealOnly(e.target.checked)} />
          Real data only
        </label>
        <Seg options={RANGES} value={days} onChange={setDays} />
      </PageHead>
      <ErrorBanner error={error} />
      {s && (
        <>
          <div className="grid kpis">
            <Kpi
              label="Documents analysed"
              value={fmt.n(s.documents)}
              delta={delta !== null ? `${delta >= 0 ? "+" : "−"}${fmt.n(Math.abs(delta))} vs previous ${days}d` : null}
            />
            <Kpi label="Ransomware attacks" value={fmt.n(s.victims)} />
            <Kpi label="High-risk (score ≥ 60)" value={fmt.n(s.high_risk)} />
            <Kpi
              label="Open alerts"
              value={fmt.n(openAlerts)}
              delta={s.alerts_open.critical ? `${s.alerts_open.critical} critical` : "none critical"}
              deltaClass={s.alerts_open.critical ? "up-bad" : ""}
            />
            <Kpi label="Indicators" value={fmt.n(s.indicators)} />
            <Kpi label="Sources online" value={`${s.sources_up} / ${s.sources}`} />
          </div>

          <div className="grid cols-2" style={{ marginBottom: 16 }}>
            <Card
              title="Global attack map"
              sub={`Ransomware victims by country${days ? ` · last ${days} days` : ""} · pulses mark the newest attacks · click a country`}
            >
              {geo?.by_country?.length ? (
                <WorldMap rows={geo.by_country} pulses={pulses} onSelect={(c) => c && go("ransomware")} />
              ) : (
                <Empty>No geolocated attacks in this period.</Empty>
              )}
            </Card>
            <Card
              title="Live activity"
              sub={
                feed
                  ? `Newest data pulled ${fmt.ago(feed.last_collected_at)}${ac ? ` · auto-collect every ${Math.round(ac.interval_seconds / 60)} min` : ""}`
                  : ""
              }
              actions={
                <span className={`live-badge ${ac ? "" : "off"}`} title={ac ? "Auto-collection running; page refreshes every 30 s" : "Page refreshes every 30 s; background collection is off"}>
                  <i />
                  {ac?.running ? "COLLECTING" : "LIVE"}
                </span>
              }
            >
              <LiveFeed data={feed} fresh={fresh} openDoc={openDoc} openInd={openInd} />
            </Card>
          </div>

          <div className="grid cols-3">
            <Card title="Newest alerts" sub="Watchlist matches awaiting triage" actions={<button className="btn small" onClick={() => go("alerts")}>All alerts</button>}>
              {!alerts?.length ? (
                <Empty>No open alerts.</Empty>
              ) : (
                alerts.map((a) => (
                  <div key={a.id} className="list-item" onClick={() => a.document_id && openDoc(a.document_id)}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <Sev level={a.severity} />
                      <span className="title" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.watch_value}</span>
                    </div>
                    <div className="meta">
                      <span className="mono">{a.matched}</span>
                      <span>{fmt.ago(a.created_at)}</span>
                    </div>
                  </div>
                ))
              )}
            </Card>
            <Card title="Content categories" sub="Click a category to investigate">
              <CountTable
                name="Category"
                unit="Documents"
                rows={s.categories.map((c) => ({ key: c.id, label: c.label, value: c.count }))}
                onClick={(r) => go(`investigate?category=${r.key}`)}
              />
            </Card>
            <Card title="Indicator types" sub="Click to browse">
              <CountTable
                name="Type"
                unit="Indicators"
                rows={Object.entries(s.indicator_types)
                  .sort((a, b) => b[1] - a[1])
                  .map(([k, v]) => ({ key: k, label: IOC_LABELS[k] || k, value: v }))}
                onClick={(r) => go(`indicators?type=${r.key}`)}
              />
            </Card>
          </div>

          {s.attack.length > 0 && (
            <Card title="MITRE ATT&CK techniques" sub="Mapped from content · click to open on attack.mitre.org" style={{ marginTop: 16 }}>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Technique</th>
                      <th>Tactic</th>
                      <th className="num">Documents</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.attack.slice(0, 10).map((t) => (
                      <tr key={t.id} className="clickable" onClick={() => window.open(t.url, "_blank", "noopener")}>
                        <td className="mono">{t.id}</td>
                        <td>{t.name}</td>
                        <td className="secondary">{t.tactic}</td>
                        <td className="num">{fmt.n(t.count)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}
    </>
  );
}
