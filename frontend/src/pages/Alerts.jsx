import { useState } from "react";
import { api, fmt, useApi } from "../api.js";
import { Card, Empty, ErrorBanner, PageHead, Seg, Sev } from "../components.jsx";

export default function Alerts({ openDoc, onAlertsChanged }) {
  const [status, setStatus] = useState("new");
  const [severity, setSeverity] = useState("");
  const { data, error, reload } = useApi("/api/alerts", { status, severity, limit: 500 });

  const setAlert = async (id, next) => {
    await api(`/api/alerts/${id}`, { method: "PATCH", body: { status: next } });
    reload();
    onAlertsChanged?.();
  };

  return (
    <>
      <PageHead title="Alerts" sub="Watchlist assets found in collected data">
        <Seg
          options={[["new", "New"], ["acknowledged", "Acknowledged"], ["resolved", "Resolved"], ["", "All"]]}
          value={status}
          onChange={setStatus}
        />
        <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </PageHead>
      <ErrorBanner error={error} />
      <Card>
        {!data ? (
          <Empty>Loading…</Empty>
        ) : data.length === 0 ? (
          <Empty>No alerts match these filters.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Watch item</th>
                  <th>Match</th>
                  <th>Where</th>
                  <th>When</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => a.document_id && openDoc(a.document_id)}>
                    <td>
                      <Sev level={a.severity} />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{a.watch_value}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{a.watch_kind.replace("_", " ")}</div>
                    </td>
                    <td style={{ maxWidth: 380 }}>
                      <div className="mono">{a.matched}</div>
                      <div className="secondary" style={{ fontSize: 12.5 }}>{a.snippet}</div>
                    </td>
                    <td style={{ maxWidth: 240 }}>
                      <div>{a.document_title}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{a.source}</div>
                    </td>
                    <td className="secondary" style={{ whiteSpace: "nowrap" }}>{fmt.datetime(a.created_at)}</td>
                    <td style={{ whiteSpace: "nowrap" }} onClick={(e) => e.stopPropagation()}>
                      {a.status === "new" && (
                        <button className="btn small" onClick={() => setAlert(a.id, "acknowledged")}>Acknowledge</button>
                      )}{" "}
                      {a.status !== "resolved" ? (
                        <button className="btn small" onClick={() => setAlert(a.id, "resolved")}>Resolve</button>
                      ) : (
                        <button className="btn small" onClick={() => setAlert(a.id, "new")}>Reopen</button>
                      )}
                    </td>
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
