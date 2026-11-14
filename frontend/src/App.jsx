import { useCallback, useEffect, useState } from "react";
import { useApi } from "./api.js";
import { DocDrawer, IndicatorDrawer } from "./components.jsx";
import Actors from "./pages/Actors.jsx";
import Alerts from "./pages/Alerts.jsx";
import Indicators from "./pages/Indicators.jsx";
import Investigate from "./pages/Investigate.jsx";
import Overview from "./pages/Overview.jsx";
import Ransomware from "./pages/Ransomware.jsx";
import Settings from "./pages/Settings.jsx";
import ThreatMap from "./pages/ThreatMap.jsx";

const PAGES = [
  ["live", "Live threat map", ThreatMap, "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.9 6h-2.9a15.7 15.7 0 0 0-1.4-3.6A8 8 0 0 1 18.9 8zM12 4c.8 1.2 1.5 2.5 1.9 4h-3.8c.4-1.5 1.1-2.8 1.9-4zM4.3 14a8.2 8.2 0 0 1 0-4h3.4a16.5 16.5 0 0 0 0 4zm.8 2h2.9c.3 1.3.8 2.5 1.4 3.6A8 8 0 0 1 5.1 16zM8 8H5.1a8 8 0 0 1 4.3-3.6C8.8 5.5 8.3 6.7 8 8zm4 12c-.8-1.2-1.5-2.5-1.9-4h3.8c-.4 1.5-1.1 2.8-1.9 4zm2.3-6H9.7a14.7 14.7 0 0 1 0-4h4.6a14.7 14.7 0 0 1 0 4zm.3 5.6c.6-1.1 1.1-2.3 1.4-3.6h2.9a8 8 0 0 1-4.3 3.6zm1.8-5.6a16.5 16.5 0 0 0 0-4h3.4a8.2 8.2 0 0 1 0 4z"],
  ["overview", "Overview", Overview, "M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z"],
  ["alerts", "Alerts", Alerts, "M12 2 1 21h22L12 2zm1 15h-2v-2h2zm0-4h-2V9h2z"],
  ["investigate", "Investigate", Investigate, "M15.5 14h-.8l-.3-.3A6.5 6.5 0 1 0 9.5 16a6.5 6.5 0 0 0 4.2-1.6l.3.3v.8l5 5 1.5-1.5zm-6 0a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z"],
  ["indicators", "Indicators", Indicators, "M4 6h16v2H4zm0 5h16v2H4zm0 5h10v2H4z"],
  ["ransomware", "Ransomware", Ransomware, "M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5zm0 6a2 2 0 0 1 2 2v1h1v6H9v-6h1V9a2 2 0 0 1 2-2zm0 1.2a.8.8 0 0 0-.8.8v1h1.6V9a.8.8 0 0 0-.8-.8z"],
  ["actors", "Threat actors", Actors, "M17 12a3 3 0 1 0-2.8-4.1L9.9 10a3 3 0 1 0 0 4l4.3 2.1A3 3 0 1 0 15 14.3l-4.3-2.1a3 3 0 0 0 0-.4l4.3-2.1A3 3 0 0 0 17 12z"],
  ["settings", "Watchlist & sources", Settings, "M19.4 13a7.6 7.6 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7.4 7.4 0 0 0-1.7-1L15 3h-4l-.4 2.7a7.4 7.4 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.6 7.6 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1a7.4 7.4 0 0 0 1.7 1L11 21h4l.4-2.7a7.4 7.4 0 0 0 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z"],
];

function readHash() {
  const p = window.location.hash.replace("#/", "").split("?")[0];
  return PAGES.some(([id]) => id === p) ? p : "live";
}

export default function App() {
  const [page, setPage] = useState(readHash);
  const [doc, setDoc] = useState(null);
  const [ind, setInd] = useState(null);
  const { data: alertCount, reload: reloadAlerts } = useApi("/api/alerts", { status: "new", limit: 1000 });

  useEffect(() => {
    const h = () => setPage(readHash());
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);

  const go = (id) => {
    window.location.hash = `#/${id}`;
  };
  const openDoc = useCallback((id) => {
    setInd(null);
    setDoc(id);
  }, []);
  const openInd = useCallback((id) => {
    setDoc(null);
    setInd(id);
  }, []);

  const Page = PAGES.find(([id]) => id === page)[2];

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
            <circle cx="16" cy="16" r="13" fill="none" stroke="var(--accent)" strokeWidth="3" />
            <circle cx="16" cy="16" r="7" fill="none" stroke="var(--accent)" strokeWidth="2" opacity=".55" />
            <circle cx="16" cy="16" r="3" fill="var(--accent)" />
          </svg>
          OnionLens
        </div>
        {PAGES.map(([id, label, , icon]) => (
          <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => go(id)}>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d={icon} />
            </svg>
            {label}
            {id === "alerts" && alertCount?.length > 0 && <span className="count">{alertCount.length}</span>}
          </button>
        ))}
        <div className="spacer" />
        <div className="foot">Passive collection only · secrets redacted at ingest</div>
      </nav>
      <main>
        <Page openDoc={openDoc} openInd={openInd} go={go} onAlertsChanged={reloadAlerts} />
      </main>
      {doc && <DocDrawer id={doc} onClose={() => setDoc(null)} onIndicator={openInd} />}
      {ind && <IndicatorDrawer id={ind} onClose={() => setInd(null)} onDoc={openDoc} onIndicator={openInd} />}
    </div>
  );
}
