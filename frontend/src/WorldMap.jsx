import { geoCentroid } from "d3-geo";
import { useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import world from "world-atlas/countries-110m.json";
import { fmt } from "./api.js";

const STEPS = ["--seq-100", "--seq-250", "--seq-400", "--seq-550", "--seq-700"];

/**
 * Choropleth of attacks per country, plus pulsing markers on the countries of the newest events.
 * rows:   [{code, name, numeric, count}]
 * pulses: [{numeric, title, label, at}]
 */
export default function WorldMap({ rows, pulses = [], selected, onSelect }) {
  const [tip, setTip] = useState(null);
  const byId = useMemo(() => Object.fromEntries(rows.filter((r) => r.numeric).map((r) => [String(+r.numeric), r])), [rows]);
  const pulseById = useMemo(() => {
    const m = {};
    pulses.forEach((p) => {
      const k = String(+p.numeric);
      if (p.numeric && !m[k]) m[k] = p;
    });
    return m;
  }, [pulses]);
  const max = Math.max(1, ...rows.map((r) => r.count));
  // log-scaled bins - attack counts are heavily skewed toward a few countries
  const bin = (n) => Math.min(STEPS.length - 1, Math.floor((Math.log(n) / Math.log(max + 1)) * STEPS.length));

  const showTip = (e, name, count, pulse) => {
    const box = e.currentTarget.ownerSVGElement.parentNode.getBoundingClientRect();
    setTip({ x: e.clientX - box.left, y: e.clientY - box.top, name, count, pulse });
  };

  return (
    <div className="map-wrap" onMouseLeave={() => setTip(null)}>
      <ComposableMap projection="geoEqualEarth" projectionConfig={{ scale: 150, center: [10, 8] }} width={800} height={400}>
        <Geographies geography={world}>
          {({ geographies }) => {
            const land = geographies.filter((g) => g.properties.name !== "Antarctica");
            return (
              <>
                {land.map((geo) => {
                  const r = byId[String(+geo.id)];
                  const isSel = r && selected === r.code;
                  const fill = r ? `var(${STEPS[bin(r.count)]})` : "var(--map-empty)";
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      onMouseMove={(e) => showTip(e, r?.name || geo.properties.name, r?.count || 0, pulseById[String(+geo.id)])}
                      onClick={() => r && onSelect?.(isSel ? "" : r.code)}
                      style={{
                        default: { fill, stroke: isSel ? "var(--text-primary)" : "var(--surface-1)", strokeWidth: isSel ? 1.5 : 0.5, outline: "none" },
                        hover: { fill, stroke: "var(--text-primary)", strokeWidth: 1, outline: "none", cursor: r ? "pointer" : "default" },
                        pressed: { fill, outline: "none" },
                      }}
                    />
                  );
                })}
                {land
                  .filter((geo) => pulseById[String(+geo.id)])
                  .map((geo) => (
                    <Marker key={`p-${geo.rsmKey}`} coordinates={geoCentroid(geo)}>
                      <circle r={5} className="pulse-ring" />
                      <circle r={4} className="pulse-core" />
                    </Marker>
                  ))}
              </>
            );
          }}
        </Geographies>
      </ComposableMap>
      {tip && (
        <div className="map-tip" style={{ left: tip.x + 14, top: tip.y + 14 }}>
          <div className="t">{tip.name}</div>
          <div className="v">{fmt.n(tip.count)} attacks</div>
          {tip.pulse && (
            <div className="t" style={{ marginTop: 3, maxWidth: 260, whiteSpace: "normal" }}>
              Latest: {tip.pulse.title} · {fmt.ago(tip.pulse.at)}
            </div>
          )}
        </div>
      )}
      <div className="scale" aria-label="Map legend">
        <span>Fewer</span>
        {STEPS.map((s) => (
          <i key={s} style={{ background: `var(${s})` }} />
        ))}
        <span>More attacks (log scale, max {fmt.n(max)})</span>
        <span style={{ marginLeft: 12, display: "inline-flex", alignItems: "center", gap: 6 }}>
          <i className="dot" /> latest activity
        </span>
      </div>
    </div>
  );
}
