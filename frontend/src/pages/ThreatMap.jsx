import { geoCentroid, geoNaturalEarth1, geoPath } from "d3-geo";
import { useEffect, useMemo, useRef, useState } from "react";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import { fmt, useApi } from "../api.js";

// --- static geography ---------------------------------------------------------------------------

const COUNTRIES = feature(world, world.objects.countries).features.filter((f) => f.properties.name !== "Antarctica");
const LAND = { type: "FeatureCollection", features: COUNTRIES };
const CENTROID = Object.fromEntries(COUNTRIES.map((f) => [String(+f.id), geoCentroid(f)]));
// countries too small for the 110m atlas
const EXTRA = { "702": [103.8, 1.35], "344": [114.17, 22.3], "048": [50.55, 26.07], "470": [14.4, 35.9], "442": [6.13, 49.6] };
const HUB = [-24, -24]; // where arcs start: the "dark web" (leak-site origin is not geolocatable)

// categorical slots (dark-surface steps), fixed per group by rank in the window; the 8th slot = "other"
const SLOTS = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9"];
const OTHER = "#b8b6ad";

const TRAVEL = 1700; // ms an arc takes to reach its target
const LINGER = 2600; // ms the impact + label stays
const SPAWN_EVERY = 1100; // ms between replayed attacks
const POLL = 30_000;

function useSize(ref) {
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, [ref]);
  return size;
}

function setupCanvas(canvas, w, h) {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  canvas.style.width = `${w}px`;
  canvas.style.height = `${h}px`;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

function CountUp({ value }) {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    let raf;
    const step = (t) => {
      const p = Math.min(1, (t - start) / 900);
      setShown(Math.round(a + (value - a) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(step);
      else from.current = value;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{shown.toLocaleString()}</>;
}

// --- bottom panel -------------------------------------------------------------------------------

function Ranking({ rows, colorOf }) {
  if (!rows?.length) return <div className="tm-empty">No data in this window.</div>;
  return (
    <ol className="tm-rank">
      {rows.map((r, i) => (
        <li key={r.name}>
          <span className="tm-rank-n">{i + 1}</span>
          {colorOf && <i style={{ background: colorOf(r.name) }} />}
          <span className="tm-rank-name">{r.name}</span>
          <span className="tm-rank-v">{fmt.n(r.count)}</span>
        </li>
      ))}
    </ol>
  );
}

function Panel({ data, colorOf, open, setOpen, openDoc }) {
  const [slide, setSlide] = useState(0);
  const slides = [
    { title: "Top targeted countries", sub: "Most leak-site victims in the selected window", body: <Ranking rows={data?.top_countries.map((c) => ({ name: c.name || c.code, count: c.count }))} /> },
    { title: "Most active threat groups", sub: "Groups posting the most victims · colors match the map", body: <Ranking rows={data?.top_groups} colorOf={colorOf} /> },
    { title: "Most targeted industries", sub: "Victim sectors in the selected window", body: <Ranking rows={data?.top_sectors} /> },
    {
      title: "Latest attacks",
      sub: "Newest victim postings · click to open the evidence",
      body: (
        <div className="tm-latest">
          {(data?.events || []).slice(0, 8).map((e) => (
            <button key={e.id} onClick={() => openDoc(e.document_id)}>
              <i style={{ background: colorOf(e.group) }} />
              <b>{e.group}</b> → {e.victim}
              <span>{e.country_name || "Unknown"} · {fmt.ago(e.at)}</span>
            </button>
          ))}
        </div>
      ),
    },
  ];
  useEffect(() => {
    if (!open) return;
    const t = setInterval(() => setSlide((s) => (s + 1) % slides.length), 9000);
    return () => clearInterval(t);
  }, [open, slides.length]);
  const s = slides[slide];
  return (
    <div className={`tm-panel ${open ? "open" : ""}`}>
      <button className="tm-chevron" onClick={() => setOpen(!open)} aria-label={open ? "Hide statistics" : "Show statistics"}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
          <circle cx="12" cy="12" r="10" />
          <path d={open ? "M8 10.5l4 4 4-4" : "M8 13.5l4-4 4 4"} />
        </svg>
      </button>
      {open && (
        <>
          <div className="tm-panel-title">{s.title}</div>
          <div className="tm-panel-sub">{s.sub}</div>
          <div className="tm-panel-body">{s.body}</div>
          <div className="tm-dots">
            {slides.map((x, i) => (
              <button key={x.title} className={i === slide ? "on" : ""} onClick={() => setSlide(i)} aria-label={x.title} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// --- page ---------------------------------------------------------------------------------------

export default function ThreatMap({ go, openDoc }) {
  const wrap = useRef(null);
  const base = useRef(null);
  const fx = useRef(null);
  const { w, h } = useSize(wrap);
  const [hours, setHours] = useState(168);
  const [realOnly, setRealOnly] = useState(() => {
    try {
      return localStorage.getItem("ol-real-only") !== "0";
    } catch {
      return true;
    }
  });
  const [panelOpen, setPanelOpen] = useState(true);
  const [tick, setTick] = useState(0);
  const { data } = useApi("/api/map", { hours, real_only: realOnly, limit: 600 }, [tick]);

  const queue = useRef([]); // events waiting to fly
  const replay = useRef({ list: [], i: 0 });
  const arcs = useRef([]);
  const seenMax = useRef(0);
  const projRef = useRef(null);

  useEffect(() => {
    try {
      localStorage.setItem("ol-real-only", realOnly ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [realOnly]);

  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), POLL);
    return () => clearInterval(t);
  }, []);

  // fixed group -> color, by rank in the current window
  const groupColor = useMemo(() => {
    const m = {};
    (data?.top_groups || []).slice(0, SLOTS.length).forEach((g, i) => (m[g.name] = SLOTS[i]));
    return m;
  }, [data]);
  const colorOf = (g) => groupColor[g] || OTHER;

  // new data: brand-new postings jump the queue, everything else becomes the replay loop
  useEffect(() => {
    if (!data) return;
    const located = data.events.filter((e) => e.numeric && (CENTROID[String(+e.numeric)] || EXTRA[e.numeric]));
    if (seenMax.current) {
      located.filter((e) => e.id > seenMax.current).reverse().forEach((e) => queue.current.push({ ...e, isNew: true }));
    }
    seenMax.current = Math.max(seenMax.current, data.max_id);
    replay.current = { list: located, i: 0 };
  }, [data]);

  // static layer: dotted continents
  useEffect(() => {
    if (!w || !h) return;
    const top = 96;
    const bottom = panelOpen ? 230 : 56;
    const proj = geoNaturalEarth1().fitExtent([[24, top], [w - 24, h - bottom]], LAND);
    projRef.current = proj;
    const ctx = setupCanvas(base.current, w, h);
    ctx.clearRect(0, 0, w, h);

    // rasterize land offscreen, then sample a dot grid from it
    const off = document.createElement("canvas");
    off.width = Math.ceil(w);
    off.height = Math.ceil(h);
    const octx = off.getContext("2d");
    octx.fillStyle = "#fff";
    octx.beginPath();
    geoPath(proj, octx)(LAND);
    octx.fill();
    const px = octx.getImageData(0, 0, off.width, off.height).data;
    const gap = Math.max(5, Math.round(w / 230));
    ctx.fillStyle = "rgba(240, 239, 236, 0.30)";
    for (let y = gap / 2; y < h; y += gap) {
      for (let x = gap / 2; x < w; x += gap) {
        if (px[(Math.floor(y) * off.width + Math.floor(x)) * 4 + 3] > 0) {
          ctx.beginPath();
          ctx.arc(x, y, gap * 0.3, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    }
  }, [w, h, panelOpen]);

  // spawner
  useEffect(() => {
    const t = setInterval(() => {
      const proj = projRef.current;
      if (!proj) return;
      let ev = queue.current.shift();
      if (!ev) {
        const r = replay.current;
        if (!r.list.length) return;
        ev = r.list[r.i % r.list.length];
        r.i += 1;
      }
      const ll = CENTROID[String(+ev.numeric)] || EXTRA[ev.numeric];
      const jitter = () => (Math.random() - 0.5) * 2.5;
      const target = proj([ll[0] + jitter(), ll[1] + jitter()]);
      const src = proj([HUB[0] + jitter() * 3, HUB[1] + jitter()]);
      if (!target || !src) return;
      arcs.current.push({ s: src, t: target, color: colorOf(ev.group), start: performance.now(), ev });
      if (arcs.current.length > 40) arcs.current.shift();
    }, SPAWN_EVERY);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupColor]);

  // animation layer
  useEffect(() => {
    if (!w || !h) return;
    const ctx = setupCanvas(fx.current, w, h);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf;
    const bez = (a, c, b, t) => [
      (1 - t) * (1 - t) * a[0] + 2 * (1 - t) * t * c[0] + t * t * b[0],
      (1 - t) * (1 - t) * a[1] + 2 * (1 - t) * t * c[1] + t * t * b[1],
    ];
    const frame = (now) => {
      ctx.clearRect(0, 0, w, h);
      const proj = projRef.current;

      // hub
      if (proj) {
        const [hx, hy] = proj(HUB);
        const ph = (now % 2400) / 2400;
        for (const k of [0, 0.5]) {
          const p = (ph + k) % 1;
          ctx.strokeStyle = `rgba(230, 103, 103, ${0.55 * (1 - p)})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(hx, hy, 6 + p * 22, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.fillStyle = "#e66767";
        ctx.beginPath();
        ctx.arc(hx, hy, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.font = "600 11px system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.fillStyle = "rgba(240, 239, 236, 0.85)";
        ctx.fillText("DARK WEB LEAK SITES", hx, hy + 30);
      }

      arcs.current = arcs.current.filter((a) => now - a.start < TRAVEL + LINGER);
      for (const a of arcs.current) {
        const age = now - a.start;
        const p = reduce ? 1 : Math.min(1, age / TRAVEL);
        const dx = a.t[0] - a.s[0];
        const dy = a.t[1] - a.s[1];
        const dist = Math.hypot(dx, dy);
        const c = [(a.s[0] + a.t[0]) / 2, Math.min(a.s[1], a.t[1]) - dist * 0.32];
        const fade = age > TRAVEL ? 1 - (age - TRAVEL) / LINGER : 1;

        // trail: segments brighten toward the head
        const n = 36;
        const tail = 0.55;
        ctx.lineCap = "round";
        for (let i = 0; i < n; i++) {
          const t0 = (i / n) * p;
          const t1 = ((i + 1) / n) * p;
          const rel = p <= 0 ? 0 : t1 / p;
          const alpha = (age > TRAVEL ? 0.6 : Math.max(0.08, (rel - (1 - tail)) / tail)) * fade;
          if (alpha <= 0.01) continue;
          const [x0, y0] = bez(a.s, c, a.t, t0);
          const [x1, y1] = bez(a.s, c, a.t, t1);
          ctx.strokeStyle = a.color;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 2.6;
          ctx.beginPath();
          ctx.moveTo(x0, y0);
          ctx.lineTo(x1, y1);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;

        if (p < 1) {
          const [hx, hy] = bez(a.s, c, a.t, p);
          ctx.fillStyle = "#fff";
          ctx.shadowColor = a.color;
          ctx.shadowBlur = 12;
          ctx.beginPath();
          ctx.arc(hx, hy, 2.6, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          // impact ripple + pin + label
          const ip = (age - TRAVEL) / LINGER;
          ctx.strokeStyle = a.color;
          ctx.globalAlpha = Math.max(0, 1 - ip * 1.4);
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.arc(a.t[0], a.t[1], 4 + ip * 26, 0, Math.PI * 2);
          ctx.stroke();
          ctx.globalAlpha = fade;
          ctx.fillStyle = a.color;
          ctx.beginPath();
          ctx.arc(a.t[0], a.t[1], 4, 0, Math.PI * 2);
          ctx.fill();

          const label = `${a.ev.isNew ? "NEW · " : ""}${a.ev.country_name || ""}`;
          const sub = `${a.ev.group} → ${a.ev.victim}`.slice(0, 48);
          ctx.textAlign = "left";
          ctx.lineWidth = 3;
          ctx.strokeStyle = "rgba(13, 13, 13, 0.85)";
          ctx.font = "600 12px system-ui, sans-serif";
          ctx.strokeText(label, a.t[0] + 9, a.t[1] - 8);
          ctx.fillStyle = a.ev.isNew ? "#e66767" : "#f0efec";
          ctx.fillText(label, a.t[0] + 9, a.t[1] - 8);
          ctx.font = "11px system-ui, sans-serif";
          ctx.strokeText(sub, a.t[0] + 9, a.t[1] + 6);
          ctx.fillStyle = "rgba(195, 194, 183, 0.95)";
          ctx.fillText(sub, a.t[0] + 9, a.t[1] + 6);
          ctx.globalAlpha = 1;
        }
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [w, h]);

  const windowLabel = { 24: "24 hours", 168: "7 days", 720: "30 days" }[hours];

  return (
    <div className="tm" ref={wrap}>
      <canvas ref={base} className="tm-layer" />
      <canvas ref={fx} className="tm-layer" />
      <div className="tm-bar" />
      <header className="tm-head">
        <button className="tm-brand" onClick={() => go("overview")} title="Open the analyst dashboard">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
            <circle cx="16" cy="16" r="13" fill="none" stroke="#e66767" strokeWidth="3" />
            <circle cx="16" cy="16" r="3.5" fill="#e66767" />
          </svg>
          OnionLens
        </button>
        <div className="tm-title">
          <h1>DARK WEB THREAT MAP</h1>
          <div className="tm-counter">
            <CountUp value={data?.counts.last_24h ?? 0} /> ATTACKS POSTED IN THE LAST 24 HOURS
          </div>
        </div>
        <div className="tm-controls">
          <label className="tm-toggle">
            <input type="checkbox" checked={realOnly} onChange={(e) => setRealOnly(e.target.checked)} />
            Real data only
          </label>
          <select value={hours} onChange={(e) => setHours(+e.target.value)} aria-label="Time window">
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
            <option value={720}>Last 30 days</option>
          </select>
          <button className="tm-btn" onClick={() => go("overview")}>Dashboard →</button>
        </div>
      </header>
      <div className="tm-note">
        Replaying {fmt.n(data?.counts.window ?? 0)} {realOnly ? "real " : ""}leak-site postings from the last {windowLabel} · new postings fly in as they are
        collected · arcs start at the dark web because attacker locations are not known
      </div>
      <Panel data={data} colorOf={colorOf} open={panelOpen} setOpen={setPanelOpen} openDoc={openDoc} />
    </div>
  );
}
