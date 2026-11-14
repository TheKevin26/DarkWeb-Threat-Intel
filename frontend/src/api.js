import { useCallback, useEffect, useState } from "react";

const KEY = import.meta.env.VITE_API_KEY;

export async function api(path, { method = "GET", body, params } = {}) {
  const url = new URL(path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    });
  }
  const res = await fetch(url, {
    method,
    headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...(KEY ? { "X-API-Key": KEY } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* not json */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.status === 204 ? null : res.json();
}

export function exportUrl(fmt, types) {
  const u = new URL(`/api/export/${fmt}`, window.location.origin);
  if (types) u.searchParams.set("types", types);
  return u.toString();
}

/** Fetch hook that re-runs when `deps` change. */
export function useApi(path, params, deps = []) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const key = JSON.stringify([path, params]);
  const load = useCallback(() => {
    if (!path) return;
    setState((s) => ({ ...s, loading: true }));
    api(path, { params })
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => setState({ data: null, error, loading: false }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(load, [load, ...deps]);
  return { ...state, reload: load };
}

export const fmt = {
  n: (v) => (v ?? 0).toLocaleString(),
  date: (v) => (v ? new Date(v + (String(v).endsWith("Z") ? "" : "Z")).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : "—"),
  datetime: (v) =>
    v ? new Date(v + (String(v).endsWith("Z") ? "" : "Z")).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—",
  ago: (v) => {
    if (!v) return "—";
    const s = (Date.now() - new Date(v + (String(v).endsWith("Z") ? "" : "Z")).getTime()) / 1000;
    if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  },
};

export const IOC_LABELS = {
  credential: "Credential",
  email: "Email",
  card: "Card",
  domain: "Domain",
  onion: "Onion",
  ipv4: "IPv4",
  btc_address: "BTC wallet",
  xmr_address: "XMR wallet",
  eth_address: "ETH wallet",
  pgp_fingerprint: "PGP key",
  jabber: "Jabber",
  tox_id: "Tox ID",
  telegram: "Telegram",
  handle: "Handle",
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
  cve: "CVE",
};
