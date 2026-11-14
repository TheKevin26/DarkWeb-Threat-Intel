import { Fragment, useState } from "react";
import { IOC_LABELS, fmt, useApi } from "../api.js";
import { Card, Empty, ErrorBanner, PageHead } from "../components.jsx";

export default function Actors({ openDoc, openInd }) {
  const { data: actors, error } = useApi("/api/actors");
  const { data: wallets } = useApi("/api/wallets");
  const [open, setOpen] = useState(null);

  return (
    <>
      <PageHead
        title="Threat actors"
        sub="Personas linked across sites by shared identifiers (PGP keys, wallets, Jabber, Tox, Telegram)"
      />
      <ErrorBanner error={error} />
      <Card>
        {!actors ? (
          <Empty>Loading…</Empty>
        ) : actors.length === 0 ? (
          <Empty>No linked personas yet.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Actor</th>
                  <th>Aliases</th>
                  <th className="num">Posts</th>
                  <th className="num">Sources</th>
                  <th className="num">Strong identifiers</th>
                  <th>Main activity</th>
                </tr>
              </thead>
              <tbody>
                {actors.map((c) => (
                  <Fragment key={c.id}>
                    <tr className="clickable" onClick={() => setOpen(open === c.id ? null : c.id)}>
                      <td>
                        <span style={{ fontWeight: 600 }}>{open === c.id ? "▾" : "▸"} {c.name}</span>{" "}
                        {c.cross_site && <span className="tag">cross-site</span>}
                      </td>
                      <td className="secondary">{c.aliases.join(", ") || "—"}</td>
                      <td className="num">{c.document_count}</td>
                      <td className="num">{c.sources.length}</td>
                      <td className="num">{c.strong_links}</td>
                      <td className="secondary">{c.top_categories.join(", ").replaceAll("_", " ")}</td>
                    </tr>
                    {open === c.id && (
                      <tr>
                        <td colSpan={6} style={{ background: "var(--surface-2)" }}>
                          <div className="grid cols-2e" style={{ gap: 24 }}>
                            <div>
                              <div className="secondary" style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>IDENTIFIERS</div>
                              {Object.entries(c.identifiers).map(([type, values]) =>
                                values.map((v) => (
                                  <div key={type + v} className="ident">
                                    <span className="tag" style={{ minWidth: 90 }}>{IOC_LABELS[type] || type}</span>
                                    <span className="mono">{v}</span>
                                  </div>
                                )),
                              )}
                            </div>
                            <div>
                              <div className="secondary" style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>SEEN ON</div>
                              <div style={{ marginBottom: 12 }}>{c.sources.join(", ")}</div>
                              <div className="secondary" style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>POSTS</div>
                              <div className="chips">
                                {c.document_ids.map((id) => (
                                  <button key={id} className="chip" onClick={() => openDoc(id)}>
                                    #{id}
                                  </button>
                                ))}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card
        title="Tracked payment wallets"
        sub={wallets ? `BTC addresses from dark web posts, checked hourly on the public blockchain · ${wallets.checked} of ${wallets.tracked} checked so far` : ""}
        style={{ marginTop: 16 }}
      >
        {!wallets ? (
          <Empty>Loading…</Empty>
        ) : wallets.items.length === 0 ? (
          <Empty>No wallets checked yet.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th className="num">Transactions</th>
                  <th className="num">Received (BTC)</th>
                  <th className="num">Balance (BTC)</th>
                  <th>Last transaction</th>
                  <th>Checked</th>
                </tr>
              </thead>
              <tbody>
                {wallets.items.slice(0, 25).map((w) => (
                  <tr key={w.id} className="clickable" onClick={() => openInd(w.id)}>
                    <td className="mono">{w.address}</td>
                    <td className="num">{fmt.n(w.tx_count)}{w.pending_tx ? ` +${w.pending_tx}` : ""}</td>
                    <td className="num">{w.received_btc.toFixed(5)}</td>
                    <td className="num">{w.balance_btc.toFixed(5)}</td>
                    <td className="secondary">{w.last_tx_at ? fmt.datetime(w.last_tx_at) : "never used"}</td>
                    <td className="secondary">{fmt.ago(w.checked_at)}</td>
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
