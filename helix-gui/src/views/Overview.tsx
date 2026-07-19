import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { HistoryEntry, Overview as OverviewData } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

export default function Overview({
  node,
  onSend,
  onReceive,
}: {
  node: string;
  onSend: () => void;
  onReceive: () => void;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [ov, hist] = await Promise.all([api.getOverview(node), api.getHistory(node, 25)]);
      setData(ov);
      setHistory(hist);
    } catch (e) {
      setError(String(e));
    }
  }, [node]);

  useEffect(() => {
    load();
    const id = setInterval(load, 6000);
    return () => clearInterval(id);
  }, [load]);

  const copy = async () => {
    if (!data) return;
    await navigator.clipboard.writeText(data.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="stack">
      {error && <div className="error">{error}</div>}

      <div className="metric-row">
        <Metric label="Available" value={data ? hlx(data.balance_hlx) : "…"} unit="HLX" />
        <Metric label="Staked" value={data ? hlx(data.staked_hlx) : "…"} unit="HLX" />
        <Metric label="Unbonding" value={data ? hlx(data.unbonding_hlx) : "…"} unit="HLX" />
      </div>

      <div className="card address-card">
        <div className="address-block">
          <div className="muted small">Your address</div>
          <div className="mono address">{data?.address ?? "…"}</div>
        </div>
        <div className="row-actions">
          <button onClick={copy}>{copied ? "Copied" : "Copy"}</button>
          <button onClick={onSend}>Send</button>
          <button onClick={onReceive}>Receive</button>
        </div>
      </div>

      <div>
        <div className="section-title">Recent activity</div>
        <div className="card list">
          {history.length === 0 && <div className="empty muted">No transactions yet.</div>}
          {history.map((t) => (
            <div className="list-row" key={t.hash}>
              <div className="list-main">
                <div className="list-title">
                  {t.tx_type}
                  {t.to ? <span className="muted"> → {shortAddr(t.to)}</span> : null}
                </div>
                <div className="muted small">
                  block {t.block_height.toLocaleString()} · {shortHash(t.hash)}
                  {t.error ? ` · ${t.error}` : ""}
                </div>
              </div>
              <div className="list-right">
                <span className="amount">{hlx(t.amount_hlx)} HLX</span>
                <StatusPill status={t.status} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">
        {value} <span className="metric-unit">{unit}</span>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const cls = status === "applied" ? "ok" : status === "failed" ? "bad" : "neutral";
  return <span className={`pill ${cls}`}>{status || "pending"}</span>;
}
