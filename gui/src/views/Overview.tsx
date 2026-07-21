import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { HistoryEntry, Overview as OverviewData } from "../types";
import { hlx, shortAddr, shortHash, timeAgo } from "../format";

export default function Overview({
  node,
  height,
  onSend,
  onReceive,
}: {
  node: string;
  /** Current chain height — turns an unbonding unlock height into "in N minutes". */
  height?: number;
  onSend: () => void;
  onReceive: () => void;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [name, setName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [ov, hist, nm] = await Promise.all([
        api.getOverview(node),
        api.getHistory(node, 25),
        api.myName(node).catch(() => null),
      ]);
      setData(ov);
      setHistory(hist);
      setName(nm);
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
      {/* An amount with no date attached is a question, not an answer: unbonding coins are
          neither spendable nor earning, and "when do I get them" is the only thing worth
          knowing about them. */}
      {data != null && data.unbonding_hlx > 0 && (
        <p className="muted small" style={{ marginTop: -6 }}>
          {height != null && data.unbonding_unlock_height > height ? (
            <>
              {hlx(data.unbonding_hlx)} HLX unbonding — claimable in{" "}
              {(data.unbonding_unlock_height - height).toLocaleString()} blocks
              {" "}(~{Math.max(1, Math.round(((data.unbonding_unlock_height - height) * 2) / 60))} min),
              at block {data.unbonding_unlock_height.toLocaleString()}.
            </>
          ) : (
            <>
              {hlx(data.unbonding_hlx)} HLX is ready to claim — collect it under{" "}
              <strong>Validate</strong>, otherwise it stays neither spendable nor earning.
            </>
          )}
        </p>
      )}

      <div className="card address-card">
        <div className="address-block">
          <div className="muted small">Your address{name ? <> · <span className="text-accent">{name}.hlx</span></> : ""}</div>
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
          {history.length === 0 && (
            <div className="empty muted">
              No transactions yet.
              {data != null && data.balance_hlx === 0 && data.staked_hlx === 0 && (
                <> Share your address above to receive HLX — it is safe to hand out, it only lets
                people send you coins.</>
              )}
            </div>
          )}
          {history.map((t) => {
            // Direction is the first thing anyone wants from a transaction list, and it was the
            // one thing this list did not say: every row read the same whether coins had arrived
            // or left. `from` was in the data all along, simply unused.
            const outgoing = data != null && t.from === data.address;
            const counterparty = outgoing ? t.to : t.from;
            const moved = t.amount_hlx > 0;
            return (
              <div className="list-row" key={t.hash}>
                <div className="list-main">
                  <div className="list-title">
                    {moved ? (outgoing ? "Sent" : "Received") : t.tx_type}
                    {counterparty && moved ? (
                      <span className="muted"> {outgoing ? "to" : "from"} {shortAddr(counterparty)}</span>
                    ) : null}
                  </div>
                  <div className="muted small">
                    {timeAgo(t.timestamp)} · block {t.block_height.toLocaleString()} · {shortHash(t.hash)}
                    {outgoing && t.fee_hlx > 0 ? ` · fee ${hlx(t.fee_hlx)}` : ""}
                    {t.error ? ` · ${t.error}` : ""}
                  </div>
                </div>
                <div className="list-right">
                  <span className={`amount ${moved ? (outgoing ? "amount-out" : "amount-in") : ""}`}>
                    {moved ? (outgoing ? "−" : "+") : ""}{hlx(t.amount_hlx)} HLX
                  </span>
                  <StatusPill status={t.status} />
                </div>
              </div>
            );
          })}
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
