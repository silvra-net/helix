import { useState } from "react";
import { api } from "../api";
import type { SubmitResult } from "../types";
import { shortHash } from "../format";

export default function Send({
  node,
  baseFee,
  onDone,
}: {
  node: string;
  baseFee?: number;
  onDone: () => void;
}) {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SubmitResult | null>(null);

  const amountNum = Number(amount);
  const valid = to.trim().startsWith("hlx") && amount.trim() !== "" && Number.isFinite(amountNum) && amountNum > 0;

  const send = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.sendHlx(node, to.trim(), amountNum);
      setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <div className="stack">
        <div className="card success-card">
          <div className="section-title">Transaction submitted</div>
          <div className="kv">
            <span className="muted">Hash</span>
            <span className="mono">{shortHash(result.tx_hash)}</span>
          </div>
          <div className="kv">
            <span className="muted">Status</span>
            <span>{result.status}</span>
          </div>
          <p className="muted small">
            Submitted to the mempool. Its final outcome (applied / failed) shows in Overview once
            it lands in a block.
          </p>
          <button className="primary" onClick={onDone}>Back to overview</button>
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      <div className="card form-card">
        <div className="section-title">Send HLX</div>

        <label className="field">
          <span>Recipient address</span>
          <input
            className="mono"
            value={to}
            spellCheck={false}
            placeholder="hlx…"
            onChange={(e) => setTo(e.target.value)}
          />
        </label>

        <label className="field">
          <span>Amount (HLX)</span>
          <input
            inputMode="decimal"
            value={amount}
            placeholder="0.0"
            onChange={(e) => setAmount(e.target.value)}
          />
        </label>

        <p className="muted small">
          The fee is priced automatically against the chain
          {typeof baseFee === "number" ? ` (base fee ${baseFee} nano/byte)` : ""}. A transfer is
          ~5.4 KB, so at the floor it costs about 0.00001 HLX.
        </p>

        {error && <div className="error">{error}</div>}

        <div className="row-actions end">
          <button className="ghost" onClick={onDone}>Cancel</button>
          <button className="primary" disabled={!valid || busy} onClick={send}>
            {busy ? "Signing…" : "Sign and send"}
          </button>
        </div>
      </div>
    </div>
  );
}
