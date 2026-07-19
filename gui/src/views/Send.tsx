import { useEffect, useState } from "react";
import { api } from "../api";
import type { SubmitResult } from "../types";
import { shortAddr, shortHash } from "../format";

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
  // undefined = input is an address or empty (nothing to resolve); null = name not found;
  // string = the address a typed name resolves to.
  const [resolved, setResolved] = useState<string | null | undefined>(undefined);

  const looksLikeName = to.trim() !== "" && !to.trim().startsWith("hlx");

  // Live-resolve a typed name so the user sees where it will actually go before signing.
  useEffect(() => {
    if (!looksLikeName) {
      setResolved(undefined);
      return;
    }
    let alive = true;
    const id = setTimeout(async () => {
      try {
        const a = await api.resolveName(node, to.trim());
        if (alive) setResolved(a);
      } catch {
        if (alive) setResolved(null);
      }
    }, 350);
    return () => {
      alive = false;
      clearTimeout(id);
    };
  }, [to, node, looksLikeName]);

  const amountNum = Number(amount);
  const recipientOk = to.trim().startsWith("hlx") || (looksLikeName && resolved != null);
  const valid = recipientOk && amount.trim() !== "" && Number.isFinite(amountNum) && amountNum > 0;

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
          <span>Recipient — address or name</span>
          <input
            className="mono"
            value={to}
            spellCheck={false}
            placeholder="hlx… or alice.hlx"
            onChange={(e) => setTo(e.target.value)}
          />
        </label>
        {looksLikeName && resolved !== undefined && (
          <div className="resolve-line small">
            {resolved ? (
              <span className="muted">→ {shortAddr(resolved)}</span>
            ) : (
              <span className="text-warn">that name is not registered</span>
            )}
          </div>
        )}

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
