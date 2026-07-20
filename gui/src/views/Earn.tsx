import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { StakeActionPanel, type StakeAction } from "../components/StakeActionPanel";
import type { Delegation, SubmitResult } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

// Delegating to *other* validators — the "earn a share of block rewards without running a node"
// product. Deliberately separate from Validate.tsx: your own validator stake is a validator
// operation, this is a passive-income choice you can make with zero relation to running anything.
export default function Earn({ node }: { node: string }) {
  const [delegations, setDelegations] = useState<Delegation[]>([]);
  const [action, setAction] = useState<StakeAction | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setDelegations(await api.getDelegations(node));
    } catch (e) {
      setError(String(e));
    }
  }, [node]);

  useEffect(() => {
    load();
    const id = setInterval(load, 6000);
    return () => clearInterval(id);
  }, [load]);

  const run = async (fn: () => Promise<SubmitResult>) => {
    setError(null);
    setNotice(null);
    try {
      const r = await fn();
      setNotice(`Submitted ${shortHash(r.tx_hash)} · ${r.status}`);
      setAction(null);
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      {action && (
        <StakeActionPanel action={action} node={node} onCancel={() => setAction(null)} onRun={run} />
      )}

      <div className="card">
        <div className="section-title">Delegations</div>
        <p className="muted small" style={{ marginTop: -6 }}>Earn a share of a validator's block rewards without running a node. Delegation auto-compounds and grants no governance vote.</p>
        <div className="row-actions" style={{ marginBottom: 12 }}>
          <button className="primary" onClick={() => setAction({ kind: "delegate" })}>Delegate to a validator</button>
        </div>
        {delegations.length === 0 ? (
          <div className="empty muted">No delegations yet.</div>
        ) : (
          <div className="list bordered">
            {delegations.map((d) => (
              <div className="list-row" key={d.validator}>
                <div className="list-main">
                  <div className="mono small">{shortAddr(d.validator)}</div>
                  <div className="muted small">{d.shares.toLocaleString()} shares</div>
                </div>
                <div className="list-right">
                  <span className="amount">{hlx(d.value_hlx)} HLX</span>
                  <button className="mini" onClick={() => setAction({ kind: "undelegate", validator: d.validator })}>Undelegate</button>
                  <button className="mini" onClick={() => setAction({ kind: "redelegate", validator: d.validator })}>Move</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
