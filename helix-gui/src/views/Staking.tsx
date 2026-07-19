import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { Delegation, Overview, SubmitResult, ValidatorPool } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

type Action =
  | { kind: "stake" }
  | { kind: "unstake" }
  | { kind: "delegate" }
  | { kind: "undelegate"; validator: string }
  | { kind: "redelegate"; validator: string }
  | { kind: "commission" };

export default function Staking({ node, height }: { node: string; height: number }) {
  const [ov, setOv] = useState<Overview | null>(null);
  const [delegations, setDelegations] = useState<Delegation[]>([]);
  const [pool, setPool] = useState<ValidatorPool | null>(null);
  const [action, setAction] = useState<Action | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [o, d, p] = await Promise.all([
        api.getOverview(node),
        api.getDelegations(node),
        api.getValidatorPool(node).catch(() => null),
      ]);
      setOv(o);
      setDelegations(d);
      setPool(p);
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

  const unbonding = ov ? ov.unbonding_hlx : 0;
  const blocksLeft = ov ? Math.max(0, ov.unbonding_unlock_height - height) : 0;
  const claimable = unbonding > 0 && blocksLeft === 0;

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      {action && (
        <ActionPanel
          action={action}
          node={node}
          onCancel={() => setAction(null)}
          onRun={run}
        />
      )}

      {/* Self-stake */}
      <div className="card">
        <div className="section-title">Self-stake</div>
        <div className="metric-row two">
          <div className="metric">
            <div className="metric-label">Staked</div>
            <div className="metric-value">{ov ? hlx(ov.staked_hlx) : "…"} <span className="metric-unit">HLX</span></div>
          </div>
          <div className="metric">
            <div className="metric-label">Available to stake</div>
            <div className="metric-value">{ov ? hlx(ov.balance_hlx) : "…"} <span className="metric-unit">HLX</span></div>
          </div>
        </div>
        <div className="row-actions" style={{ marginTop: 12 }}>
          <button onClick={() => setAction({ kind: "stake" })}>Stake</button>
          <button onClick={() => setAction({ kind: "unstake" })}>Unstake</button>
        </div>

        {unbonding > 0 && (
          <div className="unbonding-note">
            <div>
              <strong>{hlx(unbonding)} HLX</strong> unbonding
              {ov?.unbonding_source ? (
                <span className="muted"> · still slashable for {shortAddr(ov.unbonding_source)}</span>
              ) : (
                <span className="muted"> · your own unstake</span>
              )}
            </div>
            <div className="row-actions">
              {claimable ? (
                <button className="primary" onClick={() => run(() => api.claimUnbonded(node))}>Claim</button>
              ) : (
                <span className="muted small">
                  claimable at height {ov?.unbonding_unlock_height.toLocaleString()} (~{blocksLeft.toLocaleString()} blocks · ~{Math.ceil((blocksLeft * 2) / 60)} min)
                </span>
              )}
            </div>
          </div>
        )}
        <p className="muted small">Unstaking begins a 7-day unbonding period; the stake stays slashable until you claim it.</p>
      </div>

      {/* Delegations */}
      <div className="card">
        <div className="section-title">Delegations</div>
        <p className="muted small" style={{ marginTop: -6 }}>Earn a share of a validator's block rewards without running a node. Delegation auto-compounds and grants no governance vote.</p>
        <div className="row-actions" style={{ marginBottom: 12 }}>
          <button onClick={() => setAction({ kind: "delegate" })}>Delegate to a validator</button>
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

      {/* Validator pool */}
      {pool && (pool.has_pool || pool.self_staked_hlx > 0) && (
        <div className="card">
          <div className="section-title">Your validator pool</div>
          <div className="metric-row">
            <div className="metric">
              <div className="metric-label">Effective stake</div>
              <div className="metric-value">{hlx(pool.effective_stake_hlx)} <span className="metric-unit">HLX</span></div>
            </div>
            <div className="metric">
              <div className="metric-label">Delegated in</div>
              <div className="metric-value">{hlx(pool.delegated_stake_hlx)} <span className="metric-unit">HLX</span></div>
            </div>
            <div className="metric">
              <div className="metric-label">Commission</div>
              <div className="metric-value">{pool.commission_bps == null ? "—" : (pool.commission_bps / 100).toFixed(2) + "%"}</div>
            </div>
          </div>
          <div className="row-actions" style={{ marginTop: 12 }}>
            <button onClick={() => setAction({ kind: "commission" })}>Set commission</button>
          </div>
        </div>
      )}
    </div>
  );
}

function ActionPanel({
  action,
  node,
  onCancel,
  onRun,
}: {
  action: Action;
  node: string;
  onCancel: () => void;
  onRun: (fn: () => Promise<SubmitResult>) => void;
}) {
  const [amount, setAmount] = useState("");
  const [toValidator, setToValidator] = useState("");
  const [validator, setValidator] = useState("");
  const [percent, setPercent] = useState("");

  const amt = Number(amount);
  const amtValid = amount.trim() !== "" && Number.isFinite(amt) && amt > 0;

  const title: Record<Action["kind"], string> = {
    stake: "Stake HLX",
    unstake: "Unstake HLX",
    delegate: "Delegate to a validator",
    undelegate: "Undelegate",
    redelegate: "Move delegation to another validator",
    commission: "Set commission",
  };

  let canSubmit = false;
  let submit: () => Promise<SubmitResult> = async () => ({ tx_hash: "", status: "" });

  switch (action.kind) {
    case "stake":
      canSubmit = amtValid;
      submit = () => api.stake(node, amt);
      break;
    case "unstake":
      canSubmit = amtValid;
      submit = () => api.unstake(node, amt);
      break;
    case "delegate":
      canSubmit = amtValid && validator.trim().startsWith("hlx");
      submit = () => api.delegate(node, validator.trim(), amt);
      break;
    case "undelegate":
      canSubmit = amtValid;
      submit = () => api.undelegate(node, action.validator, amt);
      break;
    case "redelegate":
      canSubmit = amtValid && toValidator.trim().startsWith("hlx");
      submit = () => api.redelegate(node, action.validator, toValidator.trim(), amt);
      break;
    case "commission": {
      const p = Number(percent);
      canSubmit = percent.trim() !== "" && Number.isFinite(p) && p >= 0 && p <= 50;
      submit = () => api.setCommission(node, Math.round(p * 100));
      break;
    }
  }

  return (
    <div className="card action-panel">
      <div className="section-title">{title[action.kind]}</div>

      {action.kind === "delegate" && (
        <label className="field">
          <span>Validator address</span>
          <input className="mono" value={validator} spellCheck={false} placeholder="hlx…" onChange={(e) => setValidator(e.target.value)} />
        </label>
      )}

      {(action.kind === "undelegate" || action.kind === "redelegate") && (
        <div className="kv"><span className="muted">From validator</span><span className="mono">{shortAddr(action.validator)}</span></div>
      )}

      {action.kind === "redelegate" && (
        <label className="field">
          <span>To validator</span>
          <input className="mono" value={toValidator} spellCheck={false} placeholder="hlx…" onChange={(e) => setToValidator(e.target.value)} />
        </label>
      )}

      {action.kind === "commission" ? (
        <label className="field">
          <span>Commission (%, max 50)</span>
          <input inputMode="decimal" value={percent} placeholder="10" onChange={(e) => setPercent(e.target.value)} />
        </label>
      ) : (
        <label className="field">
          <span>Amount (HLX)</span>
          <input inputMode="decimal" value={amount} placeholder="0.0" onChange={(e) => setAmount(e.target.value)} />
        </label>
      )}

      {action.kind === "redelegate" && (
        <p className="muted small">The moved stake keeps earning at the new validator immediately, but stays slashable for the one you left for 7 days.</p>
      )}

      <div className="row-actions end">
        <button className="ghost" onClick={onCancel}>Cancel</button>
        <button className="primary" disabled={!canSubmit} onClick={() => onRun(submit)}>Sign and submit</button>
      </div>
    </div>
  );
}
