import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { GovParams, Proposal, SubmitResult } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

// On-chain governance: stakers vote (stake-weighted, yes-to-quorum) to change protocol parameters,
// and can propose changes themselves. Voting is the everyday action; proposing is advanced.
export default function Governance({ node }: { node: string }) {
  const [params, setParams] = useState<GovParams | null>(null);
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    try {
      const [p, list] = await Promise.all([
        api.getGovParams(node).catch(() => null),
        api.getProposals(node).catch(() => []),
      ]);
      setParams(p);
      setProposals(list);
    } catch (e) {
      setError(String(e));
    }
  }, [node]);

  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [load]);

  const run = async (fn: () => Promise<SubmitResult>) => {
    setError(null);
    setNotice(null);
    try {
      const r = await fn();
      setNotice(`Submitted ${shortHash(r.tx_hash)} · ${r.status}`);
      setCreating(false);
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="section-title">Current protocol parameters</div>
        <div className="metric-row two">
          <div className="metric">
            <div className="metric-label">Min. validator stake</div>
            <div className="metric-value">{params ? hlx(params.min_validator_stake_hlx) : "…"} <span className="metric-unit">HLX</span></div>
          </div>
          <div className="metric">
            <div className="metric-label">Fuel per fee unit</div>
            <div className="metric-value">{params ? params.fuel_per_fee_unit.toLocaleString() : "…"}</div>
          </div>
        </div>
        <p className="muted small">Only self-stakers can vote; delegation earns yield but carries no governance weight.</p>
      </div>

      <div className="card">
        <div className="section-title">Proposals</div>
        <div className="row-actions" style={{ marginBottom: 12 }}>
          <button onClick={() => setCreating((c) => !c)}>{creating ? "Close" : "New proposal"}</button>
        </div>

        {creating && <CreateProposal node={node} onRun={run} />}

        {proposals.length === 0 ? (
          <div className="empty muted">No proposals yet.</div>
        ) : (
          <div className="list bordered">
            {proposals.map((p) => (
              <div className="list-row" key={p.id}>
                <div className="list-main">
                  <div className="list-title">#{p.id} · {p.param} → {p.new_value.toLocaleString()}</div>
                  <div className="muted small">
                    by {shortAddr(p.proposer)} · {hlx(p.yes_stake_hlx)} HLX yes
                    {p.executed ? " · executed" : ""}
                  </div>
                </div>
                <div className="list-right">
                  {p.executed ? (
                    <span className="pill ok">passed</span>
                  ) : (
                    <button className="mini primary" onClick={() => run(() => api.voteProposal(node, p.id))}>Vote yes</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function CreateProposal({ node, onRun }: { node: string; onRun: (fn: () => Promise<SubmitResult>) => void }) {
  const [param, setParam] = useState<"min_validator_stake" | "fuel_per_fee_unit">("min_validator_stake");
  const [value, setValue] = useState("");

  const v = Number(value);
  const valid = value.trim() !== "" && Number.isInteger(v) && v > 0;

  return (
    <div className="card action-panel" style={{ marginBottom: 12 }}>
      <div className="section-title">New proposal</div>
      <label className="field">
        <span>Parameter</span>
        <select className="mono" value={param} onChange={(e) => setParam(e.target.value as typeof param)}>
          <option value="min_validator_stake">Min. validator stake (nano-HLX)</option>
          <option value="fuel_per_fee_unit">Fuel per fee unit</option>
        </select>
      </label>
      <label className="field">
        <span>New value {param === "min_validator_stake" ? "(nano-HLX — 1 HLX = 1,000,000,000)" : ""}</span>
        <input inputMode="numeric" className="mono" value={value} placeholder="0" onChange={(e) => setValue(e.target.value)} />
      </label>
      <p className="muted small">Creating a proposal requires an active self-stake. The chain rejects values outside safe bounds.</p>
      <div className="row-actions end">
        <button className="primary" disabled={!valid} onClick={() => onRun(() => api.createProposal(node, param, v))}>Create proposal</button>
      </div>
    </div>
  );
}
