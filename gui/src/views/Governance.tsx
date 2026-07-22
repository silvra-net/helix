import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { GovParams, Proposal, SubmitResult } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

// On-chain governance: stakers vote (stake-weighted, yes-to-quorum) to change protocol parameters,
// and can propose changes themselves. Voting is the everyday action; proposing is advanced.

// Render a proposal's target value in the unit that parameter is actually measured in.
//
// `min_validator_stake` is stored in nano-HLX, so a proposal to set 5,000 HLX arrived here as
// 5000000000000 and was printed raw — directly below a card reporting the *current* value of the
// same parameter as "100,000 HLX". Two numbers for one quantity, nine orders of magnitude apart,
// with no unit on either. The chain sends the parameter name as its Rust variant
// (`MinValidatorStake`), which is not the snake_case key the create form posts, so match on both
// rather than assuming one.
function formatProposedValue(param: string, newValue: number): string {
  const isStake = param === "MinValidatorStake" || param === "min_validator_stake";
  return isStake ? `${hlx(newValue / 1e9)} HLX` : newValue.toLocaleString();
}
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
                  <div className="list-title">#{p.id} · {p.param} → {formatProposedValue(p.param, p.new_value)}</div>
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

// Above which HLX figure `hlx * 1e9` stops being exact in a JS number. Number.MAX_SAFE_INTEGER
// is 9,007,199,254,740,991 nano — about 9.007 million HLX. This form used to take the nano value
// directly, so anything past that silently lost precision on the way in; asking for HLX moves the
// whole usable range far below the limit, and this guard covers the rest rather than trusting it.
const MAX_EXACT_HLX = Math.floor(Number.MAX_SAFE_INTEGER / 1e9);

function CreateProposal({ node, onRun }: { node: string; onRun: (fn: () => Promise<SubmitResult>) => void }) {
  const [param, setParam] = useState<"min_validator_stake" | "fuel_per_fee_unit">("min_validator_stake");
  const [value, setValue] = useState("");

  const isStake = param === "min_validator_stake";
  const v = Number(value);
  // The stake is an HLX amount like every other amount in this wallet — the nano conversion is
  // this form's job, not the operator's. It used to be the operator's: the field asked for
  // nano-HLX while the card directly above reported the same parameter in HLX, so reading the
  // current value and typing it back was wrong by a factor of a billion. Fuel per fee unit has
  // no unit at all and stays a plain count.
  const wellFormed =
    value.trim() !== "" && Number.isFinite(v) && v > 0 && (isStake || Number.isInteger(v));
  const inRange = !isStake || v <= MAX_EXACT_HLX;
  const valid = wellFormed && inRange;
  const onChainValue = isStake ? Math.round(v * 1e9) : v;

  return (
    <div className="card action-panel" style={{ marginBottom: 12 }}>
      <div className="section-title">New proposal</div>
      <label className="field">
        <span>Parameter</span>
        <select className="mono" value={param} onChange={(e) => setParam(e.target.value as typeof param)}>
          <option value="min_validator_stake">Min. validator stake</option>
          <option value="fuel_per_fee_unit">Fuel per fee unit</option>
        </select>
      </label>
      <label className="field">
        <span>New value {isStake ? "(HLX)" : "(count)"}</span>
        <input inputMode="decimal" className="mono" value={value} placeholder="0" onChange={(e) => setValue(e.target.value)} />
      </label>
      {wellFormed && !inRange && (
        <p className="error small">Above {hlx(MAX_EXACT_HLX)} HLX this value cannot be represented exactly.</p>
      )}
      <p className="muted small">
        Creating a proposal requires an active self-stake. The chain rejects values outside safe bounds.
        Creating a proposal does <strong>not</strong> cast your vote — use “Vote yes” on it afterwards.
      </p>
      <div className="row-actions end">
        <button className="primary" disabled={!valid} onClick={() => onRun(() => api.createProposal(node, param, onChainValue))}>Create proposal</button>
      </div>
    </div>
  );
}
