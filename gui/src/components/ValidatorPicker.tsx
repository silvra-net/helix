import { useEffect, useState } from "react";
import { api } from "../api";
import type { ValidatorSummary } from "../types";
import { hlx, shortAddr } from "../format";

// Picking who to delegate to used to mean typing an address into a box, which meant you could
// only delegate to a validator you had already heard about somewhere else. The list existed on
// no screen and at no endpoint.
//
// What a delegator is actually choosing between: how much stake is behind a validator (bigger is
// steadier, but concentrating stake is the thing this network is trying to avoid), what
// commission it takes, and whether it is currently doing its job at all. All three are shown,
// and a jailed or non-delegating validator can be seen but not selected — hiding it would leave
// "why is mine not in the list" unanswerable.
export function ValidatorPicker({
  node,
  value,
  onChange,
  exclude,
}: {
  node: string;
  value: string;
  onChange: (address: string) => void;
  /** Address to leave out — the one you are moving away from in a redelegation. */
  exclude?: string;
}) {
  const [list, setList] = useState<ValidatorSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [manual, setManual] = useState(false);

  useEffect(() => {
    api
      .listValidators(node)
      .then((r) => setList(r.validators.filter((v) => v.address !== exclude)))
      .catch((e) => {
        setError(String(e));
        setManual(true); // an older node has no list — fall back to typing rather than blocking
      });
  }, [node, exclude]);

  if (manual) {
    return (
      <label className="field">
        <span>Validator address</span>
        <input
          className="mono"
          value={value}
          spellCheck={false}
          placeholder="hlx…"
          onChange={(e) => onChange(e.target.value)}
        />
        {error && <span className="muted small">{error}</span>}
      </label>
    );
  }

  if (!list) return <div className="muted small">Loading validators…</div>;

  if (list.length === 0) {
    return (
      <div className="muted small">
        No validators are accepting delegation on this network yet.
      </div>
    );
  }

  return (
    <div className="field">
      <span>Choose a validator</span>
      <div className="list bordered" style={{ maxHeight: 260, overflowY: "auto" }}>
        {list.map((v) => {
          const jailed = v.jailed_until != null;
          const selectable = !jailed && v.accepts_delegation;
          return (
            <button
              key={v.address}
              type="button"
              className={`list-row picker-row ${value === v.address ? "active" : ""}`}
              disabled={!selectable}
              onClick={() => onChange(v.address)}
            >
              <div className="list-main">
                <div className="mono small">{shortAddr(v.address)}</div>
                <div className="muted small">
                  {hlx(v.effective_stake_hlx)} HLX staked
                  {v.commission_bps != null
                    ? ` · ${(v.commission_bps / 100).toFixed(1)}% commission`
                    : " · commission not set"}
                </div>
              </div>
              <div className="list-right">
                {jailed ? (
                  <span className="pill bad">jailed</span>
                ) : !v.accepts_delegation ? (
                  <span className="pill neutral">no pool</span>
                ) : v.active === false ? (
                  <span className="pill neutral">waiting</span>
                ) : (
                  <span className="pill ok">active</span>
                )}
              </div>
            </button>
          );
        })}
      </div>
      <button className="ghost mini" style={{ marginTop: 8 }} onClick={() => setManual(true)}>
        Enter an address instead
      </button>
    </div>
  );
}
