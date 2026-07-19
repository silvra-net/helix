import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { NetworkStatus, Overview, SubmitResult, ValidatorStatus } from "../types";
import { hlx, shortHash } from "../format";

// The Node panel is honest about what a wallet is: a client, not a node. It shows the status of the
// node you're connected to, where your stake stands against the validator threshold, and whether
// you're actually producing blocks (the only proof a client has that your node is up). Becoming a
// validator is two things — enough stake (you can do that here) AND running `helix start` with this
// key (you do that on your own machine).
export default function Node({ node, net }: { node: string; net: NetworkStatus | null }) {
  const [vs, setVs] = useState<ValidatorStatus | null>(null);
  const [ov, setOv] = useState<Overview | null>(null);
  const [amount, setAmount] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [v, o] = await Promise.all([
        api.getValidatorStatus(node),
        api.getOverview(node).catch(() => null),
      ]);
      setVs(v);
      setOv(o);
    } catch (e) {
      setError(String(e));
    }
  }, [node]);

  useEffect(() => {
    load();
    const id = setInterval(load, 6000);
    return () => clearInterval(id);
  }, [load]);

  const stake = async (fn: () => Promise<SubmitResult>) => {
    setError(null);
    setNotice(null);
    try {
      const r = await fn();
      setNotice(`Submitted ${shortHash(r.tx_hash)} · ${r.status}`);
      setAmount("");
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  const shortfall = vs ? Math.max(0, vs.min_validator_stake_hlx - vs.effective_stake_hlx) : 0;
  const pct = vs && vs.min_validator_stake_hlx > 0
    ? Math.min(100, (vs.effective_stake_hlx / vs.min_validator_stake_hlx) * 100)
    : 0;
  const amt = Number(amount);
  const amtValid = amount.trim() !== "" && Number.isFinite(amt) && amt > 0;
  const balance = ov?.balance_hlx ?? 0;

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      {/* Connected node */}
      <div className="card">
        <div className="section-title">Connected node</div>
        <div className="metric-row">
          <div className="metric">
            <div className="metric-label">Height</div>
            <div className="metric-value">{net ? net.height.toLocaleString() : "…"}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Peers</div>
            <div className="metric-value">{net ? net.peer_count : "…"}</div>
          </div>
          <div className="metric">
            <div className="metric-label">Status</div>
            <div className="metric-value">
              {!net ? "…" : net.is_syncing ? <span className="text-warn">syncing</span> : <span className="text-accent">live</span>}
            </div>
          </div>
        </div>
        <div className="kv" style={{ marginTop: 8 }}>
          <span className="muted">Endpoint</span>
          <span className="mono small">{node}</span>
        </div>
        {net && (
          <div className="kv">
            <span className="muted">Version · base fee</span>
            <span className="mono small">v{net.version} · {net.base_fee_per_byte} nano/byte</span>
          </div>
        )}
        {net && net.peer_count === 0 && (
          <p className="muted small">This network currently runs a single validator — decentralization is the goal, not yet the state.</p>
        )}
      </div>

      {/* Your validator standing */}
      <div className="card">
        <div className="section-title">Your validator standing</div>

        <div className="kv">
          <span className="muted">Effective stake (self + delegated)</span>
          <span className="mono">{vs ? hlx(vs.effective_stake_hlx) : "…"} HLX</span>
        </div>
        <div className="kv">
          <span className="muted">Entry threshold</span>
          <span className="mono">{vs ? hlx(vs.min_validator_stake_hlx) : "…"} HLX</span>
        </div>

        <div className="progress" aria-hidden>
          <div className="progress-bar" style={{ width: `${pct}%` }} />
        </div>

        {vs && (
          vs.eligible ? (
            <div className="notice" style={{ marginTop: 10 }}>
              ✓ Your stake meets the validator threshold.
              {vs.blocks_proposed > 0
                ? ` You proposed ${vs.blocks_proposed} of the last ${vs.window} blocks — your node is validating.`
                : " Now run a node with this key to actually validate (see below) — no recent blocks proposed yet."}
            </div>
          ) : (
            <p className="muted small" style={{ marginTop: 10 }}>
              You're <strong>{hlx(shortfall)} HLX</strong> short of the threshold. Staking more counts toward it.
            </p>
          )
        )}

        <div className="field" style={{ marginTop: 12 }}>
          <span>Stake toward validator (HLX)</span>
          <input inputMode="decimal" value={amount} placeholder={shortfall > 0 ? hlx(shortfall) : "0.0"} onChange={(e) => setAmount(e.target.value)} />
        </div>
        <div className="row-actions end">
          {shortfall > 0 && balance > 0 && (
            <button onClick={() => setAmount(String(Math.min(shortfall, balance)))}>
              Fill the gap ({hlx(Math.min(shortfall, balance))})
            </button>
          )}
          <button className="primary" disabled={!amtValid} onClick={() => stake(() => api.stake(node, amt))}>
            Stake
          </button>
        </div>
        <p className="muted small">Available to stake: {ov ? hlx(ov.balance_hlx) : "…"} HLX. Stake also earns you a governance vote.</p>
      </div>

      {/* Run a node */}
      <div className="card">
        <div className="section-title">Run a node</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          This wallet is a client — it can't validate for you. To actually produce blocks, run a node
          on your own machine with this wallet's key. With no configuration it joins this network,
          verifies genesis itself, and syncs; once your effective stake clears the threshold it rotates
          into the validator set within an epoch.
        </p>
        <pre className="codeblock">helix start</pre>
        <p className="muted small">
          Behind a home connection or Cloudflare, it gossips over WebSocket on port 443 — no open
          inbound port needed. Full guide at <span className="mono">github.com/silvra-net/helix</span>.
        </p>
      </div>
    </div>
  );
}
