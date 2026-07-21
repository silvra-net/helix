import { useCallback, useEffect, useRef, useState } from "react";
import { api, DEFAULT_NODE, LOCAL_NODE, isLocalNode } from "../api";
import { StakeActionPanel, type StakeAction } from "../components/StakeActionPanel";
import type { LogLine, NetworkStatus, NodeProcessStatus, Overview, SubmitResult, ValidatorPool, ValidatorStatus } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

// Everything to do with being (or becoming) a validator lives here, in one place — status of the
// node you're connected to, your own stake against the eligibility threshold (stake, unstake,
// unbonding, jailed/unjail), your pool if delegators back you, and running the bundled node
// itself. Earlier this was split across a "Node" tab and a "Staking" tab's self-stake card, which
// put the same number (your own stake) in two different mental categories for no reason — if
// you're a validator, staking IS the validator operation, not a separate generic product.
// Delegating to *other* validators (Earn.tsx) is the one genuinely separate concept: you can do
// that without ever touching this page.

const MAX_CONSOLE_LINES = 2000;

export default function Validate({ node, net, onNodeChange, walletEncrypted }: { node: string; net: NetworkStatus | null; onNodeChange: (url: string) => void; walletEncrypted: boolean }) {
  const [vs, setVs] = useState<ValidatorStatus | null>(null);
  const [ov, setOv] = useState<Overview | null>(null);
  const [pool, setPool] = useState<ValidatorPool | null>(null);
  const [amount, setAmount] = useState("");
  const [action, setAction] = useState<StakeAction | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [procStatus, setProcStatus] = useState<NodeProcessStatus | null>(null);
  const [procBusy, setProcBusy] = useState(false);
  const [procError, setProcError] = useState<string | null>(null);
  const [procNotice, setProcNotice] = useState<string | null>(null);
  const [nodePass, setNodePass] = useState("");
  const [lines, setLines] = useState<LogLine[]>([]);
  const consoleRef = useRef<HTMLDivElement | null>(null);
  const autoScroll = useRef(true);

  useEffect(() => {
    api.nodeProcessStatus().then(setProcStatus).catch(() => {});
    const unlistenLog = api.onNodeLog((l) => {
      setLines((prev) => {
        const next = prev.length >= MAX_CONSOLE_LINES ? prev.slice(prev.length - MAX_CONSOLE_LINES + 1) : prev;
        return [...next, l];
      });
    });
    const unlistenExit = api.onNodeExited((e) => {
      setProcStatus({ running: false });
      setLines((prev) => [...prev, { stream: "stderr", line: `[process exited, code ${e.code ?? "unknown"}]` }]);
    });
    return () => {
      unlistenLog.then((f) => f());
      unlistenExit.then((f) => f());
    };
  }, []);

  useEffect(() => {
    if (autoScroll.current && consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [lines]);

  const startLocalNode = async () => {
    setProcError(null);
    setProcBusy(true);
    setLines([]);
    try {
      // The node runs as this wallet's key (see node_process.rs). An encrypted wallet file
      // cannot be read without its passphrase, and the node has no terminal to ask on — so it
      // has to come from here, or the node refuses to start.
      await api.nodeStart(walletEncrypted ? { validator_key_passphrase: nodePass } : {});
      setNodePass("");
      setProcStatus({ running: true });
      // Point the wallet at the node it just started. Running one and then still asking a
      // public server for your balance defeats the purpose — and that server can be wrong or
      // simply gone. The node answers from its first second (it serves RPC while syncing, see
      // helix-node's run()), so this does not strand the wallet: `Connected node` above shows
      // `syncing` with the height climbing until it has caught up.
      if (!isLocalNode(node)) {
        onNodeChange(LOCAL_NODE);
        setProcNotice(`Wallet now reading from your own node (${LOCAL_NODE}). It may show "syncing" until it has caught up.`);
      }
    } catch (e) {
      setProcError(String(e));
    } finally {
      setProcBusy(false);
    }
  };

  const resetLocalChain = async () => {
    setProcError(null);
    setProcNotice(null);
    setProcBusy(true);
    try {
      const backup = await api.nodeResetChain();
      setProcNotice(`Local chain moved aside. Start the node to re-sync. Old copy: ${backup}`);
    } catch (e) {
      setProcError(String(e));
    } finally {
      setProcBusy(false);
    }
  };

  const stopLocalNode = async () => {
    setProcBusy(true);
    try {
      await api.nodeStop();
      setProcStatus({ running: false });
      // Back to the public seed, otherwise the wallet points at a node that is no longer there
      // and every screen goes blank with a connection error.
      if (isLocalNode(node)) {
        onNodeChange(DEFAULT_NODE);
        setProcNotice(`Local node stopped — wallet reading from ${DEFAULT_NODE} again.`);
      }
    } catch (e) {
      setProcError(String(e));
    } finally {
      setProcBusy(false);
    }
  };

  const load = useCallback(async () => {
    try {
      const [v, o, p] = await Promise.all([
        api.getValidatorStatus(node),
        api.getOverview(node).catch(() => null),
        api.getValidatorPool(node).catch(() => null),
      ]);
      setVs(v);
      setOv(o);
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
      setAmount("");
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  const submitUnjail = () => run(() => api.unjail(node));

  const shortfall = vs ? Math.max(0, vs.min_validator_stake_hlx - vs.effective_stake_hlx) : 0;
  const pct = vs && vs.min_validator_stake_hlx > 0
    ? Math.min(100, (vs.effective_stake_hlx / vs.min_validator_stake_hlx) * 100)
    : 0;
  const amt = Number(amount);
  const amtValid = amount.trim() !== "" && Number.isFinite(amt) && amt > 0;
  const balance = ov?.balance_hlx ?? 0;

  const unbonding = ov?.unbonding_hlx ?? 0;
  const blocksLeft = ov ? Math.max(0, ov.unbonding_unlock_height - (net?.height ?? 0)) : 0;
  const claimable = unbonding > 0 && blocksLeft === 0;

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      {action && (
        <StakeActionPanel action={action} node={node} onCancel={() => setAction(null)} onRun={run} />
      )}

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
              {!net ? "…" : net.is_syncing ? (
                <span className="text-warn">
                  syncing{net.sync_target_height ? ` ${Math.min(99, Math.floor((net.height / net.sync_target_height) * 100))}%` : ""}
                </span>
              ) : <span className="text-accent">live</span>}
            </div>
          </div>
        </div>
        <div className="kv" style={{ marginTop: 8 }}>
          <span className="muted">Endpoint</span>
          <span className="mono small">
            {node} {isLocalNode(node) ? "· your own node" : "· public node"}
          </span>
        </div>
        {/* Say plainly whose machine answers. Someone reading a balance off a public node is
            trusting it to tell the truth; that is a reasonable default to start on and a poor
            one to stay on without knowing. */}
        {!isLocalNode(node) && (
          <p className="muted small" style={{ marginTop: 6 }}>
            Reading from a public node. Start your own below and the wallet switches to it —
            then nobody else sees your queries or decides what your balance is.
          </p>
        )}
        {net && (
          <div className="kv">
            <span className="muted">Version · base fee</span>
            <span className="mono small">v{net.version} · {net.base_fee_per_byte} nano/byte</span>
          </div>
        )}
        {net && net.peer_count === 0 && !isLocalNode(node) && (
          <p className="muted small">This network currently runs a single validator — decentralization is the goal, not yet the state.</p>
        )}
        {net && net.peer_count === 0 && isLocalNode(node) && net.is_syncing && (
          <p className="muted small">Your node is fetching history and has not connected to peers yet — both are normal while syncing.</p>
        )}
      </div>

      {/* Your stake */}
      <div className="card">
        <div className="section-title">Your stake</div>

        <div className="kv">
          <span className="muted">Effective stake (self + delegated in)</span>
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

        {ov?.jailed_until != null && (
          <div className="error" style={{ marginTop: 10 }}>
            ⚠ Downtime-jailed until block #{ov.jailed_until.toLocaleString()} — excluded from the
            validator set, earning nothing, until you submit an unjail transaction. Only do this
            once your node is actually running and connected, or the same downtime just jails you
            again.
            {net && net.height >= ov.jailed_until && (
              <div className="row-actions end" style={{ marginTop: 8 }}>
                <button className="primary" onClick={submitUnjail}>Submit Unjail</button>
              </div>
            )}
          </div>
        )}
        {ov?.jailed_until == null && (ov?.missed_blocks ?? 0) > 0 && (
          <p className="muted small" style={{ marginTop: 10 }}>
            {ov!.missed_blocks} consecutive blocks missed without a signature seen — resets the
            moment your node signs one again.
          </p>
        )}

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
          <button onClick={() => setAction({ kind: "unstake" })}>Unstake…</button>
          <button className="primary" disabled={!amtValid} onClick={() => run(() => api.stake(node, amt))}>
            Stake
          </button>
        </div>
        <p className="muted small">
          Available to stake: {ov ? hlx(ov.balance_hlx) : "…"} HLX. Stake also earns you a
          governance vote. Unstaking begins a 7-day unbonding period; the stake stays slashable
          until you claim it.
        </p>
      </div>

      {/* Validator pool (only shown once you actually have delegators or self-stake) */}
      {pool && (pool.has_pool || pool.self_staked_hlx > 0) && (
        <div className="card">
          <div className="section-title">Your validator pool</div>
          <p className="muted small" style={{ marginTop: -6 }}>
            Delegators who back this validator — separate from your own stake above.
          </p>
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

      {/* Local node */}
      <div className="card">
        <div className="section-title">Local node</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          Runs the exact same <span className="mono">helix</span> node the CLI ships, bundled into
          this app — starting it here is running a real validator, with this wallet's key, on this
          machine. With no configuration it joins the public network, verifies genesis itself, and
          syncs; once your effective stake clears the threshold above it rotates into the validator
          set within an epoch. Prefer running it on a server instead? `helix start` in a terminal
          does the same thing — this panel and a standalone CLI node are interchangeable, not a
          choice you're locked into.
        </p>

        <div className="row-actions" style={{ marginTop: 10 }}>
          <span className={`dot ${procStatus?.running ? "ok" : "off"}`} aria-hidden />
          <span className="muted small">{procStatus?.running ? "Running" : "Stopped"}</span>
          <div style={{ flex: 1 }} />
          {procStatus?.running ? (
            <button onClick={stopLocalNode} disabled={procBusy}>Stop</button>
          ) : (
            <button
              className="primary"
              onClick={startLocalNode}
              disabled={procBusy || (walletEncrypted && nodePass.trim() === "")}
            >
              Start local node
            </button>
          )}
        </div>
        {walletEncrypted && !procStatus?.running && (
          <div style={{ marginTop: 10 }}>
            <label className="muted small" htmlFor="node-pass">
              Wallet passphrase — the node signs blocks with this wallet's key and needs it to
              read the key file. It is passed to the node process only, and not stored.
            </label>
            <input
              id="node-pass"
              type="password"
              value={nodePass}
              onChange={(e) => setNodePass(e.target.value)}
              placeholder="Wallet passphrase"
              autoComplete="off"
              style={{ marginTop: 6 }}
            />
          </div>
        )}
        {procError && <div className="error" style={{ marginTop: 8 }}>{procError}</div>}
        {procNotice && <div className="notice" style={{ marginTop: 8 }}>{procNotice}</div>}

        {/* Recovery for a local chain that can no longer follow the network — a database from
            an incompatible build, or one left behind after the network reset its own chain.
            Without this the only way out is finding the file by hand. Deliberately not offered
            while the node runs (it holds the database open), and deliberately a rename rather
            than a delete. */}
        {!procStatus?.running && (
          <details style={{ marginTop: 12 }}>
            <summary className="muted small" style={{ cursor: "pointer" }}>
              Node won't sync? Reset the local chain
            </summary>
            <p className="muted small" style={{ marginTop: 8 }}>
              Moves this machine's copy of the chain aside and re-downloads it from scratch on the
              next start. Use it if the node refuses to join the network — usually a database left
              over from an older, incompatible build. Your wallet, your key and your balance are
              untouched: they live on the chain, not in this file. The old database is{" "}
              <strong>renamed, not deleted</strong>, so nothing is lost if this wasn't the problem.
              Re-syncing takes a while — currently around half an hour.
            </p>
            <div className="row-actions end">
              <button onClick={resetLocalChain} disabled={procBusy}>Reset local chain</button>
            </div>
          </details>
        )}

        <div
          ref={consoleRef}
          className="console"
          onScroll={(e) => {
            const el = e.currentTarget;
            autoScroll.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          }}
        >
          {lines.length === 0 ? (
            <div className="console-empty muted small">
              {procStatus?.running ? "Waiting for output…" : "Start the node to see its console output here."}
            </div>
          ) : (
            lines.map((l, i) => (
              <div key={i} className={`console-line ${l.stream === "stderr" ? "console-stderr" : ""}`}>
                {l.line}
              </div>
            ))
          )}
        </div>

        <p className="muted small">
          Behind a home connection or Cloudflare, it gossips over WebSocket on port 443 — no open
          inbound port needed. Full guide at <span className="mono">github.com/silvra-net/helix</span>.
        </p>
      </div>
    </div>
  );
}
