import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { LogLine, NetworkStatus, NodeProcessStatus, Overview, SubmitResult, ValidatorStatus } from "../types";
import { hlx, shortHash } from "../format";

// The Node panel shows the status of the node you're *connected to* (top card — could be the
// public one, could be your own), where your stake stands against the validator threshold, and
// whether you're actually producing blocks (the only proof a client has that your node is up).
// Becoming a validator is still two things — enough stake, and a node actually running with this
// key — but as of the "Local node" card below, the second one no longer needs a terminal: the
// same `helix` binary the CLI ships is bundled into this app and can be started right here (see
// `node_process.rs`). Running your own node externally (a server, `helix start` in a terminal)
// works exactly the same and this panel doesn't need to know about it either way — it only ever
// reflects chain state, never assumes who's actually proposing blocks.

// Console lines are capped rather than kept forever — a validator node can run for weeks, and
// nothing here needs full scrollback history; it's a live tail, not a log file (the real one is
// still on disk, wherever the node's data dir is).
const MAX_CONSOLE_LINES = 2000;
export default function Node({ node, net }: { node: string; net: NetworkStatus | null }) {
  const [vs, setVs] = useState<ValidatorStatus | null>(null);
  const [ov, setOv] = useState<Overview | null>(null);
  const [amount, setAmount] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [procStatus, setProcStatus] = useState<NodeProcessStatus | null>(null);
  const [procBusy, setProcBusy] = useState(false);
  const [procError, setProcError] = useState<string | null>(null);
  const [lines, setLines] = useState<LogLine[]>([]);
  const consoleRef = useRef<HTMLDivElement | null>(null);
  const autoScroll = useRef(true);

  // Local node lifecycle: poll status once on mount (in case one is already running from a
  // previous session), then rely entirely on events (node-log / node-exited) for live state —
  // polling the log itself would either miss lines between polls or re-fetch a growing buffer.
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

  // Auto-scroll the console to the newest line, but only if the user hasn't scrolled up to
  // read earlier output — the same convention every terminal/log viewer uses.
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
      await api.nodeStart({});
      setProcStatus({ running: true });
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
    } catch (e) {
      setProcError(String(e));
    } finally {
      setProcBusy(false);
    }
  };

  const submitUnjail = async () => {
    setError(null);
    setNotice(null);
    try {
      const r = await api.unjail(node);
      setNotice(`Submitted ${shortHash(r.tx_hash)} · ${r.status}`);
      load();
    } catch (e) {
      setError(String(e));
    }
  };

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
            <button className="primary" onClick={startLocalNode} disabled={procBusy}>Start local node</button>
          )}
        </div>
        {procError && <div className="error" style={{ marginTop: 8 }}>{procError}</div>}

        <div
          ref={consoleRef}
          className="console"
          onScroll={(e) => {
            const el = e.currentTarget;
            // Within ~24px of the bottom counts as "still following" — keeps auto-scroll on
            // through minor rounding/animation jitter instead of needing a pixel-perfect match.
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
