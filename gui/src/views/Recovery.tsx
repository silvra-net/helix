import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { GuardianInfo, RecoveryStatus, SubmitResult } from "../types";
import { shortAddr, shortHash } from "../format";

// Social recovery: guardians that can together rotate a lost account to a new key — the thing a
// seed phrase alone can't give you, and something Bitcoin has no notion of. Three jobs on one page:
// manage your own guardians, help recover an account you're a guardian for, and (if you're the one
// recovering) hand your new public key to your guardians.
export default function Recovery({ node, address }: { node: string; address: string }) {
  const [guardians, setGuardians] = useState<GuardianInfo | null>(null);
  const [mine, setMine] = useState<RecoveryStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [g, r] = await Promise.all([
        api.getGuardians(node),
        api.getRecovery(node, address).catch(() => null),
      ]);
      setGuardians(g);
      setMine(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoaded(true);
    }
  }, [node, address]);

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
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  const pendingOnMe = mine && mine.pending_approvals != null;

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      {pendingOnMe && (
        <div className="card action-panel">
          <div className="section-title text-warn">A recovery is in progress on your account</div>
          <p className="muted small" style={{ marginTop: -4 }}>
            {mine!.pending_approvals} of {mine!.threshold ?? "?"} guardians have approved rotating your
            account to a new key. If you didn't ask for this, cancel it now — a single guardian starting
            a recovery shouldn't be able to lock you out.
          </p>
          <div className="row-actions end">
            <button className="primary" onClick={() => run(() => api.cancelRecovery(node))}>Cancel recovery</button>
          </div>
        </div>
      )}

      <GuardianCard node={node} loaded={loaded} guardians={guardians} onRun={run} />
      <ApproveCard node={node} onRun={run} />
      <RecoveringCard />
    </div>
  );
}

function GuardianCard({
  node, loaded, guardians, onRun,
}: {
  node: string;
  loaded: boolean;
  guardians: GuardianInfo | null;
  onRun: (fn: () => Promise<SubmitResult>) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");

  const list = text.split("\n").map((s) => s.trim()).filter(Boolean);
  const valid = list.length >= 3 && list.length <= 10 && list.every((a) => a.startsWith("hlx"));

  return (
    <div className="card">
      <div className="section-title">Your guardians</div>
      {!loaded ? (
        <div className="muted">…</div>
      ) : guardians && !editing ? (
        <>
          <p className="muted small" style={{ marginTop: -4 }}>
            {guardians.threshold} of {guardians.guardians.length} must approve to recover your account.
          </p>
          <div className="list bordered">
            {guardians.guardians.map((g) => (
              <div className="list-row" key={g}>
                <div className="mono small">{shortAddr(g)}</div>
              </div>
            ))}
          </div>
          <div className="row-actions" style={{ marginTop: 12 }}>
            <button onClick={() => { setText(guardians.guardians.join("\n")); setEditing(true); }}>Replace guardians</button>
          </div>
        </>
      ) : (
        <>
          <p className="muted small" style={{ marginTop: -4 }}>
            Pick 3–10 people you trust (their <code>hlx…</code> addresses), one per line. Together they
            can rotate this account to a new key if you ever lose it. Replacing the set overwrites the old one.
          </p>
          <label className="field">
            <textarea
              className="mono"
              rows={5}
              value={text}
              spellCheck={false}
              placeholder={"hlx…\nhlx…\nhlx…"}
              onChange={(e) => setText(e.target.value)}
            />
          </label>
          <div className="row-actions end">
            {guardians && <button className="ghost" onClick={() => setEditing(false)}>Cancel</button>}
            <button className="primary" disabled={!valid} onClick={() => onRun(() => api.registerGuardians(node, list))}>
              {valid ? `Register ${list.length} guardians` : "Register guardians"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ApproveCard({ node, onRun }: { node: string; onRun: (fn: () => Promise<SubmitResult>) => void }) {
  const [target, setTarget] = useState("");
  const [pubkey, setPubkey] = useState("");
  const valid = target.trim().startsWith("hlx") && /^[0-9a-fA-F]+$/.test(pubkey.trim()) && pubkey.trim().length > 0;

  return (
    <div className="card">
      <div className="section-title">Approve a recovery</div>
      <p className="muted small" style={{ marginTop: -4 }}>
        You're a guardian for someone who lost their key? Enter their address and the new public key
        they gave you. Once enough guardians approve, the account rotates to that key.
      </p>
      <label className="field">
        <span>Account being recovered</span>
        <input className="mono" value={target} spellCheck={false} placeholder="hlx…" onChange={(e) => setTarget(e.target.value)} />
      </label>
      <label className="field">
        <span>Their new public key (hex)</span>
        <input className="mono" value={pubkey} spellCheck={false} placeholder="a1b2c3…" onChange={(e) => setPubkey(e.target.value)} />
      </label>
      <div className="row-actions end">
        <button className="primary" disabled={!valid} onClick={() => onRun(() => api.approveRecovery(node, target.trim(), pubkey.trim()))}>
          Approve recovery
        </button>
      </div>
    </div>
  );
}

function RecoveringCard() {
  const [pubkey, setPubkey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const show = async () => setPubkey(await api.myPublicKey());
  const copy = async () => {
    if (!pubkey) return;
    await navigator.clipboard.writeText(pubkey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="card">
      <div className="section-title">Recovering an account?</div>
      <p className="muted small" style={{ marginTop: -4 }}>
        If you're rebuilding a lost account into this fresh wallet, give this wallet's public key to
        your guardians — it's the key they rotate the old account to. Safe to share.
      </p>
      {pubkey ? (
        <>
          <div className="receive-address mono small">{pubkey}</div>
          <div className="row-actions end">
            <button onClick={copy}>{copied ? "Copied" : "Copy public key"}</button>
          </div>
        </>
      ) : (
        <div className="row-actions">
          <button onClick={show}>Show my public key</button>
        </div>
      )}
    </div>
  );
}
