import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { GuardianInfo, RecoveryStatus, SubmitResult } from "../types";
import { shortAddr, shortHash } from "../format";

// Everything about who you are on-chain: your .hlx name, and social recovery (the guardians who
// can rotate a lost account, and helping recover someone else's). Two previously separate tabs —
// merged because both answer the same underlying question ("how does this address represent me,
// and what happens if I lose it"), not because either shrank.
export default function Identity({ node, address }: { node: string; address: string }) {
  const [myName, setMyName] = useState<string | null>(null);
  const [nameLoaded, setNameLoaded] = useState(false);
  const [newName, setNewName] = useState("");
  const [nameBusy, setNameBusy] = useState(false);

  const [guardians, setGuardians] = useState<GuardianInfo | null>(null);
  const [mine, setMine] = useState<RecoveryStatus | null>(null);
  const [recoveryLoaded, setRecoveryLoaded] = useState(false);

  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadName = useCallback(async () => {
    try {
      setMyName(await api.myName(node));
    } catch {
      setMyName(null);
    } finally {
      setNameLoaded(true);
    }
  }, [node]);

  const loadRecovery = useCallback(async () => {
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
      setRecoveryLoaded(true);
    }
  }, [node, address]);

  useEffect(() => {
    loadName();
    loadRecovery();
    const id = setInterval(() => {
      loadName();
      loadRecovery();
    }, 8000);
    return () => clearInterval(id);
  }, [loadName, loadRecovery]);

  const run = async (fn: () => Promise<SubmitResult>) => {
    setError(null);
    setNotice(null);
    try {
      const r = await fn();
      setNotice(`Submitted ${shortHash(r.tx_hash)} · ${r.status}`);
      loadName();
      loadRecovery();
    } catch (e) {
      setError(String(e));
    }
  };

  const registerName = async () => {
    setNameBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.registerName(node, newName.trim());
      setNotice(`Submitted (${r.status}) — your name appears once it lands in a block.`);
      setNewName("");
      loadName();
    } catch (e) {
      setError(String(e));
    } finally {
      setNameBusy(false);
    }
  };

  const cleanedName = newName.trim().replace(/\.hlx$/, "");
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

      <div className="card">
        <div className="section-title">Your name</div>
        {!nameLoaded ? (
          <div className="muted">…</div>
        ) : myName ? (
          <>
            <div className="your-name mono">{myName}.hlx</div>
            <p className="muted small">
              This name resolves to your address across Helix. Registering another name replaces it.
            </p>
          </>
        ) : (
          <p className="muted small" style={{ marginTop: -4 }}>
            You don't have a name yet. Register one so people can send to <code>you.hlx</code>
            {" "}instead of a raw address.
          </p>
        )}

        <label className="field" style={{ marginTop: 12 }}>
          <span>Register a name</span>
          <div className="name-input">
            <input
              value={newName}
              spellCheck={false}
              placeholder="alice"
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && cleanedName && registerName()}
            />
            <span className="suffix">.hlx</span>
          </div>
        </label>
        <button className="primary" disabled={nameBusy || !cleanedName} onClick={registerName}>
          {nameBusy ? "Signing…" : cleanedName ? `Register ${cleanedName}.hlx` : "Register"}
        </button>
      </div>

      <NameResolver node={node} />

      <div className="card">
        <div className="section-title">Recovering a lost account into this wallet?</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          This wallet's public key — the one your guardians rotate the old account to — is in
          <strong> Settings → Wallet identity</strong>.
        </p>
      </div>

      <GuardianCard node={node} loaded={recoveryLoaded} guardians={guardians} onRun={run} />
      <ApproveCard node={node} onRun={run} />
    </div>
  );
}

function NameResolver({ node }: { node: string }) {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<{ name: string; address: string | null } | null>(null);
  const [busy, setBusy] = useState(false);

  const resolve = async () => {
    const name = query.trim().replace(/\.hlx$/, "");
    if (!name) return;
    setBusy(true);
    try {
      const address = await api.resolveName(node, name);
      setResult({ name, address });
    } catch {
      setResult({ name, address: null });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="section-title">Look up a name</div>
      <label className="field">
        <span>Name</span>
        <div className="name-input">
          <input
            value={query}
            spellCheck={false}
            placeholder="alice"
            onChange={(e) => {
              setResult(null);
              setQuery(e.target.value);
            }}
            onKeyDown={(e) => e.key === "Enter" && resolve()}
          />
          <span className="suffix">.hlx</span>
        </div>
      </label>
      <button disabled={busy || !query.trim()} onClick={resolve}>
        {busy ? "Resolving…" : "Resolve"}
      </button>

      {result && (
        <div className="resolve-result">
          {result.address ? (
            <div className="kv">
              <span className="mono">{result.name}.hlx</span>
              <span className="mono" title={result.address}>→ {shortAddr(result.address)}</span>
            </div>
          ) : (
            <span className="muted">{result.name}.hlx is not registered.</span>
          )}
        </div>
      )}
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
