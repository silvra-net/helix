import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { shortAddr } from "../format";

export default function Names({ node }: { node: string }) {
  const [myName, setMyName] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [newName, setNewName] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setMyName(await api.myName(node));
    } catch {
      setMyName(null);
    } finally {
      setLoaded(true);
    }
  }, [node]);

  useEffect(() => {
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [load]);

  const register = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.registerName(node, newName.trim());
      setNotice(`Submitted (${r.status}) — your name appears once it lands in a block.`);
      setNewName("");
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const cleaned = newName.trim().replace(/\.hlx$/, "");

  return (
    <div className="stack">
      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="section-title">Your name</div>
        {!loaded ? (
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
              onKeyDown={(e) => e.key === "Enter" && cleaned && register()}
            />
            <span className="suffix">.hlx</span>
          </div>
        </label>
        <button className="primary" disabled={busy || !cleaned} onClick={register}>
          {busy ? "Signing…" : cleaned ? `Register ${cleaned}.hlx` : "Register"}
        </button>
      </div>

      <Resolver node={node} />
    </div>
  );
}

function Resolver({ node }: { node: string }) {
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
