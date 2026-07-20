import { useEffect, useState } from "react";
import { api } from "../api";

// Settings: the deliberate backup path. A wallet created before you wrote the 24 words down would
// otherwise have no recovery — here you can re-reveal the phrase (re-authenticating with the
// passphrase), and read the address / public key you hand to guardians for social recovery.
export default function Settings({ address }: { address: string }) {
  const [passphrase, setPassphrase] = useState("");
  const [words, setWords] = useState<string[] | null>(null);
  const [pubkey, setPubkey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [logDir, setLogDir] = useState<string | null>(null);

  useEffect(() => {
    api.logDirPath().then(setLogDir).catch(() => setLogDir(null));
  }, []);

  const reveal = async () => {
    setBusy(true);
    setError(null);
    try {
      const m = await api.revealMnemonic(passphrase);
      setWords(m.trim().split(/\s+/));
      setPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const showPubkey = async () => {
    setError(null);
    try {
      setPubkey(await api.myPublicKey());
    } catch (e) {
      setError(String(e));
    }
  };

  const copy = async (what: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(what);
    setTimeout(() => setCopied(null), 1200);
  };

  return (
    <div className="stack">
      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="section-title">Recovery phrase</div>
        {words ? (
          <>
            <div className="warn-inline">
              Anyone who reads these 24 words owns this wallet. Reveal them only somewhere private.
            </div>
            <ol className="mnemonic-grid">
              {words.map((w, i) => (
                <li key={i}>
                  <span className="idx">{i + 1}</span>
                  <span className="word">{w}</span>
                </li>
              ))}
            </ol>
            <div className="row-actions end">
              <button className="ghost" onClick={() => setWords(null)}>Hide</button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small" style={{ marginTop: -4 }}>
              Re-show the 24-word phrase for this wallet — your only backup if you lose the device.
              Enter your passphrase to confirm (leave blank if you didn't set one).
            </p>
            <div className="row-actions" style={{ gap: 8 }}>
              <input
                type="password"
                className="node-input"
                style={{ width: 220 }}
                value={passphrase}
                placeholder="passphrase"
                onChange={(e) => setPassphrase(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && reveal()}
              />
              <button className="primary" disabled={busy} onClick={reveal}>
                {busy ? "…" : "Reveal recovery phrase"}
              </button>
            </div>
          </>
        )}
      </div>

      <div className="card">
        <div className="section-title">Wallet identity</div>
        <div className="kv">
          <span className="muted">Address</span>
          <span className="mono" style={{ wordBreak: "break-all", textAlign: "right" }}>{address}</span>
        </div>
        <div className="row-actions end">
          <button onClick={() => copy("address", address)}>{copied === "address" ? "Copied" : "Copy address"}</button>
        </div>

        {pubkey ? (
          <>
            <div className="kv" style={{ marginTop: 10 }}>
              <span className="muted">Public key</span>
              <span className="mono small" style={{ wordBreak: "break-all", textAlign: "right", maxWidth: "70%" }}>{pubkey}</span>
            </div>
            <p className="muted small">Hand this to your guardians when recovering a lost account — it is the key they rotate the account to. Safe to share.</p>
            <div className="row-actions end">
              <button onClick={() => copy("pubkey", pubkey)}>{copied === "pubkey" ? "Copied" : "Copy public key"}</button>
            </div>
          </>
        ) : (
          <div className="row-actions" style={{ marginTop: 10 }}>
            <button onClick={showPubkey}>Show public key</button>
          </div>
        )}
      </div>

      <div className="card">
        <div className="section-title">Diagnostics</div>
        <p className="muted small" style={{ marginTop: -4 }}>
          If something goes wrong, this file has the details — attach it when reporting a bug.
          It never contains your passphrase, mnemonic, or private key.
        </p>
        {logDir ? (
          <>
            <div className="kv">
              <span className="muted">Log folder</span>
              <span className="mono small" style={{ wordBreak: "break-all", textAlign: "right", maxWidth: "70%" }}>{logDir}</span>
            </div>
            <div className="row-actions end">
              <button onClick={() => copy("logdir", logDir)}>{copied === "logdir" ? "Copied" : "Copy path"}</button>
            </div>
          </>
        ) : (
          <p className="muted small">Log folder unavailable.</p>
        )}
      </div>
    </div>
  );
}
