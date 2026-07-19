import { useState } from "react";
import { api } from "../api";

export default function Setup({
  onCreated,
  onRestored,
}: {
  onCreated: (mnemonic: string) => void;
  onRestored: () => void;
}) {
  const [tab, setTab] = useState<"create" | "restore">("create");
  const [passphrase, setPassphrase] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const w = await api.createWallet(passphrase || undefined);
      onCreated(w.mnemonic);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.restoreWallet(mnemonic.trim(), passphrase || undefined);
      onRestored();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="onboarding">
      <div className="card onboard-card">
        <div className="onboard-head">
          <span className="brand-mark big" aria-hidden>⛓</span>
          <h1>Helix Wallet</h1>
          <p className="muted">A quantum-secure wallet for the Helix testnet.</p>
        </div>

        <div className="tabs">
          <button className={tab === "create" ? "active" : ""} onClick={() => setTab("create")}>New wallet</button>
          <button className={tab === "restore" ? "active" : ""} onClick={() => setTab("restore")}>Restore</button>
        </div>

        {tab === "restore" && (
          <label className="field">
            <span>Recovery phrase (24 words)</span>
            <textarea
              rows={3}
              value={mnemonic}
              spellCheck={false}
              placeholder="abandon amount liar …"
              onChange={(e) => setMnemonic(e.target.value)}
            />
          </label>
        )}

        <label className="field">
          <span>Passphrase (optional, encrypts the wallet file)</span>
          <input
            type="password"
            value={passphrase}
            placeholder="leave empty for an unencrypted wallet"
            onChange={(e) => setPassphrase(e.target.value)}
          />
        </label>

        {error && <div className="error">{error}</div>}

        {tab === "create" ? (
          <button className="primary" disabled={busy} onClick={create}>
            {busy ? "Creating…" : "Create wallet"}
          </button>
        ) : (
          <button className="primary" disabled={busy || mnemonic.trim().split(/\s+/).length < 24} onClick={restore}>
            {busy ? "Restoring…" : "Restore wallet"}
          </button>
        )}

        <p className="fineprint muted">
          Your key is generated and stored on this machine. The 24 words are the only backup —
          they work in the Spark app too.
        </p>
      </div>
    </div>
  );
}
