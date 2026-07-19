import { useState } from "react";
import { api } from "../api";

export default function Unlock({ encrypted, onUnlocked }: { encrypted: boolean; onUnlocked: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.unlockWallet(encrypted ? passphrase : undefined);
      onUnlocked();
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
          <h1>Unlock your wallet</h1>
        </div>

        {encrypted ? (
          <label className="field">
            <span>Passphrase</span>
            <input
              type="password"
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && unlock()}
            />
          </label>
        ) : (
          <p className="muted">This wallet is not passphrase-protected.</p>
        )}

        {error && <div className="error">{error}</div>}

        <button className="primary" disabled={busy || (encrypted && !passphrase)} onClick={unlock}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </div>
    </div>
  );
}
