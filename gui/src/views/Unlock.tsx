import { useState } from "react";
import { api } from "../api";

export default function Unlock({
  encrypted,
  notice,
  onUnlocked,
}: {
  encrypted: boolean;
  /** Why the wallet is locked, when it locked itself after going unused. */
  notice?: string | null;
  onUnlocked: () => void;
}) {
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

        {notice && (
          <p className="muted" role="status">
            {notice}
          </p>
        )}

        {encrypted ? (
          <label className="field">
            <span>Passphrase</span>
            <input
              type="password"
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !busy && passphrase && unlock()}
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
