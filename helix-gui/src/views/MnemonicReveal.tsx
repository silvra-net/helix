import { useState } from "react";

// Shown once, right after a wallet is created. The words are never persisted — the user writes
// them down here or loses the only backup. A confirm gate stops an accidental click-through.
export default function MnemonicReveal({ mnemonic, onDone }: { mnemonic: string; onDone: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const words = mnemonic.trim().split(/\s+/);

  return (
    <div className="onboarding">
      <div className="card onboard-card">
        <h1>Write down your recovery phrase</h1>
        <p className="muted">
          These 24 words are your wallet. Anyone who reads them owns it, and this is the only time
          they are shown. Write them on paper — not a screenshot, not a file.
        </p>

        <ol className="mnemonic-grid">
          {words.map((w, i) => (
            <li key={i}>
              <span className="idx">{i + 1}</span>
              <span className="word">{w}</span>
            </li>
          ))}
        </ol>

        <label className="checkbox">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          I have written these 24 words down and stored them safely.
        </label>

        <button className="primary" disabled={!confirmed} onClick={onDone}>
          Continue to wallet
        </button>
      </div>
    </div>
  );
}
