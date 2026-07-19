import { useState } from "react";

export default function Receive({ address }: { address: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="stack">
      <div className="card receive-card">
        <div className="section-title">Receive HLX</div>
        <p className="muted">Share this address to receive HLX on the Helix testnet.</p>
        <div className="receive-address mono">{address || "—"}</div>
        <button className="primary" onClick={copy}>
          {copied ? "Copied" : "Copy address"}
        </button>
        <p className="muted small">
          Reminder: HLX on the testnet is a valueless test token — anything received here does not
          survive a chain reset.
        </p>
      </div>
    </div>
  );
}
