import { useState } from "react";

export default function Receive({ address }: { address: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard access can be refused (permissions / insecure context). Better to do nothing
      // than to leave an unhandled rejection — the address stays visible to copy by hand.
    }
  };

  return (
    <div className="stack">
      <div className="card receive-card">
        <div className="section-title">Receive HLX</div>
        <p className="muted">Share this address to receive HLX on the Helix testnet.</p>
        <div className="receive-address mono">{address || "—"}</div>
        <button className="primary" onClick={copy} disabled={!address}>
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
