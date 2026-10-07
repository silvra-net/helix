import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";

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
        <p className="muted">Share this address to receive HLX.</p>
        {address && (
          // Rendered entirely client-side (qrcode.react is pure JS, no network fetch — CSP-safe).
          // Fixed white background with dark modules regardless of the app theme: a QR needs
          // dark-on-light contrast to scan, and a dark-themed inversion would silently not.
          <div className="qr-frame">
            <QRCodeSVG value={address} size={176} level="M" marginSize={2} bgColor="#ffffff" fgColor="#0a0a0a" />
          </div>
        )}
        <div className="receive-address mono">{address || "—"}</div>
        <button className="primary" onClick={copy} disabled={!address}>
          {copied ? "Copied" : "Copy address"}
        </button>
        <p className="muted small">
          A transfer cannot be undone: have the sender check the address before they send.
        </p>
      </div>
    </div>
  );
}
