import { useEffect, useState } from "react";
import { api } from "../api";
import type { SubmitResult } from "../types";
import { hlx, shortAddr, shortHash } from "../format";

// Everything here exists to make a mistake visible *before* it is signed. A transfer cannot be
// undone, and the two ways to get one wrong — a mistyped recipient and an amount you don't have
// — were both only caught after pressing send, by an error from the node phrased for a
// developer. So: the recipient is validated (checksum and all) while typing, the amount is
// checked against the actual balance, and a confirmation step restates who gets what.
const FEE_RESERVE_HLX = 0.001;

export default function Send({
  node,
  baseFee,
  onDone,
}: {
  node: string;
  baseFee?: number;
  onDone: () => void;
}) {
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SubmitResult | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [balance, setBalance] = useState<number | null>(null);
  // undefined = nothing to resolve yet; null = looked up and not found; string = the address.
  const [resolved, setResolved] = useState<string | null | undefined>(undefined);
  // undefined = not checked yet (still typing / not address-shaped); boolean = the verdict.
  const [addrValid, setAddrValid] = useState<boolean | undefined>(undefined);

  const trimmed = to.trim();
  const looksLikeName = trimmed !== "" && !trimmed.startsWith("hlx");
  const looksLikeAddress = trimmed.startsWith("hlx");

  useEffect(() => {
    api.getOverview(node).then((o) => setBalance(o.balance_hlx)).catch(() => setBalance(null));
  }, [node]);

  // Check the recipient as it is typed — a name against the chain, an address against its own
  // checksum. Debounced so neither runs on every keystroke.
  useEffect(() => {
    if (trimmed === "") {
      setResolved(undefined);
      setAddrValid(undefined);
      return;
    }
    let alive = true;
    const id = setTimeout(async () => {
      if (looksLikeAddress) {
        try {
          const ok = await api.isValidAddress(trimmed);
          if (alive) {
            setAddrValid(ok);
            setResolved(undefined);
          }
        } catch {
          if (alive) setAddrValid(false);
        }
      } else {
        try {
          const a = await api.resolveName(node, trimmed);
          if (alive) {
            setResolved(a);
            setAddrValid(undefined);
          }
        } catch {
          if (alive) setResolved(null);
        }
      }
    }, 300);
    return () => {
      alive = false;
      clearTimeout(id);
    };
  }, [trimmed, node, looksLikeAddress]);

  const amountNum = Number(amount);
  const amountParses = amount.trim() !== "" && Number.isFinite(amountNum) && amountNum > 0;
  const overBalance = balance != null && amountParses && amountNum > balance;
  const recipientOk = looksLikeAddress ? addrValid === true : resolved != null;
  const valid = recipientOk && amountParses && !overBalance;

  // "Max" leaves a little behind for the fee. A transfer is ~5.4 KB and costs ~0.00001 HLX at
  // the floor, so this reserve is generous by two orders of magnitude on purpose: sending
  // *almost* everything and having it rejected for one nano is a worse outcome than a rounding
  // remainder nobody notices.
  const setMax = () => {
    if (balance == null) return;
    setAmount(Math.max(0, balance - FEE_RESERVE_HLX).toFixed(6).replace(/0+$/, "").replace(/\.$/, ""));
  };

  const send = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.sendHlx(node, trimmed, amountNum);
      setResult(r);
    } catch (e) {
      setError(String(e));
      setConfirming(false);
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <div className="stack">
        <div className="card success-card">
          <div className="section-title">Transaction submitted</div>
          <div className="kv">
            <span className="muted">Hash</span>
            <span className="mono">{shortHash(result.tx_hash)}</span>
          </div>
          <div className="kv">
            <span className="muted">Status</span>
            <span>{result.status}</span>
          </div>
          <p className="muted small">
            Accepted into the mempool — not yet in a block. It is normally included within a few
            seconds; Overview shows the final outcome (applied or failed) once it lands.
          </p>
          <button className="primary" onClick={onDone}>Back to overview</button>
        </div>
      </div>
    );
  }

  // Confirmation step: the last chance to notice that the address is not the one you meant.
  // Deliberately restates the recipient in full rather than shortened — a truncated address
  // hides exactly the middle characters a typo lives in.
  if (confirming) {
    return (
      <div className="stack">
        <div className="card form-card">
          <div className="section-title">Confirm transfer</div>
          <div className="kv">
            <span className="muted">Amount</span>
            <span className="mono" style={{ fontSize: 18 }}>{hlx(amountNum)} HLX</span>
          </div>
          <div className="kv" style={{ alignItems: "flex-start" }}>
            <span className="muted">To</span>
            <span className="mono small" style={{ wordBreak: "break-all", textAlign: "right" }}>
              {looksLikeName ? `${trimmed} → ${resolved}` : trimmed}
            </span>
          </div>
          {balance != null && (
            <div className="kv">
              <span className="muted">Left afterwards</span>
              <span className="mono">{hlx(Math.max(0, balance - amountNum))} HLX</span>
            </div>
          )}
          <p className="muted small">
            This cannot be reversed. Helix has no way to recall a transfer, and nobody — including
            us — can return coins sent to the wrong address.
          </p>
          {error && <div className="error">{error}</div>}
          <div className="row-actions end">
            <button className="ghost" onClick={() => setConfirming(false)} disabled={busy}>Back</button>
            <button className="primary" onClick={send} disabled={busy}>
              {busy ? "Signing…" : `Send ${hlx(amountNum)} HLX`}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      <div className="card form-card">
        <div className="section-title">Send HLX</div>

        <label className="field">
          <span>Recipient — address or name</span>
          <input
            className="mono"
            value={to}
            spellCheck={false}
            placeholder="hlx… or alice.hlx"
            onChange={(e) => setTo(e.target.value)}
          />
        </label>
        {looksLikeAddress && addrValid === false && (
          <div className="resolve-line small">
            <span className="text-warn">
              Not a valid Helix address — the checksum does not match, so a character is off
              somewhere. Paste it again rather than correcting it by eye.
            </span>
          </div>
        )}
        {looksLikeAddress && addrValid === true && (
          <div className="resolve-line small"><span className="muted">✓ valid address</span></div>
        )}
        {looksLikeName && resolved !== undefined && (
          <div className="resolve-line small">
            {resolved ? (
              <span className="muted">→ {shortAddr(resolved)}</span>
            ) : (
              <span className="text-warn">that name is not registered</span>
            )}
          </div>
        )}

        <label className="field">
          <span>
            Amount (HLX)
            {balance != null && (
              <span className="muted small" style={{ fontWeight: 400 }}> · available {hlx(balance)}</span>
            )}
          </span>
          <div className="row-actions" style={{ gap: 8 }}>
            <input
              inputMode="decimal"
              value={amount}
              placeholder="0.0"
              onChange={(e) => setAmount(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="ghost" onClick={setMax} disabled={balance == null}>Max</button>
          </div>
        </label>
        {overBalance && (
          <div className="resolve-line small">
            <span className="text-warn">
              More than you have — available is {hlx(balance!)} HLX.
            </span>
          </div>
        )}

        <p className="muted small">
          The fee is priced automatically against the chain
          {typeof baseFee === "number" ? ` (base fee ${baseFee} nano/byte)` : ""}. A transfer is
          ~5.4 KB, so at the floor it costs about 0.00001 HLX.
        </p>

        {error && <div className="error">{error}</div>}

        <div className="row-actions end">
          <button className="ghost" onClick={onDone}>Cancel</button>
          <button className="primary" disabled={!valid || busy} onClick={() => setConfirming(true)}>
            Review
          </button>
        </div>
      </div>
    </div>
  );
}
