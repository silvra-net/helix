export function hlx(n: number): string {
  return n.toLocaleString(undefined, { maximumFractionDigits: 9 });
}

/// The amount rule the wallet's backend applies (`helix_core::fee::parse_hlx`): digits, at most one
/// decimal separator (`.` or `,`), at most nine decimals — a nano-HLX is the smallest amount. The
/// text itself goes to the backend and is signed exactly as typed; the number returned here is only
/// for comparing against a balance. `null` when the backend would refuse the text, so a form never
/// offers to send what will be turned down (`Number("1e3")` is 1000, but "1e3" is not an amount).
export function amountValue(text: string): number | null {
  const t = text.trim();
  if (!/^(\d+([.,]\d{0,9})?|[.,]\d{1,9})$/.test(t)) return null;
  return Number(t.replace(",", "."));
}

/// A computed amount (balance minus a reserve, a shortfall) as text the backend reads: at most
/// `decimals` places, trailing zeros dropped. `String(n)` would hand over whatever a float
/// subtraction left behind — `9999.999999999998` has twelve decimals and would be refused.
export function amountInput(n: number, decimals = 9): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  const text = n.toFixed(decimals);
  return text.includes(".") ? text.replace(/0+$/, "").replace(/\.$/, "") : text;
}

export function shortAddr(a: string | null | undefined): string {
  if (!a) return "—";
  return a.length > 18 ? `${a.slice(0, 10)}…${a.slice(-6)}` : a;
}

export function shortHash(h: string): string {
  return h.length > 14 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h;
}

/// "3 min ago" for anything recent, an absolute date once that stops being useful.
///
/// A block height answers "where in the chain", never "was this today or last week" — which is
/// the question someone scanning their own history is actually asking.
///
/// **Milliseconds in.** `BlockHeader::timestamp` is milliseconds since the epoch and the RPC
/// hands it through unchanged, so the history rows carry milliseconds. This used to take
/// seconds, which made every subtraction wildly negative and every transaction ever made read
/// "just now" — the one word that made the column useless while looking like it worked.
export function timeAgo(unixMillis: number): string {
  if (!unixMillis) return "";
  const secs = Math.floor((Date.now() - unixMillis) / 1000);
  if (secs < 0) return "just now"; // clock skew between node and desktop — don't show "-2 min"
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} d ago`;
  return new Date(unixMillis).toLocaleDateString();
}
