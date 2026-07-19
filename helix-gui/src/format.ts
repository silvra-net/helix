export function hlx(n: number): string {
  return n.toLocaleString(undefined, { maximumFractionDigits: 9 });
}

export function shortAddr(a: string | null | undefined): string {
  if (!a) return "—";
  return a.length > 18 ? `${a.slice(0, 10)}…${a.slice(-6)}` : a;
}

export function shortHash(h: string): string {
  return h.length > 14 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h;
}
