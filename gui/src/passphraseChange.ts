/**
 * Giving a wallet a passphrase after the fact, or a new one (#226).
 *
 * The idle lock only means something for a wallet that has a passphrase — without one, unlocking
 * is a click — and the app could set one only at creation. The backend does the work
 * (`change_passphrase`: re-authenticate, re-encrypt, check, replace in one step); this decides
 * when the form may be sent.
 */

/**
 * What keeps the new passphrase from being set, or `null` when nothing does. Typed twice because
 * nothing echoes it: a typo would otherwise be found the next time the wallet is opened, when
 * only the 24 words can help. Taken as typed — spaces included (#223) — so nothing is trimmed.
 */
export function newPassphraseProblem(next: string, repeat: string): string | null {
  if (next === "") return "Choose a new passphrase.";
  if (repeat === "") return "Type it a second time.";
  if (next !== repeat) return "The two entries are not the same.";
  return null;
}
