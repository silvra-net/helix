/**
 * Whether to offer running your own node, and remembering that the offer was answered.
 *
 * The wallet works out of the box against the public network, which is what makes a fresh install
 * usable — and is also how someone ends up reading every balance off our server forever without
 * ever deciding to. Detection covers the people who already run a node; this covers the people who
 * would, if anyone had mentioned it.
 *
 * Asked once, never repeated, and never blocking: it is a card on Overview with a way to decline,
 * not a modal in front of a wallet somebody opened to check a balance. A prompt that has to be
 * dismissed before the app is usable teaches people to click past it, which is worse than not
 * asking — they would have "answered" without reading.
 */

/**
 * Deliberately its own key, not `helix-node`.
 *
 * Writing the answer into the node preference would record an endpoint the user never typed and
 * switch off auto-detection permanently — the wallet would then ignore a node they start later,
 * which is the exact failure this whole line of work exists to remove. Declining the offer must
 * leave detection fully intact.
 */
const ANSWERED_KEY = "helix-node-prompt-answered";

export function nodeOfferAnswered(): boolean {
  return localStorage.getItem(ANSWERED_KEY) !== null;
}

export function rememberNodeOfferAnswered(): void {
  localStorage.setItem(ANSWERED_KEY, "1");
}

export interface NodeOfferSituation {
  /** The user already answered this offer, either way. */
  answered: boolean;
  /** The wallet is already reading from a node on this machine. */
  usingLocalNode: boolean;
  /** The user typed an endpoint in Settings — they have thought about this already. */
  stated: boolean;
}

/**
 * Whether the offer is worth making.
 *
 * Every "no" here is someone who has already answered the question in some form, and asking them
 * anyway would be noise that trains people to ignore the card.
 */
export function shouldOfferOwnNode(s: NodeOfferSituation): boolean {
  if (s.answered) return false;
  // Already running one — the offer would be asking someone to do what they are doing.
  if (s.usingLocalNode) return false;
  // They named an endpoint themselves, so they know this setting exists and chose something else.
  if (s.stated) return false;
  return true;
}
