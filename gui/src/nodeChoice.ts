import { DEFAULT_NODE, LOCAL_NODE, isLocalNode } from "./api";

/**
 * How many consecutive silent polls before the wallet gives up on an auto-detected local node.
 *
 * The poll runs every 5s, so this is ~15 seconds of silence. Not one: a node restarting, a
 * momentary hiccup, or a slow reply during heavy sync would otherwise bounce the wallet back and
 * forth between endpoints — and a wallet whose data source flickers is worse than one that waits.
 */
export const MISSES_BEFORE_FALLBACK = 3;

export interface NodeSituation {
  /** The endpoint the wallet is reading from right now. */
  current: string;
  /** The user typed an endpoint in Settings. That is an answer, and it is not ours to override. */
  stated: boolean;
  /** Consecutive polls in which `current` did not answer. */
  misses: number;
  /** Whether a node on this machine answered just now. */
  localIsUp: boolean;
}

/**
 * Decide which endpoint the wallet should read from, or `null` to stay put.
 *
 * Pulled out of the polling effect so the rules can be stated once and checked. Detection used to
 * run exactly once, in a `useEffect` with an empty dependency list, which left two ordinary
 * situations broken:
 *
 *   - Start the wallet, *then* start your node (terminal, systemd, pm2) — the wallet never
 *     noticed and kept reading balances off our public server, which is the whole thing this
 *     feature exists to stop.
 *   - An auto-detected local node stops — the wallet kept pointing at it and every screen failed
 *     with a connection error, with no way back short of a restart.
 *
 * The asymmetry is deliberate. Switching *to* a local node happens on the first successful probe,
 * because being wrong costs nothing (it answered, it works). Switching *away* waits for
 * `MISSES_BEFORE_FALLBACK`, because being wrong there means abandoning a healthy node over a
 * hiccup.
 */
export function nextNode(s: NodeSituation): string | null {
  // A stated preference outranks anything we detect. Someone who typed an address has already
  // answered this question, and silently moving them elsewhere would be the same disrespect as
  // ignoring their node in the first place — just in the other direction.
  if (s.stated) return null;

  if (isLocalNode(s.current)) {
    // Our own node has gone quiet for long enough that "temporarily busy" no longer explains it.
    return s.misses >= MISSES_BEFORE_FALLBACK ? DEFAULT_NODE : null;
  }

  // Reading from the public network while a node of our own is up and answering.
  return s.localIsUp ? LOCAL_NODE : null;
}
