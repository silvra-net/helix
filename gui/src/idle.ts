/**
 * The frontend's half of the idle lock: telling the backend that somebody is using the wallet.
 *
 * The backend decides when to lock and does it (`gui/src-tauri/src/state.rs`) — a timer in this
 * webview would stop counting whenever the operating system throttles or suspends a background
 * window, and the key would sit in memory with nothing watching. What only the webview can see is
 * input, so it reports that, and nothing else.
 */

/// At most this often. The backend locks after ten minutes, so reporting every half minute makes
/// the lock land between 9½ and 10 minutes after the last input — close enough — without an IPC
/// call on every mouse movement.
export const ACTIVITY_REPORT_EVERY_MS = 30_000;

/// What counts as somebody being there. Pointer movement too: reading a long history with the
/// mouse resting on it is use, and without it the wallet would lock under someone scrolling
/// with a trackpad's inertia or reading a page they just opened.
export const ACTIVITY_EVENTS = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"] as const;

/**
 * Returns a handler to attach to every activity event; it calls `report` on the first activity
 * and then at most once per `everyMs`, however many events arrive in between.
 */
export function createActivityReporter(
  report: () => void,
  everyMs: number = ACTIVITY_REPORT_EVERY_MS,
  now: () => number = Date.now,
): () => void {
  let last = -Infinity;
  return () => {
    const t = now();
    if (t - last >= everyMs) {
      last = t;
      report();
    }
  };
}

/** What the unlock screen says after the backend locked by itself. */
export function inactivityNotice(minutes: number): string {
  return `Locked after ${minutes} minutes without use — the key was cleared from memory. Unlock to continue.`;
}
