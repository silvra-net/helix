import { describe, expect, it } from "vitest";
import { createActivityReporter, inactivityNotice } from "./idle";

/**
 * Telling the backend somebody is using the wallet — the one thing only the webview can see.
 *
 * The backend enforces the lock; this only has to report input promptly and not flood the IPC
 * bridge with one call per mouse movement.
 */
describe("reporting activity to the idle lock", () => {
  function reporterAt(start: number) {
    let clock = start;
    let reports = 0;
    const onActivity = createActivityReporter(() => reports++, 30_000, () => clock);
    return {
      onActivity,
      advance: (ms: number) => (clock += ms),
      reports: () => reports,
    };
  }

  /** The first input after unlocking must count straight away, not half a minute later. */
  it("reports the first activity at once", () => {
    const r = reporterAt(1_000_000);
    r.onActivity();
    expect(r.reports()).toBe(1);
  });

  /** A burst of mouse movement is one report, not hundreds of IPC calls. */
  it("reports a burst of input once", () => {
    const r = reporterAt(1_000_000);
    for (let i = 0; i < 500; i++) {
      r.onActivity();
      r.advance(10);
    }
    expect(r.reports()).toBe(1);
  });

  /**
   * Ongoing use keeps being reported, or the backend would lock a wallet somebody is working in
   * — ten minutes after the first keystroke, however busy they were since.
   */
  it("keeps reporting while the wallet is in use", () => {
    const r = reporterAt(1_000_000);
    for (let minute = 0; minute < 15; minute++) {
      r.onActivity();
      r.advance(60_000);
    }
    expect(r.reports()).toBe(15);
  });

  it("says why the wallet locked, in minutes", () => {
    expect(inactivityNotice(10)).toContain("10 minutes");
  });
});
