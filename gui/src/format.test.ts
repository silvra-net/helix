import { describe, expect, it } from "vitest";
import { timeAgo, hlx, shortAddr, shortHash } from "./format";

describe("timeAgo", () => {
  // The regression: `BlockHeader::timestamp` is **milliseconds**, and the RPC hands it through
  // unchanged. Reading it as seconds made every subtraction hugely negative, and the negative
  // branch answers "just now" — so every transaction in the wallet's history, however old, read
  // "just now". It looked like a working column.
  it("reads the chain's millisecond timestamps, not seconds", () => {
    const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
    expect(timeAgo(tenMinutesAgo)).toBe("10 min ago");
  });

  it("handles the units that used to be confused without falling back to 'just now'", () => {
    // A real block timestamp from the live chain (2026-08-27 00:15 UTC, in ms).
    const realBlockTimestamp = 1787789751970;
    // Whatever it renders, it must not be the catch-all — the value is a valid past instant.
    const rendered = timeAgo(realBlockTimestamp);
    expect(rendered).not.toBe("");
    // Read as seconds this would be ~56000 years in the future and render "just now".
    if (Date.now() - realBlockTimestamp > 3 * 60 * 1000) {
      expect(rendered).not.toBe("just now");
    }
  });

  it("still says 'just now' for something genuinely recent", () => {
    expect(timeAgo(Date.now() - 5_000)).toBe("just now");
  });

  it("does not show a negative age when the node's clock runs ahead", () => {
    expect(timeAgo(Date.now() + 120_000)).toBe("just now");
  });

  it("is empty for a missing timestamp rather than 1970", () => {
    expect(timeAgo(0)).toBe("");
  });

  it("climbs through the units", () => {
    expect(timeAgo(Date.now() - 90 * 60 * 1000)).toBe("1 h ago");
    expect(timeAgo(Date.now() - 3 * 24 * 3600 * 1000)).toBe("3 d ago");
  });

  it("falls back to a date once 'd ago' stops helping", () => {
    const old = Date.now() - 30 * 24 * 3600 * 1000;
    expect(timeAgo(old)).toBe(new Date(old).toLocaleDateString());
  });
});

describe("address and hash shortening", () => {
  it("keeps enough of an address on both sides to compare it by eye", () => {
    const a = "hlxRy5cA5oNJ4n2KU5JQSSCcu78Y5Dq1i5QF";
    const s = shortAddr(a);
    expect(s.startsWith(a.slice(0, 10))).toBe(true);
    expect(s.endsWith(a.slice(-6))).toBe(true);
  });

  it("renders a missing address as a dash, never as 'null'", () => {
    expect(shortAddr(null)).toBe("—");
    expect(shortAddr(undefined)).toBe("—");
  });

  it("leaves a short hash alone instead of mangling it", () => {
    expect(shortHash("abc")).toBe("abc");
  });
});

describe("hlx", () => {
  it("keeps all nine decimals a nano-HLX amount can carry", () => {
    expect(hlx(0.000000001)).toContain("000000001");
  });
});
