import { describe, expect, it } from "vitest";
import { timeAgo, hlx, shortAddr, shortHash, amountValue, amountInput } from "./format";

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

describe("amountValue", () => {
  // The backend signs the typed text exactly (`helix_core::fee::parse_hlx`); a form that enabled
  // "Send" for text the backend refuses would only move the error one click later.
  it("accepts what the backend reads, with either decimal separator", () => {
    expect(amountValue("2.01")).toBe(2.01);
    expect(amountValue(" 0,5 ")).toBe(0.5);
    expect(amountValue("5.")).toBe(5);
    expect(amountValue(".5")).toBe(0.5);
    expect(amountValue("0.000000001")).toBe(0.000000001);
  });

  it("refuses what the backend refuses", () => {
    for (const text of ["", ".", "1e3", "-1", "+1", "NaN", "Infinity", "1.2.3", "0.0000000001", "1 000"]) {
      expect(amountValue(text), text).toBeNull();
    }
  });
});

describe("amountInput", () => {
  it("never hands over a float's leftover digits", () => {
    const leftover = 10000 - 0.000000000002; // 9999.999999999998
    expect(amountValue(String(leftover))).toBeNull(); // the premise: String(n) would be refused
    expect(amountValue(amountInput(leftover))).not.toBeNull();
  });

  it("drops trailing zeros but not the zeros of a whole number", () => {
    expect(amountInput(1000)).toBe("1000");
    expect(amountInput(1000, 0)).toBe("1000");
    expect(amountInput(2.5, 6)).toBe("2.5");
    expect(amountInput(-1)).toBe("0");
  });
});
