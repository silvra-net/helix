import { describe, expect, it } from "vitest";
import { proposalState } from "./views/Governance";

const p = (over: Partial<{ executed: boolean; expires_at_height: number }> = {}) => ({
  executed: false,
  expires_at_height: 1000,
  ...over,
});

describe("proposalState", () => {
  it("is open while the chain is still inside the voting period", () => {
    expect(proposalState(p(), 999)).toBe("open");
    expect(proposalState(p(), 1000)).toBe("open");
  });

  // The defect this exists for: the chain reports an expired proposal with exactly the same
  // fields as a live one — `executed: false` and nothing else to go on. The wallet offered a
  // "Vote yes" button on it, and the chain had been answering "voting period has expired" for
  // however many thousands of blocks had passed.
  it("is expired one block past the voting period, not still open", () => {
    expect(proposalState(p(), 1001)).toBe("expired");
    expect(proposalState(p(), 50_000)).toBe("expired");
  });

  it("reports a passed proposal as passed even long after its period ended", () => {
    expect(proposalState(p({ executed: true }), 50_000)).toBe("passed");
  });

  // Before the first status poll the header has no height. Defaulting that to 0 must read as
  // "open", never "expired" — a wallet that greys out a live vote because it has not finished
  // loading is worse than one that offers a vote a moment early.
  it("does not call anything expired before the height is known", () => {
    expect(proposalState(p(), 0)).toBe("open");
  });
});
