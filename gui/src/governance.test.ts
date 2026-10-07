import { describe, expect, it } from "vitest";
import { describeProposal, proposalState, upgradeNotice } from "./views/Governance";

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

describe("describeProposal", () => {
  // A voter must see when an upgrade bites, not just which version it names.
  it("names the version and the activation block of a protocol upgrade", () => {
    // Numbers in the reader's locale, like every other figure in the wallet.
    expect(describeProposal({ param: "ProtocolUpgrade", new_value: 2, activation_height: 520000 })).toBe(
      `Protocol upgrade → version 2 from block ${(520000).toLocaleString()}`,
    );
  });

  it("leaves the other parameters as they were", () => {
    expect(describeProposal({ param: "FuelPerFeeUnit", new_value: 3 })).toBe("FuelPerFeeUnit → 3");
  });
});

describe("upgradeNotice", () => {
  const scheduled = (supported: boolean) => ({ scheduled_upgrade: { version: 2, height: 1000, supported } });

  it("says nothing when no upgrade is scheduled, or the node does not report one", () => {
    expect(upgradeNotice({ scheduled_upgrade: null }, 500)).toBeNull();
    expect(upgradeNotice({}, 500)).toBeNull();
    expect(upgradeNotice(null, 500)).toBeNull();
  });

  // The one case that asks the user to act, by a deadline: the wallet's node stops there.
  it("warns, with the blocks left, when the answering node does not run the version", () => {
    const n = upgradeNotice(scheduled(false), 400)!;
    expect(n.warn).toBe(true);
    expect(n.text).toContain(`block ${(1000).toLocaleString()} (600 blocks from now)`);
    expect(n.text).toContain("stops before that block");
  });

  it("is a plain note when the answering node runs it", () => {
    const n = upgradeNotice(scheduled(true), 400)!;
    expect(n.warn).toBe(false);
    expect(n.text).toContain("nothing to do");
  });
});
