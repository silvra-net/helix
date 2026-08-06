import { describe, expect, it } from "vitest";
import { shouldOfferOwnNode } from "./nodePrompt";

/**
 * When the wallet offers to set up a node of your own.
 *
 * The default — reading from a public server — is what makes a fresh install work, and is also how
 * somebody ends up trusting someone else's answer about their own balance forever without ever
 * deciding to. The offer exists to turn that from a default into a choice, exactly once.
 */
describe("offering to run your own node", () => {
  /** The case it exists for: a fresh wallet, no node, nothing configured. */
  it("asks a wallet that is reading from the public network", () => {
    expect(
      shouldOfferOwnNode({ answered: false, usingLocalNode: false, stated: false })
    ).toBe(true);
  });

  /** Asked and answered — either way. Asking again is how a prompt becomes noise. */
  it("never asks twice", () => {
    expect(
      shouldOfferOwnNode({ answered: true, usingLocalNode: false, stated: false })
    ).toBe(false);
  });

  /** Asking someone to do the thing they are already doing. */
  it("does not ask someone who is already running a node", () => {
    expect(
      shouldOfferOwnNode({ answered: false, usingLocalNode: true, stated: false })
    ).toBe(false);
  });

  /**
   * Someone who typed an endpoint knows the setting exists and picked something else — a remote
   * node of their own, a friend's, a second machine. Offering them the bundled one second-guesses
   * a decision they already made.
   */
  it("does not ask someone who chose an endpoint themselves", () => {
    expect(
      shouldOfferOwnNode({ answered: false, usingLocalNode: false, stated: true })
    ).toBe(false);
  });
});
