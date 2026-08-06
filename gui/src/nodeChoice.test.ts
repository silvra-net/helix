import { describe, expect, it } from "vitest";
import { DEFAULT_NODE, LOCAL_NODE } from "./api";
import { MISSES_BEFORE_FALLBACK, nextNode } from "./nodeChoice";

/**
 * The rules for which node the wallet reads from. These used to be spread across a startup effect
 * and two call sites in Validate, and the startup one ran exactly once — so the two situations
 * below were simply not handled at all.
 */
describe("choosing which node the wallet reads from", () => {
  /** The case the whole feature exists for: run your own node, and the wallet uses it. */
  it("moves to a local node as soon as one answers", () => {
    expect(
      nextNode({ current: DEFAULT_NODE, stated: false, misses: 0, localIsUp: true })
    ).toBe(LOCAL_NODE);
  });

  /**
   * The situation the single startup probe could not see: the wallet was already open when the
   * node started. Nothing distinguishes it from the case above except *when* it happens, which is
   * exactly why detection cannot be a one-off.
   */
  it("still moves across when the node appears after the wallet is already running", () => {
    // Same inputs, arrived at later — the rule must not care how long the wallet has been up.
    expect(
      nextNode({ current: DEFAULT_NODE, stated: false, misses: 12, localIsUp: true })
    ).toBe(LOCAL_NODE);
  });

  /** A fresh install with no node of its own must keep working against the public network. */
  it("stays on the public network when there is no local node", () => {
    expect(
      nextNode({ current: DEFAULT_NODE, stated: false, misses: 0, localIsUp: false })
    ).toBeNull();
  });

  /**
   * The other half that was missing: an auto-detected node that goes away used to leave every
   * screen erroring against an endpoint that no longer existed.
   */
  it("falls back to the public network once the local node has gone quiet for long enough", () => {
    expect(
      nextNode({ current: LOCAL_NODE, stated: false, misses: MISSES_BEFORE_FALLBACK, localIsUp: false })
    ).toBe(DEFAULT_NODE);
  });

  /**
   * And the control that keeps that from being trigger-happy. A node restarting, or busy during a
   * heavy sync, misses a poll or two — abandoning it there would mean a wallet whose data source
   * flickers between two chains' worth of answers.
   */
  it("does not abandon a local node over one or two missed polls", () => {
    for (let misses = 0; misses < MISSES_BEFORE_FALLBACK; misses++) {
      expect(
        nextNode({ current: LOCAL_NODE, stated: false, misses, localIsUp: false })
      ).toBeNull();
    }
  });

  /**
   * A typed-in address is an answer, and outranks anything detected — in both directions. Getting
   * this wrong once already meant the wallet recording a preference nobody stated and switching
   * detection off permanently.
   */
  it("never overrides an endpoint the user chose themselves", () => {
    expect(
      nextNode({ current: DEFAULT_NODE, stated: true, misses: 0, localIsUp: true })
    ).toBeNull();
    expect(
      nextNode({ current: "https://someone-elses-node.example", stated: true, misses: 99, localIsUp: true })
    ).toBeNull();
    expect(
      nextNode({ current: LOCAL_NODE, stated: true, misses: 99, localIsUp: false })
    ).toBeNull();
  });
});
