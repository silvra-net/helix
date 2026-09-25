import { describe, expect, it } from "vitest";
import { refusedLocalChain } from "./nodeRefusal";

const line = (text: string) => ({ line: text });

describe("recognising a node that refused this machine's chain", () => {
  /** After a network reset: the database holds the old chain (helix-node, #239). */
  it("recognises a database from another chain", () => {
    expect(
      refusedLocalChain([
        line("INFO helix::node: Validator address : hlx…"),
        line("Error: helix-data.redb holds the chain whose genesis is 1a2b…, but Helix 0.16.0 joins the public network"),
      ]),
    ).toBe(true);
  });

  /** A database written by an older build this one cannot read. */
  it("recognises a database this build cannot read", () => {
    expect(
      refusedLocalChain([line("Error: helix-data.redb holds a block 0 this build cannot read: invalid value")]),
    ).toBe(true);
  });

  /** Anything else is not a reason to offer throwing the local chain away. */
  it("stays quiet about other failures", () => {
    expect(refusedLocalChain([])).toBe(false);
    expect(
      refusedLocalChain([
        line("Error: the data directory helix-data.redb is already in use by another running helix node."),
        line("[process exited, code 1]"),
      ]),
    ).toBe(false);
  });
});
