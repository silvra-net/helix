import { describe, expect, it } from "vitest";
import { DEFAULT_NODE, LOCAL_NODE, usableStoredNode } from "./api";

/**
 * A wallet that ever had `helix.silvra.net` in its node field kept it through every update after
 * the public node moved to `node.silvra.net` (2026-08-26), and every request failed with "error
 * sending request". Seen on 2026-10-14 with a freshly installed wallet that had run an old one.
 */
describe("usableStoredNode", () => {
  it("forgets the retired public endpoint, in any spelling a person might have stored", () => {
    for (const stored of [
      "https://helix.silvra.net",
      "https://helix.silvra.net/",
      "http://helix.silvra.net",
      " https://helix.silvra.net ",
    ]) {
      expect(usableStoredNode(stored), stored).toBeNull();
    }
  });

  it("keeps every other endpoint the person chose", () => {
    for (const stored of [DEFAULT_NODE, LOCAL_NODE, "https://my-node.example:8545", "http://192.168.1.5:8545"]) {
      expect(usableStoredNode(stored)).toBe(stored);
    }
  });

  it("has nothing to say about nothing stored, or about text that is not a URL", () => {
    expect(usableStoredNode(null)).toBeNull();
    expect(usableStoredNode("not a url")).toBe("not a url");
  });
});
