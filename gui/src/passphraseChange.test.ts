import { describe, expect, it } from "vitest";
import { newPassphraseProblem } from "./passphraseChange";

describe("setting a new passphrase", () => {
  it("can be sent once both entries match", () => {
    expect(newPassphraseProblem("correct horse", "correct horse")).toBeNull();
  });

  /** An empty passphrase protects nothing; the backend refuses it too. */
  it("is not sent empty", () => {
    expect(newPassphraseProblem("", "")).not.toBeNull();
  });

  /** Nothing echoes a passphrase, so one entry is a typo waiting to lock someone out. */
  it("is not sent before it was typed twice, or when the two differ", () => {
    expect(newPassphraseProblem("correct horse", "")).not.toBeNull();
    expect(newPassphraseProblem("correct horse", "correct hose")).not.toBeNull();
  });

  /** A space is part of the passphrase (#223) — "pw " and "pw" are two different ones. */
  it("treats spaces as part of the passphrase", () => {
    expect(newPassphraseProblem("pw ", "pw")).not.toBeNull();
    expect(newPassphraseProblem(" pw ", " pw ")).toBeNull();
  });
});
