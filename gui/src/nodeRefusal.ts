import type { LogLine } from "./types";

/// What the bundled node prints when it refuses the chain database it finds on this machine:
/// one from another chain — the network was reset and this copy was not — or one this build
/// cannot read, written by an older, incompatible one. Both are repaired by the same button,
/// "Reset local chain", which renames the database so the next start fetches the current chain.
///
/// helix-node's tests read this list and check that its refusals still say these words — the
/// node and the wallet are separate programs, and a reworded message would otherwise switch the
/// hint off without anything failing.
export const LOCAL_CHAIN_REFUSALS = [
  "holds the chain whose genesis is",
  "holds a block 0 this build cannot read",
] as const;

/// Whether the node's output says it refused this machine's copy of the chain.
export function refusedLocalChain(lines: readonly Pick<LogLine, "line">[]): boolean {
  return lines.some((l) => LOCAL_CHAIN_REFUSALS.some((marker) => l.line.includes(marker)));
}
