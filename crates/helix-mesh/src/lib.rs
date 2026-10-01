//! A Mesh (formerly Rosetta) Data API for Helix.
//!
//! A separate service in front of a node's own REST API — the interface any integration uses —
//! so it can run, fail and be upgraded without touching consensus. It serves the read side:
//! networks, blocks with every balance change as operations, balances, the mempool — and the
//! Construction API for a transfer of HLX, signed by the caller with ML-DSA-65 (`ml_dsa_65`, in
//! the specification since July 2026). Run with `--offline`, it serves only what needs no node:
//! the steps around signing, on a machine that never talks to the network.
//!
//! Coinbase's `mesh-cli` cannot check the Construction API yet — its SDK signs no ML-DSA — so it
//! is checked here end to end against a real chain, signed with this repository's ML-DSA.
//!
//! **It needs a node that executed every block itself with a build that records balance changes
//! (#260)** — synced from genesis, not joined from a checkpoint, and not pruned. A block without
//! the record is refused with error 5 rather than shown incomplete.

pub mod cli;
pub mod construction;
pub mod map;
pub mod node;
pub mod server;
pub mod types;

pub use server::{offline_router, router};
