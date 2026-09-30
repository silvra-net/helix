//! A Mesh (formerly Rosetta) Data API for Helix.
//!
//! A separate service in front of a node's own REST API — the interface any integration uses —
//! so it can run, fail and be upgraded without touching consensus. It serves the read side:
//! networks, blocks with every balance change as operations, balances, the mempool. Construction
//! (building and signing transactions) is not served yet: Coinbase's Go SDK and `mesh-cli` do not
//! know ML-DSA-65, although the specification has since July 2026.
//!
//! **It needs a node that executed every block itself with a build that records balance changes
//! (#260)** — synced from genesis, not joined from a checkpoint, and not pruned. A block without
//! the record is refused with error 5 rather than shown incomplete.

pub mod cli;
pub mod map;
pub mod node;
pub mod server;
pub mod types;

pub use server::router;
