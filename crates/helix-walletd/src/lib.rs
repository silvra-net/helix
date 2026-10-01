//! A wallet with Bitcoin Core's JSON-RPC interface, for exchanges.
//!
//! Most exchanges integrate a chain through the interface they already run for Bitcoin and its
//! descendants: `getnewaddress` for a deposit address per customer, `listsinceblock` to find
//! deposits, `sendtoaddress` for withdrawals. This service gives Helix that interface, in front of
//! a Helix node the exchange runs itself.
//!
//! Helix keeps an account per address, where Bitcoin keeps coins, so the wallet does what an
//! exchange would otherwise build around an account chain: each deposit is **swept** to one hot
//! address once a block holds it (a block is final), and every send draws from that address. A
//! sweep costs one base fee and moves nothing out of the wallet; it shows as a `send` of 0 with
//! its fee and `helix_sweep: true`.
//!
//! Keys are signed with ML-DSA-65 inside this service — no external key service needs to know
//! the scheme — and stored in the `KeyFile` format the CLI and the node use.
//!
//! **The node behind it must record balance changes (0.20.2 or later) for every block from the
//! wallet's birth on** — every node that ran 0.20.2 when those blocks came does.

pub mod amount;
pub mod cli;
pub mod client;
pub mod conf;
pub mod daemon;
pub mod keys;
pub mod ledger;
pub mod methods;
pub mod node;
pub mod notify;
pub mod rpc;
pub mod server;
