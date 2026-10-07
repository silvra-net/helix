//! What the chain state costs per block as the number of accounts grows (point B of the mainnet
//! preparation, #269). It prints the whole table and holds the one budget the numbers support.
//!
//! Measured on 2026-10-07, release, 100,000 accounts, a block that moves 20 of them:
//! `HelixDb::save_chain_state` took 545 ms and grew the file by 3.9 MB per block, because it wrote
//! every account back after every block. Writing only the changed ones: 24.5 ms and 36 KB. The
//! budget below sits well above the second and well below the first, so a loaded machine passes
//! and the old behaviour does not.
//!
//! The state root (#270) is measured twice: once in full — what a loaded or received state costs,
//! one time — and per block, after 20 accounts moved: what every block costs from then on. Before
//! #270 every call rehashed the whole state, 54–58 ms at 100,000 accounts; the per-block budget
//! below is far under that and holds at any account count, because a block costs what it wrote.

use std::time::{Duration, Instant};

use helix_executor::{AccountState, ChainState};
use helix_storage::db::HelixDb;

fn chain_with(accounts: u64) -> ChainState {
    let mut state = ChainState::new(0);
    for i in 0..accounts {
        let address = format!("hlx{i:033}");
        state.accounts.insert(
            address.clone(),
            AccountState {
                address,
                balance: 1_000_000_000 + i,
                staked: 0,
                unbonding_stake: 0,
                unbonding_unlock_height: 0,
                unbonding_source: None,
                nonce: i % 50,
                code: None,
            },
        );
    }
    state
}

/// One block's worth of change: `touched` accounts move, the height moves on.
fn next_block(state: &mut ChainState, touched: u64) {
    let height = state.applied_height + 1;
    let n = state.accounts.len() as u64;
    for k in 0..touched {
        let address = format!("hlx{:033}", (height * 7919 + k * 104_729) % n);
        let account = state.accounts.get_mut(&address).expect("an existing account");
        account.balance += 1;
        account.nonce += 1;
    }
    state.applied_height = height;
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn allocated_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.blocks() * 512).unwrap_or(0)
}

#[test]
#[ignore = "up to 100,000 accounts — run with --release --ignored (build-all does)"]
fn state_scale() {
    println!(
        "{:>8} | {:>11} | {:>11} | {:>11} | {:>12} | {:>12} | {:>9} | {:>14}",
        "accounts", "root, full", "root, block", "serialize", "save, first", "save, block", "load", "file per block"
    );
    for accounts in [1_000u64, 10_000, 100_000] {
        let mut state = chain_with(accounts);
        state.applied_height = 1;

        // In full: a state that was built whole has no settlement to start from.
        let root_full = median((0..3).map(|_| {
            let mut fresh = state.clone();
            fresh.commitment = Default::default();
            let t = Instant::now();
            fresh.settle_commitment();
            std::hint::black_box(fresh.state_hash());
            t.elapsed()
        }).collect());
        state.settle_commitment();
        // Per block: 20 accounts move, the commitment is settled as `execute_block` does, and the
        // root is read — as every proposal and `/status` reads it.
        let root_block = median((0..10).map(|_| {
            let mut block = state.clone();
            next_block(&mut block, 20);
            let t = Instant::now();
            block.settle_commitment();
            std::hint::black_box(block.state_hash());
            t.elapsed()
        }).collect());
        let mut check = state.clone();
        next_block(&mut check, 20);
        let incremental = check.state_hash();
        check.commitment = Default::default();
        assert_eq!(incremental, check.state_hash(), "positive control: the per-block root is the full one");
        let serialize = median((0..5).map(|_| {
            let t = Instant::now();
            std::hint::black_box(bincode::serialize(&state).unwrap());
            t.elapsed()
        }).collect());

        // Snapshots off: they are taken every 10,000 heights, not per block, and would only
        // blur the per-block figure.
        let db = HelixDb::open_temporary("helix-state-scale").unwrap();
        let path = db.path().to_path_buf();
        drop(db);
        let db = HelixDb::open_with_snapshot_interval(&path, 0).unwrap();
        let t = Instant::now();
        db.save_chain_state(&state).unwrap();
        let save_first = t.elapsed();

        let blocks = 10;
        let before = allocated_bytes(&path);
        let save_block = median((0..blocks).map(|_| {
            next_block(&mut state, 20);
            let t = Instant::now();
            db.save_chain_state(&state).unwrap();
            t.elapsed()
        }).collect());
        let per_block = allocated_bytes(&path).saturating_sub(before) / blocks;

        let t = Instant::now();
        let loaded = db.load_chain_state(0).unwrap();
        let load = t.elapsed();
        assert_eq!(loaded.accounts.len() as u64, accounts, "positive control: everything came back");
        drop(db);
        let _ = std::fs::remove_file(&path);

        println!(
            "{accounts:>8} | {:>9.1}ms | {:>9.3}ms | {:>9.2}ms | {:>10.1}ms | {:>10.1}ms | {:>7.0}ms | {:>11} KB",
            root_full.as_secs_f64() * 1e3,
            root_block.as_secs_f64() * 1e3,
            serialize.as_secs_f64() * 1e3,
            save_first.as_secs_f64() * 1e3,
            save_block.as_secs_f64() * 1e3,
            load.as_secs_f64() * 1e3,
            per_block / 1024,
        );
        if accounts == 100_000 {
            assert!(
                root_block < Duration::from_millis(5),
                "settling a block that moved 20 of {accounts} accounts and reading the root took \
                 {root_block:?} — the commitment is being recomputed from every entry"
            );
            assert!(
                save_block < Duration::from_millis(200),
                "saving a block that moved 20 of {accounts} accounts took {save_block:?} — it is \
                 writing accounts the block did not change again"
            );
            assert!(
                per_block < 1024 * 1024,
                "a block that moved 20 of {accounts} accounts grew the file by {per_block} bytes"
            );
        }
    }
}
