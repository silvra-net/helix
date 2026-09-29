//! Every message a peer can send is decoded with bincode from a bounded buffer. #246 found a
//! library one layer below (winterfell) reserving memory for a length it read from untrusted
//! bytes, before checking the bytes were there — one changed byte, one aborted process, on every
//! node. This test asks the same question of every decoder that reads a peer's bytes: write the
//! largest length a field could say over every position of a real message, decode, and measure
//! the largest single allocation the decode made.
//!
//! What should hold, and why: bincode's slice reader checks a byte buffer's length against what
//! is left, and serde reserves at most 1 MiB ahead for any sequence or map. So no decode of a
//! message of a few KB may ask for more than a couple of MiB. Not asserted as "did not abort"
//! alone: a reservation of gigabytes that the kernel happens to grant (overcommit) is the same
//! fault, just quieter — the counting allocator sees it either way.
//!
//! Its own binary, so the allocator it installs counts nothing but this test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use helix_consensus::proposal::Proposal;
use helix_consensus::vote::{Vote, VoteType};
use helix_core::block::{genesis_block, Block, CommitSig};
use helix_core::{CryptoVersion, Transaction, TxType};
use helix_crypto::{Address, Hash, PublicKey, Signature};
use helix_p2p::blocksync::BlockSyncResponse;
use helix_p2p::compact::{CompactBlock, CompactProposal};
use helix_p2p::genesis_sync::{GenesisPayload, GenesisResponse};
use helix_p2p::roundsync::RoundSyncResponse;
use serde::de::DeserializeOwned;
use serde::Serialize;

struct Counting;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// serde's 1 MiB ahead-of-time cap, plus room for the ordinary allocations of a decode.
const MOST_A_DECODE_MAY_RESERVE: usize = 2 << 20;

fn key() -> PublicKey {
    PublicKey::from_bytes(vec![7; 32])
}

fn a_transaction() -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        from: Address::from_public_key(&key()),
        to: Some(Address::from_public_key(&PublicKey::from_bytes(vec![2; 32]))),
        amount: 1,
        fee: 1,
        nonce: 3,
        data: vec![5; 16],
        crypto_version: CryptoVersion::MlDsa,
        chain_id: Hash::digest(b"chain"),
        signature: Signature::from_bytes(vec![1; 16]),
        public_key: Some(key()),
    }
}

/// A block with every variable-length part populated: transactions, a commit certificate.
fn a_block() -> Block {
    let mut block = genesis_block(
        Address::from_public_key(&key()),
        key(),
        Signature::from_bytes(vec![9; 16]),
        1_700_000_000_000,
    );
    block.header.height = 7;
    block.header.last_commit = vec![CommitSig {
        validator: Address::from_public_key(&key()),
        crypto_version: CryptoVersion::MlDsa,
        round: 1,
        signature: Signature::from_bytes(vec![3; 16]),
    }];
    block.transactions = vec![a_transaction(), a_transaction()];
    block
}

fn a_vote() -> Vote {
    Vote {
        vote_type: VoteType::Precommit,
        height: 7,
        round: 0,
        block_hash: Hash::digest(b"a block"),
        validator: Address::from_public_key(&key()),
        public_key: key(),
        crypto_version: CryptoVersion::MlDsa,
        signature: Signature::from_bytes(vec![4; 16]),
    }
}

/// The largest single allocation `decode` makes.
fn largest_allocation(decode: impl FnOnce()) -> usize {
    LARGEST.store(0, Ordering::SeqCst);
    decode();
    LARGEST.load(Ordering::SeqCst)
}

/// Writes each length in `lengths` over every position of `message` and decodes the result as
/// `T`, the way the node decodes that message from a peer. Returns the worst case it found.
fn sweep<T: Serialize + DeserializeOwned>(name: &str, message: &T) -> (usize, usize) {
    let honest = bincode::serialize(message).unwrap();
    assert!(
        bincode::deserialize::<T>(&honest).is_ok(),
        "{name}: premise — the honest message decodes"
    );
    let lengths: [[u8; 8]; 3] = [u64::MAX.to_le_bytes(), (1u64 << 40).to_le_bytes(), (64u64 << 20).to_le_bytes()];
    let mut worst = (0, 0);
    for pos in 0..honest.len() {
        for length in &lengths {
            let mut bytes = honest.clone();
            let end = (pos + 8).min(bytes.len());
            bytes[pos..end].copy_from_slice(&length[..end - pos]);
            let largest = largest_allocation(|| {
                let _ = bincode::deserialize::<T>(&bytes);
            });
            if largest > worst.0 {
                worst = (largest, pos);
            }
        }
    }
    assert!(
        worst.0 <= MOST_A_DECODE_MAY_RESERVE,
        "{name}: a length written at byte {} of a {}-byte message made the decode reserve {} bytes",
        worst.1,
        honest.len(),
        worst.0
    );
    worst
}

#[test]
fn a_length_anywhere_in_a_peer_message_is_never_reserved_for() {
    // Positive control: the instrument sees a large allocation when there is one.
    let seen = largest_allocation(|| drop(std::hint::black_box(Vec::<u8>::with_capacity(64 << 20))));
    assert!(seen >= 64 << 20, "the counting allocator missed a 64 MiB reservation ({seen})");

    let mut report = Vec::new();
    // Gossip, one per topic, in the types `decode_gossip` reads them as — proposals and committed
    // blocks compact since #235.
    report.push((
        "proposal",
        sweep("proposal", &CompactProposal::of(&Proposal::fresh(0, a_block()))),
    ));
    report.push(("vote", sweep("vote", &a_vote())));
    report.push((
        "committed block",
        sweep("committed block", &(CompactBlock::of(&a_block()), vec![a_vote(), a_vote()])),
    ));
    report.push(("transaction", sweep("transaction", &a_transaction())));
    // Peer exchange is private to the service; its shape is strings and numbers, mirrored here.
    let peer_exchange: (Vec<String>, String, u64, String, u64) = (
        vec!["/ip4/203.0.113.7/tcp/8546".into(), "/dns4/p2p.silvra.net/tcp/443/tls/ws".into()],
        "0.15.3".into(),
        7,
        "141c8e0f".into(),
        0,
    );
    report.push(("peer exchange", sweep("peer exchange", &peer_exchange)));
    // The three request-response protocols, answers as the requester decodes them.
    report.push((
        "blocksync response",
        sweep(
            "blocksync response",
            &BlockSyncResponse { blocks: vec![a_block(), a_block()], tip_certificate: vec![a_vote()] },
        ),
    ));
    report.push((
        "roundsync response",
        sweep(
            "roundsync response",
            &RoundSyncResponse { proposal: Some(Proposal::fresh(0, a_block())), votes: vec![a_vote()] },
        ),
    ));
    report.push((
        "genesis response",
        sweep(
            "genesis response",
            &GenesisResponse {
                genesis: Some(GenesisPayload {
                    block: a_block(),
                    personhood_authorities: vec![key()],
                    validator_stake: 1,
                    allocations: vec![(Address::from_public_key(&key()), 5)],
                    min_validator_stake: 1,
                    fuel_per_fee_unit: 1,
                    state_hash: Some("abc".into()),
                }),
            },
        ),
    ));
    for (name, (largest, pos)) in report {
        println!("{name}: largest reservation {largest} bytes (length written at byte {pos})");
    }
}
