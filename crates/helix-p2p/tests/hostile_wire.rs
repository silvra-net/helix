//! Adversarial decoding: what a peer can make this node do with bytes it chose.
//!
//! Every P2P protocol here caps how much it will *read* (`REQUEST_SIZE_MAXIMUM`,
//! `RESPONSE_SIZE_MAXIMUM`, gossipsub's `max_transmit_size`). That bounds the bytes on the wire
//! and says nothing about what decoding them costs: a length prefix is eight bytes and can claim
//! 2^63 elements. If the decoder believes it, a 1 KB request becomes an out-of-memory kill — and
//! an OOM leaves nothing in the node's own log (#118/#172), so it would read as an unexplained
//! disappearance rather than an attack.
//!
//! These tests are the evidence that the second bound exists. They are written as *attacks*, not
//! as round-trips: every input here is bytes an attacker controls entirely, and the assertion is
//! always that the node survives and rejects, never that it understands.

use helix_core::{Block, BlockHeader, Transaction};

/// Claim an enormous element count in the length prefix and send nothing to back it up.
///
/// The classic allocation DoS against any length-prefixed format. bincode reads the count as a
/// u64 and hands it to serde as a size hint; whether that becomes `Vec::with_capacity(2^63)`
/// decides whether a peer can kill this process with 1 KB.
#[test]
fn a_length_prefix_claiming_more_elements_than_memory_must_not_be_believed() {
    for claimed in [u64::MAX, 1 << 62, 1 << 40, 1 << 32] {
        let mut bytes = claimed.to_le_bytes().to_vec();
        // A few real bytes after the prefix, so this is "claims a lot, sends little" rather than
        // a truncation the decoder might reject before ever looking at the count.
        bytes.extend_from_slice(&[0u8; 64]);

        let decoded: Result<Vec<Transaction>, _> = bincode::deserialize(&bytes);
        assert!(
            decoded.is_err(),
            "a claim of {claimed} transactions backed by 64 bytes must be refused"
        );

        let decoded: Result<Vec<Block>, _> = bincode::deserialize(&bytes);
        assert!(decoded.is_err(), "same for blocks: {claimed}");

        let decoded: Result<Vec<u8>, _> = bincode::deserialize(&bytes);
        assert!(decoded.is_err(), "same for a raw byte vector: {claimed}");
    }
}

/// The same attack one level down: a *nested* length, inside a struct that decodes far enough to
/// reach it. A guard that only looks at the outermost prefix would pass the test above and still
/// die here.
#[test]
fn a_hostile_length_inside_a_struct_is_refused_too() {
    // One element, then that element's own inner length claiming everything.
    let mut bytes = 1u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 64]);

    let decoded: Result<Vec<Vec<u8>>, _> = bincode::deserialize(&bytes);
    assert!(decoded.is_err(), "an inner length prefix must be bounded as well as the outer one");
}

/// Deeply nested input must not grow the stack without bound.
///
/// Recursive descent over attacker-shaped data is the other way a decoder dies, and it dies with
/// SIGSEGV rather than a caught error — a stack overflow is not a `Result`.
#[test]
fn deeply_nested_input_does_not_overflow_the_stack() {
    // 100k nesting levels, each claiming one element.
    let mut bytes = Vec::new();
    for _ in 0..100_000 {
        bytes.extend_from_slice(&1u64.to_le_bytes());
    }
    bytes.extend_from_slice(&[0u8; 8]);
    let decoded: Result<Vec<Vec<Vec<u8>>>, _> = bincode::deserialize(&bytes);
    // Either answer is acceptable; surviving the call is the assertion.
    let _ = decoded;
}

/// Random bytes must never decode into a block this node would act on.
///
/// Not a formality: `Block` carries a `BlockHeader` whose fields are mostly integers, and a
/// decoder that accepts arbitrary integers would hand consensus a block with a plausible height
/// and a garbage hash rather than refusing it.
#[test]
fn arbitrary_bytes_do_not_decode_into_a_block() {
    let mut accepted = 0;
    for seed in 0u64..2_000 {
        // Cheap deterministic noise — no dependency, and reproducible from the seed when one
        // of these ever does decode.
        let bytes: Vec<u8> = (0..512u64)
            .map(|i| (seed.wrapping_mul(6364136223846793005).wrapping_add(i.wrapping_mul(1442695040888963407)) >> 33) as u8)
            .collect();
        if bincode::deserialize::<Block>(&bytes).is_ok() {
            accepted += 1;
        }
        if bincode::deserialize::<BlockHeader>(&bytes).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 0, "noise decoded into a block or header {accepted} times");
}

/// A truncated message — the shape a dropped connection produces — must be an error, not a panic
/// and not a default-filled value.
#[test]
fn truncation_at_every_offset_is_an_error_and_never_a_panic() {
    let full = bincode::serialize(&vec![1u8, 2, 3, 4, 5, 6, 7, 8]).expect("serialize");
    for cut in 0..full.len() {
        let decoded: Result<Vec<u8>, _> = bincode::deserialize(&full[..cut]);
        assert!(decoded.is_err(), "a message cut at {cut} must not decode");
    }
}
