//! ZK-STARK Proof of Personhood for Helix validators.
//!
//! # Protocol
//!
//! The personhood authority issues a credential to a verified human:
//! a `secret` value (128-bit field element). The validator derives:
//!
//!   `commitment = secret^(2^63)  mod p`   (p = 2^128 − 45·2^40 + 1)
//!
//! and registers the `commitment` on-chain via `TxType::RegisterPersonhood`.
//!
//! To claim full personhood voting weight (the full stake entering the one
//! `total_stake / 100` cap, rather than half of it — not a higher cap), the
//! validator submits `TxType::ProvePersonhood` with a STARK proof that they
//! know a `secret` such that `secret^(2^63) = commitment` — without ever
//! revealing `secret`.
//!
//! # Security
//!
//! The squaring chain is a VDF-style one-way function over a 128-bit prime
//! field.  The STARK uses Blake3 hashing and 48 FRI queries, drawing its
//! soundness from the query count (which Grover does not weaken) up to the
//! f128 field's ~128-bit ceiling, rather than from Grover-halvable grinding.
//! The personhood authority's secret prevents validators from self-minting
//! credentials — the STARK proves knowledge of the committed secret.

pub mod air;
pub mod prover;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, StarkField},
    AcceptableOptions, Proof,
};

use air::{PersonhoodAir, PersonhoodInputs, TRACE_LEN};
use prover::PersonhoodProver;
use winter_utils::Serializable;
use winterfell::{math::FieldElement, Air, TraceInfo};

/// The largest proof `verify_personhood` reads. An honest one is ~11 KB; its size varies a little
/// with how the query paths batch. Anything much larger is not ours.
pub const MAX_PROOF_BYTES: usize = 32 * 1024;

/// Walks a proof in winterfell 0.13.1's serialisation, after the header, and says whether every
/// length in it fits the bytes that follow and every byte winterfell would panic on holds a value
/// it accepts — before winterfell reads it.
///
/// The header check is not enough on its own. Lengths live in the body too: the two byte vectors
/// of each `Queries`, and inside each of those opening proofs — and each FRI layer's — a batch
/// Merkle proof with a count of node vectors and a length per vector. winter-utils decodes all of
/// them by taking the length from the data and calling `Vec::with_capacity` with it before a
/// single element is read, so a length of 2^56 anywhere in the body aborts the process as surely
/// as one in the header. This reads the same fields in the same order, checks each length against
/// what is left, and requires the walk to end exactly at the last byte. The three bytes whose
/// out-of-range values winterfell answers with a panic — a Merkle depth, an out-of-domain frame
/// size, the FRI partition count — are held to the values an honest proof has, so the
/// `catch_unwind` around verification is a last resort and not the way a malformed proof is
/// turned away. Every other size winterfell derives comes from the header, which is ours.
///
/// Mirrors `Proof::read_from` of winter-air 0.13.1 and the readers it calls; `winterfell` is pinned
/// to that version. The tests walk real proofs through this to the last byte, so a change of
/// layout fails them instead of passing hostile bytes through, and they corrupt every byte of a
/// real proof and count the panics winterfell raises: there must be none.
fn proof_is_well_formed(bytes: &[u8], header_len: usize) -> bool {
    let num_queries = prover::proof_options().num_queries();
    let num_trace_segments = TraceInfo::new(1, TRACE_LEN).num_segments();
    let walk = |w: &mut Walk| -> Option<()> {
        let unique = w.u8()? as usize;
        if unique == 0 || unique > num_queries {
            return None;
        }
        w.sized(Walk::u16)?; // commitments
        for _ in 0..num_trace_segments + 1 {
            // trace queries per segment, then the constraint queries: values, then the opening
            // proof — itself a batch Merkle proof with lengths of its own
            w.sized(Walk::usize_vint)?;
            merkle_proof_is_well_formed(w.sized(Walk::usize_vint)?)?;
        }
        // Out-of-domain trace states, then constraint evaluations: each starts with its frame
        // size, which winterfell asserts is 2 — an assertion is a panic, and a panic is not how a
        // malformed proof should be turned away.
        for _ in 0..2 {
            if w.sized(Walk::u16)?.first() != Some(&2) {
                return None;
            }
        }
        for _ in 0..w.u8()? {
            // FRI layers: values, then a batch Merkle proof
            w.sized(Walk::u32)?;
            merkle_proof_is_well_formed(w.sized(Walk::u32)?)?;
        }
        // FRI remainder
        w.sized(Walk::u16)?;
        // FRI partitions, stored as a power of two. The prover always writes one partition
        // (`FriProof::new(.., 1)`, byte 0); winterfell reads `2usize.pow(byte)`, so any other byte
        // is either a second encoding of the same proof or an overflow the verifier panics on.
        if w.u8()? != 0 {
            return None;
        }
        w.take(8)?; // proof-of-work nonce
        Some(())
    };
    let mut w = Walk {
        bytes,
        at: header_len,
    };
    walk(&mut w).is_some() && w.at == bytes.len()
}

/// A batch Merkle proof as winter-crypto 0.13.1 writes it: a depth, a number of node vectors, and
/// each vector as a length and that many 32-byte digests — the two counts are the ones
/// `BatchMerkleProof::read_from` reserves for, so both must be backed by bytes that are there.
fn merkle_proof_is_well_formed(bytes: &[u8]) -> Option<()> {
    const DIGEST_BYTES: usize = 32;
    let mut w = Walk { bytes, at: 0 };
    // The depth sizes the proof's domain as `1 << depth`, which overflows — a panic — for a
    // depth no domain can have.
    if u32::from(w.u8()?) >= usize::BITS {
        return None;
    }
    let vectors = w.usize_vint()?;
    // Each vector costs at least its length byte, so more vectors than bytes cannot be real —
    // checked before the loop, because winterfell reserves for this count before it reads one.
    if vectors > bytes.len() {
        return None;
    }
    for _ in 0..vectors {
        let digests = w.usize_vint()?;
        w.take(digests.checked_mul(DIGEST_BYTES)?)?;
    }
    (w.at == bytes.len()).then_some(())
}

/// A cursor over proof bytes that refuses to go past their end.
struct Walk<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Walk<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    }
    fn u32(&mut self) -> Option<usize> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    /// winter-utils' variable-length `usize`: the first byte's trailing zeros give the length.
    fn usize_vint(&mut self) -> Option<usize> {
        let first = *self.bytes.get(self.at)?;
        let length = first.trailing_zeros() as usize + 1;
        let value = if length == 9 {
            self.take(1)?;
            u64::from_le_bytes(self.take(8)?.try_into().ok()?)
        } else {
            let mut encoded = [0u8; 8];
            encoded[..length].copy_from_slice(self.take(length)?);
            u64::from_le_bytes(encoded) >> length
        };
        usize::try_from(value).ok()
    }
    /// A length read by `read`, then that many bytes, which are returned.
    fn sized(&mut self, read: fn(&mut Self) -> Option<usize>) -> Option<&'a [u8]> {
        let n = read(self)?;
        self.take(n)
    }
}

/// The proof context — trace shape, field, options, constraint count — exactly as this crate's
/// prover writes it at the start of every proof. The same for every honest proof: none of it
/// depends on the secret or the commitment. Built the way winterfell's prover channel builds it,
/// and checked against a real proof in the tests.
fn canonical_context_bytes() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| {
        let trace_info = TraceInfo::new(1, TRACE_LEN);
        let options = prover::proof_options();
        let air = PersonhoodAir::new(
            trace_info.clone(),
            PersonhoodInputs {
                commitment: BaseElement::ZERO,
            },
            options.clone(),
        );
        let num_constraints =
            air.context().num_assertions() + air.context().num_transition_constraints();
        winter_air::proof::Context::new::<BaseElement>(trace_info, options, num_constraints)
            .to_bytes()
    })
}

/// A serialized STARK proof of personhood.
///
/// Produced by [`prove_personhood`], verified by [`verify_personhood`].
/// Safe to store in a `TxType::ProvePersonhood` transaction.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PersonhoodProof(pub Vec<u8>);

impl PersonhoodProof {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PersonhoodProof(bytes)
    }
}

/// Generate a STARK proof that the prover knows `secret` such that
/// `secret^(2^63) = commitment` in the 128-bit prime field.
///
/// `secret` is a 16-byte little-endian encoding of the field element.
///
/// Returns `(proof, commitment_bytes)` where `commitment_bytes` is the 16-byte
/// encoding of the commitment — submit this alongside the proof in the
/// `ProvePersonhood` transaction.
pub fn prove_personhood(secret_bytes: [u8; 16]) -> (PersonhoodProof, [u8; 16]) {
    let secret = BaseElement::new(u128::from_le_bytes(secret_bytes));
    let prover = PersonhoodProver::new();
    let (stark_proof, commitment) = prover.prove(secret);
    let commitment_bytes = commitment.as_int().to_le_bytes();
    let proof_bytes = stark_proof.to_bytes();
    (PersonhoodProof(proof_bytes), commitment_bytes)
}

/// Verify a personhood proof against a public commitment.
///
/// Returns `true` iff the proof is cryptographically valid and the prover
/// knows `secret` such that `secret^(2^63) = commitment`.
///
/// **The proof's header is checked against ours before winterfell reads a byte of it.** A proof
/// arrives in a transaction, from anyone, and every node executes it. winterfell sizes its buffers
/// from that header — trace length, widths, options — and `Proof::from_bytes` alone, given one
/// changed byte in it, asked for 45 petabytes (`Vec::with_capacity`), which is not a panic but a
/// process abort: every node executing the block would have stopped before storing it — so the
/// block, and the fee, never existed, and the same bytes could be sent again after every restart.
/// With the header equal to the one our prover writes, every size derived from it is the fixed,
/// small one of this circuit; the one other count read early, the number of unique queries, is bounded
/// by the queries our options draw. **The body is walked next** (`proof_is_well_formed`): it
/// carries lengths of its own, the Merkle proofs inside it too, and any one of them could make the
/// same request. Only a proof whose every length is backed by its own bytes reaches winterfell. A
/// panic winterfell might still raise becomes `false` rather than a dead task — a last resort the
/// tests show no single corrupted byte reaches.
pub fn verify_personhood(proof: &PersonhoodProof, commitment_bytes: [u8; 16]) -> bool {
    let bytes = proof.as_bytes();
    if bytes.len() > MAX_PROOF_BYTES {
        return false;
    }
    let header = canonical_context_bytes();
    if !bytes.starts_with(header) {
        return false;
    }
    if !proof_is_well_formed(bytes, header.len()) {
        return false;
    }

    let commitment = BaseElement::new(u128::from_le_bytes(commitment_bytes));
    let pub_inputs = PersonhoodInputs { commitment };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Ok(stark_proof) = Proof::from_bytes(bytes) else {
            return false;
        };
        let acceptable = AcceptableOptions::MinConjecturedSecurity(80);
        winterfell::verify::<
            PersonhoodAir,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            MerkleTree<Blake3_256<BaseElement>>,
        >(stark_proof, pub_inputs, &acceptable)
        .is_ok()
    }))
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_personhood_roundtrip() {
        // A secret credential issued by the personhood authority
        let secret = [42u8; 16];
        let (proof, commitment) = prove_personhood(secret);
        assert!(verify_personhood(&proof, commitment), "proof should verify");
    }

    #[test]
    fn verify_rejects_wrong_commitment() {
        let secret = [1u8; 16];
        let (proof, _commitment) = prove_personhood(secret);
        // Tamper: different commitment
        let wrong_commitment = [2u8; 16];
        assert!(
            !verify_personhood(&proof, wrong_commitment),
            "proof against wrong commitment must fail"
        );
    }

    #[test]
    fn verify_rejects_truncated_proof() {
        let (proof, commitment) = prove_personhood([7u8; 16]);
        let truncated = PersonhoodProof(proof.0[..proof.0.len() / 2].to_vec());
        assert!(
            !verify_personhood(&truncated, commitment),
            "truncated proof must fail"
        );
    }

    #[test]
    fn different_secrets_produce_different_commitments() {
        let (_, c1) = prove_personhood([1u8; 16]);
        let (_, c2) = prove_personhood([2u8; 16]);
        assert_ne!(c1, c2);
    }

    /// The header `verify_personhood` insists on has to be the one the prover really writes —
    /// built by hand from the same parts, it would otherwise reject every honest proof.
    #[test]
    fn the_canonical_header_is_the_one_the_prover_writes() {
        let (proof, commitment) = prove_personhood([9u8; 16]);
        assert!(proof.as_bytes().starts_with(canonical_context_bytes()));
        assert!(verify_personhood(&proof, commitment));
    }

    /// The attack, measured before it was fixed: one byte of the header changed, and
    /// `Proof::from_bytes` alone asked for 45 petabytes and aborted the process. Every node
    /// executes the proofs in a block before storing it, so one transaction would have stopped
    /// all of them for nothing — no stored block, no fee — and could be sent again after every
    /// restart. Now a foreign header is refused before winterfell reads anything —
    /// for every byte of it, not only the one found. If this regresses, the test process aborts.
    #[test]
    fn a_proof_with_a_foreign_header_is_refused_before_it_is_read() {
        let (proof, commitment) = prove_personhood([42u8; 16]);
        let header_len = canonical_context_bytes().len();
        let mut the_one_found = proof.as_bytes().to_vec();
        the_one_found[36] = 0x01;
        assert!(!verify_personhood(
            &PersonhoodProof::from_bytes(the_one_found),
            commitment
        ));

        for pos in 0..=header_len {
            for value in [0x00u8, 0x01, 0x10, 0x7f, 0x80, 0xff] {
                let mut bytes = proof.as_bytes().to_vec();
                if bytes[pos] == value {
                    continue;
                }
                bytes[pos] = value;
                assert!(
                    !verify_personhood(&PersonhoodProof::from_bytes(bytes), commitment),
                    "byte {pos} = {value:#x} must not verify"
                );
            }
        }
    }

    thread_local! {
        /// Panics raised on this thread while [`refused_without_a_panic`] watches — `None` while
        /// nothing watches, so another test's failing assertion is still reported as one.
        static PANICS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    /// Verifies `bytes` and says why it is wrong if it was accepted, or if winterfell panicked on
    /// the way to refusing it: `catch_unwind` turns such a panic into `false`, so the result alone
    /// cannot tell a clean refusal from one that relied on the safety net.
    fn refused_without_a_panic(bytes: Vec<u8>, commitment: [u8; 16]) -> Result<(), String> {
        static HOOK: std::sync::Once = std::sync::Once::new();
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let counted = PANICS.with(|p| p.get().map(|n| p.set(Some(n + 1))).is_some());
                if !counted {
                    previous(info);
                }
            }));
        });
        PANICS.with(|p| p.set(Some(0)));
        let accepted = verify_personhood(&PersonhoodProof::from_bytes(bytes), commitment);
        let panics = PANICS.with(|p| p.replace(None)).unwrap_or(0);
        match (accepted, panics) {
            (true, _) => Err("verified".into()),
            (false, 0) => Ok(()),
            (false, n) => Err(format!(
                "refused, but only after {n} panic(s) inside winterfell"
            )),
        }
    }

    /// The walk has to follow winterfell's layout to the byte, or it either refuses honest proofs
    /// or lets hostile lengths through. Real proofs, several secrets, end exactly where it ends.
    #[test]
    fn an_honest_proof_is_well_formed_to_its_last_byte() {
        for secret in [[1u8; 16], [42u8; 16], [200u8; 16]] {
            let (proof, _) = prove_personhood(secret);
            let bytes = proof.as_bytes();
            assert!(proof_is_well_formed(bytes, canonical_context_bytes().len()));
            assert!(
                !proof_is_well_formed(&bytes[..bytes.len() - 1], canonical_context_bytes().len()),
                "one byte short is not well formed"
            );
            let mut longer = bytes.to_vec();
            longer.push(0);
            assert!(
                !proof_is_well_formed(&longer, canonical_context_bytes().len()),
                "nor one long"
            );
        }
    }

    /// The attack one level down, measured before it was fixed: with the header checked, a
    /// length in the body still aborted the process — winterfell reserves for each byte vector of
    /// the queries, and for the node vectors of the Merkle proofs inside them, before reading an
    /// element. Both levels, at their first occurrence. If this regresses, the test process aborts.
    #[test]
    fn a_length_in_the_body_that_the_bytes_cannot_hold_is_refused() {
        let (proof, commitment) = prove_personhood([42u8; 16]);
        let honest = proof.as_bytes();
        let body = canonical_context_bytes().len();
        // Written over the bytes that follow, not inserted: every enclosing length stays true, so
        // winterfell reads up to this one. Inserted, the nested one shifted everything after its
        // vector and the proof failed to parse before the count was ever read — a test of nothing.
        let nine_byte_length = |at: usize, len: u64| {
            let mut m = honest.to_vec();
            m[at] = 0x00; // nine-byte form
            m[at + 1..at + 9].copy_from_slice(&len.to_le_bytes());
            m
        };

        // The trace queries' value vector starts after the query count and the commitments.
        let commitments_len = u16::from_le_bytes([honest[body + 1], honest[body + 2]]) as usize;
        let values_len = body + 1 + 2 + commitments_len;
        refused_without_a_panic(nine_byte_length(values_len, 1 << 56), commitment).unwrap();

        // Its opening proof: a length, then a depth, then the count of node vectors.
        let mut w = Walk {
            bytes: honest,
            at: values_len,
        };
        w.sized(Walk::usize_vint).unwrap();
        let opening = w.at;
        w.usize_vint().unwrap();
        let node_vectors = w.at + 1;
        assert!(
            honest[opening] != 0 && honest[node_vectors] != 0,
            "premise: both are short-form lengths"
        );
        refused_without_a_panic(nine_byte_length(node_vectors, 1 << 56), commitment).unwrap();
    }

    /// Every byte of the body, not a sample: which bytes are lengths depends on the proof's
    /// shape, and a sample that misses the one nested length winterfell reserves for aborts the
    /// process — a sample of 300 did exactly that while the walk still skipped the Merkle proofs.
    /// A maximal nine-byte length is written over every position, plus the single-byte values
    /// that change a length's form or size. Each is refused, quickly, and without winterfell
    /// panicking on the way: the depth, frame-size and partition checks exist because the first
    /// run of this found sixteen such panics that `catch_unwind` had been hiding.
    #[test]
    fn every_corrupted_byte_of_the_body_is_refused_quickly_and_without_a_panic() {
        let (proof, commitment) = prove_personhood([42u8; 16]);
        let honest = proof.as_bytes();
        let body = canonical_context_bytes().len();
        let max_len = [0x00u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut slowest = std::time::Duration::ZERO;
        let mut check = |m: Vec<u8>, what: String| {
            if m == honest {
                return;
            }
            let started = std::time::Instant::now();
            if let Err(e) = refused_without_a_panic(m, commitment) {
                panic!("{what}: {e}");
            }
            slowest = slowest.max(started.elapsed());
        };
        for pos in body..honest.len() {
            let mut m = honest.to_vec();
            let end = (pos + max_len.len()).min(m.len());
            m[pos..end].copy_from_slice(&max_len[..end - pos]);
            check(m, format!("length bomb at byte {pos}"));
            for value in [0x00u8, 0xff, 0x80, 0x01] {
                let mut m = honest.to_vec();
                m[pos] = value;
                check(m, format!("byte {pos} = {value:#x}"));
            }
        }
        for cut in 0..honest.len() {
            check(honest[..cut].to_vec(), format!("cut to {cut} bytes"));
        }
        assert!(
            slowest < std::time::Duration::from_secs(2),
            "slowest rejection took {slowest:?}"
        );
    }

    /// Bigger than any proof of this circuit is not read at all.
    #[test]
    fn an_oversized_proof_is_not_read() {
        let (proof, commitment) = prove_personhood([42u8; 16]);
        let mut padded = proof.as_bytes().to_vec();
        padded.resize(MAX_PROOF_BYTES + 1, 0);
        assert!(!verify_personhood(
            &PersonhoodProof::from_bytes(padded),
            commitment
        ));
        assert!(
            proof.as_bytes().len() * 2 < MAX_PROOF_BYTES,
            "premise: room for honest variation"
        );
    }
}
