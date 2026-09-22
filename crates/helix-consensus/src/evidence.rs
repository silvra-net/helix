use helix_crypto::{Address, Hash};
use serde::{Deserialize, Serialize};

use crate::Vote;

/// Evidence of a validator double-signing two conflicting votes at the same height/round.
/// Submitted on-chain to trigger slashing (Phase 5 foundation; slashing execution in Phase 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator: Address,
    pub height: u64,
    pub round: u32,
    /// The two conflicting votes (same validator, same height/round, different block hashes)
    pub vote_a: Vote,
    pub vote_b: Vote,
}

impl DoubleSignEvidence {
    /// Verify that this evidence is structurally valid (same validator/height/round, different hashes).
    /// Does NOT verify signatures — that happens at the execution layer.
    ///
    /// **The envelope has to agree with the votes, including about itself.** `validator`, `height`
    /// and `round` are declared by whoever submits the evidence; the votes are signed. Until
    /// 2026-09-22 only `validator` was checked against them, so the other two were free text on a
    /// document whose whole purpose is to be believed — and the execution layer keyed its
    /// replay guard on exactly those two fields. One genuine incident, resubmitted with the
    /// declared height bumped, slashed the validator again, and again: 5 % a time, to zero.
    ///
    /// The guard is fixed where it belongs (it reads the votes now), so this check is not what
    /// stands between a validator and repeated slashing. It is here because evidence that
    /// contradicts itself is not evidence, and accepting it would leave the chain recording an
    /// incident at a height where nothing happened.
    pub fn is_valid(&self) -> bool {
        self.vote_a.validator == self.vote_b.validator
            && self.vote_a.height == self.vote_b.height
            && self.vote_a.round == self.vote_b.round
            && self.vote_a.vote_type == self.vote_b.vote_type
            && self.vote_a.block_hash != self.vote_b.block_hash
            && self.vote_a.validator == self.validator
            && self.vote_a.height == self.height
            && self.vote_a.round == self.round
    }

    /// The identity of the incident: the validator and the position it signed twice at, taken
    /// from the **signed** vote rather than from the envelope around it.
    ///
    /// This is what a replay guard has to key on. A validator can only meaningfully double-sign
    /// once per `(height, round)` — true of the votes, and the point is that it must be *their*
    /// height and round that decide, not a number the reporter typed.
    pub fn incident_key(&self) -> String {
        format!("{}:{}:{}", self.vote_a.validator, self.vote_a.height, self.vote_a.round)
    }

    pub fn conflicting_hashes(&self) -> (Hash, Hash) {
        (self.vote_a.block_hash.clone(), self.vote_b.block_hash.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VoteType;
    use helix_core::block::CryptoVersion;
    use helix_crypto::{KeyPair, Signature};

    /// A vote with the fields that matter here. Unsigned: `is_valid` is documented as not
    /// checking signatures (the execution layer does), and every property below is about what
    /// the envelope claims versus what the votes say.
    fn vote(kp: &KeyPair, height: u64, round: u32, block: &[u8]) -> Vote {
        Vote {
            vote_type: VoteType::Precommit,
            height,
            round,
            block_hash: Hash::digest(block),
            validator: Address::from_public_key(&kp.public),
            public_key: kp.public.clone(),
            crypto_version: CryptoVersion::MlDsa,
            signature: Signature::from_bytes(vec![]),
        }
    }

    fn incident(kp: &KeyPair, declared_height: u64, declared_round: u32) -> DoubleSignEvidence {
        DoubleSignEvidence {
            validator: Address::from_public_key(&kp.public),
            height: declared_height,
            round: declared_round,
            vote_a: vote(kp, 10, 0, b"block-a"),
            vote_b: vote(kp, 10, 0, b"block-b"),
        }
    }

    /// Positive control. Without it the refusals below could mean the fixture was malformed.
    #[test]
    fn evidence_that_describes_its_own_votes_is_valid() {
        assert!(incident(&KeyPair::generate(), 10, 0).is_valid());
    }

    /// **The envelope may not lie about where the incident happened.**
    ///
    /// `height` and `round` are typed by whoever submits the evidence; the votes are signed.
    /// Until 2026-09-22 nothing compared them, and the execution layer's replay guard keyed on
    /// the typed pair — so one real incident, resubmitted with the height bumped, slashed the
    /// same validator again. 5 % a time, to zero, for equivocating once.
    #[test]
    fn evidence_declaring_a_height_its_votes_do_not_carry_is_refused() {
        assert!(
            !incident(&KeyPair::generate(), 11, 0).is_valid(),
            "the votes are for height 10; an envelope that says 11 describes an incident that \
             did not happen"
        );
    }

    #[test]
    fn evidence_declaring_a_round_its_votes_do_not_carry_is_refused() {
        assert!(!incident(&KeyPair::generate(), 10, 7).is_valid());
    }

    /// **The incident's identity comes from the signed votes, not from the envelope.**
    ///
    /// This is the half that holds even if `is_valid` never ran: a replay guard that reads the
    /// envelope is a guard the submitter controls. The two are independent on purpose — they do
    /// not share an input, so neither is the other's excuse for existing (the lesson from the
    /// VM-to-ledger bridge, 2026-08-05, where a second line shared the first one's input and was
    /// therefore not a second line at all).
    #[test]
    fn relabelling_the_envelope_does_not_change_the_incidents_identity() {
        let kp = KeyPair::generate();
        let honest = incident(&kp, 10, 0);
        let relabelled = incident(&kp, 11, 3);
        assert_eq!(
            honest.incident_key(),
            relabelled.incident_key(),
            "same validator, same two votes, same position signed twice — one incident, whatever \
             the envelope around it says"
        );
    }

    /// Two genuinely different incidents by the same validator stay different. Without this the
    /// fix above could be "return a constant", which would make the first double-sign the only
    /// one that is ever punished.
    #[test]
    fn two_incidents_at_different_heights_keep_separate_identities() {
        let kp = KeyPair::generate();
        let mut later = incident(&kp, 10, 0);
        later.height = 11;
        later.vote_a.height = 11;
        later.vote_b.height = 11;
        assert!(later.is_valid(), "precondition: this is a well-formed second incident");
        assert_ne!(incident(&kp, 10, 0).incident_key(), later.incident_key());
    }
}
