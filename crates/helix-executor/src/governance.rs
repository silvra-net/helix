use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::genesis::MIN_VALIDATOR_STAKE;

/// Fuel granted per nano-HLX of `tx.fee` when calling a WASM contract. Governance-adjustable
/// starting value — see `execute_call_contract` in lib.rs.
pub const DEFAULT_FUEL_PER_FEE_UNIT: u64 = 1;

/// Blocks a proposal stays open for voting before it expires unexecuted.
pub const VOTING_PERIOD_BLOCKS: u64 = 1000;

/// The protocol version a chain starts at. A passed [`GovernanceParam::ProtocolUpgrade`] moves the
/// chain to the next one at its activation height (`ChainState::protocol_version`).
pub const GENESIS_PROTOCOL_VERSION: u64 = 1;

/// How far ahead of its proposal an upgrade may take effect: 30 days at the 2-second block target.
///
/// Without a bound, one typo in the height — passed by a voter who read the version and not the
/// digits — would schedule an upgrade nobody lives to see, and with one upgrade at a time it would
/// block every other upgrade until then. There is no cancelling a scheduled upgrade; a bound is
/// the simpler of the two ways out.
pub const MAX_UPGRADE_LEAD_BLOCKS: u64 = 30 * 24 * 60 * 30;

/// An upgrade a passed proposal has scheduled: from `height` on, blocks are executed under protocol
/// `version`. A node whose build does not know `version` stops before that block instead of going
/// on under the rules it knows — which would split the chain (`ChainState::refuses_block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledUpgrade {
    pub version: u64,
    pub height: u64,
}

/// Protocol parameters that a governance proposal may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceParam {
    MinValidatorStake,
    FuelPerFeeUnit,
    /// Move the chain to protocol `new_value` — the next one — at the proposal's
    /// `activation_height`. Changes rules without a reset: a node that does not know the version
    /// stops at that height and says so; a node that does goes on under the new rules.
    ProtocolUpgrade,
}

impl GovernanceParam {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(GovernanceParam::MinValidatorStake),
            1 => Some(GovernanceParam::FuelPerFeeUnit),
            2 => Some(GovernanceParam::ProtocolUpgrade),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            GovernanceParam::MinValidatorStake => 0,
            GovernanceParam::FuelPerFeeUnit => 1,
            GovernanceParam::ProtocolUpgrade => 2,
        }
    }

    /// Minimum safe value for this parameter — below this, the parameter is close enough
    /// to zero to cause (or contribute to) the same failure a value of exactly zero would.
    ///
    /// `MinValidatorStake`: `MIN_VALIDATOR_STAKE / 100` — **100 HLX against today's genesis
    /// default of 10,000** (it read "1,000 HLX vs. 100,000" until 2026-08-27, from before the
    /// minimum was lowered; the ratio is the rule, the numbers were only ever an illustration and
    /// went stale the moment the constant moved). A value near zero (even a nonzero one, e.g. 1 nano-HLX) would let
    /// almost every account pass `ChainState::stakers()`'s filter, exploding the validator
    /// set and — since unverified-personhood voting power is `stake / 2` — collapsing total
    /// voting power toward 0, stalling BFT quorum. The floor is expressed relative to the
    /// genesis constant (rather than a fresh magic number) so it scales automatically if
    /// that constant is ever revisited. Two orders of magnitude below genesis still allows
    /// real downward adjustment while keeping "dust stake" accounts out of the validator set.
    ///
    /// `FuelPerFeeUnit`: `1` — unlike `MinValidatorStake`, this parameter has no meaningful
    /// near-zero danger zone once it's nonzero: `fuel_limit = tx.fee * fuel_per_fee_unit`,
    /// so a low value just means callers pay more fee for the same fuel (an economic
    /// inconvenience), not the "every call gets 0 fuel" catastrophe a true zero causes. `1`
    /// is also the genesis default (`DEFAULT_FUEL_PER_FEE_UNIT`), so this floor is really
    /// just the existing zero-check restated — kept as an explicit case here (rather than a
    /// wildcard `_ => 1`) so a future new `GovernanceParam` variant must deliberately pick a
    /// floor instead of silently inheriting one meant for a different parameter.
    ///
    /// Deliberately NOT implemented: a relative per-proposal change cap (e.g. "at most 10x
    /// up/down per proposal"). That would guard against a single catastrophic jump but not
    /// against a sequence of smaller proposals walking the value down over time — the
    /// absolute floor here is the actual backstop no sequence of proposals can cross,
    /// regardless of how many steps they take.
    fn min_allowed(self) -> u64 {
        match self {
            GovernanceParam::MinValidatorStake => MIN_VALIDATOR_STAKE / 100,
            GovernanceParam::FuelPerFeeUnit => 1,
            // The first version a chain can move to. That it is exactly the next one is checked
            // against the chain's state, which this static floor cannot see.
            GovernanceParam::ProtocolUpgrade => GENESIS_PROTOCOL_VERSION + 1,
        }
    }

    pub fn validate(self, new_value: u64) -> Result<(), GovernanceError> {
        let floor = self.min_allowed();
        if new_value < floor {
            Err(GovernanceError::ParamBelowFloor { param: self, value: new_value, floor })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error(
        "proposal payload must be 1 param byte + 8 value bytes, and a protocol upgrade 8 more for \
         its activation height"
    )]
    MalformedProposal,
    #[error("unknown governance parameter byte {0}")]
    UnknownParam(u8),
    #[error("vote payload must be exactly 8 bytes (proposal id)")]
    MalformedVote,
    #[error("proposed value {value} for {param:?} is below the minimum safe floor {floor}")]
    ParamBelowFloor { param: GovernanceParam, value: u64, floor: u64 },
}

/// Encode a `CreateProposal` tx payload: 1 byte param discriminant + 8 bytes new value (LE).
pub fn encode_proposal(param: GovernanceParam, new_value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(param.to_u8());
    buf.extend_from_slice(&new_value.to_le_bytes());
    buf
}

/// Encode a protocol-upgrade proposal: 1 byte param, 8 bytes version, 8 bytes activation height
/// (both LE).
pub fn encode_upgrade_proposal(version: u64, activation_height: u64) -> Vec<u8> {
    let mut buf = encode_proposal(GovernanceParam::ProtocolUpgrade, version);
    buf.extend_from_slice(&activation_height.to_le_bytes());
    buf
}

/// A proposal payload: the parameter, its new value, and — for a protocol upgrade, and only for
/// it — the activation height (0 otherwise).
pub fn decode_proposal(data: &[u8]) -> Result<(GovernanceParam, u64, u64), GovernanceError> {
    let Some(&first) = data.first() else { return Err(GovernanceError::MalformedProposal) };
    let param = GovernanceParam::from_u8(first).ok_or(GovernanceError::UnknownParam(first))?;
    let expected = if param == GovernanceParam::ProtocolUpgrade { 17 } else { 9 };
    if data.len() != expected {
        return Err(GovernanceError::MalformedProposal);
    }
    let word = |at: usize| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[at..at + 8]);
        u64::from_le_bytes(bytes)
    };
    let activation_height = if param == GovernanceParam::ProtocolUpgrade { word(9) } else { 0 };
    Ok((param, word(1), activation_height))
}

/// Encode a `VoteProposal` tx payload: 8 bytes proposal id (LE).
pub fn encode_vote(proposal_id: u64) -> Vec<u8> {
    proposal_id.to_le_bytes().to_vec()
}

pub fn decode_vote(data: &[u8]) -> Result<u64, GovernanceError> {
    if data.len() != 8 {
        return Err(GovernanceError::MalformedVote);
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(data);
    Ok(u64::from_le_bytes(bytes))
}

/// Runtime-adjustable protocol parameters. Starts at the genesis defaults and can be
/// changed by a passed [`GovernanceProposal`] (2/3-of-stake supermajority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParams {
    pub min_validator_stake: u64,
    pub fuel_per_fee_unit: u64,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        GovernanceParams {
            min_validator_stake: MIN_VALIDATOR_STAKE,
            fuel_per_fee_unit: DEFAULT_FUEL_PER_FEE_UNIT,
        }
    }
}

/// A stake-weighted governance proposal to change one protocol parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: u64,
    pub proposer: String,
    pub param: GovernanceParam,
    pub new_value: u64,
    pub created_at_height: u64,
    /// Addresses that already voted yes — prevents double-voting.
    pub voters: HashSet<String>,
    /// Cumulative staked HLX (recorded at time of vote) of everyone who voted yes.
    pub yes_stake: u64,
    /// The quorum denominator: **the largest network-wide staked total this proposal has ever
    /// seen**, starting at creation and raised — never lowered — at every vote.
    ///
    /// Both halves matter, and until 2026-09-22 only one was here.
    ///
    /// *It must not shrink*, because `yes_stake` only ever grows: a voter's contribution is
    /// counted once and never revisited, so a denominator that fell with a post-vote unstake
    /// would let a proposal cross quorum against a total that no longer contains the stake which
    /// got it there. That was the original argument and it is correct.
    ///
    /// *It must not stay behind either.* `yes_stake` adds the voter's stake **as of the vote**,
    /// so stake created after the proposal existed counted in the numerator while never
    /// appearing in a denominator frozen before it. Measured: an attacker holding nothing at
    /// creation stakes two thirds of the honest total, votes alone, and carries it — while
    /// holding **40 %** of all stake in existence, under a rule the chain calls a two-thirds
    /// supermajority.
    ///
    /// Taking the maximum closes both without storing anything per voter. Honest stake arriving
    /// mid-vote raises the bar too, which is right: the threshold is a share of the stakers, and
    /// they are who it must be a share of.
    pub quorum_denominator: u64,
    /// For a [`GovernanceParam::ProtocolUpgrade`]: the first height executed under the new
    /// version, named by the proposer and voted on with the rest — whoever votes yes agrees to the
    /// time it leaves operators to update. Past the end of the voting period by construction
    /// (`execute_create_proposal`), so an upgrade never takes effect while it is still being voted
    /// on. 0 for every other parameter.
    #[serde(default)]
    pub activation_height: u64,
    pub executed: bool,
}

impl GovernanceProposal {
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.created_at_height + VOTING_PERIOD_BLOCKS
    }
}

/// 2/3-plus-one stake-weighted supermajority — the same threshold BFT consensus uses for
/// block quorum (see `ValidatorSet::quorum_threshold`).
pub fn quorum_threshold(total_staked: u64) -> u64 {
    total_staked * 2 / 3 + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_payload_roundtrips() {
        let encoded = encode_proposal(GovernanceParam::FuelPerFeeUnit, 42);
        assert_eq!(encoded.len(), 9);
        let (param, value, activation) = decode_proposal(&encoded).unwrap();
        assert_eq!(param, GovernanceParam::FuelPerFeeUnit);
        assert_eq!(value, 42);
        assert_eq!(activation, 0);
    }

    /// An upgrade proposal carries its activation height; every other proposal is the nine bytes
    /// it always was, and the two lengths are not interchangeable.
    #[test]
    fn an_upgrade_proposal_carries_its_activation_height() {
        let encoded = encode_upgrade_proposal(2, 12_345);
        assert_eq!(encoded.len(), 17);
        assert_eq!(decode_proposal(&encoded).unwrap(), (GovernanceParam::ProtocolUpgrade, 2, 12_345));
        assert!(decode_proposal(&encode_proposal(GovernanceParam::ProtocolUpgrade, 2)).is_err(), "an upgrade without a height");
        let mut long = encode_proposal(GovernanceParam::FuelPerFeeUnit, 3);
        long.extend_from_slice(&7u64.to_le_bytes());
        assert!(decode_proposal(&long).is_err(), "a height on a proposal that has none");
        assert!(decode_proposal(&[]).is_err());
    }

    #[test]
    fn decode_proposal_rejects_wrong_length() {
        assert!(decode_proposal(&[0u8; 5]).is_err());
    }

    #[test]
    fn decode_proposal_rejects_unknown_param_byte() {
        let mut bytes = vec![255u8];
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert!(decode_proposal(&bytes).is_err());
    }

    #[test]
    fn vote_payload_roundtrips() {
        let encoded = encode_vote(7);
        assert_eq!(decode_vote(&encoded).unwrap(), 7);
    }

    #[test]
    fn quorum_threshold_matches_bft_supermajority() {
        // 100 staked -> need 67+ (2/3 + 1, integer division)
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn proposal_expires_after_voting_period() {
        let proposal = GovernanceProposal {
            id: 0,
            proposer: "x".to_string(),
            param: GovernanceParam::MinValidatorStake,
            new_value: 1,
            created_at_height: 10,
            voters: Default::default(),
            yes_stake: 0,
            quorum_denominator: 0,
            activation_height: 0,
            executed: false,
        };
        assert!(!proposal.is_expired(10 + VOTING_PERIOD_BLOCKS));
        assert!(proposal.is_expired(10 + VOTING_PERIOD_BLOCKS + 1));
    }
}
