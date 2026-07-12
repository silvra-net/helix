use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::genesis::MIN_VALIDATOR_STAKE;

/// Fuel granted per nano-HLX of `tx.fee` when calling a WASM contract. Governance-adjustable
/// starting value — see `execute_call_contract` in lib.rs.
pub const DEFAULT_FUEL_PER_FEE_UNIT: u64 = 1;

/// Blocks a proposal stays open for voting before it expires unexecuted.
pub const VOTING_PERIOD_BLOCKS: u64 = 1000;

/// Protocol parameters that a governance proposal may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceParam {
    MinValidatorStake,
    FuelPerFeeUnit,
}

impl GovernanceParam {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(GovernanceParam::MinValidatorStake),
            1 => Some(GovernanceParam::FuelPerFeeUnit),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            GovernanceParam::MinValidatorStake => 0,
            GovernanceParam::FuelPerFeeUnit => 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("proposal payload must be exactly 9 bytes: 1 param byte + 8 value bytes")]
    MalformedProposal,
    #[error("unknown governance parameter byte {0}")]
    UnknownParam(u8),
    #[error("vote payload must be exactly 8 bytes (proposal id)")]
    MalformedVote,
}

/// Encode a `CreateProposal` tx payload: 1 byte param discriminant + 8 bytes new value (LE).
pub fn encode_proposal(param: GovernanceParam, new_value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(param.to_u8());
    buf.extend_from_slice(&new_value.to_le_bytes());
    buf
}

pub fn decode_proposal(data: &[u8]) -> Result<(GovernanceParam, u64), GovernanceError> {
    if data.len() != 9 {
        return Err(GovernanceError::MalformedProposal);
    }
    let param = GovernanceParam::from_u8(data[0]).ok_or(GovernanceError::UnknownParam(data[0]))?;
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&data[1..9]);
    Ok((param, u64::from_le_bytes(value_bytes)))
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
    /// Total staked HLX network-wide at proposal creation — the fixed quorum
    /// denominator for this proposal's entire voting period. Frozen here instead of
    /// recomputed live at each vote: `yes_stake` only ever grows (a voter's stake
    /// contribution is never revisited), so if the denominator could shrink — e.g.
    /// a voter immediately unstaking after voting yes — a proposal could cross
    /// quorum against a total that no longer includes the stake that got it there.
    pub total_staked_at_creation: u64,
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
        let (param, value) = decode_proposal(&encoded).unwrap();
        assert_eq!(param, GovernanceParam::FuelPerFeeUnit);
        assert_eq!(value, 42);
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
            total_staked_at_creation: 0,
            executed: false,
        };
        assert!(!proposal.is_expired(10 + VOTING_PERIOD_BLOCKS));
        assert!(proposal.is_expired(10 + VOTING_PERIOD_BLOCKS + 1));
    }
}
