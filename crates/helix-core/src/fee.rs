//! EIP-1559-style dynamic base fee.
//!
//! Ethereum's fee market prices *gas*; Helix has no uniform gas metric (only contract calls
//! meter fuel — a transfer or stake just pays a flat fee), so the congestion signal here is
//! **serialized transaction bytes**: a uniform, deterministic proxy for the block space a
//! transaction consumes. Each block carries a `base_fee_per_byte` in its header; every
//! transaction must pay at least `base_fee_per_byte × its_serialized_size`, that portion is
//! burned, and the rest of its fee is the validator's tip (see `executor::distribute_fee`).
//!
//! The base fee is not chosen by the proposer — it is derived deterministically from the
//! parent block's fullness via [`next_base_fee_per_byte`], so every node computes the same
//! value and validation can re-check it. When a block is fuller than the target the base fee
//! rises (up to +12.5%), when emptier it falls (down to a floor), exactly like EIP-1559.

/// Base fee of the genesis block, in nano-HLX per transaction byte. Also the effective floor
/// the schedule decays back to when blocks sit below target (empty blocks → base fee → floor).
pub const INITIAL_BASE_FEE_PER_BYTE: u64 = 1;

/// The per-block transaction-byte total the fee market steers toward. Blocks above this push
/// the base fee up; blocks below it let the base fee fall. ~1 MB of transactions per ~2 s
/// block is the neutral point.
pub const TARGET_BLOCK_BYTES: u64 = 1_000_000;

/// The elasticity ceiling the fee curve is calibrated against — twice the target, the same 2×
/// elasticity EIP-1559 uses (a block exactly at this size raises the base fee by the full
/// +12.5%). NOTE: a hard block-production/validation byte cap at this value is not yet wired in
/// (blocks are currently bounded by `MAX_TXS_PER_BLOCK` count, not bytes) — see the backlog.
pub const MAX_BLOCK_BYTES: u64 = 2 * TARGET_BLOCK_BYTES;

/// Max fractional change of the base fee per block: `1/8` = ±12.5%, matching EIP-1559.
pub const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;

/// Deterministically compute the base fee (nano-HLX per byte) for the block that follows a
/// parent with `parent_base_fee` and `parent_bytes_used` transaction bytes. `floor` is the
/// minimum base fee (a governance-adjustable anti-spam floor, passed in by the caller so this
/// stays a pure function). Pure integer arithmetic — every node derives the identical value.
pub fn next_base_fee_per_byte(parent_base_fee: u64, parent_bytes_used: u64, floor: u64) -> u64 {
    let target = TARGET_BLOCK_BYTES;
    let next = if parent_bytes_used == target {
        parent_base_fee
    } else if parent_bytes_used > target {
        // Fuller than target → raise. EIP-1559 nudges by at least 1 so the fee can climb off
        // a low value even when the proportional delta rounds down to zero.
        let delta = (parent_base_fee as u128 * (parent_bytes_used - target) as u128
            / target as u128
            / BASE_FEE_MAX_CHANGE_DENOMINATOR as u128) as u64;
        parent_base_fee.saturating_add(delta.max(1))
    } else {
        // Emptier than target → lower (delta may round to zero, holding the fee flat).
        let delta = (parent_base_fee as u128 * (target - parent_bytes_used) as u128
            / target as u128
            / BASE_FEE_MAX_CHANGE_DENOMINATOR as u128) as u64;
        parent_base_fee.saturating_sub(delta)
    };
    next.max(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blocks_hold_at_the_floor() {
        // Parent at the floor, zero usage → stays at the floor, never underflows.
        assert_eq!(next_base_fee_per_byte(1, 0, 1), 1);
        // Well above the floor but empty → decays by 12.5% toward the floor.
        assert_eq!(next_base_fee_per_byte(1000, 0, 1), 875);
    }

    #[test]
    fn full_block_raises_the_fee_by_up_to_12_5_percent() {
        // Exactly at max (2× target) → the full +12.5%.
        assert_eq!(next_base_fee_per_byte(1000, MAX_BLOCK_BYTES, 1), 1125);
        // Exactly at target → unchanged.
        assert_eq!(next_base_fee_per_byte(1000, TARGET_BLOCK_BYTES, 1), 1000);
    }

    #[test]
    fn rises_by_at_least_one_off_a_low_value() {
        // Just over target with base fee 1: proportional delta rounds to 0, but it still ticks up.
        assert_eq!(next_base_fee_per_byte(1, TARGET_BLOCK_BYTES + 1, 1), 2);
    }

    #[test]
    fn never_drops_below_the_floor() {
        assert_eq!(next_base_fee_per_byte(100, 0, 500), 500);
    }

    #[test]
    fn schedule_is_deterministic() {
        for used in [0u64, 1, 500_000, 1_000_000, 1_500_000, 2_000_000] {
            assert_eq!(
                next_base_fee_per_byte(1234, used, 1),
                next_base_fee_per_byte(1234, used, 1)
            );
        }
    }
}
