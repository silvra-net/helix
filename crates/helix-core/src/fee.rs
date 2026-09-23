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
/// +12.5%). Also the hard cap on a block's transaction bytes, enforced when packing
/// (`Mempool::take_within`) and on every path that admits a block
/// (`Block::exceeds_size_limit`).
///
/// It was neither for a long time: blocks were bounded by transaction *count* alone, and at ~5.4 KB
/// per transfer the 1000-transaction cap allowed a 5.2 MB block — larger than gossipsub will
/// transmit, so it could never be broadcast, never collected votes, and was rebuilt identically by
/// the next proposer. The note that used to sit here said the cap was "not yet wired in" and
/// pointed at a backlog item that no longer existed.
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

/// Headroom a wallet adds over the bare base fee when it prices a transaction itself, in
/// percent. The base fee moves at most ±12.5% per block and a transaction pays the fee of the
/// block that *includes* it, so pricing at exactly today's rate gets anything that waits a few
/// busy blocks rejected on arrival; 100% covers about six consecutive rises (1.125⁶ ≈ 2.03).
/// Not wasted: only `base_fee × size` is burned, the rest tips the validator.
///
/// **Wallet policy, not consensus** — no node checks it. It lives here so the CLI and the
/// desktop wallet price with one rule; they used to carry a copy each, kept in step by eye.
pub const WALLET_FEE_HEADROOM_PERCENT: u64 = 100;

/// The most a wallet pays for a transaction it priced itself: 1 HLX.
///
/// A wallet learns the base fee from the node it talks to, and that node is not trusted — a
/// public endpoint, a stranger's, or a compromised one. The chain puts **no upper bound** on the
/// base fee (it may rise 12.5 % per full block without end), so nothing in the protocol lets a
/// wallet call a high number a lie. Without a ceiling, a node reporting 10¹² nano/byte had the
/// wallet sign a transfer carrying ~10.8 million HLX of fee — a valid transaction every node
/// accepts, at top priority — and the CLI printed that fee in nano in the same breath as it
/// sent it.
///
/// At the floor a transfer costs ~0.00001 HLX; the ceiling is ~92,000 times that. Honest
/// congestion reaches it only after ~100 consecutive over-target blocks, each burning more than
/// the last. Above it a wallet refuses and says why, and paying anyway is an explicit fee — a
/// decision a person makes, not a number a node supplies. What a lying node can cost someone is
/// now at most this, per transaction, instead of everything.
pub const WALLET_AUTO_FEE_CEILING_NANO: u64 = 1_000_000_000;

/// A fee a wallet will not pay unless told to — see [`WALLET_AUTO_FEE_CEILING_NANO`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoFeeRefused {
    pub base_fee_per_byte: u64,
    pub size_bytes: u64,
    pub fee_nano: u64,
}

impl std::fmt::Display for AutoFeeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the node reports a base fee of {} nano/byte, which prices this {}-byte transaction \
             at {} HLX — more than the {} HLX a wallet pays without being told to. That is either \
             extreme congestion or a node that is not telling the truth; compare with another \
             node or the explorer before paying it",
            self.base_fee_per_byte,
            self.size_bytes,
            nano_as_hlx(self.fee_nano),
            nano_as_hlx(WALLET_AUTO_FEE_CEILING_NANO),
        )
    }
}

/// Exact decimal HLX for a nano amount, without trailing zeros (integer arithmetic — a fee
/// shown to a person deciding whether to pay it should not pass through a float).
fn nano_as_hlx(nano: u64) -> String {
    let whole = nano / 1_000_000_000;
    let frac = nano % 1_000_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:09}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// The fee a wallet puts on a transaction of `size_bytes` when nobody named one: the base fee for
/// its size plus [`WALLET_FEE_HEADROOM_PERCENT`] — refused above
/// [`WALLET_AUTO_FEE_CEILING_NANO`]. Saturating, so an absurd base fee is refused, never wrapped.
pub fn wallet_auto_fee(base_fee_per_byte: u64, size_bytes: u64) -> Result<u64, AutoFeeRefused> {
    let required = base_fee_per_byte.saturating_mul(size_bytes);
    let fee = required.saturating_add(required.saturating_mul(WALLET_FEE_HEADROOM_PERCENT) / 100);
    if fee > WALLET_AUTO_FEE_CEILING_NANO {
        return Err(AutoFeeRefused {
            base_fee_per_byte,
            size_bytes,
            fee_nano: fee,
        });
    }
    Ok(fee)
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

    /// A plain ML-DSA transfer, measured: the size the CLI's own comment names (~5.4 KB).
    const TRANSFER_BYTES: u64 = 5_410;

    #[test]
    fn a_wallet_prices_the_floor_exactly_as_before() {
        // The rule moved here from two copies; at the floor it must give their answer.
        assert_eq!(wallet_auto_fee(1, TRANSFER_BYTES), Ok(2 * TRANSFER_BYTES));
    }

    #[test]
    fn a_wallet_will_not_pay_a_fee_a_node_made_up() {
        // 10^12 nano/byte: the attack. A transfer would carry ~10.8 million HLX of fee.
        let refused = wallet_auto_fee(1_000_000_000_000, TRANSFER_BYTES).unwrap_err();
        assert_eq!(refused.fee_nano, 2 * 1_000_000_000_000 * TRANSFER_BYTES);
        let text = refused.to_string();
        assert!(text.contains("10820000 HLX"), "{text}");
        assert!(text.contains("more than the 1 HLX"), "{text}");
        // Saturates to a refusal, never wraps to a small fee.
        assert!(wallet_auto_fee(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn the_ceiling_is_exact_and_leaves_room_for_honest_congestion() {
        // 1_000_000 nano/byte × 500 bytes × 2 is exactly the ceiling: paid. One nano/byte more: not.
        assert_eq!(
            wallet_auto_fee(1_000_000, 500),
            Ok(WALLET_AUTO_FEE_CEILING_NANO)
        );
        assert!(wallet_auto_fee(1_000_001, 500).is_err());
        // A transfer still goes through at 90,000 times the floor, and a 64 KiB contract deploy
        // at 7,000 times — congestion far beyond anything this chain has seen.
        assert!(wallet_auto_fee(90_000, TRANSFER_BYTES).is_ok());
        assert!(wallet_auto_fee(7_000, 65_536 + TRANSFER_BYTES).is_ok());
    }

    #[test]
    fn fees_are_shown_in_exact_hlx() {
        assert_eq!(nano_as_hlx(0), "0");
        assert_eq!(nano_as_hlx(10_820), "0.00001082");
        assert_eq!(nano_as_hlx(1_000_000_000), "1");
        assert_eq!(nano_as_hlx(1_500_000_001), "1.500000001");
    }
}
