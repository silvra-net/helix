//! Which chain is this — the genesis hash, and where a signer is allowed to learn it from.
//!
//! A Helix chain is identified by the hash of its genesis block. That is the value transactions
//! commit to ([`Transaction::chain_id`](crate::Transaction::chain_id)) and the value a joining node
//! checks a served genesis against. It lives here rather than in `helix-node` because the wallet
//! needs it as badly as the node does, and for the harder reason: the wallet has no chain to read
//! it from.

use helix_crypto::Hash;

/// The public Helix network's RPC endpoint — the one seed a brand-new node dials, and the one
/// endpoint whose answers about *which chain this is* are never believed (see [`ChainIdSource`]).
pub const DEFAULT_SEED_PEER: &str = "https://helix.silvra.net";

/// The public Helix network's genesis hash, compiled in.
///
/// Bitcoin puts its genesis in the source and asserts the hash (`chainparams.cpp`), so a node
/// cannot be talked onto another chain and nobody configures anything. Same idea, one deliberate
/// softening: this is the *default*, not a law, because a Helix devnet reset produces a new genesis
/// and a hard-coded hash that outlived a reset would lock every operator out until a release
/// shipped — trading a real outage for a hypothetical impersonation.
///
/// **Update this together with any chain reset**, in the release that accompanies it. That
/// instruction was already written down on 2026-08-07 and was missed anyway: the chain was reset,
/// this constant kept the dead chain's hash, and every operator on the published binary was refused
/// at the join by a message that read as though *they* had configured it. `scripts/check-genesis-
/// pin.sh` exists because no unit test can catch this — the stale hash was perfectly well-formed
/// and every suite was green. The check needs the live network.
pub const DEFAULT_GENESIS_HASH: &str =
    "294ee6d57be490ed8e6fc7024548805d9abaf07bc4863700a45d2bf19e14e2ce";

/// [`DEFAULT_GENESIS_HASH`] as a [`Hash`].
///
/// Panics only if the constant above is not 32 bytes of hex, which a unit test in this module
/// rules out at build time.
pub fn default_chain_id() -> Hash {
    Hash::from_hex(DEFAULT_GENESIS_HASH).expect("DEFAULT_GENESIS_HASH is valid hex")
}

/// Where a signing tool may take the chain id from, given which endpoint it was pointed at.
///
/// This is a security boundary, not a convenience. A wallet that asks the endpoint it is about to
/// submit to which chain it is on has handed that endpoint the power to decide what the signature
/// authorises: point a user at a "testnet" RPC, answer with mainnet's chain id, and the transaction
/// they thought they were throwing away is spendable. Taking the id from the endpoint is only safe
/// when the *user* named the endpoint, because then trusting it is a choice they already made.
///
/// The same shape as the genesis checkpoint in `helix-node` on purpose: compiled-in for the public
/// chain, whatever you asked for when you asked for something specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainIdSource {
    /// The operator named this endpoint (own node, devnet, private network), so it may be asked.
    AskEndpoint,
    /// The default public endpoint — use [`DEFAULT_GENESIS_HASH`] and never the endpoint's answer.
    CompiledIn,
}

/// Decides that boundary from the endpoint alone: anything but the public seed is one the user
/// either named or runs themselves, and may therefore be asked.
///
/// Split out as a pure function because it is the whole argument, and it is one negation away from
/// making every wallet trust whatever it is talking to.
pub fn chain_id_source(endpoint: &str) -> ChainIdSource {
    if endpoint.trim_end_matches('/') == DEFAULT_SEED_PEER {
        ChainIdSource::CompiledIn
    } else {
        ChainIdSource::AskEndpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape only, and worth stating what it does not cover: no unit test can tell whether this
    /// constant still names the live chain. The stale value that locked out three operators on
    /// 2026-08-08 was perfectly well-formed. That check needs the network — `check-genesis-pin.sh`.
    #[test]
    fn the_compiled_in_genesis_is_a_well_formed_hash() {
        assert_eq!(DEFAULT_GENESIS_HASH.len(), 64, "a BLAKE3 hash is 32 bytes of hex");
        assert!(
            DEFAULT_GENESIS_HASH.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "lowercase hex only — the form every node prints",
        );
        assert_eq!(default_chain_id().to_hex(), DEFAULT_GENESIS_HASH);
    }

    /// The boundary itself. Stated as a test because reversing it is invisible in review: both
    /// directions compile, both "work", and only one of them lets the endpoint choose what a
    /// signature means.
    #[test]
    fn only_an_endpoint_the_user_named_may_be_asked_which_chain_it_is() {
        assert_eq!(chain_id_source(DEFAULT_SEED_PEER), ChainIdSource::CompiledIn);
        // A trailing slash is the same endpoint, and the check is a security boundary — it must not
        // be sidestepped by a character every URL bar adds on its own.
        assert_eq!(
            chain_id_source(&format!("{DEFAULT_SEED_PEER}/")),
            ChainIdSource::CompiledIn
        );
        assert_eq!(chain_id_source("http://127.0.0.1:8545"), ChainIdSource::AskEndpoint);
        assert_eq!(chain_id_source("https://devnet.example"), ChainIdSource::AskEndpoint);
    }
}
