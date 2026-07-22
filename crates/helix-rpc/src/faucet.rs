//! Testnet faucet — hands out a small, capped amount of HLX so people can actually try the
//! chain instead of reading about it.
//!
//! **Off unless `HELIX_FAUCET_KEY` names a key file.** This binary ships to other operators,
//! and a faucet that ran by default would quietly drain whichever key it found. Enabling it is
//! a deliberate act by someone who funded an account for the purpose.
//!
//! **Never the validator key.** The faucet signs on request from the open internet; the
//! validator key signs blocks. Giving a public endpoint any path to the block signer is the one
//! mistake here that could not be undone, so the faucet refuses to start if the two addresses
//! match rather than trusting the operator to have noticed.
//!
//! **What it deliberately is not.** It cannot make validators: `MIN_VALIDATOR_STAKE` is
//! 100,000 HLX and four of those exceed the entire supply, so that is a governance question,
//! not a faucet question. It funds transactions. At the fee floor a ~5.4 KB transfer costs
//! about 0.00001 HLX, so a 10 HLX top-up is on the order of a million transactions — the amount
//! is small because nothing needs it to be large, not to be stingy.
//!
//! **Top-up, not payout.** A request tops the recipient up *to* the configured amount; an
//! address that already holds it gets nothing. That rule is derived from chain state on every
//! request, so it holds no state of its own: it survives restarts, cannot be reset by
//! restarting this node, and — the reason it is shaped this way — keeps faucet bookkeeping out
//! of `ChainState`, where it would enter `state_hash` and break genesis reconstruction for
//! every existing node (see `active_validators`' doc comment for that trap).
//!
//! It does not stop someone generating fresh addresses in a loop. Nothing short of an identity
//! check does, and every such check is an external service — which would break the promise the
//! explorer footer makes on every page ("no external requests, no tracking"). For coins with no
//! value, the small amount and the per-IP limit are the proportionate answer; the real bound is
//! that the faucet account holds only what it was funded with.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, KeyFile, KeyPair, Signature};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{info, warn};

use helix_p2p::P2PCommand;

use crate::server::AppState;

const NANO_PER_HLX: u64 = 1_000_000_000;

/// Top-up ceiling in HLX when `HELIX_FAUCET_TOPUP_HLX` says nothing else.
const DEFAULT_TOPUP_HLX: u64 = 10;

/// Same headroom `helix-cli` prices with, and for the same reason: a transaction is charged the
/// base fee of the block that *includes* it, which may be several ±12.5% steps above the one
/// current when it was signed. See `helix_cli::fee::FEE_HEADROOM_PERCENT`.
const FEE_HEADROOM_PERCENT: u64 = 100;

pub struct Faucet {
    keypair: KeyPair,
    pub address: Address,
    topup_nano: u64,
    /// Nonce to use for the next grant.
    ///
    /// The executor requires `tx.nonce == account.nonce` exactly, and the account's nonce only
    /// advances once a block *includes* the transaction. Two requests arriving in the same
    /// block interval would therefore both read the same nonce from state and the second would
    /// be rejected as a duplicate by the mempool. Held here instead, seeded from chain state
    /// when unset, and dropped back to `None` on any failure so a stuck value re-seeds itself
    /// rather than wedging the faucet until restart.
    next_nonce: Mutex<Option<u64>>,
}

impl Faucet {
    /// Builds the faucet from the environment, or `None` when `HELIX_FAUCET_KEY` is unset.
    ///
    /// `node_address` is the node's own validator address, and a match is fatal rather than a
    /// warning — see the module docs.
    pub fn from_env(node_address: &str) -> Option<Arc<Faucet>> {
        let path = PathBuf::from(std::env::var("HELIX_FAUCET_KEY").ok()?);

        let key_file = match KeyFile::load(&path) {
            Ok(k) => k,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "HELIX_FAUCET_KEY is set but the key could not be loaded — faucet disabled");
                return None;
            }
        };
        let passphrase = std::env::var("HELIX_FAUCET_KEY_PASSPHRASE").ok();
        let keypair = match key_file.to_keypair(passphrase.as_deref()) {
            Ok(kp) => kp,
            Err(e) => {
                warn!(error = %e, "faucet key could not be decrypted — faucet disabled");
                return None;
            }
        };

        let address = Address::from_public_key(&keypair.public);
        if address.to_string() == node_address {
            warn!(
                address = %address,
                "HELIX_FAUCET_KEY is this node's VALIDATOR key — faucet disabled. Fund a \
                 separate account for the faucet: this endpoint signs on request from the \
                 public internet, and that key signs blocks."
            );
            return None;
        }

        let topup_hlx = std::env::var("HELIX_FAUCET_TOPUP_HLX")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|hlx| *hlx > 0)
            .unwrap_or(DEFAULT_TOPUP_HLX);

        info!(
            address = %address,
            topup_hlx,
            "Faucet enabled — tops up any address to this balance"
        );
        Some(Arc::new(Faucet {
            keypair,
            address,
            topup_nano: topup_hlx.saturating_mul(NANO_PER_HLX),
            next_nonce: Mutex::new(None),
        }))
    }

    /// The ceiling in HLX, for `GET /status` to advertise.
    pub fn topup_hlx(&self) -> f64 {
        self.topup_nano as f64 / NANO_PER_HLX as f64
    }

    /// The ceiling in nano — what the account must still hold for the faucet to be worth
    /// advertising. See `NodeStatus::faucet_topup_hlx`.
    pub fn topup_nano(&self) -> u64 {
        self.topup_nano
    }

    /// What this address should receive, given what it already holds — `None` when it is
    /// already at or above the ceiling and is owed nothing.
    ///
    /// The distance to the ceiling, never the ceiling itself. Paying the full amount to whoever
    /// asks would make the cap meaningless to anyone willing to ask twice, which is the whole
    /// mechanism: this is what makes the faucet a top-up rather than a payout, and it is why no
    /// per-address cooldown has to be stored anywhere.
    pub fn grant_for(&self, current_balance: u64) -> Option<u64> {
        self.topup_nano.checked_sub(current_balance).filter(|g| *g > 0)
    }

    /// Signs a transfer of `amount` nano-HLX to `to`, priced against `base_fee_per_byte`.
    ///
    /// Signed twice on purpose: the fee depends on the serialized size, the size depends on the
    /// signature, so the first signature exists only to make the measurement honest. That is
    /// sound because bincode encodes the fee as a fixed 8 bytes, so re-pricing cannot change
    /// the size it was priced against — the same argument `helix_cli::fee::price_and_sign` runs
    /// on, and it must stay in step with it.
    fn signed_transfer(
        &self,
        to: &Address,
        amount: u64,
        nonce: u64,
        base_fee_per_byte: u64,
    ) -> Result<Transaction, String> {
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            from: self.address.clone(),
            to: Some(to.clone()),
            amount,
            fee: 0,
            nonce,
            data: Vec::new(),
            crypto_version: self.keypair.scheme,
            signature: Signature::from_bytes(Vec::new()),
            public_key: self.keypair.public.clone(),
        };
        let sign = |tx: &Transaction| {
            self.keypair
                .sign(tx.signing_hash().as_bytes())
                .map_err(|e| e.to_string())
        };

        tx.signature = sign(&tx)?;
        let required = base_fee_per_byte.saturating_mul(tx.size_bytes());
        tx.fee = required.saturating_add(required.saturating_mul(FEE_HEADROOM_PERCENT) / 100);
        tx.signature = sign(&tx)?;
        Ok(tx)
    }
}

#[derive(Deserialize)]
pub struct FaucetRequest {
    pub address: String,
}

/// `POST /faucet` — `{"address": "hlx…"}`.
pub async fn request_funds(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    let Some(faucet) = state.faucet.clone() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "this node does not run a faucet" })),
        );
    };

    let to = match Address::from_str(req.address.trim()) {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid address format: {}", req.address) })),
            )
        }
    };
    if to == faucet.address {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "that is the faucet's own address" })),
        );
    }

    // One grant at a time: the nonce is a single sequence, and two concurrent requests reading
    // it would both claim the same number. Held across the state read and the mempool insert so
    // nothing can interleave between choosing the nonce and spending it.
    let mut next_nonce = faucet.next_nonce.lock().await;

    let (recipient_balance, faucet_balance, state_nonce) = {
        let chain = state.chain_state.read().await;
        (
            chain.get(&to).map(|a| a.balance).unwrap_or(0),
            chain.get(&faucet.address).map(|a| a.balance).unwrap_or(0),
            chain.get(&faucet.address).map(|a| a.nonce).unwrap_or(0),
        )
    };

    let Some(grant) = faucet.grant_for(recipient_balance) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "address already holds the full amount",
                "balance_hlx": recipient_balance as f64 / NANO_PER_HLX as f64,
                "topup_hlx": faucet.topup_nano as f64 / NANO_PER_HLX as f64,
            })),
        );
    };

    let base_fee_per_byte = state.mempool.read().await.base_fee_per_byte();
    let nonce = next_nonce.unwrap_or(state_nonce);
    let tx = match faucet.signed_transfer(&to, grant, nonce, base_fee_per_byte) {
        Ok(tx) => tx,
        Err(e) => {
            *next_nonce = None;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("faucet could not sign: {e}") })),
            );
        }
    };

    // Checked here rather than left to the mempool so an empty faucet says so plainly. An
    // operator reading "insufficient balance" on someone else's behalf should not have to work
    // out whose balance was meant.
    if faucet_balance < grant.saturating_add(tx.fee) {
        *next_nonce = None;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "faucet is out of funds — please tell the operator",
                "faucet_balance_hlx": faucet_balance as f64 / NANO_PER_HLX as f64,
            })),
        );
    }

    let tx_hash = tx.hash().to_hex();
    let result = state.mempool.write().await.add(tx.clone());
    match result {
        Ok(()) => {
            *next_nonce = Some(nonce + 1);
            drop(next_nonce);
            // Same reason `submit_transaction` gossips: this node may never propose a block
            // itself, and a grant sitting in one local mempool never reaches the recipient.
            let _ = state
                .p2p_command_tx
                .try_send(P2PCommand::BroadcastTransaction(tx));
            info!(to = %to, amount_hlx = grant as f64 / NANO_PER_HLX as f64, tx = %tx_hash, "Faucet grant");
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "tx_hash": tx_hash,
                    "status": "accepted",
                    "amount_hlx": grant as f64 / NANO_PER_HLX as f64,
                })),
            )
        }
        Err(e) => {
            // Re-seed from chain state next time: a rejected nonce is the one failure this
            // cached counter can actually cause, and holding on to it would repeat it forever.
            *next_nonce = None;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn faucet_with(topup_hlx: u64) -> Faucet {
        let keypair = KeyPair::generate();
        let address = Address::from_public_key(&keypair.public);
        Faucet {
            keypair,
            address,
            topup_nano: topup_hlx * NANO_PER_HLX,
            next_nonce: Mutex::new(None),
        }
    }

    /// The grant is the *gap* to the ceiling, not the ceiling. An address holding 4 of a 10 HLX
    /// top-up must receive 6 — paying the full 10 to anyone who asks turns the top-up rule into
    /// a payout and makes the cap meaningless to anyone willing to ask twice.
    ///
    /// The over-the-ceiling cases are the ones that matter: they are the only thing standing in
    /// for a per-address cooldown, and an underflow there would hand out `u64::MAX`.
    #[test]
    fn a_grant_only_covers_the_distance_to_the_ceiling() {
        let faucet = faucet_with(10);

        assert_eq!(faucet.grant_for(0), Some(10 * NANO_PER_HLX), "empty address");
        assert_eq!(faucet.grant_for(4 * NANO_PER_HLX), Some(6 * NANO_PER_HLX), "partly funded");
        assert_eq!(faucet.grant_for(10 * NANO_PER_HLX - 1), Some(1), "one nano short");

        assert_eq!(faucet.grant_for(10 * NANO_PER_HLX), None, "exactly at the ceiling");
        assert_eq!(faucet.grant_for(10 * NANO_PER_HLX + 1), None, "one nano over");
        assert_eq!(
            faucet.grant_for(u64::MAX),
            None,
            "a balance above the ceiling must yield nothing — subtracting it the other way \
             round would wrap and pay out the entire supply"
        );
    }

    /// The fee has to be priced against the size of the transaction that will actually be sent,
    /// which is why it is signed, measured, priced and signed again. If bincode ever encoded the
    /// fee as a variable-width integer that argument would collapse silently — the transaction
    /// would be priced against a size it no longer has and would be rejected on arrival for an
    /// underpaid fee. Pin it.
    #[test]
    fn pricing_the_fee_does_not_change_the_size_it_was_priced_against() {
        let faucet = faucet_with(10);
        let to = Address::from_public_key(&KeyPair::generate().public);

        let cheap = faucet.signed_transfer(&to, NANO_PER_HLX, 0, 1).unwrap();
        let dear = faucet.signed_transfer(&to, NANO_PER_HLX, 0, 1_000_000).unwrap();

        assert_ne!(cheap.fee, dear.fee, "precondition: the two must differ in fee");
        assert_eq!(
            cheap.size_bytes(),
            dear.size_bytes(),
            "a fee of any magnitude must serialize to the same width, or the fee this faucet \
             pays was computed for a transaction that no longer exists"
        );
    }

    /// A grant must cover the fee floor of the block that includes it, not merely the floor at
    /// signing time — the whole point of the headroom.
    #[test]
    fn a_grant_is_priced_above_the_bare_minimum() {
        let faucet = faucet_with(10);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let tx = faucet.signed_transfer(&to, NANO_PER_HLX, 0, 1).unwrap();

        let bare_minimum = tx.size_bytes();
        assert!(
            tx.fee > bare_minimum,
            "fee {} must exceed the {bare_minimum} nano floor it was priced from",
            tx.fee
        );
        assert!(
            tx.fee <= bare_minimum * 3,
            "fee {} is more headroom than a ±12.5% base fee can justify",
            tx.fee
        );
    }

    /// The signature must verify after re-pricing. This is the failure the double-signing
    /// exists to prevent: sign once, change the fee, ship the stale signature.
    #[test]
    fn the_shipped_signature_covers_the_final_fee() {
        let faucet = faucet_with(10);
        let to = Address::from_public_key(&KeyPair::generate().public);
        let tx = faucet.signed_transfer(&to, NANO_PER_HLX, 7, 1).unwrap();

        assert!(tx.verify_signature().is_ok());
        assert_eq!(tx.nonce, 7, "the nonce the caller chose must be the one signed");
        assert_eq!(tx.to.as_ref(), Some(&to));
    }
}
