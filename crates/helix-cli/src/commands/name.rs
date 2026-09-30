use anyhow::{anyhow, bail, Result};
use clap::Subcommand;
use helix_core::{Transaction, TxType};
use helix_crypto::{Address, Signature};

use crate::fee::price_and_sign;
use crate::passphrase::Signer;

#[derive(Subcommand)]
pub enum NameCmd {
    /// Register a human-readable name (e.g. `alice` -> alice.hlx)
    Register {
        /// Name to register (without the .hlx suffix)
        name: String,
        #[command(flatten)]
        signer: Signer,
        /// Fee in nano-HLX. Omit to price it against the chain's current base fee.
        #[arg(long)]
        fee: Option<u64>,
        /// The name's price in HLX, confirming you pay it. Required for names shorter than five
        /// characters (50 HLX for four, 500 HLX for three); the price is burned.
        #[arg(long, value_name = "HLX")]
        accept_price: Option<crate::fee::Hlx>,
    },
    /// Resolve a name to its owning address
    Resolve {
        /// Name to resolve (without the .hlx suffix)
        name: String,
    },
}

pub async fn run(cmd: NameCmd, node: &str) -> Result<()> {
    match cmd {
        NameCmd::Register {
            name,
            signer,
            fee,
            accept_price,
        } => register(name, signer, fee, accept_price, node).await,
        NameCmd::Resolve { name } => resolve(name, node).await,
    }
}

/// The price a registration pays, once the person has agreed to it (#252).
///
/// Names of five characters and more cost the base price and go through as they are — the price is
/// printed with the fee. A shorter name costs ten or a hundred times that, and nobody should burn
/// 500 HLX because they typed a short name, so it needs `--accept-price` with exactly the price.
/// A given `--accept-price` must match for any name. Decided before the wallet is unlocked, so a
/// refusal never costs a passphrase prompt.
fn price_to_pay(bare_name: &str, accept_price: Option<crate::fee::Hlx>) -> Result<u64> {
    let price = helix_core::fee::name_registration_price(bare_name.len());
    let base = helix_core::fee::name_registration_price(usize::MAX);
    let shown = helix_core::fee::nano_as_hlx(price);
    match accept_price {
        Some(hlx) => {
            if hlx.nano() != price {
                bail!(
                    "--accept-price {hlx} does not match the price of {bare_name}.hlx, which is \
                     {shown} HLX (burned). Nothing was sent."
                );
            }
        }
        None if price > base => bail!(
            "{bare_name}.hlx costs {shown} HLX, which is burned — short names cost more than the \
             {} HLX of a name with five characters or more. Nothing was sent. To pay it, run the \
             command again with --accept-price {shown}.",
            helix_core::fee::nano_as_hlx(base)
        ),
        None => {}
    }
    Ok(price)
}

async fn register(
    name: String,
    signer: Signer,
    fee: Option<u64>,
    accept_price: Option<crate::fee::Hlx>,
    node: &str,
) -> Result<()> {
    let bare = name.trim().trim_end_matches(".hlx").to_string();
    let price = price_to_pay(&bare, accept_price)?;
    let (kf, kp) = signer.unlock()?;
    let from = Address::from_str(&kf.address)
        .map_err(|e| anyhow::anyhow!("Invalid sender address: {}", e))?;

    let nonce = super::fetch_nonce(node, &kf.address).await?;

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::RegisterName,
        from: from.clone(),
        to: None,
        amount: price,
        fee: 0, // replaced by price_and_sign below
        nonce,
        data: bare.as_bytes().to_vec(),
        crypto_version: kp.scheme,
        chain_id: super::resolve_chain_id(node).await?,

        signature: Signature::from_bytes(vec![]),
        public_key: Some(kp.public.clone()),
    };

    price_and_sign(&mut tx, fee, &kp, node).await?;

    // One name per address: a registration releases the name the address held (#252).
    let what = format!("look up the current name of {}", kf.address);
    let current = super::get_optional(node, &format!("/accounts/{}/name", kf.address), &what)
        .await?
        .and_then(|res| res["name"].as_str().map(str::to_string));

    println!("Registering name '{}.hlx' for {}", bare, kf.address);
    println!("  Price : {} HLX (burned)", helix_core::fee::nano_as_hlx(price));
    println!("  Fee   : {} nano-HLX", tx.fee);
    println!("  Nonce : {}", nonce);
    if let Some(current) = current {
        println!(
            "  This replaces {current}.hlx — it is released, and anyone can register it after."
        );
    }

    let res = super::submit_tx(&tx, node).await?;
    println!();
    super::report_submitted(&res);
    Ok(())
}

async fn resolve(name: String, node: &str) -> Result<()> {
    let what = format!("resolve {}.hlx", name);
    let res = super::get_optional(node, &format!("/names/{}", name), &what)
        .await?
        .ok_or_else(|| anyhow!("{}.hlx is not registered on this chain", name))?;

    println!(
        "{}.hlx -> {}",
        res["name"].as_str().unwrap_or(&name),
        res["address"].as_str().unwrap_or("?")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HLX: u64 = 1_000_000_000;

    #[test]
    fn a_long_name_goes_through_at_its_price() {
        assert_eq!(price_to_pay("alice", None).unwrap(), 5 * HLX);
        assert_eq!(price_to_pay("alice", Some("5".parse().unwrap())).unwrap(), 5 * HLX);
    }

    #[test]
    fn a_short_name_needs_its_price_accepted() {
        let refused = price_to_pay("bob", None).unwrap_err().to_string();
        assert!(refused.contains("costs 500 HLX"), "{refused}");
        assert!(refused.contains("--accept-price 500"), "the message says how: {refused}");
        assert_eq!(price_to_pay("bob", Some("500".parse().unwrap())).unwrap(), 500 * HLX);
        assert_eq!(price_to_pay("anna", Some("50".parse().unwrap())).unwrap(), 50 * HLX);
    }

    #[test]
    fn an_accepted_price_that_does_not_match_is_refused() {
        for (name, hlx) in [("bob", "50"), ("anna", "500"), ("alice", "50")] {
            let refused = price_to_pay(name, Some(hlx.parse().unwrap())).unwrap_err().to_string();
            assert!(refused.contains("does not match"), "{name} at {hlx}: {refused}");
        }
    }
}
