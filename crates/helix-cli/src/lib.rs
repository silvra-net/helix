//! Helix client commands, exposed as a library so the single `helix` binary
//! (in `helix-node`) can dispatch them alongside `helix start`. These are all
//! thin RPC clients (plus local KeyFile wallet management) — none of them open
//! the chain database or boot the node runtime.

pub mod commands;
pub mod fee;
pub mod keyfile;

use anyhow::Result;
use clap::Subcommand;

/// The client-facing subcommands (`wallet`, `tx`, `chain`, …). Flattened into the
/// top-level `helix` command next to `start`, so users type `helix wallet new`,
/// `helix tx send`, etc.
#[derive(Subcommand)]
pub enum Commands {
    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: commands::wallet::WalletCmd,
    },
    /// Query chain state
    Chain {
        #[command(subcommand)]
        action: commands::chain::ChainCmd,
    },
    /// Account information
    Account {
        /// HLX address (hlx...)
        address: String,
    },
    /// Transaction operations
    Tx {
        #[command(subcommand)]
        action: commands::tx::TxCmd,
    },
    /// Human-readable name registration (`alice.hlx`)
    Name {
        #[command(subcommand)]
        action: commands::name::NameCmd,
    },
    /// Proof of Personhood identity attestation
    Identity {
        #[command(subcommand)]
        action: commands::identity::IdentityCmd,
    },
    /// Social recovery wallets (guardian quorum key rotation)
    Recovery {
        #[command(subcommand)]
        action: commands::recovery::RecoveryCmd,
    },
    /// WASM smart contract deployment and calls
    Contract {
        #[command(subcommand)]
        action: commands::contract::ContractCmd,
    },
    /// On-chain governance (stake-weighted proposals to change protocol parameters)
    Governance {
        #[command(subcommand)]
        action: commands::governance::GovernanceCmd,
    },
    /// Validator delegation pool info
    Validator {
        #[command(subcommand)]
        action: commands::validator::ValidatorCmd,
    },
}

/// Dispatch a client command against the node RPC endpoint `node`.
pub async fn run(node: &str, command: Commands) -> Result<()> {
    match command {
        Commands::Wallet { action } => commands::wallet::run(action).await,
        Commands::Chain { action } => commands::chain::run(action, node).await,
        Commands::Account { address } => commands::chain::show_account(&address, node).await,
        Commands::Tx { action } => commands::tx::run(action, node).await,
        Commands::Name { action } => commands::name::run(action, node).await,
        Commands::Identity { action } => commands::identity::run(action, node).await,
        Commands::Recovery { action } => commands::recovery::run(action, node).await,
        Commands::Contract { action } => commands::contract::run(action, node).await,
        Commands::Governance { action } => commands::governance::run(action, node).await,
        Commands::Validator { action } => commands::validator::run(action, node).await,
    }
}
