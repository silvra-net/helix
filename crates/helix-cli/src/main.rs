mod commands;
mod keyfile;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hlx",
    about = "Helix blockchain CLI",
    version,
    long_about = "Interact with the Helix quantum-secure blockchain.\nManage wallets, query the chain, and submit transactions."
)]
struct Cli {
    /// Node RPC endpoint
    #[arg(long, global = true, default_value = "http://127.0.0.1:8545")]
    node: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let node = cli.node.trim_end_matches('/').to_string();

    match cli.command {
        Commands::Wallet { action } => commands::wallet::run(action).await,
        Commands::Chain { action } => commands::chain::run(action, &node).await,
        Commands::Account { address } => commands::chain::show_account(&address, &node).await,
        Commands::Tx { action } => commands::tx::run(action, &node).await,
        Commands::Name { action } => commands::name::run(action, &node).await,
        Commands::Identity { action } => commands::identity::run(action, &node).await,
        Commands::Recovery { action } => commands::recovery::run(action, &node).await,
    }
}
