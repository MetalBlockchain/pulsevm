pub mod create;
pub mod dispatcher;

use clap::{Parser, Subcommand};

use crate::logging::LogLevel;

#[derive(Parser, Debug)]
#[command(name = "cleos", version, about, long_about = None)]
pub struct Cli {
    /// URL of the nodeos RPC endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:8888", global = true)]
    pub url: String,

    /// Logging verbosity
    #[arg(long, default_value = "info", global = true, value_enum)]
    pub log_level: LogLevel,

    /// Output as JSON
    #[arg(short, long, global = true)]
    pub json: bool,

    /// Don't verify peer certificate
    #[arg(long, global = true)]
    pub no_verify: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create various items, on and off the blockchain
    Create {
        #[command(subcommand)]
        subcmd: CreateSubcommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum CreateSubcommand {
    /// Create a new account on the blockchain
    Account {
        /// Creator account
        creator: String,
        /// New account name
        name: String,
        /// Owner public key
        owner_key: String,
        /// Active public key (defaults to owner key)
        active_key: Option<String>,
    },
    /// Create a new keypair and print the public and private keys
    Key {
        /// Key type (K1 or R1)
        #[arg(long, default_value = "K1")]
        key_type: String,
        /// Save keys to file
        #[arg(long)]
        to_console: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletSubcommand {
    /// Create a new wallet locally
    Create {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Save password to file
        #[arg(long)]
        to_console: bool,
        /// File to save password
        #[arg(short, long)]
        file: Option<String>,
    },

    /// Open an existing wallet
    Open {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },

    /// Lock a wallet
    Lock {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },

    /// Lock all wallets
    #[command(name = "lock_all")]
    LockAll,

    /// Unlock a wallet
    Unlock {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Wallet password
        #[arg(long)]
        password: Option<String>,
    },

    /// Import a private key into a wallet
    Import {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Private key (will prompt if not provided)
        #[arg(long)]
        private_key: Option<String>,
    },

    /// List opened wallets (with * = unlocked)
    List,

    /// List of public keys from all unlocked wallets
    Keys,

    /// Remove a key from a wallet
    #[command(name = "remove_key")]
    RemoveKey {
        /// Public key to remove
        key: String,
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
    },

    /// Create a key within a wallet
    #[command(name = "create_key")]
    CreateKey {
        /// Wallet name
        #[arg(short, long, default_value = "default")]
        name: String,
        /// Key type (K1 or R1)
        #[arg(default_value = "K1")]
        key_type: String,
    },

    /// Stop keosd (doesn't work with nodeos-based wallet plugin)
    Stop,
}