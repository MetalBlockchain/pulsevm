pub mod create;
pub mod dispatcher;
pub mod get;
pub mod set;
pub mod wallet;

use clap::{Parser, Subcommand};

use crate::logging::LogLevel;

#[derive(Parser, Debug)]
#[command(name = "cleos", version, about, long_about = None)]
pub struct Cli {
    /// URL of the nodeos RPC endpoint
    #[arg(short, long, global = true)]
    pub url: Option<String>,

    /// URL of the keosd wallet endpoint
    #[arg(long, global = true)]
    pub wallet_url: Option<String>,

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
    /// Interact with local wallet
    Wallet {
        #[command(subcommand)]
        subcmd: WalletSubcommand,
    },
    /// Get blockchain information
    Get {
        #[command(subcommand)]
        subcmd: GetSubcommand,
    },
    /// Set configuration values
    Set {
        #[command(subcommand)]
        subcmd: SetSubcommand,
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
        /// Name of file to write private/public key output to. (Must be set, unless "--to-console" is passed
        #[arg(short, long)]
        file: Option<String>,
        /// Print private/public keys to console
        #[arg(long, default_value_t = false)]
        to_console: bool,
        /// Generate a key using the R1 curve (iPhone), instead of the K1 curve (Bitcoin)
        #[arg(long, default_value_t = false)]
        r1: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum WalletSubcommand {
    /// Create a new wallet locally
    Create {
        /// Wallet name
        #[arg(default_value = "default")]
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
        #[arg(default_value = "default")]
        name: String,
    },

    /// Lock a wallet
    Lock {
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
    },

    /// Lock all wallets
    #[command(name = "lock_all")]
    LockAll,

    /// Unlock a wallet
    Unlock {
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
        /// Wallet password
        #[arg(long)]
        password: Option<String>,
    },

    /// Import a private key into a wallet
    Import {
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
        /// Private key (will prompt if not provided)
        #[arg(long)]
        private_key: Option<String>,
    },

    /// List opened wallets (with * = unlocked)
    List,

    /// List of public keys from all unlocked wallets
    Keys {
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
        /// Password to unlock wallet (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,
    },

    /// Remove a key from a wallet
    #[command(name = "remove_key")]
    RemoveKey {
        /// Public key to remove
        key: String,
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
        /// Password to unlock wallet (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,
    },

    /// Create a key within a wallet
    #[command(name = "create_key")]
    CreateKey {
        /// Wallet name
        #[arg(default_value = "default")]
        name: String,
        /// Key type (K1 or R1)
        #[arg(default_value = "K1")]
        key_type: String,
    },

    /// Stop keosd (doesn't work with nodeos-based wallet plugin)
    Stop,
}

#[derive(Subcommand, Debug)]
pub enum GetSubcommand {
    /// Get blockchain information
    Info,
}

#[derive(Subcommand, Debug)]
pub enum SetSubcommand {
    /// Set blockchain information
    Url {
        /// URL of the RPC endpoint
        url: String,
    },
}