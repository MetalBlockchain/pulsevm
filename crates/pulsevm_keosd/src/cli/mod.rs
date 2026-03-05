use clap::Parser;

use crate::logging::LogLevel;

#[derive(Parser, Debug)]
#[command(name = "keosd", version, about, long_about = None)]
pub struct Cli {
    /// Logging verbosity
    #[arg(long, default_value = "info", global = true, value_enum)]
    pub log_level: LogLevel,

    /// The maximum body size in bytes allowed for incoming RPC requests.
    #[arg(long, default_value = "1048576")]
    pub max_body_size: usize,

    /// Timeout for unlocked wallet in seconds (default 900 = 15 minutes).
    /// Set to 0 to always lock immediately.
    #[arg(long, default_value = "900")]
    pub unlock_timeout: u64,

    /// The path of the wallet files (absolute path or relative to data dir).
    #[arg(long, default_value = ".")]
    pub wallet_dir: String,

    /// The application data directory.
    #[arg(long)]
    pub data_dir: Option<String>,

    /// The local IP and port to listen for incoming HTTP connections.
    /// Leave blank to disable TCP listening.
    #[arg(long, default_value = "")]
    pub http_server_address: String,

    /// The filename (relative to data-dir) to create a Unix socket for HTTP RPC;
    /// set blank to disable.
    #[arg(long, default_value = "pulse-keosd.sock")]
    pub unix_socket_path: String,
}