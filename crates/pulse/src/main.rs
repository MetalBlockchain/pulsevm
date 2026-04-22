mod cli;
mod config;
mod logging;
mod utils;

use clap::Parser;
use spdlog::error;

use crate::cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    logging::init(cli.log_level);

    if let Err(e) = cli::dispatcher::execute(cli).await {
        error!("error executing command: {}", e);
        std::process::exit(1);
    }
}
