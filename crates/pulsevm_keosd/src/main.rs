mod api;
mod cli;
mod keys;
mod logging;
mod manager;
mod wallet;

use std::{path::PathBuf, sync::Mutex};

use actix_web::{App, HttpServer, middleware, web};
use clap::Parser;
use spdlog::{error, info};

use crate::cli::Cli;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    logging::init(cli.log_level);

    // Resolve data directory
    let data_dir = match cli.data_dir {
        Some(ref d) => PathBuf::from(d),
        None => dirs_or_default(),
    };

    // Resolve wallet directory
    let wallet_dir = if let Some(ref data_dir) = cli.data_dir {
        let base = PathBuf::from(data_dir);
        if cli.wallet_dir == "." {
            base
        } else {
            base.join(&cli.wallet_dir)
        }
    } else {
        let default_dir = dirs_or_default();
        if cli.wallet_dir == "." {
            default_dir
        } else {
            PathBuf::from(&cli.wallet_dir)
        }
    };

    let manager = manager::WalletManager::new(wallet_dir, cli.unlock_timeout)
        .expect("Failed to initialize wallet manager");
    let state = web::Data::new(api::AppState {
        manager: Mutex::new(manager),
    });

    let mut server = HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(web::JsonConfig::default().limit(cli.max_body_size))
            .wrap(middleware::Logger::default())
            .configure(api::configure_routes)
    })
    .workers(1);

    // Bind Unix socket (default behavior, like original keosd)
    let has_uds = if !cli.unix_socket_path.is_empty() {
        let sock_path = if PathBuf::from(&cli.unix_socket_path).is_absolute() {
            PathBuf::from(&cli.unix_socket_path)
        } else {
            data_dir.join(&cli.unix_socket_path)
        };

        // Remove stale socket file if it exists
        if sock_path.exists() {
            std::fs::remove_file(&sock_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Binding Unix socket: {}", sock_path.display());
        server = server.bind_uds(&sock_path)?;
        true
    } else {
        false
    };

    // Bind TCP if specified
    let has_tcp = if !cli.http_server_address.is_empty() {
        info!("Binding TCP: {}", cli.http_server_address);
        server = server.bind(&cli.http_server_address)?;
        true
    } else {
        false
    };

    if !has_uds && !has_tcp {
        error!("No listeners configured. Set --unix-socket-path and/or --http-server-address.");
        std::process::exit(1);
    }

    server.run().await
}

/// Default wallet directory: ~/pulse-wallet
fn dirs_or_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join("pulse-wallet")
    } else {
        PathBuf::from("./pulse-wallet")
    }
}
