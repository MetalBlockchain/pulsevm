use crate::cli::{Cli, Commands, create};

pub async fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Create { subcmd } => create::handle(subcmd).await?,
    }

    Ok(())
}