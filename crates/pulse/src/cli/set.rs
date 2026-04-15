use pulsevm_api_client::PulseVmClient;
use pulsevm_keosd_client::KeosdClient;

use crate::{cli::SetSubcommand, config::Config};

pub async fn handle(
    _api_client: &PulseVmClient,
    config: &mut Config,
    _client: &KeosdClient,
    subcmd: SetSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        SetSubcommand::Url { url } => {
            config.rpc_url = url.clone();
            config.save()?;
        }
    }

    Ok(())
}
