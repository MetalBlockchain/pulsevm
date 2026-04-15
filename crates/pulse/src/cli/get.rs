use pulsevm_api_client::PulseVmClient;
use pulsevm_keosd_client::KeosdClient;

use crate::cli::GetSubcommand;

pub async fn handle(
    api_client: &PulseVmClient,
    _client: &KeosdClient,
    subcmd: GetSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        GetSubcommand::Info => {
            let info = api_client.get_info().await?;
            let json = serde_json::to_string_pretty(&info)?;
            println!("{}", json);
        }
    }

    Ok(())
}
