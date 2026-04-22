use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// URL of the RPC endpoint
    pub rpc_url: String,
}

impl Config {
    pub fn save(&self) -> anyhow::Result<()> {
        save_config(self)
    }
}

fn config_path() -> anyhow::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home.join(".pulse-cli").join("config.json"))
}

pub fn load_or_create_config() -> anyhow::Result<Config> {
    let path = config_path()?;

    if !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap())?;

        let default = Config {
            rpc_url: "http://localhost:8080".to_string(),
        };

        let json = serde_json::to_string_pretty(&default)?;
        std::fs::write(&path, json)?;
        println!("Created default config at {}", path.display());
        return Ok(default);
    }

    let contents = std::fs::read_to_string(&path)?;
    let config: Config = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn save_config(config: &Config) -> anyhow::Result<()> {
    let path = config_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, json)?;
    Ok(())
}
