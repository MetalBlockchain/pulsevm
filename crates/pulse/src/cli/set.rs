use std::{str::FromStr, sync::Arc};

use pulsevm_api_client::PulseVmClient;
use pulsevm_core::{
    ACTIVE_NAME, PULSE_NAME, abi::AbiDefinition, authority::PermissionLevel, config::{SETABI_NAME, SETCODE_NAME}, name::Name, pulse_contract::{SetAbi, SetCode}, transaction::Action
};
use pulsevm_crypto::Bytes;
use pulsevm_keosd_client::KeosdClient;
use pulsevm_serialization::Write;

use crate::{cli::SetSubcommand, config::Config, utils::push_actions};

const BINARY_WASM_HEADER: &[u8] = b"\x00\x61\x73\x6d\x01\x00\x00\x00";

pub async fn handle(
    api_client: &PulseVmClient,
    config: &mut Config,
    keosd_client: &KeosdClient,
    subcmd: SetSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        SetSubcommand::Url { url } => {
            config.rpc_url = url.clone();
            config.save()?;
        }
        SetSubcommand::Code {
            account,
            wasm_path,
            clear,
        } => {
            let account = Name::from_str(&account)?;
            let mut code_bytes = Bytes::default();

            if !clear {
                println!("Reading WASM from {}...", wasm_path);
                let wasm = std::fs::read(&wasm_path)
                    .map_err(|e| format!("failed to read wasm file {}: {}", wasm_path, e))?;

                if wasm.is_empty() {
                    return Err(format!("no wasm file found {}", wasm_path).into());
                }

                if wasm.len() < 8 || &wasm[..8] != BINARY_WASM_HEADER {
                    eprintln!(
                        "WARNING: {} doesn't look like a binary WASM file. Is it something else, like WAST? Trying anyway...",
                        wasm_path
                    );
                }

                code_bytes = Bytes::new(wasm);
            }

            let response = push_actions(
                api_client,
                keosd_client,
                vec![Action {
                    account: PULSE_NAME,
                    name: SETCODE_NAME,
                    authorization: vec![PermissionLevel {
                        actor: account.into(),
                        permission: ACTIVE_NAME.into(),
                    }],
                    data: SetCode {
                        account: account.into(),
                        vm_type: 0,
                        vm_version: 0,
                        code: Arc::new(code_bytes),
                    }
                    .try_into()?,
                }],
            )
            .await?;

            println!("Updated code for {}: {}", account, response);
        }
        SetSubcommand::ABI {
            account,
            abi_path,
            clear,
        } => {
            let account = Name::from_str(&account)?;
            let mut abi_bytes = Bytes::default();

            if !clear {
                println!("Reading ABI from {}...", abi_path);
                let abi = std::fs::read(&abi_path)
                    .map_err(|e| format!("failed to read abi file {}: {}", abi_path, e))?;

                if abi.is_empty() {
                    return Err(format!("no abi file found {}", abi_path).into());
                }

                let abi: AbiDefinition = serde_json::from_slice(&abi)
                    .map_err(|e| format!("failed to parse abi file {}: {}", abi_path, e))?;

                abi_bytes = Bytes::new(abi.pack()?);
            }

            let response = push_actions(
                api_client,
                keosd_client,
                vec![Action {
                    account: PULSE_NAME,
                    name: SETABI_NAME,
                    authorization: vec![PermissionLevel {
                        actor: account.into(),
                        permission: ACTIVE_NAME.into(),
                    }],
                    data: SetAbi {
                        account: account.into(),
                        abi: Arc::new(abi_bytes),
                    }
                    .try_into()?,
                }],
            )
            .await?;

            println!("Updated code for {}: {}", account, response);
        }
    }

    Ok(())
}
