use pulsevm_name::Name;
use wasmer::{FunctionEnvMut, RuntimeError};

use crate::{authorization_manager::AuthorizationManager, wasm_runtime::WasmContext};

pub fn get_permission_last_used(
    env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
) -> Result<i64, RuntimeError> {
    let env_data = env.data();
    let db = env_data.db();
    let permission = AuthorizationManager::get_permission(db, account, permission)?;
    let last_used = db.get_permission_last_used(permission)?;
    Ok(last_used.time_since_epoch().count())
}