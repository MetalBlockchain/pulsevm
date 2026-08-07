use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::{
    chain::webassembly::context_aware_check,
    wasm_runtime::WasmContext,
};

pub fn get_active_producers(
    mut env: FunctionEnvMut<WasmContext>,
    _data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::PRODUCER + cost::per_byte(data_len as u64))?;
    // TODO: Implement get_active_producers logic
    Ok(0)
}
