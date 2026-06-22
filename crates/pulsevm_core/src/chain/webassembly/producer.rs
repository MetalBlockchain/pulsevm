use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{chain::webassembly::context_aware_check, wasm_runtime::WasmContext};

pub fn get_active_producers(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
    // TODO: Implement get_active_producers logic
    Ok(0)
}
