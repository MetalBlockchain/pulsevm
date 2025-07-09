use anyhow::anyhow;
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn action_data_size() -> impl Fn(Caller<'_, WasmContext>) -> Result<i32, wasmtime::Error> {
    |caller| {
        let context = caller.data().context.borrow();
        return Ok(context.get_action().data().len() as i32);
    }
}

pub fn current_receiver() -> impl Fn(Caller<'_, WasmContext>) -> Result<u64, wasmtime::Error> {
    |caller| {
        let context = caller
            .data()
            .context
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        return Ok(context.get_receiver().as_u64());
    }
}
