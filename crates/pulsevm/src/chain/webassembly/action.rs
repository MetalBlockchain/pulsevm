use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn action_data_size() -> impl Fn(Caller<'_, WasmContext>) -> Result<i32, wasmtime::Error> {
    |caller| {
        return Ok(caller.data().action().data().len() as i32);
    }
}

pub fn current_receiver() -> impl Fn(Caller<'_, WasmContext>) -> Result<u64, wasmtime::Error> {
    |caller| {
        return Ok(caller.data().receiver().as_u64());
    }
}
