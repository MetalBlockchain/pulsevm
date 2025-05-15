use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn action_data_size() -> impl Fn(Caller<'_, WasmContext>) -> i32 {
    |caller| {
        return caller.data().context.get_action().data().len() as i32;
    }
}

pub fn current_receiver() -> impl Fn(Caller<'_, WasmContext>) -> u64 {
    |caller| {
        return caller.data().context.get_receiver().as_u64();
    }
}