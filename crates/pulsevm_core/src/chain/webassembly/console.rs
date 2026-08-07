use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::wasm_runtime::WasmContext;

// TODO: Implement console functions to log output from WASM modules. For now, these functions are
// no-ops to avoid unnecessary overhead in the current implementation.

pub fn prints(
    mut env: FunctionEnvMut<WasmContext>,
    _msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

pub fn prints_l(
    mut env: FunctionEnvMut<WasmContext>,
    _msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE + cost::per_byte(msg_len as u64))?;
    Ok(())
}

#[inline]
pub fn printi(mut env: FunctionEnvMut<WasmContext>, _val: i64) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printui(mut env: FunctionEnvMut<WasmContext>, _val: u64) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printi128(
    mut env: FunctionEnvMut<WasmContext>,
    _val: WasmPtr<i128>,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printui128(
    mut env: FunctionEnvMut<WasmContext>,
    _val: WasmPtr<u128>,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printsf(mut env: FunctionEnvMut<WasmContext>, _val: f32) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printdf(mut env: FunctionEnvMut<WasmContext>, _val: f64) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printqf(mut env: FunctionEnvMut<WasmContext>, _data_ptr: u32) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printn(mut env: FunctionEnvMut<WasmContext>, _val: u64) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE)?;
    Ok(())
}

#[inline]
pub fn printhex(
    mut env: FunctionEnvMut<WasmContext>,
    _data_ptr: u32,
    data_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::CONSOLE + cost::per_byte(data_len as u64))?;
    Ok(())
}
