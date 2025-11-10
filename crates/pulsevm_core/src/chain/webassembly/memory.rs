use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn memcpy() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, dest, src, length| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        // Read source bytes safely
        let mut src_bytes = vec![0u8; length as usize];
        memory.read(&caller, src as usize, &mut src_bytes)?;

        // Overlap check
        let dest_start = dest as isize;
        let src_start = src as isize;
        if (dest_start - src_start).abs() < length as isize {
            anyhow::bail!("memcpy requires non-overlapping memory regions");
        }

        // Write bytes safely to dest
        memory.write(&mut caller, dest as usize, &src_bytes)?;

        Ok(dest) // Return destination pointer like EOS does
    }
}

pub fn memmove() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error>
{
    |mut caller, dest, src, length| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        // Read source bytes safely
        let mut src_bytes = vec![0u8; length as usize];
        memory.read(&caller, src as usize, &mut src_bytes)?;

        // Write bytes safely to dest
        memory.write(&mut caller, dest as usize, &src_bytes)?;

        Ok(dest) // Return destination pointer like EOS does
    }
}

pub fn memcmp() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<i32, wasmtime::Error> {
    |mut caller, lhs, rhs, length| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let len = length as usize;
        let mut lhs_bytes = vec![0u8; len];
        memory.read(&caller, lhs as usize, &mut lhs_bytes)?;
        let mut rhs_bytes = vec![0u8; len];
        memory.read(&caller, rhs as usize, &mut rhs_bytes)?;

        let result = match lhs_bytes.cmp(&rhs_bytes) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };

        Ok(result) // Return destination pointer like EOS does
    }
}

pub fn memset() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, dest, value, length| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let len = length as usize;
        let val = value as u8;
        let fill = vec![val; len];

        memory.write(&mut caller, dest as usize, &fill)?;

        Ok(dest)
    }
}
