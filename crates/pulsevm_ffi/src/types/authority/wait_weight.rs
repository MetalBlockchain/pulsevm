use std::fmt;

use pulsevm_billable_size::BillableSize;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{Serialize, ser::SerializeStruct};

use crate::bridge::ffi::WaitWeight;

impl fmt::Debug for WaitWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitWeight")
            .field("wait_sec", &self.wait_sec)
            .field("weight", &self.weight)
            .finish()
    }
}

impl NumBytes for WaitWeight {
    fn num_bytes(&self) -> usize {
        self.wait_sec.num_bytes() + self.weight.num_bytes()
    }
}

impl Read for WaitWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let wait_sec = u32::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        Ok(WaitWeight { wait_sec, weight })
    }
}

impl Write for WaitWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.wait_sec.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for WaitWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("WaitWeight", 2)?;
        state.serialize_field("wait_sec", &self.wait_sec)?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl BillableSize for WaitWeight {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = 16;
}