use std::fmt;

use pulsevm_billable_size::BillableSize;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};

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

impl<'de> Deserialize<'de> for WaitWeight {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["wait_sec", "weight"];

        enum Field {
            WaitSec,
            Weight,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("`wait_sec` or `weight`")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
                        match value {
                            "wait_sec" => Ok(Field::WaitSec),
                            "weight" => Ok(Field::Weight),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct WaitWeightVisitor;

        impl<'de> Visitor<'de> for WaitWeightVisitor {
            type Value = WaitWeight;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct WaitWeight")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let wait_sec = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let weight = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(WaitWeight { wait_sec, weight })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut wait_sec = None;
                let mut weight = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::WaitSec => {
                            if wait_sec.is_some() {
                                return Err(de::Error::duplicate_field("wait_sec"));
                            }
                            wait_sec = Some(map.next_value()?);
                        }
                        Field::Weight => {
                            if weight.is_some() {
                                return Err(de::Error::duplicate_field("weight"));
                            }
                            weight = Some(map.next_value()?);
                        }
                    }
                }

                Ok(WaitWeight {
                    wait_sec: wait_sec.ok_or_else(|| de::Error::missing_field("wait_sec"))?,
                    weight: weight.ok_or_else(|| de::Error::missing_field("weight"))?,
                })
            }
        }

        deserializer.deserialize_struct("WaitWeight", FIELDS, WaitWeightVisitor)
    }
}

impl BillableSize for WaitWeight {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = 16;
}
