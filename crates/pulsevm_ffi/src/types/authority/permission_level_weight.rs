use std::fmt;

use pulsevm_billable_size::BillableSize;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};

use crate::bridge::ffi::{PermissionLevel, PermissionLevelWeight};

impl PermissionLevelWeight {
    pub fn new(permission: PermissionLevel, weight: u16) -> Self {
        PermissionLevelWeight { permission, weight }
    }
}

impl fmt::Debug for PermissionLevelWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermissionLevelWeight")
            .field("permission", &self.permission)
            .field("weight", &self.weight)
            .finish()
    }
}

impl NumBytes for PermissionLevelWeight {
    fn num_bytes(&self) -> usize {
        self.permission.num_bytes() + self.weight.num_bytes()
    }
}

impl Read for PermissionLevelWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let permission = PermissionLevel::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        Ok(PermissionLevelWeight { permission, weight })
    }
}

impl Write for PermissionLevelWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.permission.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for PermissionLevelWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionLevelWeight", 2)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PermissionLevelWeight {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["permission", "weight"];

        enum Field {
            Permission,
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
                        f.write_str("`permission` or `weight`")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
                        match value {
                            "permission" => Ok(Field::Permission),
                            "weight" => Ok(Field::Weight),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PermissionLevelWeightVisitor;

        impl<'de> Visitor<'de> for PermissionLevelWeightVisitor {
            type Value = PermissionLevelWeight;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct PermissionLevelWeight")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let permission = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let weight = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(PermissionLevelWeight { permission, weight })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut permission = None;
                let mut weight = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Permission => {
                            if permission.is_some() {
                                return Err(de::Error::duplicate_field("permission"));
                            }
                            permission = Some(map.next_value()?);
                        }
                        Field::Weight => {
                            if weight.is_some() {
                                return Err(de::Error::duplicate_field("weight"));
                            }
                            weight = Some(map.next_value()?);
                        }
                    }
                }

                Ok(PermissionLevelWeight {
                    permission: permission.ok_or_else(|| de::Error::missing_field("permission"))?,
                    weight: weight.ok_or_else(|| de::Error::missing_field("weight"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "PermissionLevelWeight",
            FIELDS,
            PermissionLevelWeightVisitor,
        )
    }
}

impl BillableSize for PermissionLevelWeight {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = 24;
}
