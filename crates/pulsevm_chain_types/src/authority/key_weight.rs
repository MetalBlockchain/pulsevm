use std::fmt;

use pulsevm_billable_size::BillableSize;
use pulsevm_crypto::{
    FixedBytes,
    k1::K1PublicKey,
};
use pulsevm_serialization::{
    NumBytes,
    Read,
    Write,
    WriteError,
};
use serde::{
    Deserialize,
    Serialize,
    de::{
        self,
        MapAccess,
        SeqAccess,
        Visitor,
    },
    ser::SerializeStruct,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyWeight {
    pub key: K1PublicKey,
    pub weight: u16,
}

impl KeyWeight {
    pub fn new(key: K1PublicKey, weight: u16) -> Self {
        KeyWeight { key, weight }
    }
}

impl fmt::Debug for KeyWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWeight")
            .field("key", &self.key.to_string())
            .field("weight", &self.weight)
            .finish()
    }
}

impl NumBytes for KeyWeight {
    fn num_bytes(&self) -> usize {
        // Add the number of bytes for the packed public key and the weight
        34 + self.weight.num_bytes()
    }
}

impl Read for KeyWeight {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let packed_key = FixedBytes::<34>::read(bytes, pos)?;
        let key = K1PublicKey::from_packed(packed_key.as_ref()).map_err(|e| {
            pulsevm_serialization::ReadError::CustomError(format!(
                "failed to parse public key in KeyWeight: {}",
                e
            ))
        })?;
        let weight = u16::read(bytes, pos)?;
        Ok(KeyWeight { key, weight })
    }
}

impl Write for KeyWeight {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed_key = FixedBytes::<34>(self.key.to_packed());
        packed_key.write(bytes, pos)?;
        self.weight.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for KeyWeight {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("KeyWeight", 2)?;
        state.serialize_field("key", &self.key.to_string())?;
        state.serialize_field("weight", &self.weight)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KeyWeight {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["key", "weight"];

        enum Field {
            Key,
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
                        f.write_str("`key` or `weight`")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
                        match value {
                            "key" => Ok(Field::Key),
                            "weight" => Ok(Field::Weight),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct KeyWeightVisitor;

        impl<'de> Visitor<'de> for KeyWeightVisitor {
            type Value = KeyWeight;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct KeyWeight")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let key_str: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let weight = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let key = K1PublicKey::from_string(&key_str)
                    .map_err(|e| de::Error::custom(format!("invalid public key: {}", e)))?;

                Ok(KeyWeight { key, weight })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut key: Option<String> = None;
                let mut weight = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::Weight => {
                            if weight.is_some() {
                                return Err(de::Error::duplicate_field("weight"));
                            }
                            weight = Some(map.next_value()?);
                        }
                    }
                }

                let key_str = key.ok_or_else(|| de::Error::missing_field("key"))?;
                let key = K1PublicKey::from_string(&key_str)
                    .map_err(|e| de::Error::custom(format!("invalid public key: {}", e)))?;
                let weight = weight.ok_or_else(|| de::Error::missing_field("weight"))?;

                Ok(KeyWeight { key, weight })
            }
        }

        deserializer.deserialize_struct("KeyWeight", FIELDS, KeyWeightVisitor)
    }
}

impl BillableSize for KeyWeight {
    const OVERHEAD: u64 = 0;
    const VALUE: u64 = 8;
}
