use std::fmt;

use cxx::SharedPtr;
use pulsevm_serialization::{NumBytes, Read, Write, WriteError};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};

use crate::{
    CxxPublicKey, PermissionLevel,
    bridge::ffi::{Authority, KeyWeight, PermissionLevelWeight, WaitWeight},
};

impl Authority {
    pub fn new(
        threshold: u32,
        keys: Vec<KeyWeight>,
        accounts: Vec<PermissionLevelWeight>,
        waits: Vec<WaitWeight>,
    ) -> Self {
        Authority {
            threshold,
            keys,
            accounts,
            waits,
        }
    }

    pub fn new_from_public_key(key: SharedPtr<CxxPublicKey>) -> Self {
        Authority {
            threshold: 1,
            keys: vec![KeyWeight::new(key, 1)],
            accounts: Vec::new(),
            waits: Vec::new(),
        }
    }

    pub fn new_from_permission_level(permission_level: &PermissionLevel) -> Self {
        Authority {
            threshold: 1,
            keys: Vec::new(),
            accounts: vec![PermissionLevelWeight::new(permission_level.clone(), 1)],
            waits: Vec::new(),
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn keys(&self) -> &Vec<KeyWeight> {
        &self.keys
    }

    pub fn accounts(&self) -> &Vec<PermissionLevelWeight> {
        &self.accounts
    }

    pub fn waits(&self) -> &Vec<WaitWeight> {
        &self.waits
    }

    pub fn validate(&self) -> bool {
        return true;
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Authority(threshold: {}, keys: {:?}, accounts: {:?}, waits: {:?})",
            self.threshold, self.keys, self.accounts, self.waits
        )
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("threshold", &self.threshold)
            .field("keys", &self.keys)
            .field("accounts", &self.accounts)
            .field("waits", &self.waits)
            .finish()
    }
}

impl NumBytes for Authority {
    fn num_bytes(&self) -> usize {
        self.threshold.num_bytes()
            + self.keys.num_bytes()
            + self.accounts.num_bytes()
            + self.waits.num_bytes()
    }
}

impl Read for Authority {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let threshold = u32::read(bytes, pos)?;
        let keys = Vec::<KeyWeight>::read(bytes, pos)?;
        let accounts = Vec::<PermissionLevelWeight>::read(bytes, pos)?;
        let waits = Vec::<WaitWeight>::read(bytes, pos)?;
        Ok(Authority {
            threshold,
            keys,
            accounts,
            waits,
        })
    }
}

impl Write for Authority {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        self.threshold.write(bytes, pos)?;
        self.keys.write(bytes, pos)?;
        self.accounts.write(bytes, pos)?;
        self.waits.write(bytes, pos)?;
        Ok(())
    }
}

impl Serialize for Authority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Authority", 4)?;
        state.serialize_field("threshold", &self.threshold)?;
        state.serialize_field("keys", &self.keys)?;
        state.serialize_field("accounts", &self.accounts)?;
        state.serialize_field("waits", &self.waits)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Authority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["threshold", "keys", "accounts", "waits"];

        enum Field {
            Threshold,
            Keys,
            Accounts,
            Waits,
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
                        f.write_str("`threshold`, `keys`, `accounts`, or `waits`")
                    }

                    fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
                        match value {
                            "threshold" => Ok(Field::Threshold),
                            "keys" => Ok(Field::Keys),
                            "accounts" => Ok(Field::Accounts),
                            "waits" => Ok(Field::Waits),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct AuthorityVisitor;

        impl<'de> Visitor<'de> for AuthorityVisitor {
            type Value = Authority;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct Authority")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let threshold = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let keys = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let accounts = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let waits = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                Ok(Authority {
                    threshold,
                    keys,
                    accounts,
                    waits,
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut threshold = None;
                let mut keys = None;
                let mut accounts = None;
                let mut waits = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Threshold => {
                            if threshold.is_some() {
                                return Err(de::Error::duplicate_field("threshold"));
                            }
                            threshold = Some(map.next_value()?);
                        }
                        Field::Keys => {
                            if keys.is_some() {
                                return Err(de::Error::duplicate_field("keys"));
                            }
                            keys = Some(map.next_value()?);
                        }
                        Field::Accounts => {
                            if accounts.is_some() {
                                return Err(de::Error::duplicate_field("accounts"));
                            }
                            accounts = Some(map.next_value()?);
                        }
                        Field::Waits => {
                            if waits.is_some() {
                                return Err(de::Error::duplicate_field("waits"));
                            }
                            waits = Some(map.next_value()?);
                        }
                    }
                }

                Ok(Authority {
                    threshold: threshold.ok_or_else(|| de::Error::missing_field("threshold"))?,
                    keys: keys.ok_or_else(|| de::Error::missing_field("keys"))?,
                    accounts: accounts.ok_or_else(|| de::Error::missing_field("accounts"))?,
                    waits: waits.ok_or_else(|| de::Error::missing_field("waits"))?,
                })
            }
        }

        deserializer.deserialize_struct("Authority", FIELDS, AuthorityVisitor)
    }
}
