use core::fmt;
use std::hash::{Hash, Hasher};

use crate::{CxxPublicKey, bridge::ffi};

impl CxxPublicKey {
    pub fn packed_bytes(&self) -> Vec<u8> {
        ffi::packed_public_key_bytes(self)
    }

    pub fn to_string_rust(&self) -> String {
        ffi::public_key_to_string(self)
    }

    pub fn num_bytes(&self) -> usize {
        ffi::public_key_num_bytes(self)
    }
}

impl PartialEq for CxxPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == 0
    }
}

impl Eq for CxxPublicKey {}

impl Hash for CxxPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.packed_bytes().hash(state);
    }
}

impl fmt::Display for CxxPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_rust())
    }
}

impl fmt::Debug for CxxPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_rust())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_public_key_display() {
        let public_key = crate::parse_public_key("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H").unwrap();
        let s = public_key.to_string();
        assert_eq!(s, "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H");
    }

    #[test]
    fn test_public_key_equality() {
        let public_key1 = crate::parse_public_key("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H").unwrap();
        let public_key2 = crate::parse_public_key("PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H").unwrap();
        assert_eq!(public_key1, public_key2);
    }
}