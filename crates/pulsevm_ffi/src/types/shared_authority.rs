use crate::{
    Authority,
    bridge::ffi::{
        CxxSharedAuthority,
        get_authority_from_shared_authority,
    },
    database::native_authority,
};

impl CxxSharedAuthority {
    pub fn to_authority(&self) -> Authority {
        // Keys read out of chainbase are always well-formed, so the re-parse in
        // native_authority cannot fail here.
        native_authority(&get_authority_from_shared_authority(self))
            .expect("chainbase authority has valid keys")
    }
}
