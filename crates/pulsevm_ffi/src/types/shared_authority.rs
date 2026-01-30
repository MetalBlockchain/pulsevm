use crate::{
    Authority,
    bridge::ffi::{CxxSharedAuthority, get_authority_from_shared_authority},
};

impl CxxSharedAuthority {
    pub fn to_authority(&self) -> Authority {
        get_authority_from_shared_authority(self)
    }
}
