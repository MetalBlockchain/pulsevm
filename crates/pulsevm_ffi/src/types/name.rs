use crate::CxxName;

impl PartialEq for CxxName {
    fn eq(&self, other: &Self) -> bool {
        self.to_uint64_t() == other.to_uint64_t()
    }
}

impl Eq for CxxName {}
