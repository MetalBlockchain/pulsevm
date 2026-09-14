mod index128_object;
mod index256_object;
mod index64_object;
mod index_double_object;
mod index_long_double_object;
mod key_value_object;
mod permission_object;
mod table_object;

pub use index_double_object::IndexDoubleObject;
pub use index_long_double_object::IndexLongDoubleObject;
pub use index64_object::Index64Object;
pub use index128_object::Index128Object;
pub use index256_object::Index256Object;
pub use key_value_object::KeyValueObject;
pub use permission_object::{
    PermissionObject,
    SharedAuthority,
};
pub use table_object::TableObject;

#[cfg(test)]
mod tests {
    use pulsevm_billable_size::{
        BillableSize,
        billable_size_v,
    };

    use super::{
        Index64Object,
        Index128Object,
        Index256Object,
        IndexDoubleObject,
        IndexLongDoubleObject,
        KeyValueObject,
        TableObject,
    };

    #[test]
    fn contract_database_billable_sizes_match_chainbase() {
        assert_eq!(billable_size_v::<TableObject>(), 112);
        assert_eq!(billable_size_v::<KeyValueObject>(), 112);

        // Secondary rows have three chainbase indices. Referencing the primary
        // row's two-index overhead underbills every secondary row by 32 bytes.
        assert_eq!(Index64Object::OVERHEAD, 96);
        assert_eq!(Index128Object::OVERHEAD, 96);
        assert_eq!(Index256Object::OVERHEAD, 96);
        assert_eq!(IndexDoubleObject::OVERHEAD, 96);
        assert_eq!(IndexLongDoubleObject::OVERHEAD, 96);
        assert_eq!(billable_size_v::<Index64Object>(), 128);
        assert_eq!(billable_size_v::<Index128Object>(), 144);
        assert_eq!(billable_size_v::<Index256Object>(), 160);
        assert_eq!(billable_size_v::<IndexDoubleObject>(), 128);
        assert_eq!(billable_size_v::<IndexLongDoubleObject>(), 144);
    }
}
