#[cxx::bridge(namespace = "pulsevm::chain")]
mod iterator_cache {
    unsafe extern "C++" {
        include!("iterator_cache.hpp");

        #[cxx_name = "key_value_iterator_cache"]
        pub type KeyValueIteratorCache;
        pub fn new_key_value_iterator_cache() -> UniquePtr<KeyValueIteratorCache>;
    }
}

pub struct KeyValueIteratorCache {
    inner: cxx::UniquePtr<iterator_cache::KeyValueIteratorCache>,
}

impl KeyValueIteratorCache {
    pub fn new() -> Self {
        let inner = iterator_cache::new_key_value_iterator_cache();
        KeyValueIteratorCache { inner }
    }
}