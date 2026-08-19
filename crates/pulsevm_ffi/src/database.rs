use std::{
    fs,
    io::{
        Read,
        Seek,
        SeekFrom,
        Write,
    },
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        RwLock,
        RwLockWriteGuard,
    },
};

use cxx::UniquePtr;
use pulsevm_error::ChainError;
use pulsevm_name::Name;

use crate::{
    ChainConfigV0,
    Float128,
    Index64IteratorCache,
    Index128IteratorCache,
    IndexDoubleIteratorCache,
    IndexLongDoubleIteratorCache,
    IndexLongDoubleObject,
    KeyValueObject,
    bridge::ffi::{
        self,
        Authority,
        CxxDigest,
        CxxGenesisState,
        ElasticLimitParameters,
        Index64Object,
        Index128Object,
        Index256Object,
        IndexDoubleObject,
        TableObject,
        TimePoint,
        U128,
        U256,
        get_account_info_with_core_symbol,
        get_account_info_without_core_symbol,
        get_currency_balance_with_symbol,
        get_currency_balance_without_symbol,
        get_currency_stats,
        get_table_by_scope,
        get_table_rows,
    },
    iterator_cache::{
        Index256IteratorCache,
        KeyValueIteratorCache,
    },
};

/// Field-for-field snapshot of an `account_metadata_object` read back from the
/// arena mirror, matching the chainbase accessors used to diff it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaAccountMetadata {
    pub privileged: bool,
    pub recv_sequence: u64,
    pub auth_sequence: u64,
    pub code_sequence: u64,
    pub abi_sequence: u64,
    pub code_hash: [u8; 32],
    pub vm_type: u8,
    pub vm_version: u8,
}

/// Copies a chainbase `digest_type` (sha256) into a fixed 32-byte array for the
/// arena mirror. A digest that is not 32 bytes is zero-padded/truncated, which
/// only degrades the mirror's fidelity, never chainbase.
#[cfg(feature = "arena-shadow")]
fn digest_to_array(digest: &CxxDigest) -> [u8; 32] {
    let data = ffi::get_digest_data(digest);
    let mut out = [0u8; 32];
    let n = data.len().min(32);
    out[..n].copy_from_slice(&data[..n]);
    out
}

/// Converts the FFI elastic-limit parameters into the plain form the arena
/// mirror needs to run its own `update_elastic_limit`.
#[cfg(feature = "arena-shadow")]
fn to_elastic_params(p: &ElasticLimitParameters) -> crate::shadow::ElasticParams {
    crate::shadow::ElasticParams {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract: (p.contract_rate.numerator, p.contract_rate.denominator),
        expand: (p.expand_rate.numerator, p.expand_rate.denominator),
    }
}

/// Serializes an [`Authority`] into the deterministic byte layout the arena
/// mirror stores for `permission_object::auth` (a `shared_authority`). The exact
/// encoding is private to the mirror; it only has to be stable so equal
/// authorities hash equal.
#[cfg(feature = "arena-shadow")]
fn encode_authority(auth: &Authority) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&auth.threshold.to_le_bytes());
    out.extend_from_slice(&(auth.keys.len() as u32).to_le_bytes());
    for k in &auth.keys {
        let bytes = match k.key.as_ref() {
            Some(pk) => ffi::packed_public_key_bytes(pk),
            None => Vec::new(),
        };
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
        out.extend_from_slice(&k.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.accounts.len() as u32).to_le_bytes());
    for a in &auth.accounts {
        out.extend_from_slice(&a.permission.actor.to_le_bytes());
        out.extend_from_slice(&a.permission.permission.to_le_bytes());
        out.extend_from_slice(&a.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.waits.len() as u32).to_le_bytes());
    for w in &auth.waits {
        out.extend_from_slice(&w.wait_sec.to_le_bytes());
        out.extend_from_slice(&w.weight.to_le_bytes());
    }
    out
}

/// The `(code, scope, table)` triple of a contract table, packed into `u64`s for
/// the arena mirror, which keys its contract-table rows by this triple.
#[cfg(feature = "arena-shadow")]
fn table_key(table: &TableObject) -> (u64, u64, u64) {
    (
        table.get_code().to_uint64_t(),
        table.get_scope().to_uint64_t(),
        table.get_table().to_uint64_t(),
    )
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<RwLock<UniquePtr<ffi::Database>>>,
    /// The directory and size the arena was opened with, kept so a snapshot can
    /// close the mapping, copy `shared_memory.bin`, and remap at the same path
    /// without threading the config back down from the controller.
    path: String,
    size: u64,
    /// The native pulsevm_arena mirror, shared across clones. Carried here so
    /// writes reach it through the same handle every apply/transaction context
    /// already uses (see `shadow.rs`). Only present in arena-shadow builds.
    #[cfg(feature = "arena-shadow")]
    shadow: Option<crate::shadow::ArenaShadow>,
}

/// chainbase's single memory-mapped arena file, relative to the database dir.
const SHARED_MEMORY_FILE: &str = "shared_memory.bin";

/// Wire width used only at the CXX boundary: digest followed by a LE block
/// number. The public API below immediately converts this into typed tuples.
const ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE: usize = 32 + std::mem::size_of::<u32>();

fn decode_activated_protocol_features(bytes: &[u8]) -> Result<Vec<([u8; 32], u32)>, ChainError> {
    if bytes.len() % ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE != 0 {
        return Err(ChainError::InternalError(format!(
            "invalid activated protocol feature payload length {}; expected a multiple of {}",
            bytes.len(),
            ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE
        )));
    }

    let mut features = Vec::with_capacity(bytes.len() / ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE);
    for record in bytes.chunks_exact(ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE) {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&record[..32]);
        let activation_block_num =
            u32::from_le_bytes([record[32], record[33], record[34], record[35]]);
        features.push((digest, activation_block_num));
    }
    Ok(features)
}

/// Read until `buf` is full or EOF, so each snapshot chunk is a fixed,
/// block-aligned size regardless of how the OS splits the underlying reads —
/// which keeps the sparse run boundaries (and thus the snapshot bytes)
/// deterministic. Returns the number of bytes read (< `buf.len()` only at EOF).
fn fill(f: &mut fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Make an atomic rename durable. Syncing the file alone does not guarantee
/// its containing directory entry survives a power loss on Unix.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

impl Database {
    pub fn new(path: &str, size: u64) -> Result<Self, String> {
        let db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, size)
            .map_err(|e| format!("Failed to open database: {e}"))?;

        if db.is_null() {
            Err("Failed to open database".to_string())
        } else {
            Ok(Database {
                inner: Arc::new(RwLock::new(db)),
                path: path.to_string(),
                size,
                #[cfg(feature = "arena-shadow")]
                shadow: None,
            })
        }
    }

    fn open_with_indices(
        path: &str,
        size: u64,
        operation: &str,
    ) -> Result<UniquePtr<ffi::Database>, ChainError> {
        let mut db = ffi::open_database(path, ffi::DatabaseOpenFlags::ReadWrite, size)
            .map_err(|e| ChainError::InternalError(format!("{operation}: open database: {e}")))?;
        if db.is_null() {
            return Err(ChainError::InternalError(format!(
                "{operation}: open database returned null"
            )));
        }
        db.pin_mut()
            .add_indices()
            .map_err(|e| ChainError::InternalError(format!("{operation}: add indices: {e}")))?;
        Ok(db)
    }

    // ----- arena shadow (differential testing; no-ops without the feature) ---

    /// Attaches a fresh arena mirror at chainbase's current revision. Every
    /// clone of this handle then shares it, so ported writes are mirrored.
    pub fn enable_shadow(&mut self) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let shadow = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena shadow init: {e:?}")))?;
            shadow
                .set_revision(self.revision())
                .map_err(|e| ChainError::InternalError(format!("arena set_revision: {e:?}")))?;
            self.shadow = Some(shadow);
        }
        Ok(())
    }

    /// The arena mirror's account_metadata privileged flag for `name`, or
    /// `None` if the mirror has no such row / shadowing is off — for diffing
    /// against chainbase's `find_account_metadata`.
    pub fn arena_account_metadata_privileged(&self, name: u64) -> Option<bool> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_metadata_privileged(name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            None
        }
    }

    /// Full account_metadata snapshot from the mirror, or `None` when shadowing
    /// is off / the row is absent — for field-for-field diffing against the
    /// chainbase `account_metadata_object` accessors.
    pub fn arena_account_metadata(&self, name: u64) -> Option<ArenaAccountMetadata> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_metadata(name))
                .map(
                    |(
                        privileged,
                        recv_sequence,
                        auth_sequence,
                        code_sequence,
                        abi_sequence,
                        code_hash,
                        vm_type,
                        vm_version,
                    )| {
                        ArenaAccountMetadata {
                            privileged,
                            recv_sequence,
                            auth_sequence,
                            code_sequence,
                            abi_sequence,
                            code_hash,
                            vm_type,
                            vm_version,
                        }
                    },
                )
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            None
        }
    }

    /// Permission snapshot `(parent id, authority threshold)` from the mirror, or
    /// `None` when shadowing is off / the permission is absent — for diffing
    /// against chainbase's `find_permission_by_actor_and_permission`.
    pub fn arena_permission(&self, owner: u64, perm_name: u64) -> Option<(i64, u32)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.permission(owner, perm_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (owner, perm_name);
            None
        }
    }

    /// Required permission of the mirrored permission_link for `(account, code,
    /// message_type)`, or `None` when shadowing is off / the link is absent — for
    /// diffing against chainbase's `find_permission_link`.
    pub fn arena_permission_link(&self, account: u64, code: u64, message_type: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.permission_link(account, code, message_type))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (account, code, message_type);
            None
        }
    }

    /// Mirrored RAM usage for `account_name`, or `None` when shadowing is off /
    /// the account is absent — for diffing against chainbase's
    /// `get_account_ram_usage`.
    pub fn arena_account_ram_usage(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_ram_usage(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    /// Canonical serialization of chainbase's whole account_metadata table in
    /// by_name order — hash it to get a cross-implementation state root for the
    /// account set.
    pub fn account_metadata_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_metadata_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// The arena mirror's canonical account_metadata serialization, or `None`
    /// when shadowing is off — byte-compatible with `account_metadata_state_bytes`
    /// so their hashes match iff the tables hold the same state.
    pub fn arena_account_metadata_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.account_metadata_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Canonical serialization of chainbase's whole account_object table in
    /// by_name order — the account-table counterpart of
    /// `account_metadata_state_bytes`.
    pub fn account_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// The arena mirror's canonical account_object serialization, or `None` when
    /// shadowing is off.
    pub fn arena_account_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.account_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Canonical serialization of chainbase's whole permission table in
    /// (owner, perm_name) order. The authority is reconstructed from each
    /// permission's `shared_authority` and re-encoded with the same
    /// `encode_authority` the mirror stores, so the two streams match without
    /// reimplementing the encoding in C++. Reserved perm 0 is skipped by the
    /// C++ key enumerator. Gated on the mirror feature since it reuses
    /// `encode_authority`.
    #[cfg(feature = "arena-shadow")]
    pub fn permission_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        let keys = guard
            .permission_keys_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let mut out = Vec::new();
        for quad in keys.chunks_exact(32) {
            let owner = u64::from_le_bytes(quad[0..8].try_into().unwrap());
            let perm_name = u64::from_le_bytes(quad[8..16].try_into().unwrap());
            let parent = u64::from_le_bytes(quad[16..24].try_into().unwrap());
            let last_used = u64::from_le_bytes(quad[24..32].try_into().unwrap());
            let ptr = guard
                .find_permission_by_actor_and_permission(owner, perm_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if ptr.is_null() {
                continue;
            }
            // Safe: non-null, read-only, no mutation between the find and read.
            let auth = ffi::get_authority_from_shared_authority(unsafe { &*ptr }.get_authority());
            let auth_bytes = encode_authority(&auth);
            out.extend_from_slice(&owner.to_le_bytes());
            out.extend_from_slice(&perm_name.to_le_bytes());
            out.extend_from_slice(&parent.to_le_bytes());
            out.extend_from_slice(&last_used.to_le_bytes());
            out.extend_from_slice(&(auth_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&auth_bytes);
        }
        Ok(out)
    }

    /// The arena mirror's canonical permission serialization, or `None` when
    /// shadowing is off.
    pub fn arena_permission_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.permission_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn permission_link_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .permission_link_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn code_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .code_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn transaction_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .transaction_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn resource_usage_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .resource_usage_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn account_limits_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .account_limits_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn resource_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .resource_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Arena mirror canonical serializations for the remaining tables, `None`
    /// when shadowing is off — each byte-compatible with the chainbase method of
    /// the same name for the cross-impl root.
    pub fn arena_permission_link_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.permission_link_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_code_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.code_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_transaction_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.transaction_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_resource_usage_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.resource_usage_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_account_limits_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.account_limits_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_resource_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.resource_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn contract_table_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .contract_table_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn contract_kv_state_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;
        guard
            .contract_kv_state_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Activated protocol feature checkpoints in their chainbase insertion
    /// order. Each tuple contains the persisted 32-byte digest and the block at
    /// which it became active.
    pub fn activated_protocol_features(&self) -> Result<Vec<([u8; 32], u32)>, ChainError> {
        let guard = self.locked_read()?;
        let bytes = guard
            .activated_protocol_features_bytes()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        decode_activated_protocol_features(&bytes)
    }

    /// Append one activated checkpoint to the protocol-state singleton. Call
    /// this only after opening the candidate block's undo session. The C++ side
    /// also refuses the write when chainbase has no undo state at all.
    pub fn append_activated_protocol_feature(
        &mut self,
        digest: [u8; 32],
        activation_block_num: u32,
    ) -> Result<(), ChainError> {
        let mut record = [0u8; ACTIVATED_PROTOCOL_FEATURE_RECORD_SIZE];
        record[..32].copy_from_slice(&digest);
        record[32..].copy_from_slice(&activation_block_num.to_le_bytes());

        let mut guard = self.locked_write()?;
        guard
            .pin_mut()
            .append_activated_protocol_feature(&record)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn arena_contract_table_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.contract_table_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn arena_contract_kv_state_bytes(&self) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.contract_kv_state_bytes())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Serve a raw contract-db read from the arena: the value stored at
    /// `(code, scope, table, primary_key)`, or `None` if absent. This is the
    /// primitive behind db_get_i64/db_find_i64 — the read the arena must answer
    /// identically to chainbase to stand in as the primary store.
    pub fn arena_kv_get(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary_key: u64,
    ) -> Option<Vec<u8>> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_get(code, scope, table, primary_key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary_key);
            None
        }
    }

    /// Serve a contract-table forward scan from the arena: `(primary_key, value)`
    /// for every row in `(code, scope, table)`, ascending by primary — the order
    /// a contract sees walking db_lowerbound_i64 -> db_next_i64. Empty when the
    /// table is absent or shadowing is off.
    pub fn arena_table_range(&self, code: u64, scope: u64, table: u64) -> Vec<(u64, Vec<u8>)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.table_range(code, scope, table))
                .unwrap_or_default()
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            Vec::new()
        }
    }

    /// Inline read cross-check: confirm the arena would serve `expected` (the
    /// value the node is handing a contract) for `(code, scope, table, primary)`.
    /// No-op when shadowing is off. Tallies match/mismatch; see
    /// `arena_read_crosscheck_counts`.
    pub fn arena_crosscheck_kv(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
        expected: &[u8],
    ) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.crosscheck_kv(code, scope, table, primary, expected);
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary, expected);
        }
    }

    /// Route contract reads through the arena instead of chainbase (the staged
    /// cutover switch). No-op when shadowing is off.
    pub fn enable_arena_reads(&self) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.enable_reads();
            }
        }
    }

    pub fn arena_reads_enabled(&self) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.reads_enabled())
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            false
        }
    }

    /// (matches, mismatches) tallied by the inline read cross-check, or (0, 0)
    /// when shadowing is off.
    pub fn arena_read_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.read_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Arena iterator positioning: the primary a cursor lands on. `lower_bound` =
    /// first primary >= key, `upper_bound` = first primary > key (also the
    /// db_next successor), `prev` = last primary < key. `None` = off the end.
    /// All return `None` when shadowing is off.
    pub fn arena_kv_lower_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_lower_bound(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    pub fn arena_kv_upper_bound(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_upper_bound(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    pub fn arena_kv_prev(&self, code: u64, scope: u64, table: u64, key: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_prev(code, scope, table, key))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, key);
            None
        }
    }

    /// Largest primary in the table — db_previous_i64's landing when stepping
    /// back from the end iterator. `None` if empty or shadowing is off.
    pub fn arena_kv_last(&self, code: u64, scope: u64, table: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.kv_last(code, scope, table))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table);
            None
        }
    }

    /// Arena idx64 secondary-index positioning, mirroring db_idx64_find_secondary
    /// (primary of the first row with that secondary), db_idx64_lowerbound /
    /// db_idx64_upperbound (`(primary, secondary)` landing), and
    /// db_idx64_find_primary (secondary stored for a primary). All `None` when
    /// shadowing is off.
    pub fn arena_idx64_find_secondary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_find_secondary(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_lower_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_lower_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_upper_bound(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        secondary: u64,
    ) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_upper_bound(code, scope, table, secondary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, secondary);
            None
        }
    }

    pub fn arena_idx64_find_primary(
        &self,
        code: u64,
        scope: u64,
        table: u64,
        primary: u64,
    ) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.idx64_find_primary(code, scope, table, primary))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = (code, scope, table, primary);
            None
        }
    }

    /// Tally an iterator-positioning cross-check (arena landing vs chainbase).
    pub fn arena_note_pos(&self, matched: bool) {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.note_pos(matched);
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = matched;
        }
    }

    /// (matches, mismatches) tallied by iterator-positioning cross-checks.
    pub fn arena_pos_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.pos_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Persistence round-trip at the mirror's current (real) state size:
    /// checkpoint the live mirror to `path`, load it into a fresh, empty mirror,
    /// and return `(state_roots_match, checkpoint_bytes)`. A `true` means the
    /// arena survived a full save/load with a byte-identical state root — the
    /// durability the primary store needs. Returns `None` when shadowing is off.
    pub fn arena_persistence_roundtrip(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<(bool, u64)>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(None);
            };
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let fresh = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .load(path)
                .map_err(|e| ChainError::InternalError(format!("arena load: {e:?}")))?;
            Ok(Some((cur.state_root() == fresh.state_root(), size)))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(None)
        }
    }

    /// Append the mirror's committed delta since the last flush to the WAL at
    /// `path`. Call once per accepted block for incremental durability. No-op
    /// when shadowing is off.
    pub fn arena_flush_delta(&self, path: &std::path::Path) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            if let Some(s) = &self.shadow {
                s.flush_delta(path)
                    .map_err(|e| ChainError::InternalError(format!("arena flush_delta: {e:?}")))?;
            }
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
        }
        Ok(())
    }

    /// Reconstruct a fresh mirror by replaying the WAL at `path` (no base
    /// checkpoint), and return whether its state root matches the live mirror —
    /// the crash-recovery guarantee for the incremental path. `None` when
    /// shadowing is off.
    pub fn arena_wal_reload_matches(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<bool>, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(None);
            };
            let fresh = crate::shadow::ArenaShadow::new()
                .map_err(|e| ChainError::InternalError(format!("arena new: {e:?}")))?;
            fresh
                .replay_log(path)
                .map_err(|e| ChainError::InternalError(format!("arena replay_log: {e:?}")))?;
            Ok(Some(cur.state_root() == fresh.state_root()))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(None)
        }
    }

    /// Simulate a node restart: checkpoint the live mirror to `path`, then
    /// rebuild it in place from that checkpoint. After this the shadow holds
    /// reloaded-from-disk state (same object, restored revision) and keeps
    /// serving — so the caller can carry on applying blocks and confirm the
    /// mirror stays in lockstep with chainbase across the restart. `Ok(false)`
    /// when shadowing is off.
    pub fn arena_restart(&self, path: &std::path::Path) -> Result<bool, ChainError> {
        #[cfg(feature = "arena-shadow")]
        {
            let Some(cur) = &self.shadow else {
                return Ok(false);
            };
            cur.checkpoint(path)
                .map_err(|e| ChainError::InternalError(format!("arena checkpoint: {e:?}")))?;
            cur.reload_from(path)
                .map_err(|e| ChainError::InternalError(format!("arena reload: {e:?}")))?;
            Ok(true)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = path;
            Ok(false)
        }
    }

    /// (matches, mismatches) tallied by non-contract read cross-checks
    /// (accounts/permissions read during authorization and dispatch).
    pub fn arena_noncontract_crosscheck_counts(&self) -> (u64, u64) {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.noncontract_crosscheck_counts())
                .unwrap_or((0, 0))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            (0, 0)
        }
    }

    /// Whether the arena mirror holds an account_object for `name` — for diffing
    /// against chainbase's `find_account`.
    pub fn arena_account_exists(&self, name: u64) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.account_exists(name))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = name;
            false
        }
    }

    /// State root of the mirrored subset, or `None` when shadowing is off. Only
    /// ported tables contribute, so it is comparable to chainbase for those.
    pub fn arena_state_root(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().map(|s| s.state_root())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    /// Arena undo-session lifecycle, driven by the controller in lockstep with
    /// the chainbase session boundaries.
    pub fn arena_start_undo_session(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.start_undo_session();
        }
    }
    pub fn arena_squash(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.squash();
        }
    }
    pub fn arena_undo(&self) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.undo();
        }
    }
    pub fn arena_commit(&self, revision: i64) {
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.commit(revision);
        }
        #[cfg(not(feature = "arena-shadow"))]
        let _ = revision;
    }

    // Replace the inner database with null to call the destructors
    pub fn close(&self) -> Result<(), ChainError> {
        let mut db = self.locked_write()?;
        *db = UniquePtr::<ffi::Database>::null();
        Ok(())
    }

    /// Capture a physical snapshot of the current arena, wrapped in the
    /// transport envelope (see `snapshot`).
    ///
    /// There is no live msync in chainbase, so the only way to read a
    /// self-consistent `shared_memory.bin` is to drop the mapping first: the
    /// destructor flushes dirty pages and clears the on-disk dirty flag. We then
    /// read the clean file and remap exactly as a restart would. The write lock
    /// is held across the whole window, so no other thread ever observes the
    /// database in its momentarily-closed state, and we always remap — even if
    /// the read fails — so a snapshot error never leaves the node with a closed
    /// database.
    ///
    /// Call this only at a quiescent point (no open undo session): the copy
    /// reflects whatever is committed to the arena at that instant.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let mut guard = self.locked_write()?;
        if guard.is_null() {
            return Err(ChainError::InternalError(
                "snapshot: database is not open".into(),
            ));
        }
        let revision = guard.revision();

        // Tear the mapping down: flushes and clears the dirty flag on disk.
        *guard = UniquePtr::<ffi::Database>::null();

        let file = Path::new(&self.path).join(SHARED_MEMORY_FILE);
        let snapshot = Self::read_sparse_snapshot(&file, revision);

        // Remap before propagating any read error, so the database is never
        // left closed behind us.
        match Self::open_with_indices(&self.path, self.size, "snapshot: reopen after copy") {
            Ok(db) => *guard = db,
            Err(error) => {
                return Err(ChainError::fatal_consistency(format!(
                    "snapshot creation closed the live database and could not reopen it: {error}"
                )));
            }
        }

        snapshot
    }

    /// Read `shared_memory.bin` into a sparse, envelope-wrapped snapshot without
    /// ever holding the whole (mostly-zero) file in memory. Fixed-size,
    /// block-aligned chunks keep the run boundaries deterministic, so re-reading
    /// an unchanged file yields byte-identical output.
    fn read_sparse_snapshot(file: &Path, revision: i64) -> Result<Vec<u8>, ChainError> {
        let mut f = fs::File::open(file).map_err(|e| {
            ChainError::InternalError(format!("snapshot: open {}: {e}", file.display()))
        })?;
        let len = f
            .metadata()
            .map_err(|e| ChainError::InternalError(format!("snapshot: stat: {e}")))?
            .len();

        let mut payload = crate::snapshot::sparse_begin(len);
        // A multiple of SPARSE_BLOCK, so every full chunk starts block-aligned.
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut offset = 0u64;
        loop {
            let n = fill(&mut f, &mut buf)
                .map_err(|e| ChainError::InternalError(format!("snapshot: read: {e}")))?;
            if n == 0 {
                break;
            }
            crate::snapshot::sparse_append(&mut payload, offset, &buf[..n]);
            offset += n as u64;
        }
        Ok(crate::snapshot::encode(revision, &payload))
    }

    /// Expand a validated sparse payload into `file`: write each run at its
    /// offset over a freshly-truncated file, then extend to the logical length so
    /// the unwritten remainder stays a (zeroed) hole.
    fn write_sparse_snapshot(file: &Path, payload: &[u8]) -> Result<(), ChainError> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file)
            .map_err(|e| {
                ChainError::InternalError(format!("restore: create {}: {e}", file.display()))
            })?;
        let logical_len = crate::snapshot::sparse_expand(payload, |off, data| {
            f.seek(SeekFrom::Start(off))?;
            f.write_all(data)
        })?;
        f.set_len(logical_len).map_err(|e| {
            ChainError::InternalError(format!("restore: size {}: {e}", file.display()))
        })?;
        f.sync_all().map_err(|e| {
            ChainError::InternalError(format!("restore: sync {}: {e}", file.display()))
        })?;
        Ok(())
    }

    /// Replace the live arena with the state carried in `snapshot`, in place.
    ///
    /// The generic form retains the historical behavior. Consensus callers
    /// should use [`Self::restore_from_bytes_validated`] to inspect staged state
    /// before it can replace the live mapping.
    pub fn restore_from_bytes(
        &self,
        snapshot: &[u8],
    ) -> Result<crate::snapshot::SnapshotHeader, ChainError> {
        self.restore_from_bytes_impl(snapshot, None, || Ok(()))
    }

    /// Stage, open, and validate a physical snapshot before atomically swapping
    /// it into the live database.
    ///
    /// The staged arena is opened as a real chainbase database, so corrupt or
    /// semantically incompatible state is rejected while the live mapping is
    /// untouched. A hard-link backup keeps the old arena inode available during
    /// the swap; if the replacement cannot be reopened, the old mapping is
    /// restored before this method returns an error.
    pub fn restore_from_bytes_validated<F>(
        &self,
        snapshot: &[u8],
        expected_activated_protocol_features: &[([u8; 32], u32)],
        before_swap: F,
    ) -> Result<crate::snapshot::SnapshotHeader, ChainError>
    where
        F: FnOnce() -> Result<(), ChainError>,
    {
        self.restore_from_bytes_impl(
            snapshot,
            Some(expected_activated_protocol_features),
            before_swap,
        )
    }

    fn restore_from_bytes_impl<F>(
        &self,
        snapshot: &[u8],
        expected_activated_protocol_features: Option<&[([u8; 32], u32)]>,
        before_swap: F,
    ) -> Result<crate::snapshot::SnapshotHeader, ChainError>
    where
        F: FnOnce() -> Result<(), ChainError>,
    {
        // Validate and locate the payload before touching the running database.
        let (header, payload) = crate::snapshot::decode(snapshot)?;

        let dir = Path::new(&self.path);
        let dest = dir.join(SHARED_MEMORY_FILE);
        let live_arena_len = fs::metadata(&dest)
            .map_err(|e| {
                ChainError::InternalError(format!(
                    "restore: stat live arena {}: {e}",
                    dest.display()
                ))
            })?
            .len();
        let snapshot_arena_len = crate::snapshot::sparse_logical_len(payload)?;
        if snapshot_arena_len > live_arena_len {
            return Err(ChainError::InternalError(format!(
                "restore: snapshot arena size {snapshot_arena_len} exceeds local arena size {live_arena_len}"
            )));
        }
        let staging_dir = tempfile::Builder::new()
            .prefix(".pulsevm-snapshot-restore-")
            .tempdir_in(dir)
            .map_err(|e| {
                ChainError::InternalError(format!("restore: create staging directory: {e}"))
            })?;
        let staged = staging_dir.path().join(SHARED_MEMORY_FILE);
        let backup = staging_dir.path().join("previous-shared-memory.bin");
        Self::write_sparse_snapshot(&staged, payload)?;

        // Opening the staged file catches chainbase-level corruption that the
        // transport checksum cannot. Read consensus metadata from that opened
        // arena and let the caller compare it with the summary/configuration.
        let staged_features = {
            let staged_path = staging_dir.path().to_str().ok_or_else(|| {
                ChainError::InternalError("restore: staging path is not UTF-8".into())
            })?;
            // Opening with the target's current reservation grows a smaller
            // source arena before installation. Chainbase supports this and it
            // lets validators use different local `db_size` reservations while
            // still refusing a snapshot too large for the receiver.
            let staged_db = Self::open_with_indices(
                staged_path,
                live_arena_len,
                "restore: validate staged arena",
            )?;
            let staged_revision = staged_db.revision();
            if staged_revision != header.revision {
                return Err(ChainError::InternalError(format!(
                    "restore: staged arena revision {staged_revision} does not match snapshot header revision {}",
                    header.revision
                )));
            }
            let features = if expected_activated_protocol_features.is_some() {
                let bytes = staged_db.activated_protocol_features_bytes().map_err(|e| {
                    ChainError::InternalError(format!("restore: protocol state: {e}"))
                })?;
                Some(decode_activated_protocol_features(&bytes)?)
            } else {
                None
            };
            // Closing clears chainbase's dirty flag before the staged inode is
            // installed as the live mapping.
            drop(staged_db);
            features
        };
        if let (Some(expected), Some(actual)) = (
            expected_activated_protocol_features,
            staged_features.as_deref(),
        ) && actual != expected
        {
            let first_difference = actual
                .iter()
                .zip(expected)
                .position(|(actual, expected)| actual != expected)
                .unwrap_or_else(|| actual.len().min(expected.len()));
            return Err(ChainError::InternalError(format!(
                "restore: snapshot activation ledger does not match configured history (actual {} record(s), expected {}, first difference at index {first_difference})",
                actual.len(),
                expected.len()
            )));
        }

        // `arena-shadow` is differential-test instrumentation, not a second
        // durable snapshot backend. Installing chainbase state while retaining
        // the old in-memory mirror would make every later comparison invalid,
        // so fail before touching either live representation.
        #[cfg(feature = "arena-shadow")]
        if self.shadow.is_some() {
            return Err(ChainError::InternalError(
                "restore: physical state sync is unavailable while arena-shadow is enabled".into(),
            ));
        }

        // Consensus callers use this hook to unwind speculative undo sessions.
        // It deliberately runs only after every staged-state validation above,
        // so a rejected snapshot does not disturb their live view.
        before_swap()?;

        let mut guard = self.locked_write()?;
        if guard.is_null() {
            return Err(ChainError::InternalError(
                "restore: database is not open".into(),
            ));
        }

        // Close the mapping, retain the old inode with a cheap same-filesystem
        // hard link, then atomically replace the live path with the staged file.
        *guard = UniquePtr::<ffi::Database>::null();
        if let Err(link_error) = fs::hard_link(&dest, &backup) {
            let old = Self::open_with_indices(
                &self.path,
                self.size,
                "restore: reopen after backup-link failure",
            )
            .map_err(|reopen_error| {
                ChainError::fatal_consistency(format!(
                    "restore: retaining the live database failed ({link_error}); reopening it also failed ({reopen_error})"
                ))
            })?;
            *guard = old;
            return Err(ChainError::InternalError(format!(
                "restore: could not retain live database before swap: {link_error}"
            )));
        }

        if let Err(swap_error) = fs::rename(&staged, &dest) {
            let old = Self::open_with_indices(
                &self.path,
                self.size,
                "restore: reopen after swap failure",
            )
            .map_err(|reopen_error| {
                ChainError::fatal_consistency(format!(
                    "restore: swapping the staged database failed ({swap_error}); reopening the live database also failed ({reopen_error})"
                ))
            })?;
            *guard = old;
            return Err(ChainError::InternalError(format!(
                "restore: swap into {} failed: {swap_error}",
                dest.display()
            )));
        }

        let replacement = sync_parent_dir(&dest)
            .map_err(|error| {
                ChainError::InternalError(format!(
                    "restore: sync replacement database directory: {error}"
                ))
            })
            .and_then(|_| {
                Self::open_with_indices(&self.path, self.size, "restore: open replacement database")
            });
        let replacement = match replacement {
            Ok(replacement) => replacement,
            Err(install_error) => {
                // Put the old inode back at the live path. `rename` replaces the bad
                // staged inode atomically; the temporary directory owns its other
                // files and cleans them up after the old mapping is safely reopened.
                if let Err(rollback_error) = fs::rename(&backup, &dest) {
                    // Keep the staging directory: it still contains the only
                    // known-good link to the previous arena, so automatic temp
                    // cleanup would turn a failed rollback into data loss.
                    let preserved = staging_dir.keep();
                    return Err(ChainError::fatal_consistency(format!(
                        "{install_error}; restoring the previous database path also failed: {rollback_error}; recoverable files retained at {}",
                        preserved.display()
                    )));
                }
                if let Err(rollback_sync_error) = sync_parent_dir(&dest) {
                    // Recreate a diagnostic/recovery link before consuming the
                    // temp directory. Even if the directory sync failed, this
                    // gives an operator another name for the old inode while
                    // the process fail-stops.
                    let _ = fs::hard_link(&dest, &backup);
                    let preserved = staging_dir.keep();
                    return Err(ChainError::fatal_consistency(format!(
                        "{install_error}; the previous database path was restored but its directory entry could not be synced: {rollback_sync_error}; recoverable files retained at {}",
                        preserved.display()
                    )));
                }
                let old = Self::open_with_indices(
                    &self.path,
                    self.size,
                    "restore: reopen rolled-back database",
                )
                .map_err(|rollback_open_error| {
                    ChainError::fatal_consistency(format!(
                        "{install_error}; the previous database path was restored but could not be reopened: {rollback_open_error}"
                    ))
                })?;
                *guard = old;
                return Err(ChainError::InternalError(format!(
                    "{install_error}; live database was restored"
                )));
            }
        };
        *guard = replacement;

        // The backup is inside `staging_dir`; dropping it unlinks the old inode.
        // No fallible cleanup is allowed after the replacement becomes live.
        Ok(header)
    }

    pub fn commit(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .commit(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn undo(&mut self) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .undo()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn revision(&self) -> i64 {
        self.locked_read().unwrap().revision()
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), ChainError> {
        self.inner
            .write()?
            .pin_mut()
            .set_revision(revision)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn add_indices(&mut self) -> Result<(), ChainError> {
        self.locked_write()?
            .pin_mut()
            .add_indices()
            .map_err(|e| ChainError::InternalError(format!("add indices: {e}")))
    }

    pub fn initialize_database(&mut self, genesis: &CxxGenesisState) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .initialize_database(genesis)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        // Genesis creates the resource_limits state singleton inside C++, out of
        // reach of the per-write mirror hooks, so seed the mirror's copy here
        // with the same slow-start virtual limits (each resource's max).
        #[cfg(feature = "arena-shadow")]
        if self.shadow.is_some() {
            match (
                self.get_cpu_limit_parameters(),
                self.get_net_limit_parameters(),
            ) {
                (Ok(cpu), Ok(net)) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.initialize_resource_state(cpu.max, net.max)
                    {
                        eprintln!("arena mirror of resource state init diverged: {e:?}");
                    }
                }
                _ => eprintln!("arena mirror could not read limit parameters at init"),
            }
            // Genesis creates its native accounts inside C++, below the mirror
            // hooks, so seed their account_metadata into the mirror from
            // chainbase once here. Later accounts flow through the live path.
            match self.account_metadata_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_account_metadata(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis account_metadata: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis account_metadata: {e:?}"),
            }
            match self.account_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_accounts(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis accounts: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis accounts: {e:?}"),
            }
            match self.permission_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_permissions(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis permissions: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis permissions: {e:?}"),
            }
            // Genesis native accounts get resource_usage (billed ram) and
            // resource_limits rows inside create_native_account; seed them.
            match self.resource_usage_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_resource_usage(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis resource_usage: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis resource_usage: {e:?}"),
            }
            match self.account_limits_state_bytes() {
                Ok(bytes) => {
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.hydrate_account_limits(&bytes)
                    {
                        eprintln!("arena mirror could not hydrate genesis resource_limits: {e:?}");
                    }
                }
                Err(e) => eprintln!("arena mirror could not read genesis resource_limits: {e:?}"),
            }
        }
        Ok(())
    }

    pub fn create_account(
        &mut self,
        account_name: u64,
        creation_date: u32,
    ) -> Result<*const ffi::AccountObject, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account(account_name, creation_date)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account(account_name, creation_date)
        {
            eprintln!("arena mirror of account {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account(&self, account_name: u64) -> Result<*const ffi::AccountObject, ChainError> {
        let guard = self.locked_read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        Ok(account)
    }

    /// Whether `account_name` exists, decided under the read guard so no pointer
    /// escapes the lock. Prefer this to `find_account(..).is_null()` at call sites
    /// that only need existence.
    pub fn account_exists(&self, account_name: u64) -> Result<bool, ChainError> {
        Ok(self.read()?.find_account(account_name)?.is_some())
    }

    pub fn get_account(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountObject, ChainError> {
        let guard = self.locked_read()?;
        let account = guard
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;

        if account.is_null() {
            return Err(ChainError::InternalError(format!(
                "account not found: {}",
                account_name
            )));
        }

        Ok(unsafe { &*account })
    }

    pub fn create_account_metadata(
        &mut self,
        account_name: u64,
        is_privileged: bool,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_account_metadata(account_name, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::AccountMetadataObject
        };
        // Mirror after releasing the chainbase lock, so the two locks are never
        // held at once. Chainbase is authoritative; a mirror error is logged.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_account_metadata(account_name, is_privileged)
        {
            eprintln!("arena mirror of account_metadata {account_name} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<*const ffi::AccountMetadataObject, ChainError> {
        let guard = self.locked_read()?;

        guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })
    }

    pub fn set_privileged(&mut self, account: u64, is_privileged: bool) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .set_privileged(account, is_privileged)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_privileged(account, is_privileged)
        {
            eprintln!("arena mirror of set_privileged {account} diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<&'static ffi::AccountMetadataObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard.find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                account_name
            )));
        }

        Ok(unsafe { &*res })
    }

    pub fn unlink_account_code(
        &mut self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let hash = digest_to_array(code_hash);
        {
            let mut guard = self.locked_write()?;
            // Resolve the code object under this guard, then drop the borrow to a
            // raw pointer so its reference is confined to the C++ call rather than
            // passed in by the caller.
            let obj_ptr: *const ffi::CodeObject = {
                let obj = guard
                    .get_code_object_by_hash(code_hash, vm_type, vm_version)
                    .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
                obj as *const ffi::CodeObject
            };
            guard
                .pin_mut()
                .unlink_account_code(unsafe { &*obj_ptr })
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_account_code(hash)
        {
            eprintln!("arena mirror of unlink_account_code diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_account_code(
        &mut self,
        account_name: u64,
        new_code: &[u8],
        head_block_num: u32,
        pending_block_time: &TimePoint,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let obj = guard
                .find_account_metadata(account_name)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
            if obj.is_null() {
                return Err(ChainError::ActionValidationError(format!(
                    "account metadata not found for account: {}",
                    account_name
                )));
            }
            guard
                .pin_mut()
                .update_account_code(
                    unsafe { &*obj },
                    new_code,
                    head_block_num,
                    pending_block_time,
                    code_hash,
                    vm_type,
                    vm_version,
                )
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let hash = digest_to_array(code_hash);
            if let Err(e) = s.update_account_code(
                account_name,
                new_code,
                hash,
                head_block_num,
                vm_type,
                vm_version,
            ) {
                eprintln!("arena mirror of update_account_code diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_account_abi(&mut self, account_name: u64, abi: &[u8]) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let account = guard
                .find_account(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            let account_metadata = guard
                .find_account_metadata(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if account.is_null() || account_metadata.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account not found: {}",
                    account_name
                )));
            }
            guard
                .pin_mut()
                .update_account_abi(unsafe { &*account }, unsafe { &*account_metadata }, abi)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_account_abi(account_name, abi)
        {
            eprintln!("arena mirror of update_account_abi diverged: {e:?}");
        }
        Ok(())
    }

    pub fn create_undo_session(
        &mut self,
        enabled: bool,
    ) -> Result<cxx::UniquePtr<ffi::UndoSession>, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .create_undo_session(enabled)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_resource_limits(&mut self) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .initialize_resource_limits()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn initialize_account_resource_limits(
        &mut self,
        account_name: u64,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .initialize_account_resource_limits(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.initialize_account_resource_limits(account_name)
        {
            eprintln!("arena mirror of initialize_account_resource_limits diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_account_usage(
        &mut self,
        account: &Name,
        time_slot: u32,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .update_account_usage(account.as_u64(), time_slot)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        self.mirror_account_usage(account.as_u64(), 0, 0, time_slot);
        Ok(())
    }

    pub fn add_transaction_usage(
        &mut self,
        account: &Name,
        cpu_usage: u64,
        net_usage: u64,
        time_slot: u32,
        validate: bool,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .add_transaction_usage(account.as_u64(), cpu_usage, net_usage, time_slot, validate)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        self.mirror_account_usage(account.as_u64(), cpu_usage, net_usage, time_slot);
        Ok(())
    }

    /// Replays a net/cpu usage advance onto the arena mirror, pulling the average
    /// windows from chainbase config so the accumulator decay matches. Best
    /// effort: a divergence is logged, never propagated.
    #[cfg(feature = "arena-shadow")]
    fn mirror_account_usage(&self, account: u64, cpu_usage: u64, net_usage: u64, time_slot: u32) {
        if self.shadow.is_none() {
            return;
        }
        let windows = self.get_account_net_usage_average_window().and_then(|nw| {
            self.get_account_cpu_usage_average_window()
                .map(|cw| (nw, cw))
        });
        let (net_window, cpu_window) = match windows {
            Ok(w) => w,
            Err(e) => {
                eprintln!("arena mirror could not read usage windows: {e:?}");
                return;
            }
        };
        if let Some(s) = &self.shadow {
            if let Err(e) = s.add_transaction_usage(
                account, cpu_usage, net_usage, time_slot, net_window, cpu_window,
            ) {
                eprintln!("arena mirror of add_transaction_usage diverged: {e:?}");
            }
            // The same call also folds the usage into the block's pending totals
            // on the state singleton (the block-accounting half in chainbase).
            if let Err(e) = s.add_block_usage(cpu_usage, net_usage) {
                eprintln!("arena mirror of block usage diverged: {e:?}");
            }
        }
    }

    pub fn add_pending_ram_usage(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .add_pending_ram_usage(account_name, ram_bytes)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.add_pending_ram_usage(account_name, ram_bytes)
        {
            eprintln!("arena mirror of add_pending_ram_usage diverged: {e:?}");
        }
        Ok(())
    }

    pub fn verify_account_ram_usage(&mut self, account_name: u64) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .verify_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_ram_usage(&self, account_name: u64) -> Result<i64, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_account_ram_usage(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_usage_average_window(&self) -> Result<u32, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_net_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_usage_average_window(&self) -> Result<u32, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_cpu_usage_average_window()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_usage_value_ex(&self, account_name: u64) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_net_usage_value_ex(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_usage_value_ex(&self, account_name: u64) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_account_cpu_usage_value_ex(account_name)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored net/cpu usage `value_ex` for `account_name`, or `None` when
    /// shadowing is off / the account is absent — for diffing against chainbase.
    pub fn arena_account_net_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_net_usage_value_ex(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn arena_account_cpu_usage_value_ex(&self, account_name: u64) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_cpu_usage_value_ex(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn get_virtual_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_virtual_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_cpu_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_cpu_limit_parameters()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_net_limit_parameters(&self) -> Result<ElasticLimitParameters, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_net_limit_parameters()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored `(virtual_cpu_limit, virtual_net_limit)`, or `None` when
    /// shadowing is off / the state row is absent — for diffing against
    /// chainbase's `get_virtual_cpu_limit`/`get_virtual_net_limit`.
    pub fn arena_virtual_limits(&self) -> Option<(u64, u64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow.as_ref().and_then(|s| s.state_virtual_limits())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn set_account_limits(
        &mut self,
        account_name: u64,
        ram_bytes: i64,
        net_weight: i64,
        cpu_weight: i64,
    ) -> Result<bool, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
        {
            eprintln!("arena mirror of set_account_limits diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_account_limits(
        &self,
        account_name: u64,
        ram_bytes: &mut i64,
        net_weight: &mut i64,
        cpu_weight: &mut i64,
    ) -> Result<(), ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_account_limits(account_name, ram_bytes, net_weight, cpu_weight)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_cpu_weight(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_total_cpu_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_total_net_weight(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_total_net_weight()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_net_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::NetLimitResult, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_account_net_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_cpu_limit(
        &self,
        name: u64,
        greylist_limit: u32,
    ) -> Result<ffi::CpuLimitResult, ChainError> {
        let guard = self.locked_read()?;

        guard
            .get_account_cpu_limit(name, greylist_limit)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn process_account_limit_updates(&mut self) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .process_account_limit_updates()
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.process_account_limit_updates()
        {
            eprintln!("arena mirror of process_account_limit_updates diverged: {e:?}");
        }
        Ok(())
    }

    /// Mirrored effective limits `(ram_bytes, net_weight, cpu_weight)` for
    /// `account_name`, or `None` when shadowing is off / the account is absent —
    /// for diffing against chainbase's `get_account_limits`.
    pub fn arena_account_limits(&self, account_name: u64) -> Option<(i64, i64, i64)> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.account_limits(account_name))
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = account_name;
            None
        }
    }

    pub fn set_block_parameters(
        &mut self,
        cpu_limit_parameters: &ElasticLimitParameters,
        net_limit_parameters: &ElasticLimitParameters,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_block_parameters(cpu_limit_parameters, net_limit_parameters)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn process_block_usage(&mut self, block_num: u32) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .process_block_usage(block_num)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if self.shadow.is_some() {
            match (
                self.get_cpu_limit_parameters(),
                self.get_net_limit_parameters(),
            ) {
                (Ok(cpu), Ok(net)) => {
                    let (cpu, net) = (to_elastic_params(&cpu), to_elastic_params(&net));
                    if let Some(s) = &self.shadow
                        && let Err(e) = s.process_block_usage(block_num, cpu, net)
                    {
                        eprintln!("arena mirror of process_block_usage diverged: {e:?}");
                    }
                }
                _ => eprintln!("arena mirror could not read limit parameters for block usage"),
            }
        }
        Ok(())
    }

    pub fn find_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn get_table(
        &self,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<*const TableObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_table(code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "table not found for code: {} scope: {} table: {}",
                code, scope, table
            )));
        }

        Ok(res)
    }

    pub fn create_table(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        payer: u64,
    ) -> Result<*const TableObject, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_table(code, scope, table, payer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const TableObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_table(code, scope, table, payer)
        {
            eprintln!("arena mirror of create_table diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_find_i64(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
        keyval_cache: &mut KeyValueIteratorCache,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        { pinned.db_find_i64(code, scope, table, id, keyval_cache.pin_mut()) }
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_key_value_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        buffer: &[u8],
    ) -> Result<*const KeyValueObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_key_value_object(table, payer, id, buffer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const KeyValueObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_key_value_object(key.0, key.1, key.2, payer, id, buffer)
        {
            eprintln!("arena mirror of create_key_value_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn create_index64_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const Index64Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index64_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index64Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index64_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index64_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_key_value_object(
        &mut self,
        obj: &KeyValueObject,
        payer: u64,
        buffer: &[u8],
    ) -> Result<(), ChainError> {
        // Resolve the row's table (code, scope, table) + primary before the write,
        // so the arena mirror can locate the row the FFI reaches by opaque handle.
        #[cfg(feature = "arena-shadow")]
        let key = {
            let guard = self.locked_read()?;
            let t = guard.get_table_by_kv(obj);
            (
                t.get_code().to_uint64_t(),
                t.get_scope().to_uint64_t(),
                t.get_table().to_uint64_t(),
                obj.get_primary_key(),
            )
        };
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .update_key_value_object(obj, payer, buffer)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.update_key_value_object(key.0, key.1, key.2, key.3, payer, buffer)
        {
            eprintln!("arena mirror of update_key_value_object diverged: {e:?}");
        }
        Ok(())
    }

    pub fn update_index64_object(
        &mut self,
        obj: &Index64Object,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index64_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_table(&mut self, table: &TableObject) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_table(table)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_table(key.0, key.1, key.2)
        {
            eprintln!("arena mirror of remove_table diverged: {e:?}");
        }
        Ok(())
    }

    pub fn is_account(&self, account: u64) -> Result<bool, ChainError> {
        let guard = self.locked_read()?;

        guard
            .is_account(account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn find_permission(&self, id: i64) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn find_permission_link(
        &self,
        account_name: u64,
        code_name: u64,
        message_type: u64,
    ) -> Result<*const ffi::PermissionLinkObject, ChainError> {
        let guard = self.locked_read()?;
        guard
            .find_permission_link(account_name, code_name, message_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Err(ChainError::InternalError(format!(
                "permission not found for actor: {} permission: {}",
                pulsevm_name::Name::new(actor),
                pulsevm_name::Name::new(permission)
            )));
        }

        Ok(res)
    }

    pub fn delete_auth(&mut self, account: u64, permission_name: u64) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .delete_auth(account, permission_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        // delete_auth removes the permission (and its usage row) in C++.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(account, permission_name)
        {
            eprintln!("arena mirror of delete_auth {account} diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn link_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .link_auth(account_name, code_name, requirement_name, requirement_type)
                .map_err(|e| ChainError::ActionValidationError(format!("{}", e)))?
        };
        // In C++ the link's message_type is the requirement_type and its
        // required_permission is the requirement_name.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.link_auth(account_name, code_name, requirement_type, requirement_name)
        {
            eprintln!("arena mirror of link_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn unlink_auth(
        &mut self,
        account_name: u64,
        code_name: u64,
        requirement_type: u64,
    ) -> Result<i64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .unlink_auth(account_name, code_name, requirement_type)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.unlink_auth(account_name, code_name, requirement_type)
        {
            eprintln!("arena mirror of unlink_auth diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_code_object_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<*const ffi::CodeObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_code_object_by_hash(code_hash, vm_type, vm_version)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn next_recv_sequence(&mut self, account_name: u64) -> Result<u64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            // Look up the metadata object under this same guard and confine the
            // reference to the C++ call, so no chainbase reference is handed in by
            // (or escapes to) the caller.
            let obj = guard
                .find_account_metadata(account_name)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if obj.is_null() {
                return Err(ChainError::InternalError(format!(
                    "account metadata not found for account: {}",
                    account_name
                )));
            }
            guard
                .pin_mut()
                .next_recv_sequence(unsafe { &*obj })
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.next_recv_sequence(account_name)
        {
            eprintln!("arena mirror of next_recv_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn next_auth_sequence(&mut self, actor: u64) -> Result<u64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .next_auth_sequence(actor)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.next_auth_sequence(actor)
        {
            eprintln!("arena mirror of next_auth_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn next_global_sequence(&mut self) -> Result<u64, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .next_global_sequence()
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.set_global_action_sequence(res)
        {
            eprintln!("arena mirror of next_global_sequence diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn get_global_action_sequence(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_global_action_sequence()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Mirrored `global_action_sequence`, or `None` when shadowing is off / the
    /// singleton row is unwritten — for diffing against chainbase.
    pub fn arena_global_action_sequence(&self) -> Option<u64> {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .and_then(|s| s.global_action_sequence())
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            None
        }
    }

    pub fn db_remove_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<i64, ChainError> {
        // Resolve the row's (code, scope, table, primary) through the cache
        // before it is deleted; a mirror-resolution error must never abort the
        // authoritative removal, so it is swallowed to `None`.
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_remove_i64(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
        };
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_key_value_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_remove_i64 diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn db_idx64_remove(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx64_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index64_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx64_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx64_find_secondary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_find_primary(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_lowerbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_upperbound(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_end(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_next(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx64_previous(
        &mut self,
        keyval_cache: &mut Index64IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx64_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index128_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u128,
    ) -> Result<*const Index128Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index128_object(table, payer, id, secondary_key.into())
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index128Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index128_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_index128_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index128_object(
        &mut self,
        obj: &Index128Object,
        payer: u64,
        secondary_key: u128,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index128_object(obj, payer, secondary_key.into())
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_remove(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx128_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index128_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx128_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx128_find_secondary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let secondary_key_u128: U128 = secondary_key.into();

        let res = pinned
            .db_idx128_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx128_find_primary(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_u128: U128 = (*secondary).into();
        let res = pinned
            .db_idx128_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_u128,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary = secondary_u128.into();
        Ok(res)
    }

    pub fn db_idx128_lowerbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();

        let res = pinned
            .db_idx128_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_upperbound(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let mut secondary_key_u128: U128 = (*secondary_key).into();
        let res = pinned
            .db_idx128_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                &mut secondary_key_u128,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        *secondary_key = secondary_key_u128.into();
        Ok(res)
    }

    pub fn db_idx128_end(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_next(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx128_previous(
        &mut self,
        keyval_cache: &mut Index128IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx128_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_index256_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: U256,
    ) -> Result<*const Index256Object, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let sec_bytes = secondary_key.value;
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_index256_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const Index256Object
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.create_index256_object(key.0, key.1, key.2, payer, id, sec_bytes)
        {
            eprintln!("arena mirror of create_index256_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_index256_object(
        &mut self,
        obj: &Index256Object,
        payer: u64,
        secondary_key: U256,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_index256_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_remove(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx256_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_index256_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx256_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx256_find_secondary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_find_primary(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut U256,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_lowerbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx256_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_upperbound(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut U256,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx256_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx256_end(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_next(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx256_previous(
        &mut self,
        keyval_cache: &mut Index256IteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx256_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: u64,
    ) -> Result<*const IndexDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.create_idx_double_object(key.0, key.1, key.2, payer, id, secondary_key)
        {
            eprintln!("arena mirror of create_idx_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_double_object(
        &mut self,
        obj: &IndexDoubleObject,
        payer: u64,
        secondary_key: u64,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_remove(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut u64,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut u64,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_double_end(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_next(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_double_previous(
        &mut self,
        keyval_cache: &mut IndexDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn create_idx_long_double_object(
        &mut self,
        table: &TableObject,
        payer: u64,
        id: u64,
        secondary_key: Float128,
    ) -> Result<*const IndexLongDoubleObject, ChainError> {
        #[cfg(feature = "arena-shadow")]
        let key = table_key(table);
        #[cfg(feature = "arena-shadow")]
        let (sec_lo, sec_hi) = (secondary_key.lo, secondary_key.hi);
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_idx_long_double_object(table, payer, id, secondary_key)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const IndexLongDoubleObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.create_idx_long_double_object(key.0, key.1, key.2, payer, id, (sec_lo, sec_hi))
        {
            eprintln!("arena mirror of create_idx_long_double_object diverged: {e:?}");
        }
        Ok(res)
    }

    pub fn update_idx_long_double_object(
        &mut self,
        obj: &IndexLongDoubleObject,
        payer: u64,
        secondary_key: Float128,
    ) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .update_idx_long_double_object(obj, payer, secondary_key)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_remove(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        receiver: u64,
    ) -> Result<(), ChainError> {
        #[cfg(feature = "arena-shadow")]
        let mirror_key = self.shadow.as_ref().and_then(|_| {
            let obj = keyval_cache.get(iterator).ok()?;
            let tbl = keyval_cache.get_table(obj.get_table_id()).ok()?;
            let (code, scope, table) = table_key(tbl);
            Some((code, scope, table, obj.get_primary_key()))
        });
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .db_idx_long_double_remove(keyval_cache.pin_mut(), iterator, receiver)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let (Some(s), Some((code, scope, table, primary))) = (&self.shadow, mirror_key)
            && let Err(e) = s.remove_idx_long_double_object(code, scope, table, primary)
        {
            eprintln!("arena mirror of db_idx_long_double_remove diverged: {e:?}");
        }
        Ok(())
    }

    pub fn db_idx_long_double_find_secondary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_find_secondary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_find_primary(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary: &mut Float128,
        primary_key: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_find_primary(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary,
                primary_key,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_lowerbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        let res = pinned
            .db_idx_long_double_lowerbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_upperbound(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        secondary_key: &mut Float128,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();
        let res = pinned
            .db_idx_long_double_upperbound(
                keyval_cache.pin_mut(),
                code,
                scope,
                table,
                secondary_key,
                primary,
            )
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    pub fn db_idx_long_double_end(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_end(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_next(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_next(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_idx_long_double_previous(
        &mut self,
        keyval_cache: &mut IndexLongDoubleIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_idx_long_double_previous(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_next_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_next_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_previous_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        iterator: i32,
        primary: &mut u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_previous_i64(keyval_cache.pin_mut(), iterator, primary)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_end_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_end_i64(keyval_cache.pin_mut(), code, scope, table)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_lowerbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_lowerbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn db_upperbound_i64(
        &mut self,
        keyval_cache: &mut KeyValueIteratorCache,
        code: u64,
        scope: u64,
        table: u64,
        id: u64,
    ) -> Result<i32, ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .db_upperbound_i64(keyval_cache.pin_mut(), code, scope, table, id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn remove_permission(
        &mut self,
        permission: &ffi::PermissionObject,
    ) -> Result<(), ChainError> {
        // Read the key before removal, while the object is still valid.
        #[cfg(feature = "arena-shadow")]
        let owner_perm = (
            permission.get_owner().to_uint64_t(),
            permission.get_name().to_uint64_t(),
        );
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .remove_permission(permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.remove_permission(owner_perm.0, owner_perm.1)
        {
            eprintln!("arena mirror of remove_permission diverged: {e:?}");
        }
        Ok(())
    }

    pub fn create_permission(
        &mut self,
        account: u64,
        name: u64,
        parent: u64,
        auth: &Authority,
        creation_time: &TimePoint,
    ) -> Result<*const ffi::PermissionObject, ChainError> {
        let res = {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .create_permission(account, name, parent, auth, creation_time)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?
                as *const ffi::PermissionObject
        };
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(auth);
            if let Err(e) = s.create_permission(
                parent as i64,
                account,
                name,
                creation_time.elapsed.count,
                &auth_bytes,
            ) {
                eprintln!("arena mirror of create_permission diverged: {e:?}");
            }
        }
        Ok(res)
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))?;

        Ok(res)
    }

    /// Null-checked `Pin<&mut ffi::Database>` from a write guard. `UniquePtr::pin_mut`
    /// panics on a null pointer; `as_mut` lets us return an error instead.
    fn db_mut<'a>(
        guard: &'a mut RwLockWriteGuard<'_, UniquePtr<ffi::Database>>,
    ) -> Result<Pin<&'a mut ffi::Database>, ChainError> {
        guard
            .as_mut()
            .ok_or_else(|| ChainError::InternalError("Database pointer is null".to_owned()))
    }

    /// A permission's authority as an owned value, or `None` if it doesn't exist.
    ///
    /// Handing back an owned `Authority` rather than a database-bound reference is
    /// what lets a caller read a permission, drop the read lock, edit the
    /// authority, and write it back with [`Database::modify_permission`] — no
    /// reference held across the mutation and no lock held while editing, so a
    /// read-modify-write on one permission never has to nest a read inside a
    /// write.
    pub fn permission_authority(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<Authority>, ChainError> {
        let guard = self.locked_read()?;
        let perm = guard
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        // The pointer is only dereferenced while the read guard is alive, and the
        // authority is copied out before it is dropped.
        let authority = unsafe { perm.as_ref() }
            .map(|p| ffi::get_authority_from_shared_authority(p.get_authority()));
        Ok(authority)
    }

    pub fn modify_permission(
        &mut self,
        actor: u64,
        permission: u64,
        authority: &Authority,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            // Lookup and mutation both happen inside C++, so no database-owned
            // PermissionObject reference is held across the write.
            let modified = Self::db_mut(&mut guard)?
                .modify_permission_by_actor_and_permission(
                    actor,
                    permission,
                    authority,
                    pending_block_time,
                )
                .map_err(|e| ChainError::InternalError(e.to_string()))?;
            if !modified {
                return Err(ChainError::PermissionNotFound(
                    Name::new(actor).to_string(),
                    Name::new(permission).to_string(),
                ));
            }
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let auth_bytes = encode_authority(authority);
            if let Err(e) = s.modify_permission(
                actor,
                permission,
                &auth_bytes,
                pending_block_time.elapsed.count,
            ) {
                eprintln!("arena mirror of modify_permission diverged: {e:?}");
            }
        }
        Ok(())
    }

    pub fn update_permission_usage(
        &mut self,
        actor: u64,
        permission: u64,
        pending_block_time: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            // Resolve and modify under one write guard; the resolved pointer never
            // escapes this method, so no shared reference is held across the mutation.
            let perm = guard
                .find_permission_by_actor_and_permission(actor, permission)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
            if perm.is_null() {
                return Err(ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                )));
            }
            let perm = unsafe { &*perm };
            let pinned = guard.pin_mut();

            pinned
                .update_permission_usage(perm, pending_block_time)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) =
                s.update_permission_usage(actor, permission, pending_block_time.elapsed.count)
        {
            eprintln!("arena mirror of update_permission_usage diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_permission_last_used(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        if res.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { &*res }.to_uint64_t()))
    }

    pub fn get_global_properties(&self) -> Result<*const ffi::GlobalPropertyObject, ChainError> {
        let guard = self.locked_read()?;
        let res = guard
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(res)
    }

    pub fn set_global_properties(&self, cfg: &ChainConfigV0) -> Result<(), ChainError> {
        let mut guard = self.locked_write()?;
        let pinned = guard.pin_mut();

        pinned
            .set_global_properties(cfg)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        Ok(())
    }

    pub fn get_virtual_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_virtual_block_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_virtual_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_cpu_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_block_cpu_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_block_net_limit(&self) -> Result<u64, ChainError> {
        let guard = self.locked_read()?;
        guard
            .get_block_net_limit()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn is_known_unexpired_transaction(
        &self,
        trx_id: &ffi::CxxDigest,
    ) -> Result<bool, ChainError> {
        let guard = self.locked_read()?;

        guard
            .is_known_unexpired_transaction(trx_id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn record_transaction(
        &mut self,
        trx_id: &ffi::CxxDigest,
        expiration: u32,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .record_transaction(trx_id, expiration)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let id = digest_to_array(trx_id);
            if let Err(e) = s.record_transaction(id, expiration) {
                eprintln!("arena mirror of record_transaction diverged: {e:?}");
            }
        }
        Ok(())
    }

    /// Whether the arena mirror holds a dedupe row for `trx_id` — for diffing
    /// against chainbase's `is_known_unexpired_transaction`. Uses the same
    /// digest-to-bytes conversion `record_transaction` mirrors with.
    pub fn arena_transaction_exists(&self, trx_id: &ffi::CxxDigest) -> bool {
        #[cfg(feature = "arena-shadow")]
        {
            self.shadow
                .as_ref()
                .map(|s| s.transaction_exists(digest_to_array(trx_id)))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "arena-shadow"))]
        {
            let _ = trx_id;
            false
        }
    }

    pub fn clear_expired_input_transactions(
        &mut self,
        cutoff: &TimePoint,
    ) -> Result<(), ChainError> {
        {
            let mut guard = self.locked_write()?;
            let pinned = guard.pin_mut();
            pinned
                .clear_expired_input_transactions(cutoff)
                .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        }
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow
            && let Err(e) = s.clear_expired_input_transactions(cutoff.elapsed.count)
        {
            eprintln!("arena mirror of clear_expired_input_transactions diverged: {e:?}");
        }
        Ok(())
    }

    pub fn get_currency_balance_with_symbol(
        &self,
        code: u64,
        account: u64,
        symbol: &str,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_balance_with_symbol(guard.as_ref().unwrap(), code, account, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_balance_without_symbol(
        &self,
        code: u64,
        account: u64,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_balance_without_symbol(guard.as_ref().unwrap(), code, account)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_currency_stats(&self, code: u64, symbol: &str) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_currency_stats(guard.as_ref().unwrap(), code, symbol)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_by_scope(
        &self,
        code: u64,
        table: u64,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        reverse: bool,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_table_by_scope(
            guard.as_ref().unwrap(),
            code,
            table,
            lower_bound,
            upper_bound,
            limit,
            reverse,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_table_rows(
        &self,
        json: bool,
        code: u64,
        scope: &str,
        table: u64,
        table_key: &str,
        lower_bound: &str,
        upper_bound: &str,
        limit: u32,
        key_type: &str,
        index_position: &str,
        encode_type: &str,
        reverse: bool,
        show_payer: bool,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_table_rows(
            guard.as_ref().unwrap(),
            json,
            code,
            scope,
            table,
            table_key,
            lower_bound,
            upper_bound,
            limit,
            key_type,
            index_position,
            encode_type,
            reverse,
            show_payer,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_info_without_core_symbol(
        &self,
        account: u64,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_account_info_without_core_symbol(
            guard.as_ref().unwrap(),
            account,
            head_block_num,
            head_block_time,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn get_account_info_with_core_symbol(
        &self,
        account: u64,
        expected_core_symbol: &str,
        head_block_num: u32,
        head_block_time: &TimePoint,
    ) -> Result<String, ChainError> {
        let guard = self.locked_read()?;

        get_account_info_with_core_symbol(
            guard.as_ref().unwrap(),
            account,
            expected_core_symbol,
            head_block_num,
            head_block_time,
        )
        .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn pack_deltas(&self, full_snapshot: bool) -> Result<Vec<u8>, ChainError> {
        let guard = self.locked_read()?;

        guard
            .pack_deltas(full_snapshot)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::string_to_name;

    use super::*;

    #[test]
    fn test_database_creation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let _name = string_to_name("test").unwrap();
        db.add_indices().unwrap();
    }

    // The hazard the guard API introduced, and the reason `check_reentry`
    // exists. Binding chainbase references to a guard stops them dangling; it
    // also means holding one across a call that locks again is a deadlock, not
    // a compile error. `Database` is an `Arc` handle and `read(&self)` borrows
    // immutably, so nothing in the type system objects — and the re-entry
    // usually arrives through a call that never names the database.
    //
    // Without the check, each of these blocks forever. `onblock_consumes_min_
    // transaction_cpu_usage` did exactly this and took CI to its six-hour limit
    // on both architectures, twice, reporting nothing.
    #[test]
    fn a_write_while_holding_a_read_view_is_refused_rather_than_deadlocking() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        // Through a *clone*, which is how this happens in practice and why the
        // borrow checker does not catch it. `Database` is an `Arc` handle: the
        // two values are distinct owners of one lock, so `&self` on one and
        // `&mut self` on the other never conflict. In the real failure the
        // clone was several frames away, inside `Controller`.
        let mut other = db.clone();
        let view = db.read().unwrap();
        let err = match other.create_undo_session(true) {
            Err(e) => e,
            Ok(_) => panic!("a mutator under a held read view must be refused"),
        };
        assert!(
            format!("{err:?}").contains("re-entered"),
            "expected a re-entry refusal, got {err:?}"
        );
        drop(view);

        // And the same call succeeds once the view is gone, so the check is
        // refusing the pattern rather than the call.
        assert!(other.create_undo_session(true).is_ok());
    }

    #[test]
    fn a_second_view_while_holding_a_write_view_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        let other = db.clone();
        let view = db.write().unwrap();
        assert!(
            other.read().is_err(),
            "a read under a held write view must be refused"
        );
        assert!(
            other.write().is_err(),
            "a second write view must be refused"
        );
        drop(view);

        assert!(other.read().is_ok());
    }

    // Guards must stop counting when they drop, or the first one poisons every
    // later acquisition on the thread and the check becomes the outage.
    #[test]
    fn the_count_is_released_with_the_view() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();

        for _ in 0..3 {
            let view = db.read().unwrap();
            drop(view);
            let view = db.write().unwrap();
            drop(view);
        }
        assert!(db.create_undo_session(true).is_ok());
    }

    #[test]
    fn test_pack_deltas() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        let name = string_to_name("test").unwrap();
        db.add_indices().unwrap();
        let mut session = db.create_undo_session(true).unwrap();
        let _account = db.create_account(name.to_uint64_t(), 0).unwrap();
        session.pin_mut().push().unwrap();
        let deltas = db.pack_deltas(false).unwrap();
        let hex_deltas = hex::encode(deltas);
        assert_eq!(
            hex_deltas,
            "0100076163636f756e7401010e00000000000090b1ca0000000000"
        );
    }

    #[test]
    fn activated_protocol_features_are_typed_ordered_and_undoable() {
        assert!(decode_activated_protocol_features(&[0u8; 35]).is_err());

        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut db = Database::new(path, 1 * 1024 * 1024 * 1024).unwrap();
        db.add_indices().unwrap();
        let genesis = CxxGenesisState::new(include_str!("../../../genesis.json")).unwrap();
        db.initialize_database(&genesis).unwrap();

        assert_eq!(db.activated_protocol_features().unwrap(), Vec::new());
        assert!(db.append_activated_protocol_feature([1; 32], 7).is_err());

        let mut session = db.create_undo_session(true).unwrap();
        db.append_activated_protocol_feature([1; 32], 7).unwrap();
        db.append_activated_protocol_feature([2; 32], 11).unwrap();
        assert_eq!(
            db.activated_protocol_features().unwrap(),
            vec![([1; 32], 7), ([2; 32], 11)]
        );
        session.pin_mut().undo().unwrap();
        assert_eq!(db.activated_protocol_features().unwrap(), Vec::new());

        let mut malformed_session = db.create_undo_session(true).unwrap();
        let mut guard = db.inner.write().unwrap();
        let error = guard
            .pin_mut()
            .append_activated_protocol_feature(&[0u8; 35])
            .unwrap_err();
        assert!(error.what().contains("exactly 36 bytes"));
        drop(guard);
        malformed_session.pin_mut().undo().unwrap();

        let mut committed_session = db.create_undo_session(true).unwrap();
        db.append_activated_protocol_feature([3; 32], 13).unwrap();
        committed_session.pin_mut().push().unwrap();
        assert_eq!(
            db.activated_protocol_features().unwrap(),
            vec![([3; 32], 13)]
        );
    }

    // 64 MiB is a multiple of chainbase's 1 MiB sizing requirement and leaves
    // ample room for a handful of rows, while keeping the file cheap to copy in
    // a test.
    const TEST_DB_SIZE: u64 = 64 * 1024 * 1024;

    fn name_u64(s: &str) -> u64 {
        string_to_name(s).unwrap().to_uint64_t()
    }

    #[test]
    fn snapshot_round_trips_state() {
        let src = TempDir::new().unwrap();
        let src_path = src.path().to_str().unwrap();

        let mut db = Database::new(src_path, TEST_DB_SIZE).unwrap();
        db.add_indices().unwrap();
        // Stamp the revision before any undo activity — chainbase refuses to set
        // it while an undo stack exists. Then write committed rows directly.
        db.set_revision(7).unwrap();

        let alice = name_u64("alice");
        let bob = name_u64("bob");
        db.create_account(alice, 1).unwrap();
        db.create_account(bob, 2).unwrap();

        let snap = db.snapshot_bytes().unwrap();
        assert_eq!(crate::snapshot::peek_header(&snap).unwrap().revision, 7);

        // The source database keeps working after the close/reopen cycle.
        assert!(!db.find_account(alice).unwrap().is_null());

        // Restore into a fresh directory and open it as a node would on restart.
        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        let header = restore_snapshot(dst_path, &snap).unwrap();
        assert_eq!(header.revision, 7);

        let mut db2 = Database::new(dst_path, TEST_DB_SIZE).unwrap();
        db2.add_indices().unwrap();
        assert_eq!(db2.revision(), 7);
        assert!(!db2.find_account(alice).unwrap().is_null());
        assert!(!db2.find_account(bob).unwrap().is_null());
        assert!(db2.find_account(name_u64("carol")).unwrap().is_null());

        // A file copy is faithful, so restore -> snapshot is a fixpoint: the
        // payload out of the restored arena matches the payload that went in.
        let snap2 = db2.snapshot_bytes().unwrap();
        let payload = &snap[crate::snapshot::HEADER_LEN..];
        let payload2 = &snap2[crate::snapshot::HEADER_LEN..];
        assert_eq!(payload, payload2);
    }

    #[test]
    fn restore_rejects_corrupt_snapshot() {
        let src = TempDir::new().unwrap();
        let mut db = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        db.add_indices().unwrap();

        let mut snap = db.snapshot_bytes().unwrap();
        let last = snap.len() - 1;
        snap[last] ^= 0xFF;

        let dst = TempDir::new().unwrap();
        let dst_path = dst.path().to_str().unwrap();
        assert!(restore_snapshot(dst_path, &snap).is_err());
        // The envelope is validated before anything touches disk.
        assert!(!Path::new(dst_path).join(SHARED_MEMORY_FILE).exists());
    }

    #[test]
    fn snapshot_on_closed_db_errors() {
        let db = Database::default();
        assert!(db.snapshot_bytes().is_err());
    }

    #[test]
    fn restore_from_bytes_swaps_live_state() {
        // Source arena: revision 3 with alice.
        let src = TempDir::new().unwrap();
        let mut a = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        a.add_indices().unwrap();
        a.set_revision(3).unwrap();
        let alice = name_u64("alice");
        a.create_account(alice, 1).unwrap();
        let snap = a.snapshot_bytes().unwrap();

        // Target arena: different state (revision 9 with bob).
        let dst = TempDir::new().unwrap();
        let mut b = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        b.add_indices().unwrap();
        b.set_revision(9).unwrap();
        let bob = name_u64("bob");
        b.create_account(bob, 2).unwrap();

        // Restoring the source snapshot into the live target replaces its state.
        let header = b.restore_from_bytes(&snap).unwrap();
        assert_eq!(header.revision, 3);
        assert_eq!(b.revision(), 3);
        assert!(
            !b.find_account(alice).unwrap().is_null(),
            "alice not restored"
        );
        assert!(
            b.find_account(bob).unwrap().is_null(),
            "bob's state survived"
        );

        // The target is still a working database after the swap.
        let carol = name_u64("carol");
        b.create_account(carol, 3).unwrap();
        assert!(!b.find_account(carol).unwrap().is_null());
    }

    #[test]
    fn restore_from_bytes_rejects_corrupt_without_disturbing_db() {
        let src = TempDir::new().unwrap();
        let mut a = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        a.add_indices().unwrap();
        a.set_revision(5).unwrap();
        let alice = name_u64("alice");
        a.create_account(alice, 1).unwrap();

        let mut snap = a.snapshot_bytes().unwrap();
        let last = snap.len() - 1;
        snap[last] ^= 0xFF;

        // A corrupt snapshot is rejected up front; the running database is
        // untouched and still holds its own state.
        assert!(a.restore_from_bytes(&snap).is_err());
        assert_eq!(a.revision(), 5);
        assert!(!a.find_account(alice).unwrap().is_null());
    }

    #[test]
    fn validated_restore_rejects_wrong_protocol_ledger_before_swap() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.add_indices().unwrap();
        let genesis = CxxGenesisState::new(include_str!("../../../genesis.json")).unwrap();
        source.initialize_database(&genesis).unwrap();
        let mut session = source.create_undo_session(true).unwrap();
        source
            .append_activated_protocol_feature([7; 32], 2)
            .unwrap();
        session.pin_mut().push().unwrap();
        source.commit(source.revision()).unwrap();
        let snapshot = source.snapshot_bytes().unwrap();

        let dst = TempDir::new().unwrap();
        let mut target = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        target.add_indices().unwrap();
        target.initialize_database(&genesis).unwrap();
        let keeper = name_u64("keeper");
        target.create_account(keeper, 1).unwrap();
        let revision_before = target.revision();
        let before_swap_called = std::cell::Cell::new(false);

        let error = target
            .restore_from_bytes_validated(&snapshot, &[], || {
                before_swap_called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("activation ledger"));
        assert!(!before_swap_called.get());
        assert_eq!(target.revision(), revision_before);
        assert!(!target.find_account(keeper).unwrap().is_null());
    }

    #[test]
    fn validated_restore_rejects_header_arena_revision_mismatch_before_swap() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.add_indices().unwrap();
        source.set_revision(5).unwrap();
        let snapshot = source.snapshot_bytes().unwrap();
        let (header, payload) = crate::snapshot::decode(&snapshot).unwrap();
        let mismatched = crate::snapshot::encode(header.revision + 1, payload);

        let dst = TempDir::new().unwrap();
        let mut target = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        target.add_indices().unwrap();
        target.set_revision(9).unwrap();
        let keeper = name_u64("keeper");
        target.create_account(keeper, 1).unwrap();
        let before_swap_called = std::cell::Cell::new(false);

        let error = target
            .restore_from_bytes_validated(&mismatched, &[], || {
                before_swap_called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("does not match snapshot header"));
        assert!(!before_swap_called.get());
        assert_eq!(target.revision(), 9);
        assert!(!target.find_account(keeper).unwrap().is_null());
    }

    #[test]
    fn validated_restore_rejects_mismatched_arena_size_before_swap() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.add_indices().unwrap();
        let snapshot = source.snapshot_bytes().unwrap();
        let (header, payload) = crate::snapshot::decode(&snapshot).unwrap();
        let mut wrong_size_payload = payload.to_vec();
        wrong_size_payload[..8].copy_from_slice(&(TEST_DB_SIZE * 2).to_le_bytes());
        let mismatched = crate::snapshot::encode(header.revision, &wrong_size_payload);

        let dst = TempDir::new().unwrap();
        let mut target = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        target.add_indices().unwrap();
        target.set_revision(9).unwrap();
        let keeper = name_u64("keeper");
        target.create_account(keeper, 1).unwrap();
        let before_swap_called = std::cell::Cell::new(false);

        let error = target
            .restore_from_bytes_validated(&mismatched, &[], || {
                before_swap_called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("arena size"));
        assert!(!before_swap_called.get());
        assert_eq!(target.revision(), 9);
        assert!(!target.find_account(keeper).unwrap().is_null());
    }

    #[test]
    fn restore_grows_smaller_source_arena_to_target_reservation() {
        let src = TempDir::new().unwrap();
        let mut source = Database::new(src.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        source.add_indices().unwrap();
        source.set_revision(3).unwrap();
        let alice = name_u64("alice");
        source.create_account(alice, 1).unwrap();
        let snapshot = source.snapshot_bytes().unwrap();

        let dst = TempDir::new().unwrap();
        let target_size = TEST_DB_SIZE * 2;
        let mut target = Database::new(dst.path().to_str().unwrap(), target_size).unwrap();
        target.add_indices().unwrap();
        target.set_revision(9).unwrap();
        target.restore_from_bytes(&snapshot).unwrap();

        assert_eq!(target.revision(), 3);
        assert!(!target.find_account(alice).unwrap().is_null());
        assert_eq!(
            fs::metadata(dst.path().join(SHARED_MEMORY_FILE))
                .unwrap()
                .len(),
            target_size
        );
    }

    #[test]
    fn validated_restore_catches_chainbase_open_failure_before_swap() {
        // The transport envelope and sparse encoding are valid, but the
        // expanded file is not a chainbase arena. CXX exceptions from opening
        // staged state must cross the bridge as an error, never abort the VM or
        // disturb the live database.
        let malformed_payload = crate::snapshot::sparse_begin(TEST_DB_SIZE);
        let malformed = crate::snapshot::encode(0, &malformed_payload);

        let dst = TempDir::new().unwrap();
        let mut target = Database::new(dst.path().to_str().unwrap(), TEST_DB_SIZE).unwrap();
        target.add_indices().unwrap();
        target.set_revision(9).unwrap();
        let keeper = name_u64("keeper");
        target.create_account(keeper, 1).unwrap();
        let before_swap_called = std::cell::Cell::new(false);

        let error = target
            .restore_from_bytes_validated(&malformed, &[], || {
                before_swap_called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(error.to_string().contains("validate staged arena"));
        assert!(!before_swap_called.get());
        assert_eq!(target.revision(), 9);
        assert!(!target.find_account(keeper).unwrap().is_null());
    }
}

thread_local! {
    /// Database guards this thread is currently holding, as `(reads, writes)`.
    ///
    /// Binding chainbase references to a guard removed one hazard and created
    /// another. A raw `*const CodeObject` could dangle, which the guard fixes;
    /// but a guard is a *held lock*, and `std::sync::RwLock` is not reentrant,
    /// so code that keeps one alive across a call that locks again does not
    /// fail — it stops, forever. The compiler cannot see it: `Database` is an
    /// `Arc` handle, `read(&self)` borrows immutably, and the re-entry usually
    /// arrives through something that never mentions the database at all
    /// (`controller.run_onblock(..)`), holding its own clone of the handle.
    ///
    /// So the invariant is enforced here instead. Every acquisition checks what
    /// this thread already holds and returns an error naming the problem rather
    /// than blocking on a lock only this thread can release.
    static HELD: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
}

/// Counts one held guard for the thread, and uncounts it on drop.
struct LockScope {
    write: bool,
}

impl LockScope {
    fn enter(write: bool) -> Self {
        HELD.with(|held| {
            let (r, w) = held.get();
            held.set(if write { (r, w + 1) } else { (r + 1, w) });
        });
        LockScope { write }
    }
}

impl Drop for LockScope {
    fn drop(&mut self) {
        HELD.with(|held| {
            let (r, w) = held.get();
            held.set(if self.write {
                (r, w.saturating_sub(1))
            } else {
                (r.saturating_sub(1), w)
            });
        });
    }
}

/// The two acquisitions that can only ever deadlock, refused up front.
///
/// Read-while-read is left alone: it is what the current code does on a single
/// thread and it completes. It is not *safe* — a writer queued between the two
/// reads blocks both, because this `RwLock` is fair — but rejecting it would
/// reject working paths, so it is a known hazard rather than an error here.
fn check_reentry(want_write: bool) -> Result<(), ChainError> {
    let (reads, writes) = HELD.with(|held| held.get());
    if writes > 0 || (want_write && reads > 0) {
        return Err(ChainError::InternalError(format!(
            "database lock re-entered on this thread: asking for a {} while holding {} read \
             guard(s) and {} write guard(s). std::sync::RwLock is not reentrant, so this would \
             deadlock rather than fail. Narrow the scope of the outer guard — take what you need \
             out of it in a block, drop it, and only then call back into the database.",
            if want_write { "write" } else { "read" },
            reads,
            writes,
        )));
    }
    Ok(())
}

impl Database {
    /// The write lock, refusing re-entry instead of hanging on it.
    ///
    /// Every `&mut self` method on `Database` goes through here, so a caller
    /// holding a view and calling any mutator gets an error naming the call.
    fn locked_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, UniquePtr<ffi::Database>>, ChainError> {
        check_reentry(true)?;
        Ok(self.inner.write()?)
    }

    /// The read lock, refusing only the acquisition that cannot succeed: a read
    /// taken while this thread holds the exclusive lock.
    fn locked_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, UniquePtr<ffi::Database>>, ChainError> {
        check_reentry(false)?;
        Ok(self.inner.read()?)
    }

    /// Acquire a read view. The lock is held for the lifetime of the returned
    /// `DbRead`, and every reference it hands out is bound to `&self`, so a
    /// chainbase reference can never outlive the lock or escape the view.
    pub fn read(&self) -> Result<DbRead<'_>, ChainError> {
        let guard = self.locked_read()?;
        Ok(DbRead {
            guard,
            _scope: LockScope::enter(false),
            #[cfg(feature = "arena-shadow")]
            shadow: self.shadow.clone(),
        })
    }

    /// Acquire a write view. Exposes the same reads as [`DbRead`] plus mutation,
    /// all under a single write lock, so reads and the mutations that depend on
    /// them share one guard instead of re-locking.
    pub fn write(&self) -> Result<DbWrite<'_>, ChainError> {
        let guard = self.locked_write()?;
        Ok(DbWrite {
            guard,
            _scope: LockScope::enter(true),
        })
    }
}

/// Read view over the chainbase database. Holds an [`RwLockReadGuard`] for its
/// lifetime; references returned by its methods borrow `&self` and therefore
/// cannot outlive the held lock.
pub struct DbRead<'g> {
    guard: std::sync::RwLockReadGuard<'g, UniquePtr<ffi::Database>>,
    /// Counts this guard against the thread while it lives. Declared after
    /// `guard` only for readability; drop order does not matter, since the
    /// count and the lock are released in the same scope either way.
    _scope: LockScope,
    // The arena mirror, so reads served here can be cross-checked against it
    // during execution. A cheap Arc clone; `None` when shadowing is off.
    #[cfg(feature = "arena-shadow")]
    shadow: Option<crate::shadow::ArenaShadow>,
}

impl<'g> DbRead<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        let res = unsafe { res.as_ref() };

        // The arena must answer this authorization read the same way: same
        // existence, same parent in the permission tree, same authority
        // threshold. Consensus depends on it — every transaction authorizes here.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let chainbase = res.map(|p| {
                let threshold =
                    ffi::get_authority_from_shared_authority(p.get_authority()).threshold;
                (p.get_parent_id(), threshold)
            });
            s.note_noncontract(s.permission(actor, permission) == chainbase);
        }

        Ok(res)
    }

    pub fn find_permission(&self, id: i64) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission(id)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }

    pub fn find_account(
        &self,
        account_name: u64,
    ) -> Result<Option<&ffi::AccountObject>, ChainError> {
        let res = self
            .db()
            .find_account(account_name)
            .map_err(|e| ChainError::InternalError(format!("failed to get account: {}", e)))?;
        let res = unsafe { res.as_ref() };

        // Account existence gates authorization and dispatch; the arena must
        // agree on whether the account is there.
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.note_noncontract(s.account_exists(account_name) == res.is_some());
        }

        Ok(res)
    }

    pub fn find_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<Option<&ffi::AccountMetadataObject>, ChainError> {
        let res = self.db().find_account_metadata(account_name).map_err(|e| {
            ChainError::InternalError(format!("failed to find account metadata: {}", e))
        })?;
        let res = unsafe { res.as_ref() };

        // The privileged flag changes execution (privileged contracts skip some
        // checks), so the arena must reproduce it (and existence).
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            let chainbase = res.map(|m| m.is_privileged());
            s.note_noncontract(s.account_metadata_privileged(account_name) == chainbase);
        }

        Ok(res)
    }

    pub fn get_global_properties(&self) -> Result<&ffi::GlobalPropertyObject, ChainError> {
        let res = self
            .db()
            .get_global_properties()
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(res)
    }

    /// Like [`find_account`] but errors when absent. The returned reference borrows
    /// the held guard, so it cannot outlive the lock.
    pub fn get_account(&self, account_name: u64) -> Result<&ffi::AccountObject, ChainError> {
        self.find_account(account_name)?.ok_or_else(|| {
            ChainError::InternalError(format!("account not found: {}", account_name))
        })
    }

    /// Like [`find_account_metadata`] but errors when absent.
    pub fn get_account_metadata(
        &self,
        account_name: u64,
    ) -> Result<&ffi::AccountMetadataObject, ChainError> {
        self.find_account_metadata(account_name)?.ok_or_else(|| {
            ChainError::InternalError(format!(
                "account metadata not found for account: {}",
                account_name
            ))
        })
    }

    pub fn get_code_object_by_hash(
        &self,
        code_hash: &CxxDigest,
        vm_type: u8,
        vm_version: u8,
    ) -> Result<&ffi::CodeObject, ChainError> {
        self.db()
            .get_code_object_by_hash(code_hash, vm_type, vm_version)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    /// Like [`find_permission_by_actor_and_permission`] but errors when absent.
    pub fn get_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<&ffi::PermissionObject, ChainError> {
        self.find_permission_by_actor_and_permission(actor, permission)?
            .ok_or_else(|| {
                ChainError::InternalError(format!(
                    "permission not found for actor: {} permission: {}",
                    Name::new(actor),
                    Name::new(permission)
                ))
            })
    }

    pub fn permission_satisfies_other_permission(
        &self,
        permission: &ffi::PermissionObject,
        other_permission: &ffi::PermissionObject,
    ) -> Result<bool, ChainError> {
        self.db()
            .permission_satisfies_other_permission(permission, other_permission)
            .map_err(|e| ChainError::TransactionError(format!("{}", e)))
    }

    pub fn get_permission_last_used(
        &self,
        permission: &ffi::PermissionObject,
    ) -> Result<TimePoint, ChainError> {
        self.db()
            .get_permission_last_used(permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))
    }

    pub fn lookup_linked_permission(
        &self,
        account: u64,
        code: u64,
        requirement_type: u64,
    ) -> Result<Option<u64>, ChainError> {
        let res = self
            .db()
            .lookup_linked_permission(account, code, requirement_type)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;

        let linked = if res.is_null() {
            None
        } else {
            Some(unsafe { &*res }.to_uint64_t())
        };

        // linkauth resolution feeds authorization: the arena must resolve the
        // same linked permission (or agree there's none).
        #[cfg(feature = "arena-shadow")]
        if let Some(s) = &self.shadow {
            s.note_noncontract(s.permission_link(account, code, requirement_type) == linked);
        }

        Ok(linked)
    }
}

/// Write view over the chainbase database. Wraps a write guard and exposes the
/// same reads as [`DbRead`] (via [`DbWrite::reads`]) plus mutating operations.
pub struct DbWrite<'g> {
    guard: std::sync::RwLockWriteGuard<'g, UniquePtr<ffi::Database>>,
    _scope: LockScope,
}

impl<'g> DbWrite<'g> {
    fn db(&self) -> &ffi::Database {
        &self.guard
    }

    pub fn find_permission_by_actor_and_permission(
        &self,
        actor: u64,
        permission: u64,
    ) -> Result<Option<&ffi::PermissionObject>, ChainError> {
        let res = self
            .db()
            .find_permission_by_actor_and_permission(actor, permission)
            .map_err(|e| ChainError::InternalError(format!("{}", e)))?;
        Ok(unsafe { res.as_ref() })
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(UniquePtr::null())),
            path: String::new(),
            size: 0,
            #[cfg(feature = "arena-shadow")]
            shadow: None,
        }
    }
}

unsafe impl Send for Database {}
unsafe impl Sync for Database {}

/// Install a physical snapshot into `db_path`, ready to be opened normally.
///
/// The envelope is validated (magic, version, checksum) before anything touches
/// disk, so a corrupt transfer is rejected here rather than surfacing as a
/// chainbase open failure. The payload is written verbatim as
/// `shared_memory.bin`; the snapshot was taken from a cleanly-closed mapping, so
/// its dirty flag is clear and the directory opens without `allow_dirty`.
///
/// The caller must hold no open handle to `db_path` — this replaces the arena
/// file wholesale. It is meant to run during bootstrap, before the controller
/// opens the database. Returns the decoded header (notably the revision) so the
/// caller can reconcile its block logs against the restored state.
pub fn restore_snapshot(
    db_path: &str,
    snapshot: &[u8],
) -> Result<crate::snapshot::SnapshotHeader, ChainError> {
    let (header, payload) = crate::snapshot::decode(snapshot)?;
    fs::create_dir_all(db_path)
        .map_err(|e| ChainError::InternalError(format!("restore: create {db_path}: {e}")))?;
    let file = Path::new(db_path).join(SHARED_MEMORY_FILE);
    Database::write_sparse_snapshot(&file, payload)?;
    Ok(header)
}
