//! Record the frozen XPR schedule and the post-H emptiness proof into a
//! migration manifest.
//!
//! These are the file-format halves of `xpr_attach_source_block`: the example
//! owns CLI parsing and file IO, while everything that interprets bytes
//! lives here so unit tests can drive it against the real restore gate.
//! The wire layout packed here must stay byte-identical to the layout the
//! gate's `verify_migration_post_chain` parses: hand-rolled packing is
//! deliberate, so a shared-serializer change can never silently move the
//! consensus bytes.

use std::{
    collections::VecDeque,
    str::FromStr,
};

use chrono::NaiveDateTime;
use pulsevm_crypto::{
    Digest,
    k1::K1PublicKey,
};
use serde_json::Value;

use crate::{
    block::{
        BlockHeader,
        SignedBlock,
        SignedBlockHeader,
    },
    crypto::Signature,
    id::Id,
    name::Name,
};
use pulsevm_database::{
    BlockTimestamp,
    HaltWeight,
    MigrationHaltRosterEntry,
    MigrationManifest,
    MigrationMemoAccount,
};

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("source block field {field} is missing or not a string"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("source block field {field} is missing or not an integer"))
}

fn parse_digest(value: &str) -> Result<Digest, String> {
    let bytes =
        hex::decode(value).map_err(|error| format!("digest is not hexadecimal: {error}"))?;
    Ok(Digest(bytes.try_into().map_err(|_| {
        "digest must contain exactly 32 bytes".to_string()
    })?))
}

fn parse_extensions(value: Option<&Value>) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| "header_extensions is not an array".to_string())?;
    entries
        .iter()
        .map(|entry| {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| "header extension is not an [id, hex] pair".to_string())?;
            let id = pair[0]
                .as_u64()
                .ok_or_else(|| "header extension id is not an integer".to_string())?
                .try_into()
                .map_err(|_| "header extension id does not fit u16".to_string())?;
            let payload = pair[1]
                .as_str()
                .ok_or_else(|| "header extension payload is not a string".to_string())?;
            let payload = hex::decode(payload)
                .map_err(|error| format!("header extension payload is not hex: {error}"))?;
            Ok((id, payload))
        })
        .collect()
}

/// One `get_block` response's timestamp as an Antelope slot: block slots
/// count 500ms steps from the Antelope epoch. `source` names the file in
/// diagnostics only.
pub fn boundary_block_slot(value: &Value, source: &str) -> Result<u32, String> {
    let text = required_str(value, "timestamp")
        .map_err(|error| format!("block {source} timestamp unreadable: {error}"))?;
    parse_slot(text).map_err(|error| format!("block {source} timestamp invalid: {error}"))
}

/// One `get_block` response's timestamp on the deferred rows' clock
/// (Unix microseconds): block slots count 500ms steps from the Antelope
/// epoch, while deferred `delay_until`/`expiration` are Unix `time_point`
/// microseconds. `source` names the file in diagnostics only.
pub fn boundary_block_unix_micros(value: &Value, source: &str) -> Result<i64, String> {
    let text = required_str(value, "timestamp")
        .map_err(|error| format!("post-H block {source} timestamp unreadable: {error}"))?;
    let slot = parse_slot(text)
        .map_err(|error| format!("post-H block {source} timestamp invalid: {error}"))?;
    Ok(pulsevm_database::antelope_slot_to_unix_micros(slot))
}

/// Deferred-inventory window from staged block responses: the H response
/// opens the window at its header time, the last staged post-H response
/// closes it — or H itself when no post-H headers are staged (legacy
/// commitment path without the two-step pair; the pair always stages a
/// window past H). Each entry is `(source, response)` with `source`
/// naming the file in diagnostics only.
pub fn post_window_unix_micros(
    halt: &Value,
    posts: &[(&str, &Value)],
) -> Result<(i64, i64), String> {
    let start = boundary_block_unix_micros(halt, "cutover block")?;
    let mut end = start;
    for (source, response) in posts {
        let value = response.get("result").unwrap_or(response);
        // The latest observed header time closes the window: a deferred
        // due by any staged header is due in-window.
        end = end.max(boundary_block_unix_micros(value, source)?);
    }
    if end < start {
        return Err(format!(
            "post-H headers end ({end}) before the cutover block ({start}): refusing an unorderable window"
        ));
    }
    Ok((start, end))
}

fn parse_slot(value: &str) -> Result<u32, String> {
    let format = if value.contains('.') {
        "%Y-%m-%dT%H:%M:%S%.f"
    } else {
        "%Y-%m-%dT%H:%M:%S"
    };
    let timestamp = NaiveDateTime::parse_from_str(value.trim_end_matches('Z'), format)
        .map_err(|error| format!("timestamp: {error}"))?;
    let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
        .expect("valid Antelope epoch")
        .and_hms_opt(0, 0, 0)
        .expect("valid Antelope epoch time");
    let milliseconds = (timestamp - epoch).num_milliseconds();
    if milliseconds < 0 || milliseconds % 500 != 0 {
        return Err("timestamp is before the Antelope epoch or not slot-aligned".into());
    }
    (milliseconds / 500)
        .try_into()
        .map_err(|_| "timestamp slot does not fit u32".to_string())
}

/// Parse one `get_block` response into a signed block, enforcing the
/// boundary shape: no producer schedule change, no unsupported block
/// extensions. Whether transactions are allowed depends on the caller:
/// post-H headers must be empty (the window proves nothing landed after
/// the freeze), while the cutover block H itself is an ordinary
/// source-chain block and may carry traffic — the snapshot covers the
/// state its transactions produced. Shared by the H anchor and every
/// post-H header so both run the same shape check otherwise.
pub fn parse_boundary_block(
    value: &Value,
    allow_transactions: bool,
) -> Result<SignedBlock, String> {
    let transactions = value
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| "source block has no transactions array".to_string())?;
    if !allow_transactions && !transactions.is_empty() {
        return Err("source block is not empty; select an empty snapshot boundary".into());
    }
    if value
        .get("new_producers")
        .is_some_and(|new_producers| !new_producers.is_null())
    {
        return Err("source block carries a producer schedule change".into());
    }
    let block_extensions = value.get("block_extensions");
    if block_extensions.is_some_and(|extensions| {
        !extensions.is_null() && extensions.as_array().is_none_or(|items| !items.is_empty())
    }) {
        return Err("source block carries unsupported block extensions".into());
    }
    let header_extensions = parse_extensions(value.get("header_extensions"))?;
    Ok(SignedBlock {
        signed_block_header: SignedBlockHeader {
            header: BlockHeader {
                timestamp: BlockTimestamp::new(parse_slot(required_str(value, "timestamp")?)?),
                producer: Name::from_str(required_str(value, "producer")?)
                    .map_err(|error| format!("producer: {error}"))?,
                confirmed: required_u64(value, "confirmed")?
                    .try_into()
                    .map_err(|_| "confirmed does not fit u16".to_string())?,
                previous: Id::from_str(required_str(value, "previous")?)
                    .map_err(|error| format!("previous: {error}"))?,
                transaction_mroot: parse_digest(required_str(value, "transaction_mroot")?)?,
                action_mroot: parse_digest(required_str(value, "action_mroot")?)?,
                schedule_version: required_u64(value, "schedule_version")?
                    .try_into()
                    .map_err(|_| "schedule_version does not fit u32".to_string())?,
                new_producers: None,
                header_extensions,
            },
            signature: Signature::from_str(required_str(value, "producer_signature")?)
                .map_err(|error| format!("producer_signature: {error}"))?,
        },
        transactions: VecDeque::new(),
        block_extensions: Vec::new(),
    })
}

fn push_varuint32(bytes: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Pack one boundary header in the gate's wire layout (timestamp, producer,
/// confirmed, previous, roots, schedule version, schedule-change flag,
/// header extensions): the exact bytes Leap hashes for the block id and the
/// producer signs over. Shared by the H entry and every post-H entry so the
/// two can never drift apart; the hand-rolled packing stays byte-identical
/// to `BlockHeader::pack` for boundary headers by construction (the id
/// cross-checks on both sides prove it on every run).
fn pack_block_header_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.timestamp.slot().to_le_bytes());
    bytes.extend_from_slice(&header.producer.as_u64().to_le_bytes());
    bytes.extend_from_slice(&header.confirmed.to_le_bytes());
    bytes.extend_from_slice(header.previous.as_bytes());
    bytes.extend_from_slice(&header.transaction_mroot.0);
    bytes.extend_from_slice(&header.action_mroot.0);
    bytes.extend_from_slice(&header.schedule_version.to_le_bytes());
    bytes.push(0); // no schedule change (boundary-checked by every caller)
    push_varuint32(&mut bytes, header.header_extensions.len() as u32);
    for (id, payload) in &header.header_extensions {
        bytes.extend_from_slice(&id.to_le_bytes());
        push_varuint32(&mut bytes, payload.len() as u32);
        bytes.extend_from_slice(payload);
    }
    bytes
}

/// The recorded schedule as a producer-name to signing-key map. Shared by
/// the H entry and the post-H window so both resolve producers against the
/// same set the gate compares to the declaration.
fn recorded_schedule_keys(
    roster: &[MigrationHaltRosterEntry],
) -> Result<std::collections::BTreeMap<String, K1PublicKey>, String> {
    let mut keys = std::collections::BTreeMap::new();
    for entry in roster {
        let key = K1PublicKey::from_string(&entry.key).map_err(|error| {
            format!(
                "recorded schedule key for {} invalid: {error:?}",
                entry.producer
            )
        })?;
        if keys.insert(entry.producer.clone(), key).is_some() {
            return Err(format!("recorded schedule names {} twice", entry.producer));
        }
    }
    Ok(keys)
}

/// Record the frozen active schedule from H's header state
/// (`get_block_header_state`, captured by coordinator infra in the same
/// poll iteration that first observes head == H): every active producer at
/// unit weight with its schedule signing key. `source` names the file in
/// diagnostics only. The restore gate requires this schedule to equal the
/// declared set exactly. The state must be captured at the freeze — header
/// state is served only while reversible, and no export nodeos can serve H
/// later (a node hydrated from the H snapshot takes H as its irreversible
/// base). A live-network `get_producer_schedule` response is
/// exporter-pointed and cannot authenticate the committee — so the
/// `active_schedule` envelope is required; the bare `active` envelope of a
/// live query is refused.
/// Fills in `halt_schedule_version` when the contract-ceremony path did
/// not pin one already; a conflict between the two fails closed.
pub fn record_halt_schedule(
    manifest: &mut MigrationManifest,
    schedule: &Value,
    source: &str,
    expected_version: u32,
) -> Result<usize, String> {
    let active = schedule.get("active_schedule").ok_or_else(|| {
        format!(
            "schedule {source} has no active_schedule: record the frozen schedule from H's header state (captured at the freeze), not from a live get_producer_schedule query"
        )
    })?;
    let version: u32 = active
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("schedule {source} has no active version"))?
        .try_into()
        .map_err(|_| format!("schedule {source} version does not fit u32"))?;
    if version != expected_version {
        return Err(format!(
            "schedule {source} version {version} does not match the H schedule version {expected_version}"
        ));
    }
    let producers = active
        .get("producers")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("schedule {source} has no active producers"))?;
    if producers.is_empty() {
        return Err(format!("schedule {source} carries no producers"));
    }
    // A checkpoint taken mid-rotation would boot the new chain with a
    // pending proposal the ceremony never froze. The header state must
    // carry no pending schedule: absence is recorded into the manifest
    // (the gate requires `Some(false)`), anything staged fails fast here
    // instead of shipping an unbootable manifest. This is derived from the
    // same header state the roster comes from — never hand-typed — so the
    // attestation cannot diverge from the recorded schedule. The header
    // state carries the pending schedule nested under `pending_schedule`
    // (with its own `schedule` object); a live-query `pending`/`proposed`
    // envelope is refused along with the live schedule itself.
    if schedule.get("pending").is_some() || schedule.get("proposed").is_some() {
        return Err(format!(
            "schedule {source} is a live get_producer_schedule envelope: record the frozen schedule from H's header state (captured at the freeze)"
        ));
    }
    let pending_staged = schedule
        .get("pending_schedule")
        .and_then(|pending| pending.get("schedule"))
        .and_then(|schedule| schedule.get("producers"))
        .and_then(Value::as_array)
        .is_some_and(|producers| !producers.is_empty());
    if pending_staged {
        return Err(format!(
            "schedule {source} stages a pending producer schedule: freeze the ceremony after it activates"
        ));
    }
    manifest.halt_proposed_schedule = Some(false);
    let mut roster = Vec::with_capacity(producers.len());
    for producer in producers {
        let name = producer
            .get("producer_name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("schedule {source} producer has no producer_name"))?;
        // Leap 4+ schedules carry the block-signing key inside the producer
        // authority (outer threshold plus threshold-and-keys), not a flat
        // block_signing_key field. Only a single-key, threshold-1 authority
        // maps to one roster key; anything else fails closed rather than
        // guessing which key signs the producer's blocks.
        let authority = producer
            .get("authority")
            .and_then(|authority| authority.as_array())
            .ok_or_else(|| format!("schedule {source} producer {name} has no authority"))?;
        let [tag, versioned] = authority.as_slice() else {
            return Err(format!(
                "schedule {source} producer {name} authority is not a versioned pair"
            ));
        };
        // Leap 4 serves the v0 authority at tag 0, Leap 5 at tag 1; both
        // carry the threshold-and-keys object. Anything else is a shape
        // the exporter must not guess at.
        let known = tag.as_u64().is_some_and(|tag| tag <= 1);
        if !known {
            return Err(format!(
                "schedule {source} producer {name} authority has unknown variant tag {tag}"
            ));
        }
        let threshold = versioned
            .get("threshold")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("schedule {source} producer {name} authority has no threshold")
            })?;
        if threshold != 1 {
            return Err(format!(
                "schedule {source} producer {name} authority threshold is {threshold}, not 1"
            ));
        }
        let keys = versioned
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("schedule {source} producer {name} authority has no keys"))?;
        let [entry] = keys.as_slice() else {
            return Err(format!(
                "schedule {source} producer {name} authority does not name exactly one block-signing key"
            ));
        };
        let key = entry
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("schedule {source} producer {name} authority key has no key"))?;
        K1PublicKey::from_string(key)
            .map_err(|error| format!("schedule key for {name} is not a K1 key: {error:?}"))?;
        if roster
            .iter()
            .any(|entry: &MigrationHaltRosterEntry| entry.producer == name)
        {
            return Err(format!("schedule {source} names {name} twice"));
        }
        roster.push(MigrationHaltRosterEntry {
            producer: name.to_string(),
            key: key.to_string(),
            weight: HaltWeight::MEMBER,
        });
    }
    let count = roster.len();
    match manifest.halt_schedule_version {
        Some(pinned) if pinned != version => {
            return Err(format!(
                "schedule {source} version {version} conflicts with the recorded schedule version {pinned}"
            ));
        }
        Some(_) => {}
        None => manifest.halt_schedule_version = Some(version),
    }
    manifest.halt_schedule = Some(roster);
    Ok(count)
}

/// Leap's block-signature digest, mirrored from the consensus rule
/// (`block_header_state::sig_digest`): the producer signs
/// `sha256(sha256(sha256(header) || blockroot_root) || pending_schedule_hash)`,
/// with the root read as the blockroot Merkle's last active node
/// (`incremental_merkle::get_root`), not the bare header digest. The
/// blockroot root commits the header to its full ancestry and the
/// schedule hash binds the pending schedule; both inputs are
/// authenticated by the signature itself (only the true pair recovers to
/// the signing key), so the gate can trust the recorded values after
/// re-verifying the signature. See `verify_migration_post_chain` for the
/// identical computation at boot.
pub fn leap_sig_digest(
    header_digest: &[u8; 32],
    blockroot_root: &[u8; 32],
    schedule_hash: &[u8; 32],
) -> [u8; 32] {
    // Inner: sha256 of the header digest concatenated with the root —
    // the header bytes are NOT re-hashed with the root.
    let mut digest_and_root = Vec::with_capacity(64);
    digest_and_root.extend_from_slice(header_digest);
    digest_and_root.extend_from_slice(blockroot_root);
    let header_bound = Digest::hash(&digest_and_root).0;
    let mut bound_and_schedule = Vec::with_capacity(64);
    bound_and_schedule.extend_from_slice(&header_bound);
    bound_and_schedule.extend_from_slice(schedule_hash);
    Digest::hash(&bound_and_schedule).0
}

/// Read one `get_block_header_state` response down to the two signature
/// inputs the header alone cannot supply: the blockroot Merkle root (the
/// last active node — the repo's `IncrementalBlockMerkle::root` reads the
/// same element) and the pending schedule hash, served verbatim so no
/// Leap packing has to be reproduced.
pub fn read_post_state(state: &Value, source: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let nodes = state
        .get("blockroot_merkle")
        .and_then(|merkle| merkle.get("_active_nodes"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("post-H state {source} has no blockroot active nodes"))?;
    let root_hex = nodes
        .last()
        .and_then(Value::as_str)
        .ok_or_else(|| format!("post-H state {source} has an empty blockroot"))?;
    let root: [u8; 32] = hex::decode(root_hex)
        .map_err(|error| format!("post-H state {source} blockroot is not hex: {error}"))?
        .try_into()
        .map_err(|_| format!("post-H state {source} blockroot is not 32 bytes"))?;
    let hash_hex = state
        .get("pending_schedule")
        .and_then(|pending| pending.get("schedule_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("post-H state {source} has no pending schedule hash"))?;
    let schedule_hash: [u8; 32] = hex::decode(hash_hex)
        .map_err(|error| format!("post-H state {source} schedule hash is not hex: {error}"))?
        .try_into()
        .map_err(|_| format!("post-H state {source} schedule hash is not 32 bytes"))?;
    Ok((root, schedule_hash))
}

/// Record post-H headers from `get_block` responses and authenticate each
/// one at record time: the header hash-links from the trusted H id with
/// ascending numbers, carries an empty transaction root, introduces no
/// schedule change, and its producer signature — over Leap's signature
/// digest (header, blockroot, schedule hash) — recovers to the recorded
/// schedule key for its producer. `states` carries the matching
/// `get_block_header_state` responses in the same order; `source` names the
/// file in diagnostics only. The packed hex (`root || schedule-hash ||
/// header || signature || counts || block-id`) is what the restore gate
/// re-verifies, so the packing here must stay byte-identical to its wire
/// layout. The trailing id is the header-derived block id (Leap's formula,
/// checked against the response's stated id above): both sides recompute
/// it instead of chaining stated bytes.
pub fn record_post_blocks(
    manifest: &mut MigrationManifest,
    halt_id: &Id,
    halt_height: u32,
    halt_schedule_version: u32,
    blocks: &[(&str, &Value)],
    states: &[(&str, &Value)],
) -> Result<usize, String> {
    if blocks.len() != states.len() {
        return Err(format!(
            "post-H headers need one header state each: {} blocks but {} states",
            blocks.len(),
            states.len()
        ));
    }
    let roster = manifest.halt_schedule.as_ref().ok_or_else(|| {
        "post-H headers need a recorded schedule: record --halt-state first, or attach a declaration pair carrying the roster".to_string()
    })?;
    let keys = recorded_schedule_keys(roster)?;
    // No hash pin on the state's pending schedule: with no staged change
    // Leap serves the EMPTY pending schedule, whose hash cannot equal the
    // active roster's (proven against live header states). The signature
    // itself binds the exact (root, hash) pair — only the true pair
    // recovers to the roster key — so a forged state fails at recovery,
    // not at a comparison.
    let halt_bytes = halt_id.as_bytes();
    let mut expected_previous: [u8; 32] = halt_bytes
        .try_into()
        .map_err(|_| "halt block id is not 32 bytes".to_string())?;
    let mut expected_num = halt_height
        .checked_add(1)
        .ok_or_else(|| "halt height overflows u32".to_string())?;
    let mut packed_all = Vec::with_capacity(blocks.len());
    for ((source, response), (state_source, state)) in blocks.iter().zip(states.iter()) {
        let value = response.get("result").unwrap_or(response);
        let block = parse_boundary_block(value, false)
            .map_err(|error| format!("post-H block {source}: {error}"))?;
        let header = &block.signed_block_header.header;
        let parent_num = u32::from_be_bytes(
            expected_previous[0..4]
                .try_into()
                .map_err(|_| format!("post-H block {source} has a malformed parent id"))?,
        );
        if parent_num.checked_add(1) != Some(expected_num) {
            return Err(format!(
                "post-H block {source} does not follow its parent height"
            ));
        }
        if header.previous.as_bytes() != expected_previous {
            return Err(format!(
                "post-H block {source} does not hash-link to its parent"
            ));
        }
        if header.transaction_mroot != Digest([0u8; 32]) {
            return Err(format!(
                "post-H block {source} is not empty: transaction root is set"
            ));
        }
        if header.schedule_version != halt_schedule_version {
            return Err(format!(
                "post-H block {source} rotates the schedule version to {}",
                header.schedule_version
            ));
        }
        // The block id is derived from the parsed header — Leap's formula
        // (sha256 of the packed header with the number spliced into the
        // first four bytes, as `SignedBlock::id` computes) — and the
        // response's stated id must equal the recomputation exactly. The
        // trailing entry id the gate replays is this derived id, so an
        // empty sibling stated under the real block's number never enters
        // the proof. It runs after the shape checks above so a malformed
        // header keeps its own diagnostic; the number check below proves
        // the derived id belongs to this height.
        let stated_id: [u8; 32] = value
            .get("id")
            .and_then(Value::as_str)
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("post-H block {source} has no 32-byte id"))?;
        let derived_id: [u8; 32] = block
            .id()
            .map_err(|error| format!("post-H block {source} id cannot be derived: {error}"))?
            .as_bytes()
            .try_into()
            .map_err(|_| format!("post-H block {source} derived id is not 32 bytes"))?;
        if stated_id != derived_id {
            return Err(format!(
                "post-H block {source} stated id does not derive from its header"
            ));
        }
        if stated_id[0..4] != expected_num.to_be_bytes() {
            return Err(format!(
                "post-H block {source} id does not carry its own height"
            ));
        }
        let state_value = state.get("result").unwrap_or(state);
        let (blockroot_root, schedule_hash) = read_post_state(state_value, state_source)
            .map_err(|error| format!("post-H block {source}: {error}"))?;
        // The header state must be for this block: its id must equal the
        // derived block id, or a state from another height (with another
        // blockroot) could be paired with this header. This runs after
        // the field checks above so malformed states keep their own
        // diagnostic.
        let state_id = state_value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("post-H block {source} header state has no block id"))?;
        if state_id != hex::encode(stated_id) {
            return Err(format!(
                "post-H block {source} header state is for block {state_id}, not the staged block"
            ));
        }
        let header_bytes = pack_block_header_bytes(header);
        // The recorded proof leads with the two signature inputs the header
        // cannot supply, so the gate recomputes Leap's digest from the packed
        // bytes alone.
        let mut packed = Vec::with_capacity(64 + header_bytes.len() + 67);
        packed.extend_from_slice(&blockroot_root);
        packed.extend_from_slice(&schedule_hash);
        packed.extend_from_slice(&header_bytes);
        let header_digest = Digest::hash(&header_bytes).0;
        let digest = leap_sig_digest(&header_digest, &blockroot_root, &schedule_hash);
        let signature_str = value
            .get("producer_signature")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("post-H block {source} has no producer_signature"))?;
        let signature = pulsevm_crypto::k1::K1Signature::from_string(signature_str)
            .map_err(|error| format!("post-H block {source} signature is not K1: {error:?}"))?;
        let recovered = signature.recover(&digest).map_err(|error| {
            format!("post-H block {source} signature does not recover: {error:?}")
        })?;
        let producer_name = header.producer.to_string();
        let expected_key = keys.get(&producer_name).ok_or_else(|| {
            format!(
                "post-H block {source} producer {producer_name} is not in the recorded schedule"
            )
        })?;
        if recovered != *expected_key {
            return Err(format!(
                "post-H block {source} is not signed by the recorded schedule key for {producer_name}"
            ));
        }
        packed.push(0); // K1 tag
        packed.extend_from_slice(&signature.compact65());
        packed.push(0); // no transactions (boundary-checked above)
        packed.push(0); // no block extensions
        packed.extend_from_slice(&stated_id);
        expected_previous = stated_id;
        expected_num = expected_num
            .checked_add(1)
            .ok_or_else(|| "post-H height overflows u32".to_string())?;
        packed_all.push(hex::encode(&packed));
    }
    let count = packed_all.len();
    manifest.halt_post_blocks = Some(packed_all);
    Ok(count)
}

/// Record the memo-vehicle declaration accounts from harness-captured
/// `get_account` responses (a JSON list of `{"name", "account": {created,
/// ...}, ...}` in chunk order — a map would lose the chunk order because
/// JSON objects are unordered): every name must re-decode to the
/// declaration digest and every account must predate H (by Antelope slot),
/// otherwise the declaration's on-chain landing is unproven and the record
/// fails fast. The digest comes from the manifest's recorded declaration;
/// `h_slot` is H's slot (from the H block response's timestamp). The names
/// are deterministic from the digest (`h` + round letter + hex nibbles
/// mapped to `a`–`p`), so this re-derives the harness's chain scan instead
/// of trusting it. Returns the recorded account count. Existence in
/// checkpoint state is checked at restore (and by the offline verifier),
/// where the state is available.
pub fn record_memo_accounts(
    manifest: &mut MigrationManifest,
    memo_accounts: &Value,
    h_slot: u32,
    source: &str,
) -> Result<usize, String> {
    let declaration = manifest
        .halt_declaration
        .as_ref()
        .ok_or_else(|| "memo accounts need a recorded declaration to decode against".to_string())?;
    let digest = declaration
        .digest()
        .map_err(|error| format!("memo accounts need a valid declaration digest: {error:?}"))?;
    let expected = hex::encode(digest);
    let accounts = memo_accounts.as_array().ok_or_else(|| {
        format!("memo accounts {source} is not a chunk-ordered list of name/account pairs")
    })?;
    if accounts.is_empty() {
        return Err(format!(
            "memo accounts {source} records no accounts: stage the declaration accounts or drop the file"
        ));
    }
    let mut all = String::with_capacity(64);
    let mut recorded = Vec::with_capacity(accounts.len());
    for entry in accounts {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("memo accounts {source} entry has no name"))?;
        let account = entry.get("account").ok_or_else(|| {
            format!("memo account {name} in {source} has no get_account response")
        })?;
        let mut chars = name.chars();
        let (Some('h'), Some(_round), rest) = (chars.next(), chars.next(), chars.as_str()) else {
            return Err(format!(
                "memo account {name} in {source} does not carry the declaration digest"
            ));
        };
        if rest.is_empty() || !rest.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
            return Err(format!(
                "memo account {name} in {source} does not carry the declaration digest"
            ));
        }
        for byte in rest.bytes() {
            let hex = if byte <= b'j' {
                b'0' + (byte - b'a')
            } else {
                b'a' + (byte - b'k')
            };
            all.push(hex as char);
        }
        let created = account
            .get("created")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("memo account {name} in {source} has no creation time"))?;
        let created_slot = parse_slot(created)
            .map_err(|error| format!("memo account {name} creation time invalid: {error}"))?;
        if created_slot >= h_slot {
            return Err(format!(
                "memo account {name} in {source} was created at slot {created_slot} (H is slot {h_slot}): the declaration must land before H"
            ));
        }
        recorded.push(MigrationMemoAccount {
            name: name.to_string(),
            created_slot,
        });
    }
    if all != expected {
        return Err(format!(
            "memo accounts in {source} do not decode to the declaration digest"
        ));
    }
    let count = recorded.len();
    manifest.halt_memo_accounts = Some(recorded);
    Ok(count)
}

/// Record the cutover block H itself as a gate entry (root ||
/// schedule-hash || header || signature || block-id — no counts: H may
/// carry traffic), authenticated like a post-H header minus the emptiness
/// proof: H's schedule version, no schedule rotation, and a producer
/// signature — over Leap's true digest with H's header-state root and
/// pending schedule hash — that recovers to the recorded schedule key for
/// H's producer. The entry's derived id must equal the trusted H id, so
/// the window opens on the block the confirmation binds, not on an
/// exporter substitution. `halt` is the `get_block` response for H,
/// `halt_state` its `get_block_header_state` response; `source` names the
/// files in diagnostics only.
pub fn record_halt_block(
    manifest: &mut MigrationManifest,
    halt: &Value,
    halt_state: &Value,
    halt_id: &Id,
    halt_height: u32,
    halt_schedule_version: u32,
    source: &str,
) -> Result<String, String> {
    let roster = manifest.halt_schedule.as_ref().ok_or_else(|| {
        "the H entry needs a recorded schedule from H's header state (--halt-state), or attach a declaration pair carrying the roster".to_string()
    })?;
    let keys = recorded_schedule_keys(roster)?;
    let value = halt.get("result").unwrap_or(halt);
    let block = parse_boundary_block(value, true)
        .map_err(|error| format!("cutover block {source}: {error}"))?;
    let header = &block.signed_block_header.header;
    // H itself is an ordinary source-chain block: it may carry traffic
    // (the snapshot covers the state its transactions produced), so no
    // emptiness check. Only the post-H window must be empty.
    if header.schedule_version != halt_schedule_version {
        return Err(format!(
            "cutover block {source} rotates the schedule version to {}",
            header.schedule_version
        ));
    }
    for (id, _) in &header.header_extensions {
        if *id == 1 {
            return Err(format!(
                "cutover block {source} carries a producer schedule change"
            ));
        }
    }
    let header_bytes = pack_block_header_bytes(header);
    let header_digest = Digest::hash(&header_bytes).0;
    // The entry must open on the trusted H: the confirmation binds this id,
    // so a substituted H fails here instead of anchoring the window. This
    // runs before the state checks so a wrong anchor keeps its own
    // diagnostic.
    let mut derived_id = header_digest;
    derived_id[0..4].copy_from_slice(&halt_height.to_be_bytes());
    if derived_id.as_slice() != halt_id.as_bytes() {
        return Err(format!(
            "cutover block {source} id does not derive to the trusted cutover id"
        ));
    }
    let state_value = halt_state.get("result").unwrap_or(halt_state);
    // The header state must be FOR H: its block id must equal the trusted
    // cutover id, or a state from another height (with another schedule)
    // could smuggle a foreign committee into the window.
    let state_id = state_value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("cutover block {source} header state has no block id"))?;
    if state_id != hex::encode(halt_id.as_bytes()) {
        return Err(format!(
            "cutover block {source} header state is for block {state_id}, not the trusted cutover block"
        ));
    }
    let (blockroot_root, schedule_hash) = read_post_state(state_value, source)
        .map_err(|error| format!("cutover block {source}: {error}"))?;
    let digest = leap_sig_digest(&header_digest, &blockroot_root, &schedule_hash);
    let signature_str = value
        .get("producer_signature")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("cutover block {source} has no producer_signature"))?;
    let signature = pulsevm_crypto::k1::K1Signature::from_string(signature_str)
        .map_err(|error| format!("cutover block {source} signature is not K1: {error:?}"))?;
    let recovered = signature
        .recover(&digest)
        .map_err(|error| format!("cutover block {source} signature does not recover: {error:?}"))?;
    let producer_name = header.producer.to_string();
    let expected_key = keys.get(&producer_name).ok_or_else(|| {
        format!("cutover block {source} producer {producer_name} is not in the recorded schedule")
    })?;
    if recovered != *expected_key {
        return Err(format!(
            "cutover block {source} is not signed by the recorded schedule key for {producer_name}"
        ));
    }
    // The H entry carries no transaction/block-extension counts: H may
    // carry traffic, and the entry proves the anchor (id, signature,
    // version), not the contents — emptiness is the post-H window's job.
    // The derived id was already checked against the trusted H above, so
    // the packed entry opens on exactly the block the confirmation binds.
    let mut derived_id = header_digest;
    derived_id[0..4].copy_from_slice(&halt_height.to_be_bytes());
    let mut packed = Vec::with_capacity(64 + header_bytes.len() + 65);
    packed.extend_from_slice(&blockroot_root);
    packed.extend_from_slice(&schedule_hash);
    packed.extend_from_slice(&header_bytes);
    packed.push(0); // K1 tag
    packed.extend_from_slice(&signature.compact65());
    packed.extend_from_slice(&derived_id);
    let hex = hex::encode(&packed);
    manifest.halt_h_block = Some(hex.clone());
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_crypto::{
        R1Signature,
        k1::K1PrivateKey,
    };
    use pulsevm_database::{
        HaltDeclaration,
        HaltDeclarationMember,
        ImportSummary,
        verify_migration_halt_block,
        verify_migration_post_chain,
    };

    const VERSION: u32 = 1436;
    const HEIGHT: u32 = 8;

    fn slot_iso(slot: u32) -> String {
        let ms = u64::from(slot) * 500;
        let secs = ms / 1000;
        let millis = ms % 1000;
        // Test slots stay within the first minute of the Antelope epoch.
        if millis == 0 {
            format!("2000-01-01T00:00:{secs:02}")
        } else {
            format!("2000-01-01T00:00:{secs:02}.{millis:03}")
        }
    }

    /// Independent re-derivation of the gate's empty-header wire layout: any
    /// drift between this and [`record_post_blocks`] breaks the signatures
    /// below or the gate oracle at the end of the round-trip test.
    fn pack_header(slot: u32, producer: u64, previous: &[u8; 32], version: u32) -> Vec<u8> {
        let mut packed = Vec::new();
        packed.extend_from_slice(&slot.to_le_bytes());
        packed.extend_from_slice(&producer.to_le_bytes());
        packed.extend_from_slice(&0u16.to_le_bytes());
        packed.extend_from_slice(previous);
        packed.extend_from_slice(&[0u8; 32]);
        packed.extend_from_slice(&[0u8; 32]);
        packed.extend_from_slice(&version.to_le_bytes());
        packed.push(0); // no schedule change
        packed.push(0); // no header extensions
        packed
    }

    fn block_json(
        slot: u32,
        producer: &str,
        previous: [u8; 32],
        version: u32,
        signature: &str,
        num: u32,
        id: [u8; 32],
    ) -> Value {
        serde_json::json!({
            "timestamp": slot_iso(slot),
            "producer": producer,
            "confirmed": 0,
            "previous": hex::encode(previous),
            "transaction_mroot": "00".repeat(32),
            "action_mroot": "00".repeat(32),
            "schedule_version": version,
            "new_producers": null,
            "header_extensions": [],
            "producer_signature": signature,
            "transactions": [],
            "block_num": num,
            "id": hex::encode(id),
        })
    }

    fn schedule_json(version: u32, members: &[(&K1PrivateKey, &str)]) -> Value {
        schedule_json_with(
            version,
            &members
                .iter()
                .map(|(key, name)| {
                    (
                        (*name).to_string(),
                        key.public_key().to_string(),
                        1u64,
                        1usize,
                    )
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Build an H header state's schedule section in the Leap shape:
    /// `active_schedule` with the version and producers plus an empty
    /// `pending_schedule`. Each member is (name, key, threshold, key
    /// count). Multi-key members exercise the fail-closed path. A live
    /// `get_producer_schedule` envelope (`active`/`pending`/`proposed`) is
    /// deliberately not built here: record_halt_schedule refuses it, since
    /// only H's header state authenticates the committee.
    fn schedule_json_with(version: u32, members: &[(String, String, u64, usize)]) -> Value {
        serde_json::json!({
            "active_schedule": {
                "version": version,
                "producers": members.iter().map(|(name, key, threshold, count)| {
                    let keys: Vec<Value> = (0..*count).map(|i| {
                        serde_json::json!({"key": if i == 0 { key.clone() } else { key.clone() + &i.to_string() }, "weight": 1})
                    }).collect();
                    serde_json::json!({
                        "producer_name": name,
                        "authority": [1, {"threshold": threshold, "keys": keys}],
                    })
                }).collect::<Vec<_>>(),
            },
            "pending_schedule": {"schedule": {"version": version, "producers": []}},
        })
    }

    fn manifest_for(halt_id: [u8; 32]) -> MigrationManifest {
        MigrationManifest::new(
            b"migration attach test",
            halt_id,
            b"checkpoint",
            1,
            ImportSummary::default(),
        )
    }

    fn declaration_for(members: &[(&K1PrivateKey, &str)]) -> HaltDeclaration {
        let mut validator_set: Vec<HaltDeclarationMember> = members
            .iter()
            .map(|(key, name)| HaltDeclarationMember {
                producer: (*name).to_string(),
                key: key.public_key().to_string(),
                weight: HaltWeight::MEMBER,
            })
            .collect();
        validator_set.sort_by(|a, b| a.producer.cmp(&b.producer));
        HaltDeclaration {
            version: 2,
            source_chain_id: "00".repeat(32),
            last_height: HEIGHT,
            validator_set,
            signatures: Vec::new(),
        }
    }

    /// Encode a declaration digest hex the way the memo vehicle names its
    /// accounts: `h` + round letter + hex nibbles mapped to `a`–`p`, ten
    /// per account (the last chunk holds the remainder).
    fn memo_names_for(digest_hex: &str, round: char) -> Vec<String> {
        let letters: String = digest_hex
            .bytes()
            .map(|b| {
                let nibble = if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                (b'a' + nibble) as char
            })
            .collect();
        letters
            .chars()
            .collect::<Vec<_>>()
            .chunks(10)
            .map(|chunk| format!("h{round}{}", chunk.iter().collect::<String>()))
            .collect()
    }

    fn memo_json(names: &[String], created_slot: u32) -> Value {
        Value::Array(
            names
                .iter()
                .map(|name| {
                    serde_json::json!({
                        "name": name,
                        "account": {"created": slot_iso(created_slot)},
                    })
                })
                .collect(),
        )
    }

    /// Synthetic but fixed signature inputs: every test signs and verifies
    /// over the same root/schedule-hash pair, so the round-trip exercises
    /// the true Leap digest path with deterministic fixtures.
    const TEST_ROOT_A: [u8; 32] = [0xA1; 32];
    const TEST_ROOT_B: [u8; 32] = [0xB2; 32];

    fn state_json(root: &[u8; 32], schedule_hash: &[u8; 32], block_id_hex: &str) -> Value {
        serde_json::json!({
            "id": block_id_hex,
            "blockroot_merkle": {
                "_active_nodes": [hex::encode([0u8; 32]), hex::encode([1u8; 32]), hex::encode(root)],
                "_node_count": 9,
            },
            "pending_schedule": {"schedule_hash": hex::encode(schedule_hash)},
        })
    }

    /// H's own header-state root: distinct from the post-H roots so a test
    /// that swaps states across heights fails at signature recovery.
    const TEST_ROOT_H: [u8; 32] = [0xC0; 32];

    /// Build H plus two signed post-H headers; returns the manifest with the
    /// schedule recorded, the parsed H id, the H response and its header
    /// state, the post-H responses, and the matching header states.
    #[allow(clippy::type_complexity)]
    fn frozen_setup() -> (
        MigrationManifest,
        [u8; 32],
        K1PrivateKey,
        K1PrivateKey,
        Value,
        Value,
        Vec<(&'static str, Value)>,
        Vec<(&'static str, Value)>,
    ) {
        let key_a = K1PrivateKey::random();
        let key_b = K1PrivateKey::random();
        let members = [(&key_a, "alice"), (&key_b, "bob")];
        // The header states name a fixed schedule hash: the record path
        // binds the exact (root, hash) pair through the producer
        // signature, so any consistent value exercises the real check.
        let schedule_hash = FIXTURE_SCHEDULE_HASH;

        let mut halt_previous = [0u8; 32];
        halt_previous[0..4].copy_from_slice(&7u32.to_be_bytes());
        let halt_packed = pack_header(100, name_u64("alice"), &halt_previous, VERSION);
        let halt_digest = Digest::hash(&halt_packed).0;
        // H is produced by a schedule member and signed over Leap's true
        // digest with its own header-state inputs — exactly like every
        // post-H header, so the record path authenticates H the same way
        // it authenticates the window.
        let halt_sig_digest = leap_sig_digest(&halt_digest, &TEST_ROOT_H, &schedule_hash);
        let halt_json = block_json(
            100,
            "alice",
            halt_previous,
            VERSION,
            &key_a.sign(&halt_sig_digest).to_string(),
            HEIGHT,
            halt_digest_with_num(&halt_digest, HEIGHT),
        );
        let halt_state_json = state_json(
            &TEST_ROOT_H,
            &schedule_hash,
            &hex::encode(halt_digest_with_num(&halt_digest, HEIGHT)),
        );
        let halt_block = parse_boundary_block(&halt_json, false).expect("H parses");
        let halt_id: [u8; 32] = halt_block
            .id()
            .expect("H id")
            .as_bytes()
            .try_into()
            .expect("H id is 32 bytes");

        let mut manifest = manifest_for(halt_id);
        let schedule = schedule_json(VERSION, &members);
        let recorded = record_halt_schedule(&mut manifest, &schedule, "test-schedule", VERSION)
            .expect("schedule records");
        assert_eq!(recorded, 2);
        assert_eq!(manifest.halt_schedule_version, Some(VERSION));

        let mut previous = halt_id;
        let mut posts = Vec::new();
        let mut post_states = Vec::new();
        for (num, (slot, (key, name, root))) in (HEIGHT + 1..).zip(
            [101u32, 102]
                .into_iter()
                .zip([(&key_a, "alice", TEST_ROOT_A), (&key_b, "bob", TEST_ROOT_B)]),
        ) {
            let packed = pack_header(slot, name_u64(name), &previous, VERSION);
            let header_digest = Digest::hash(&packed).0;
            let digest = leap_sig_digest(&header_digest, &root, &schedule_hash);
            let id = halt_digest_with_num(&header_digest, num);
            let json = block_json(
                slot,
                name,
                previous,
                VERSION,
                &key.sign(&digest).to_string(),
                num,
                id,
            );
            posts.push((name, json));
            post_states.push((name, state_json(&root, &schedule_hash, &hex::encode(id))));
            previous = id;
        }
        (
            manifest,
            halt_id,
            key_a,
            key_b,
            halt_json,
            halt_state_json,
            posts,
            post_states,
        )
    }

    fn name_u64(name: &str) -> u64 {
        Name::from_str(name).expect("valid producer name").as_u64()
    }

    fn halt_digest_with_num(digest: &[u8; 32], num: u32) -> [u8; 32] {
        let mut id = *digest;
        id[0..4].copy_from_slice(&num.to_be_bytes());
        id
    }

    /// Fixed schedule hash the fixtures stage: the signature binds the
    /// exact (root, hash) pair Leap signed over, so any consistent value
    /// exercises the real check.
    const FIXTURE_SCHEDULE_HASH: [u8; 32] = [0x5E; 32];

    #[test]
    fn schedule_records_unit_weights_and_pins_version() {
        let key_a = K1PrivateKey::random();
        let key_b = K1PrivateKey::random();
        let schedule = schedule_json(VERSION, &[(&key_a, "alice"), (&key_b, "bob")]);
        let mut manifest = manifest_for([7u8; 32]);
        let recorded =
            record_halt_schedule(&mut manifest, &schedule, "test-schedule", VERSION).unwrap();
        assert_eq!(recorded, 2);
        assert_eq!(manifest.halt_schedule_version, Some(VERSION));
        let roster = manifest.halt_schedule.expect("schedule recorded");
        assert!(
            roster
                .iter()
                .all(|entry| entry.weight == HaltWeight::MEMBER)
        );
        let names: Vec<_> = roster.iter().map(|entry| entry.producer.as_str()).collect();
        assert_eq!(names, ["alice", "bob"]);
    }

    #[test]
    fn schedule_rejects_version_mismatch() {
        let key = K1PrivateKey::random();
        let schedule = schedule_json(VERSION + 1, &[(&key, "alice")]);
        let mut manifest = manifest_for([7u8; 32]);
        let error =
            record_halt_schedule(&mut manifest, &schedule, "test-schedule", VERSION).unwrap_err();
        assert!(
            error.contains("does not match the H schedule version"),
            "{error}"
        );
    }

    #[test]
    fn schedule_rejects_duplicate_bad_key_and_empty() {
        let key = K1PrivateKey::random();
        let mut manifest = manifest_for([7u8; 32]);
        let dup = schedule_json(VERSION, &[(&key, "alice"), (&key, "alice")]);
        let error = record_halt_schedule(&mut manifest, &dup, "s", VERSION).unwrap_err();
        assert!(error.contains("twice"), "{error}");
        let bad_key = schedule_json_with(
            VERSION,
            &[("alice".to_string(), "not-a-key".to_string(), 1, 1)],
        );
        let error = record_halt_schedule(&mut manifest, &bad_key, "s", VERSION).unwrap_err();
        assert!(error.contains("not a K1 key"), "{error}");
        let empty = serde_json::json!({
            "active_schedule": {"version": VERSION, "producers": []}
        });
        let error = record_halt_schedule(&mut manifest, &empty, "s", VERSION).unwrap_err();
        assert!(error.contains("no producers"), "{error}");
    }

    #[test]
    fn schedule_rejects_multi_key_and_threshold_authorities() {
        let key = K1PrivateKey::random();
        let key_str = key.public_key().to_string();
        let mut manifest = manifest_for([7u8; 32]);
        // Two keys: no single block-signing key to record.
        let multi = schedule_json_with(VERSION, &[("alice".to_string(), key_str.clone(), 1, 2)]);
        let error = record_halt_schedule(&mut manifest, &multi, "s", VERSION).unwrap_err();
        assert!(error.contains("exactly one block-signing key"), "{error}");
        // Threshold 2 with one key: the key alone cannot sign.
        let thresholded =
            schedule_json_with(VERSION, &[("alice".to_string(), key_str.clone(), 2, 1)]);
        let error = record_halt_schedule(&mut manifest, &thresholded, "s", VERSION).unwrap_err();
        assert!(error.contains("threshold is 2, not 1"), "{error}");
        // Missing authority entirely (pre-Leap-4 shape): fail closed.
        let flat = serde_json::json!({
            "active_schedule": {
                "version": VERSION,
                "producers": [{"producer_name": "alice", "block_signing_key": key_str}],
            }
        });
        let error = record_halt_schedule(&mut manifest, &flat, "s", VERSION).unwrap_err();
        assert!(error.contains("has no authority"), "{error}");
    }

    #[test]
    fn schedule_derives_proposed_absence_and_rejects_staged_rotations() {
        let key = K1PrivateKey::random();
        // A clean schedule records the absence the gate requires.
        let mut manifest = manifest_for([7u8; 32]);
        record_halt_schedule(
            &mut manifest,
            &schedule_json(VERSION, &[(&key, "alice")]),
            "s",
            VERSION,
        )
        .unwrap();
        assert_eq!(manifest.halt_proposed_schedule, Some(false));
        // A staged pending schedule fails the record fast: the checkpoint
        // would otherwise boot with a proposal the ceremony never froze.
        // The header state nests it under pending_schedule.
        let mut pending = schedule_json(VERSION, &[(&key, "alice")]);
        pending["pending_schedule"]["schedule"]["producers"] = serde_json::json!([
            {"producer_name": "alice", "authority": [1, {"threshold": 1, "keys": [{"key": key.public_key().to_string(), "weight": 1}]}]},
        ]);
        let mut manifest = manifest_for([7u8; 32]);
        let error = record_halt_schedule(&mut manifest, &pending, "s", VERSION).unwrap_err();
        assert!(error.contains("pending"), "{error}");
        assert_eq!(manifest.halt_proposed_schedule, None);
        // A live get_producer_schedule envelope is refused outright: only
        // H's header state authenticates the committee.
        let live = serde_json::json!({
            "active": {"version": VERSION, "producers": []},
        });
        let mut manifest = manifest_for([7u8; 32]);
        let error = record_halt_schedule(&mut manifest, &live, "s", VERSION).unwrap_err();
        assert!(error.contains("active_schedule"), "{error}");
    }

    #[test]
    fn memo_accounts_record_decode_and_timing() {
        let key = K1PrivateKey::from_seed_string("memo-1").unwrap();
        let declaration = declaration_for(&[(&key, "alice")]);
        let digest_hex = hex::encode(declaration.digest().unwrap());
        let names = memo_names_for(&digest_hex, 'a');
        assert_eq!(names.len(), 7);
        let mut manifest = manifest_for([7u8; 32]);
        manifest.halt_declaration = Some(declaration);
        let count =
            record_memo_accounts(&mut manifest, &memo_json(&names, 50), 100, "memo").unwrap();
        assert_eq!(count, 7);
        let recorded = manifest.halt_memo_accounts.unwrap();
        assert_eq!(recorded.len(), 7);
        assert!(recorded.iter().all(|m| m.created_slot == 50));
        // A digest from another declaration fails: names commit to exactly
        // one digest.
        let other = declaration_for(&[(&key, "bob")]);
        let mut bad_manifest = manifest_for([7u8; 32]);
        bad_manifest.halt_declaration = Some(other);
        let error = record_memo_accounts(&mut bad_manifest, &memo_json(&names, 50), 100, "memo")
            .unwrap_err();
        assert!(error.contains("do not decode"), "{error}");
        // Created at or after H fails: the declaration must land before H.
        for slot in [100, 101] {
            let mut late_manifest = manifest_for([7u8; 32]);
            late_manifest.halt_declaration = manifest.halt_declaration.clone();
            let error =
                record_memo_accounts(&mut late_manifest, &memo_json(&names, slot), 100, "memo")
                    .unwrap_err();
            assert!(error.contains("must land before H"), "{error}");
        }
        // Malformed names fail: the digest alphabet is exactly a-p after
        // the round letter.
        let mut broken = memo_json(&names, 50);
        broken
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name": "xyz", "account": {"created": slot_iso(50)}}));
        let mut broken_manifest = manifest_for([7u8; 32]);
        broken_manifest.halt_declaration = manifest.halt_declaration.clone();
        let error = record_memo_accounts(&mut broken_manifest, &broken, 100, "memo").unwrap_err();
        assert!(
            error.contains("does not carry the declaration digest"),
            "{error}"
        );
        // No declaration recorded: nothing to decode against.
        let mut bare = manifest_for([7u8; 32]);
        let error =
            record_memo_accounts(&mut bare, &memo_json(&names, 50), 100, "memo").unwrap_err();
        assert!(error.contains("recorded declaration"), "{error}");
    }

    #[test]
    fn schedule_accepts_legacy_eos_key_form() {
        // Real Leap 5 responses render schedule keys in legacy EOS form;
        // the roster must accept them exactly as nodeos serves them.
        let schedule = schedule_json_with(
            VERSION,
            &[(
                "eosio".to_string(),
                "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV".to_string(),
                1,
                1,
            )],
        );
        let mut manifest = manifest_for([7u8; 32]);
        let recorded = record_halt_schedule(&mut manifest, &schedule, "s", VERSION).unwrap();
        assert_eq!(recorded, 1);
    }

    #[test]
    fn schedule_rejects_conflict_with_pinned_version() {
        let key = K1PrivateKey::random();
        let schedule = schedule_json(VERSION, &[(&key, "alice")]);
        let mut manifest = manifest_for([7u8; 32]);
        manifest.halt_schedule_version = Some(VERSION + 1);
        let error = record_halt_schedule(&mut manifest, &schedule, "s", VERSION).unwrap_err();
        assert!(
            error.contains("conflicts with the recorded schedule version"),
            "{error}"
        );
    }

    #[test]
    fn post_blocks_roundtrip_through_the_restore_gate() {
        let (mut manifest, halt_id, key_a, key_b, _, _, posts, post_states) = frozen_setup();
        let refs: Vec<(&str, &Value)> = posts.iter().map(|(name, json)| (*name, json)).collect();
        let state_refs: Vec<(&str, &Value)> = post_states
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let recorded = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &state_refs,
        )
        .unwrap();
        assert_eq!(recorded, 2);
        // The recorded headers are structurally sound before the gate runs:
        // first links from H, second links from the first, roots are empty.
        let packed = manifest.halt_post_blocks.clone().expect("posts recorded");
        assert_eq!(packed.len(), 2);
        let first = hex::decode(&packed[0]).unwrap();
        assert_eq!(&first[0..32], &TEST_ROOT_A);
        assert_eq!(&first[32..64], &FIXTURE_SCHEDULE_HASH);
        assert_eq!(&first[78..110], &halt_id);
        assert_eq!(&first[110..142], &[0u8; 32]);
        // The real restore gate is the oracle: it parses the recorded hex
        // with its own parser and re-authenticates every link and signature.
        // The two staged headers (HEIGHT+1, HEIGHT+2) cover exactly the
        // attested pause head.
        let declaration = declaration_for(&[(&key_a, "alice"), (&key_b, "bob")]);
        let attested = verify_migration_post_chain(
            &manifest,
            &declaration,
            HEIGHT,
            &halt_id,
            VERSION,
            HEIGHT + 2,
        )
        .expect("gate accepts the recorded proof");
        assert_eq!(attested, 2);
    }

    #[test]
    fn halt_block_roundtrip_through_the_restore_gate() {
        let (mut manifest, halt_id, _, _, halt_json, halt_state_json, _, _) = frozen_setup();
        let recorded = record_halt_block(
            &mut manifest,
            &halt_json,
            &halt_state_json,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            "halt",
        )
        .expect("H records");
        assert_eq!(manifest.halt_h_block.as_deref(), Some(recorded.as_str()));
        // The real restore gate is the oracle: it parses the recorded H
        // with its own parser and re-authenticates the derived id,
        // emptiness, version, and producer signature.
        verify_migration_halt_block(&manifest, HEIGHT, &halt_id, VERSION)
            .expect("gate accepts the recorded H");
    }

    #[test]
    fn halt_block_rejects_a_foreign_signature_and_a_substituted_anchor() {
        let (mut manifest, halt_id, _, _, halt_json, halt_state_json, _, _) = frozen_setup();
        // Signed by an outsider over the true digest: recovery succeeds,
        // but the key is not in the recorded schedule.
        let key_c = K1PrivateKey::random();
        let mut foreign = halt_json.clone();
        let packed = pack_header(
            100,
            name_u64("alice"),
            &{
                let mut previous = [0u8; 32];
                previous[0..4].copy_from_slice(&7u32.to_be_bytes());
                previous
            },
            VERSION,
        );
        let header_digest = Digest::hash(&packed).0;
        let digest = leap_sig_digest(&header_digest, &TEST_ROOT_H, &FIXTURE_SCHEDULE_HASH);
        foreign["producer_signature"] = serde_json::json!(key_c.sign(&digest).to_string());
        let error = record_halt_block(
            &mut manifest,
            &foreign,
            &halt_state_json,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            "halt",
        )
        .unwrap_err();
        assert!(
            error.contains("not signed by the recorded schedule key"),
            "{error}"
        );
        // Anchored at the wrong id: the entry must open on the trusted H.
        let mut wrong_anchor = [9u8; 32];
        wrong_anchor[0..4].copy_from_slice(&HEIGHT.to_be_bytes());
        let error = record_halt_block(
            &mut manifest,
            &halt_json,
            &halt_state_json,
            &Id::new(wrong_anchor),
            HEIGHT,
            VERSION,
            "halt",
        )
        .unwrap_err();
        assert!(error.contains("trusted cutover id"), "{error}");
        // Header state from another height: a state carrying a different
        // block id — with a different schedule — cannot open this window,
        // even when the block itself is trusted.
        let mut foreign_state = halt_state_json.clone();
        foreign_state["id"] = serde_json::json!("ff".repeat(32));
        let error = record_halt_block(
            &mut manifest,
            &halt_json,
            &foreign_state,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            "halt",
        )
        .unwrap_err();
        assert!(error.contains("not the trusted cutover block"), "{error}");
    }

    #[test]
    fn post_blocks_reject_a_sibling_stated_under_the_wrong_id() {
        let (mut manifest, halt_id, key_a, key_b, _, _, mut posts, post_states) = frozen_setup();
        // Flip a byte in the first response id past its embedded height:
        // the stated number still names HEIGHT+1, but the id is no longer
        // the header's. The record path must derive the id instead of
        // chaining the stated bytes.
        let mut tampered = posts.remove(0).1.clone();
        let mut id_bytes = hex::decode(tampered["id"].as_str().expect("stated id")).unwrap();
        id_bytes[4] ^= 1;
        tampered["id"] = serde_json::json!(hex::encode(&id_bytes));
        posts.insert(0, ("alice", tampered));
        let refs: Vec<(&str, &Value)> = posts.iter().map(|(n, j)| (*n, j)).collect();
        let state_refs: Vec<(&str, &Value)> = post_states
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &state_refs,
        )
        .unwrap_err();
        assert!(error.contains("id"), "{error}");
        let _ = (key_a, key_b);
    }

    #[test]
    fn post_blocks_reject_broken_linkage() {
        let (mut manifest, halt_id, key_a, key_b, _, _, mut posts, post_states) = frozen_setup();
        let mut tampered = posts.remove(0).1.clone();
        tampered["previous"] = serde_json::json!(hex::encode([9u8; 32]));
        posts.insert(0, ("alice", tampered));
        let refs: Vec<(&str, &Value)> = posts.iter().map(|(n, j)| (*n, j)).collect();
        let state_refs: Vec<(&str, &Value)> = post_states
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &state_refs,
        )
        .unwrap_err();
        assert!(error.contains("hash-link"), "{error}");
        let _ = (key_a, key_b);
    }

    #[test]
    fn post_blocks_reject_traffic_rotation_and_unknown_producers() {
        let (mut manifest, halt_id, key_a, key_b, _, _, posts, post_states) = frozen_setup();
        let stated_hash = FIXTURE_SCHEDULE_HASH;
        // A transaction in the first post-H header.
        let mut with_tx = posts[0].1.clone();
        with_tx["transactions"] = serde_json::json!([{"trx": "00".repeat(32)}]);
        let refs = vec![("alice", &with_tx)];
        let single_state = vec![("alice", &post_states[0].1)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &single_state,
        )
        .unwrap_err();
        assert!(error.contains("not empty"), "{error}");
        // A schedule version rotation mid-window.
        let mut rotated = posts[0].1.clone();
        rotated["schedule_version"] = serde_json::json!(VERSION + 1);
        let refs = vec![("alice", &rotated)];
        let single_state = vec![("alice", &post_states[0].1)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &single_state,
        )
        .unwrap_err();
        assert!(error.contains("rotates"), "{error}");
        // A producer outside the recorded schedule, validly signed over the
        // true Leap digest (wrong roster, right cryptography).
        let key_c = K1PrivateKey::random();
        let unknown_packed = pack_header(101, name_u64("carol"), &halt_id, VERSION);
        let unknown_header = Digest::hash(&unknown_packed).0;
        let unknown_digest = leap_sig_digest(&unknown_header, &TEST_ROOT_A, &stated_hash);
        let unknown = block_json(
            101,
            "carol",
            halt_id,
            VERSION,
            &key_c.sign(&unknown_digest).to_string(),
            HEIGHT + 1,
            halt_digest_with_num(&unknown_header, HEIGHT + 1),
        );
        let unknown_id = unknown
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let unknown_state = state_json(&TEST_ROOT_A, &stated_hash, &unknown_id);
        let refs = vec![("carol", &unknown)];
        let states = vec![("carol", &unknown_state)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &states,
        )
        .unwrap_err();
        assert!(error.contains("not in the recorded schedule"), "{error}");
        // Alice's header signed by Bob's key: recovers, but not to Alice.
        let forged_packed = pack_header(101, name_u64("alice"), &halt_id, VERSION);
        let forged_header = Digest::hash(&forged_packed).0;
        let forged_digest = leap_sig_digest(&forged_header, &TEST_ROOT_A, &stated_hash);
        let forged = block_json(
            101,
            "alice",
            halt_id,
            VERSION,
            &key_b.sign(&forged_digest).to_string(),
            HEIGHT + 1,
            halt_digest_with_num(&forged_header, HEIGHT + 1),
        );
        let forged_id = forged
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let forged_state = state_json(&TEST_ROOT_A, &stated_hash, &forged_id);
        let refs = vec![("alice", &forged)];
        let states = vec![("alice", &forged_state)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &states,
        )
        .unwrap_err();
        assert!(
            error.contains("not signed by the recorded schedule key"),
            "{error}"
        );
        let _ = key_a;
    }

    #[test]
    fn post_blocks_reject_non_k1_signatures_and_missing_schedule() {
        let (mut manifest, halt_id, _, _, _, _, posts, post_states) = frozen_setup();
        let mut non_k1 = posts[0].1.clone();
        // Well-formed R1 encoding, so the boundary parser accepts it and the
        // record step is what refuses the non-K1 signature.
        non_k1["producer_signature"] =
            serde_json::json!(R1Signature::from_compact65(&[1u8; 65]).to_string());
        let refs = vec![("alice", &non_k1)];
        let single_state = vec![("alice", &post_states[0].1)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &single_state,
        )
        .unwrap_err();
        assert!(error.contains("not K1"), "{error}");
        // No schedule recorded at all: fail closed instead of trusting any key.
        let mut bare = manifest_for(halt_id);
        let refs: Vec<(&str, &Value)> = posts.iter().map(|(name, json)| (*name, json)).collect();
        let state_refs: Vec<(&str, &Value)> = post_states
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let error = record_post_blocks(
            &mut bare,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &state_refs,
        )
        .unwrap_err();
        assert!(error.contains("recorded schedule"), "{error}");
    }

    #[test]
    fn post_blocks_reject_wrong_root_wrong_hash_and_state_mismatch() {
        let (mut manifest, halt_id, _, _, _, _, posts, post_states) = frozen_setup();
        let refs: Vec<(&str, &Value)> = posts.iter().map(|(name, json)| (*name, json)).collect();
        // A blockroot from a different window: the signature no longer
        // recovers to the schedule key.
        let mut wrong_root = post_states.clone();
        let stated_hash = FIXTURE_SCHEDULE_HASH;
        let first_id = posts[0]
            .1
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        wrong_root[0].1 = state_json(&[0xFF; 32], &stated_hash, &first_id);
        let wrong_root_refs: Vec<(&str, &Value)> = wrong_root
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &wrong_root_refs,
        )
        .unwrap_err();
        assert!(
            error.contains("not signed by the recorded schedule key"),
            "{error}"
        );
        // A schedule hash from a different schedule: the staged pair no
        // longer matches what the producer signed, so recovery misses the
        // roster key. The signature binds the exact pair; there is no
        // comparison to fool.
        let mut wrong_hash = post_states.clone();
        let second_id = posts[1]
            .1
            .get("id")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        wrong_hash[1].1 = state_json(&TEST_ROOT_B, &[0xEE; 32], &second_id);
        let wrong_hash_refs: Vec<(&str, &Value)> = wrong_hash
            .iter()
            .map(|(name, json)| (*name, json))
            .collect();
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &wrong_hash_refs,
        )
        .unwrap_err();
        assert!(
            error.contains("not signed by the recorded schedule key"),
            "{error}"
        );
        // Missing header-state fields fail closed before any crypto runs.
        let bare_state = serde_json::json!({"blockroot_merkle": {}, "pending_schedule": {}});
        let bare_refs = vec![("alice", &bare_state), ("bob", &post_states[1].1)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &bare_refs,
        )
        .unwrap_err();
        assert!(error.contains("blockroot"), "{error}");
        // Block/state count skew fails closed instead of zipping silently.
        let short_refs = vec![(post_states[0].0, &post_states[0].1)];
        let error = record_post_blocks(
            &mut manifest,
            &Id::new(halt_id),
            HEIGHT,
            VERSION,
            &refs,
            &short_refs,
        )
        .unwrap_err();
        assert!(error.contains("one header state each"), "{error}");
    }

    #[test]
    fn boundary_parser_rejects_schedule_changes_and_extensions() {
        let (_, _, _, _, _, _, posts, _) = frozen_setup();
        let mut changed = posts[0].1.clone();
        changed["new_producers"] = serde_json::json!({"version": VERSION + 1, "producers": []});
        let error = parse_boundary_block(&changed, false).unwrap_err();
        assert!(error.contains("schedule change"), "{error}");
        let mut extended = posts[0].1.clone();
        extended["block_extensions"] = serde_json::json!([[1, "00"]]);
        let error = parse_boundary_block(&extended, false).unwrap_err();
        assert!(error.contains("block extensions"), "{error}");
    }
}
