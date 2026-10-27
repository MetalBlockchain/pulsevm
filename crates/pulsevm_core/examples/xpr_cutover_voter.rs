//! Automatic cutover voter: after upgrading, a BP's node signs for them.
//!
//! The operator installs the release, drops in a small config file (node
//! URL, contract, producer name, the two key files they already hold, the
//! coordinated height and source chain id), and starts the voter. It polls
//! the ceremony tables and:
//!
//! * signs the frozen declaration digest with the block-signing key and submits the on-chain `vote`
//!   once, inside the window;
//! * after H is final, signs the confirmation digest and delivers it to the coordinator (or a file
//!   when no coordinator is configured).
//!
//! Guardrails (all enforced, all logged, never silent):
//!
//! * The frozen ceremony must match the config: same H, same source chain, and a declaration digest
//!   recomputed locally from the published roster. Anything else is refused, never signed.
//! * The signing key must belong to the frozen member row, and the row must not already show a
//!   vote. Outsider keys and double votes refuse.
//! * No vote at or after H, no confirmation before H is irreversible.
//! * Keys come from files with owner-only permissions (refused otherwise) or the environment, never
//!   from the command line, and are never logged.
//! * `--dry-run` evaluates every decision and logs it without signing, submitting, or writing
//!   anything.
//!
//! The vote this tool submits is byte-identical to the manual `cvote` path
//! (same digest, same action layout), so automated and manual fleets verify
//! together.

use std::{
    process::ExitCode,
    str::FromStr,
    time::Duration,
};

use pulsevm_core::{
    authority::PermissionLevel,
    crypto::PrivateKey,
    id::Id,
    name::Name,
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
        TransactionHeader,
    },
};
use pulsevm_crypto::K1PrivateKey;
use pulsevm_database::{
    HaltConfirmation,
    HaltDeclaration,
    HaltDeclarationMember,
    HaltSignature,
};
use serde::Deserialize;

macro_rules! log_line {
    ($($arg:tt)*) => {{
        println!("[cutover-voter {}] {}", now_stamp(), format!($($arg)*));
    }};
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct Config {
    nodeos_url: String,
    /// HTTP Host header Leap validates against its listening address
    /// (e.g. "0.0.0.0:8888" for a port-mapped container, "127.0.0.1:8888"
    /// for a node on localhost). Requests without it get HTTP 400.
    #[serde(default = "default_host_header")]
    host_header: String,
    contract: String,
    producer: String,
    source_chain_id: String,
    height: u32,
    /// Coordinated active schedule version the freeze must name: the
    /// voter refuses unless the contract init params (H, chain id,
    /// schedule version, schedule) equal the live `get_producer_schedule`
    /// exactly. Missing (not zero) fails closed at startup so an old
    /// config cannot sign under an unpinned schedule.
    schedule_version: u32,
    roster_file: String,
    vote_key_file: String,
    payer_account: String,
    payer_key_file: String,
    #[serde(default = "default_poll_secs")]
    poll_secs: u64,
    #[serde(default)]
    dry_run: bool,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    confirmation: ConfirmationConfig,
    /// Opt-in local producer stop. When `at_h` is set with a
    /// `producer_api_url`, the voter pauses its own producer after the
    /// confirmation for H is delivered (Leap `producer/pause`). A contract
    /// cannot halt block production — only the producer can — so this is
    /// the half of the halt that lives in the binary. Off by default: a
    /// surprise pause is worse than a loud refusal to start.
    #[serde(default)]
    stop_producer: StopConfig,
}

/// Local producer stop at H. Both fields are required together: `at_h`
/// without a URL fails fast at startup instead of silently never pausing.
#[derive(Debug, Clone, Default, Deserialize)]
struct StopConfig {
    #[serde(default)]
    at_h: bool,
    producer_api_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ConfirmationConfig {
    coordinator_url: Option<String>,
    #[serde(default = "default_confirmation_out")]
    out_file: String,
    migration_genesis: Option<String>,
    checkpoint_sha256: Option<String>,
    /// The MetalGo blockchain id wallets sign under, from the ceremony
    /// config. Bound into the confirmation digest; the restore gate fails
    /// closed without it, so an unset value warns loudly and stays a
    /// rehearsal-only mode.
    #[serde(default)]
    platform_chain_id: Option<String>,
}

fn default_poll_secs() -> u64 {
    5
}

fn default_host_header() -> String {
    "0.0.0.0:8888".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_confirmation_out() -> String {
    "confirmation.json".to_string()
}

#[derive(Debug, Clone)]
struct LoadedConfig {
    inner: Config,
    vote_key: K1PrivateKey,
    payer_key: PrivateKey,
    payer_account: String,
    expected_digest: [u8; 32],
}

fn load_config(path: &str) -> Result<Config, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read config {path}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse config {path}: {error}"))
}

/// Read a WIF from a file that must be owner-only (mode 0600 or stricter).
/// Group/world-readable key files are refused: a key that every local user
/// can read is already compromised.
#[cfg(unix)]
fn read_key_file(path: &str) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("read key file {path}: {error}"))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "key file {path} has permissions {mode:04o}: make it owner-only (chmod 600) or the voter refuses to start"
        ));
    }
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("read key file {path}: {error}"))?;
    let wif = text.trim().to_string();
    if wif.is_empty() {
        return Err(format!("key file {path} is empty"));
    }
    Ok(wif)
}

#[cfg(not(unix))]
fn read_key_file(path: &str) -> Result<String, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("read key file {path}: {error}"))?;
    let wif = text.trim().to_string();
    if wif.is_empty() {
        return Err(format!("key file {path} is empty"));
    }
    Ok(wif)
}

fn read_roster(path: &str) -> Result<Vec<HaltDeclarationMember>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read roster {path}: {error}"))?;
    let roster: Vec<pulsevm_database::MigrationHaltRosterEntry> =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse roster {path}: {error}"))?;
    if roster.is_empty() {
        return Err(format!("roster {path} carries no entries"));
    }
    // The ceremony roster is the frozen active schedule: one member, one
    // vote. A vote-weight entry is not the schedule and must never be
    // signed, so it fails here instead of minting a foreign digest.
    for entry in &roster {
        if entry.weight != pulsevm_database::HaltWeight::MEMBER {
            return Err(format!(
                "roster {path} entry {} weight {} is not the schedule weight 1: refusing a non-schedule roster",
                entry.producer, entry.weight.0
            ));
        }
    }
    let mut members: Vec<HaltDeclarationMember> = roster
        .into_iter()
        .map(|entry| HaltDeclarationMember {
            producer: entry.producer,
            key: entry.key,
            weight: entry.weight,
        })
        .collect();
    HaltDeclaration::sort_members(&mut members);
    Ok(members)
}

fn expected_declaration_digest(
    source_chain_id: &str,
    height: u32,
    members: &[HaltDeclarationMember],
) -> Result<[u8; 32], String> {
    let unsigned = HaltDeclaration {
        version: HaltDeclaration::VERSION,
        source_chain_id: source_chain_id.to_string(),
        last_height: height,
        validator_set: members.to_vec(),
        signatures: Vec::new(),
    };
    unsigned
        .digest()
        .map_err(|error| format!("declaration digest: {error}"))
}

fn load_loaded_config(path: &str) -> Result<LoadedConfig, String> {
    let inner = load_config(path)?;
    if !inner.enabled {
        return Err("voter is disabled by config (enabled = false): refusing to run".to_string());
    }
    if inner.poll_secs == 0 {
        return Err("poll_secs must be at least 1".to_string());
    }
    hex::decode(&inner.source_chain_id)
        .map_err(|_| "source_chain_id is not hex".to_string())
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(())
            } else {
                Err("source_chain_id must be 32 bytes of hex".to_string())
            }
        })?;
    Name::from_str(&inner.producer).map_err(|_| "producer is not a valid name".to_string())?;
    Name::from_str(&inner.contract).map_err(|_| "contract is not a valid name".to_string())?;
    Name::from_str(&inner.payer_account)
        .map_err(|_| "payer_account is not a valid name".to_string())?;
    let vote_wif = read_key_file(&inner.vote_key_file)?;
    let vote_key = K1PrivateKey::from_string(&vote_wif)
        .map_err(|error| format!("vote key invalid: {error:?}"))?;
    let payer_wif = read_key_file(&inner.payer_key_file)?;
    let payer_key =
        PrivateKey::from_str(&payer_wif).map_err(|_| "payer key invalid".to_string())?;
    let payer_account = inner.payer_account.clone();
    let members = read_roster(&inner.roster_file)?;
    let expected_digest =
        expected_declaration_digest(&inner.source_chain_id, inner.height, &members)?;
    Ok(LoadedConfig {
        inner,
        vote_key,
        payer_key,
        payer_account,
        expected_digest,
    })
}

// ---------------------------------------------------------------------------
// Chain view and the pure decision function
// ---------------------------------------------------------------------------

/// Everything the voter needs from the node, fetched once per poll.
#[derive(Debug, Clone)]
struct CeremonyView {
    head_num: u32,
    lib_num: u32,
    /// Head block timestamp in microseconds: the expiry check runs on
    /// chain time (the same clock the contract's `publication_time()`
    /// window uses), never on the operator's wall clock.
    head_time_us: u64,
    /// Live active schedule version from `get_producer_schedule`: the
    /// vote refuses unless this equals both the frozen ceremony version
    /// and the coordinated config version.
    live_version: u32,
    singleton: Option<CeremonyRow>,
    member: Option<MemberRow>,
    /// A schedule change is staged (pending or proposed): the frozen set
    /// may no longer name the active set, so the vote refuses until the
    /// freeze is re-taken on the new set.
    schedule_blocked: bool,
    /// The frozen ceremony set no longer matches the live active schedule
    /// (member or schedule-key drift since the freeze): the freeze is stale
    /// and the vote refuses until it is re-taken.
    schedule_mismatch: bool,
}

#[derive(Debug, Clone)]
struct CeremonyRow {
    h: u32,
    source_chain_id: String,
    /// Frozen schedule version from the contract `init`: the vote refuses
    /// unless this equals the coordinated config version and the live
    /// active version, so a freeze taken under a rotated schedule signs
    /// nothing even when the member set still matches.
    schedule_version: u32,
    finalized: bool,
    digest: String,
    /// Freeze instant (`publication_time()` microseconds at init). Votes
    /// are accepted by the contract only inside the vote window past it.
    init_time_us: u64,
}

#[derive(Debug, Clone)]
struct MemberRow {
    key: String,
    voted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// Sign the digest and submit the on-chain vote.
    Vote,
    /// The vote is already on-chain; keep watching for confirmation time.
    AlreadyVoted,
    /// Nothing to do yet; keep polling.
    Wait(String),
    /// Never sign under this view; log the reason and keep polling (the
    /// view may change, e.g. the coordinator publishes the freeze).
    Refuse(String),
}

/// Pure policy: exactly when the key may sign. Every refusal names its
/// reason so the operator log, not a silent skip, explains each poll.
fn decide(config: &LoadedConfig, view: &CeremonyView) -> Decision {
    let Some(singleton) = view.singleton.as_ref() else {
        return Decision::Wait("no frozen ceremony on-chain yet".to_string());
    };
    if singleton.h != config.inner.height {
        return Decision::Refuse(format!(
            "ceremony height {} does not match coordinated H {}",
            singleton.h, config.inner.height
        ));
    }
    if singleton.source_chain_id != config.inner.source_chain_id {
        return Decision::Refuse("ceremony source chain does not match config".to_string());
    }
    if singleton.digest != hex::encode(config.expected_digest) {
        return Decision::Refuse(
            "ceremony digest does not match the locally recomputed declaration: refusing to sign a foreign freeze"
                .to_string(),
        );
    }
    // The contract init params (H, chain id, schedule version, schedule)
    // must equal the live schedule exactly: names and keys are pinned by
    // the digest plus the freeze-vs-schedule comparison below, and the
    // version is pinned here on all three sides (frozen, coordinated,
    // live). A rotation anywhere in the triangle refuses.
    if singleton.schedule_version != config.inner.schedule_version {
        return Decision::Refuse(format!(
            "ceremony schedule version {} does not match coordinated version {}: refusing to sign a freeze taken under the wrong schedule",
            singleton.schedule_version, config.inner.schedule_version
        ));
    }
    if view.live_version != config.inner.schedule_version {
        return Decision::Refuse(format!(
            "live schedule version {} does not match coordinated version {}: the schedule rotated, refusing to sign until the freeze is re-taken",
            view.live_version, config.inner.schedule_version
        ));
    }
    // The contract stops accepting votes past the freeze window; submitting
    // into an expired freeze burns payer CPU/NET on a doomed transaction,
    // so refuse here and wait for a fresh freeze instead. Same clock as the
    // contract (head timestamp vs init_time), same bound.
    if view.head_time_us > singleton.init_time_us + pulsevm_chain_types::CEREMONY_VOTE_WINDOW_US {
        return Decision::Refuse(format!(
            "ceremony freeze expired (vote window is {} seconds)",
            pulsevm_chain_types::CEREMONY_VOTE_WINDOW_US / 1_000_000
        ));
    }
    if view.schedule_blocked {
        return Decision::Refuse(
            "a producer schedule change is staged (pending or proposed): refusing to sign until the freeze names the active set"
                .to_string(),
        );
    }
    if view.schedule_mismatch {
        return Decision::Refuse(
            "the frozen ceremony set does not match the live active schedule (member or schedule-key drift): refusing to sign a stale freeze"
                .to_string(),
        );
    }
    if singleton.finalized {
        return Decision::Refuse("ceremony already finalized".to_string());
    }
    let Some(member) = view.member.as_ref() else {
        return Decision::Refuse(format!(
            "producer {} is not in the frozen set",
            config.inner.producer
        ));
    };
    // Member keys come back in whatever form the node renders (legacy EOS
    // or PUB_K1_); compare parsed keys, never strings.
    let ours = config.vote_key.public_key();
    match pulsevm_crypto::k1::K1PublicKey::from_string(&member.key) {
        Ok(frozen) if frozen == ours => {}
        _ => {
            return Decision::Refuse(format!(
                "frozen member key does not match this voter (member {})",
                config.inner.producer
            ));
        }
    }
    if member.voted {
        return Decision::AlreadyVoted;
    }
    if view.head_num >= config.inner.height {
        return Decision::Refuse(format!(
            "head {} reached H {}: vote window closed, refusing to spam a vote the contract must reject",
            view.head_num, config.inner.height
        ));
    }
    Decision::Vote
}

// ---------------------------------------------------------------------------
// Chain client (Leap nodeos HTTP API)
// ---------------------------------------------------------------------------

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|error| format!("POST {url}: {error}"))?;
    let status = response.status();
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|error| format!("POST {url}: bad JSON: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "POST {url}: HTTP {status}: {}",
            value
                .get("error")
                .and_then(|error| error.get("what"))
                .and_then(|what| what.as_str())
                .unwrap_or("unknown node error")
        ));
    }
    if let Some(error) = value.get("error") {
        return Err(format!("node error: {error}"));
    }
    Ok(value)
}

async fn get_info(client: &reqwest::Client, base: &str) -> Result<(u32, u32, String), String> {
    let info = post_json(
        client,
        &format!("{base}/v1/chain/get_info"),
        &serde_json::json!({}),
    )
    .await?;
    let head = info
        .get("head_block_num")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "get_info missing head_block_num".to_string())? as u32;
    let lib = info
        .get("last_irreversible_block_num")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "get_info missing last_irreversible_block_num".to_string())?
        as u32;
    let chain_id = info
        .get("chain_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "get_info missing chain_id".to_string())?
        .to_string();
    Ok((head, lib, chain_id))
}

async fn get_table_rows(
    client: &reqwest::Client,
    base: &str,
    code: &str,
    table: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let rows = post_json(
        client,
        &format!("{base}/v1/chain/get_table_rows"),
        &serde_json::json!({
            "json": true, "code": code, "scope": code, "table": table,
            "limit": 100,
        }),
    )
    .await?;
    rows.get("rows")
        .and_then(|rows| rows.as_array())
        .cloned()
        .ok_or_else(|| format!("get_table_rows {table} missing rows"))
}

/// Whether a producer schedule change is staged. Leap reports the staged
/// slots as null when empty; any present slot with producers means the
/// active set is about to change and the freeze may name a stale set.
/// Unknown shapes fail closed (blocked): signing on a schedule we cannot
/// read is exactly what the gate would reject downstream.
fn schedule_staged(value: &serde_json::Value) -> bool {
    for slot in ["pending", "proposed"] {
        let Some(staged) = value.get(slot) else {
            continue;
        };
        if staged.is_null() {
            continue;
        }
        let empty = staged
            .get("producers")
            .and_then(|producers| producers.as_array())
            .map(|producers| producers.is_empty())
            .unwrap_or(false);
        if !empty {
            return true;
        }
    }
    false
}

/// The live producer schedule as the voter needs it: whether a change is
/// staged, the active version, plus the active set to compare the frozen
/// set against. A freeze taken under a rotating set signs nothing, and a
/// freeze whose members no longer match the live active schedule is stale
/// — both refuse.
struct LiveSchedule {
    blocked: bool,
    version: u32,
    active: Vec<(String, pulsevm_crypto::k1::K1PublicKey)>,
}

/// Parse one `get_producer_schedule` active producer: name plus its schedule
/// (block-signing) key. Leap 4+ carries the key inside the producer
/// authority (`authority: [1, {threshold, keys}]`), not a flat
/// `block_signing_key`: only a single-key, threshold-1 authority maps to
/// one signing key, anything else fails closed. A schedule the voter
/// cannot read is one it must not sign under.
fn parse_active_producer(
    value: &serde_json::Value,
) -> Result<(String, pulsevm_crypto::k1::K1PublicKey), String> {
    let name = value
        .get("producer_name")
        .and_then(|name| name.as_str())
        .ok_or_else(|| "active schedule producer missing producer_name".to_string())?
        .to_string();
    let authority = value
        .get("authority")
        .and_then(|authority| authority.as_array())
        .ok_or_else(|| format!("active schedule producer {name} has no authority"))?;
    let [tag, versioned] = authority.as_slice() else {
        return Err(format!(
            "active schedule producer {name} authority is not a versioned pair"
        ));
    };
    // Leap 4 serves the v0 authority at tag 0, Leap 5 at tag 1; both carry
    // the threshold-and-keys object. Anything else is a shape the voter
    // must not guess at.
    if !tag.as_u64().is_some_and(|tag| tag <= 1) {
        return Err(format!(
            "active schedule producer {name} authority has unknown variant tag {tag}"
        ));
    }
    let threshold = versioned
        .get("threshold")
        .and_then(|threshold| threshold.as_u64())
        .ok_or_else(|| format!("active schedule producer {name} authority has no threshold"))?;
    if threshold != 1 {
        return Err(format!(
            "active schedule producer {name} authority threshold is {threshold}, not 1"
        ));
    }
    let keys = versioned
        .get("keys")
        .and_then(|keys| keys.as_array())
        .ok_or_else(|| format!("active schedule producer {name} authority has no keys"))?;
    let [entry] = keys.as_slice() else {
        return Err(format!(
            "active schedule producer {name} authority does not name exactly one block-signing key"
        ));
    };
    let key = entry
        .get("key")
        .and_then(|key| key.as_str())
        .ok_or_else(|| format!("active schedule producer {name} authority key has no key"))?;
    let parsed = pulsevm_crypto::k1::K1PublicKey::from_string(key)
        .map_err(|error| format!("active schedule producer {name} key invalid: {error:?}"))?;
    Ok((name, parsed))
}

async fn read_live_schedule(client: &reqwest::Client, base: &str) -> Result<LiveSchedule, String> {
    let schedule = post_json(
        client,
        &format!("{base}/v1/chain/get_producer_schedule"),
        &serde_json::json!({}),
    )
    .await
    .map_err(|error| format!("producer schedule unreadable: {error}"))?;
    let blocked = schedule_staged(&schedule);
    let mut active = Vec::new();
    let version: Option<u32>;
    match schedule.get("active") {
        None => {
            return Err(
                "producer schedule carries no active slot: cannot prove the freeze names the live set"
                    .to_string(),
            );
        }
        Some(slot) if slot.is_null() => {
            return Err(
                "producer schedule active slot is null: cannot prove the freeze names the live set"
                    .to_string(),
            );
        }
        Some(slot) => {
            version = slot
                .get("version")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok());
            let producers = slot
                .get("producers")
                .and_then(|p| p.as_array())
                .ok_or_else(|| "producer schedule active slot carries no producers".to_string())?;
            for producer in producers {
                active.push(parse_active_producer(producer)?);
            }
        }
    }
    if active.is_empty() {
        return Err("producer schedule active set is empty: refusing to sign".to_string());
    }
    let version = version.ok_or_else(|| {
        "producer schedule active slot carries no version: cannot prove the freeze names the coordinated schedule"
            .to_string()
    })?;
    Ok(LiveSchedule {
        blocked,
        version,
        active,
    })
}

/// Confirmation-time schedule gate: the voter refuses to sign a
/// confirmation unless the coordinated init params still equal the live
/// `get_producer_schedule` exactly — same version, same member names, same
/// schedule keys — and no change is staged. The declaration-time `decide`
/// covers the vote; this covers the confirmation, so a schedule that
/// rotates (or stages a proposed replacement) between the vote and H+1
/// refuses at confirmation time instead of attesting a superseded freeze.
/// Pending *and* proposed slots both block: a proposed schedule is a
/// staged change the freeze never named.
fn verify_confirmation_schedule(
    expected_version: u32,
    expected_members: &[HaltDeclarationMember],
    live: &LiveSchedule,
) -> Result<(), String> {
    if live.blocked {
        return Err(
            "a producer schedule change is staged (pending or proposed): refusing to confirm until the freeze is re-taken on the active set"
                .to_string(),
        );
    }
    if live.version != expected_version {
        return Err(format!(
            "live schedule version {} does not match coordinated version {expected_version}: refusing to confirm a superseded freeze",
            live.version
        ));
    }
    let mut expected: Vec<(String, pulsevm_crypto::k1::K1PublicKey)> =
        Vec::with_capacity(expected_members.len());
    for member in expected_members {
        let key = pulsevm_crypto::k1::K1PublicKey::from_string(&member.key).map_err(|error| {
            format!(
                "coordinated roster key for {} invalid: {error:?}",
                member.producer
            )
        })?;
        expected.push((member.producer.clone(), key));
    }
    if !schedule_matches_freeze(&expected, &live.active) {
        return Err(
            "coordinated roster does not match the live active schedule (member or schedule-key drift): refusing to confirm a superseded freeze"
                .to_string(),
        );
    }
    Ok(())
}

/// Whether the frozen ceremony set still names the live active schedule:
/// same members both ways, same schedule keys. This closes the gap where
/// `producers.producer_key` can differ from the schedule key — the voter
/// compares the frozen ceremony keys against the schedule keys directly,
/// never against the producers table. Key forms may differ (legacy EOS vs
/// PUB_K1_); the comparison runs on parsed keys, never strings.
fn schedule_matches_freeze(
    frozen: &[(String, pulsevm_crypto::k1::K1PublicKey)],
    active: &[(String, pulsevm_crypto::k1::K1PublicKey)],
) -> bool {
    if frozen.len() != active.len() {
        return false;
    }
    let mut frozen_sorted: Vec<&(String, pulsevm_crypto::k1::K1PublicKey)> =
        frozen.iter().collect();
    let mut active_sorted: Vec<&(String, pulsevm_crypto::k1::K1PublicKey)> =
        active.iter().collect();
    frozen_sorted.sort_by(|left, right| left.0.cmp(&right.0));
    active_sorted.sort_by(|left, right| left.0.cmp(&right.0));
    frozen_sorted
        .iter()
        .zip(active_sorted.iter())
        .all(|(left, right)| left.0 == right.0 && left.1 == right.1)
}

/// Leap renders contract bools inconsistently across versions (JSON bool
/// vs 0/1); accept both rather than failing a healthy freeze.
fn parse_abi_bool(value: &serde_json::Value, field: &str) -> Result<bool, String> {
    if let Some(flag) = value.get(field).and_then(|v| v.as_bool()) {
        return Ok(flag);
    }
    if let Some(number) = value.get(field).and_then(|v| v.as_u64()) {
        return Ok(number != 0);
    }
    if let Some(text) = value.get(field).and_then(|v| v.as_str()) {
        if text == "true" || text == "1" {
            return Ok(true);
        }
        if text == "false" || text == "0" {
            return Ok(false);
        }
    }
    Err(format!("row missing bool field {field}"))
}

/// Leap renders uint64 ABI fields as decimal strings; accept a JSON number
/// too. Missing fails closed: without the freeze instant the vote window
/// cannot be proven, so an old row must not be signed.
fn parse_leap_uint64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    if let Some(number) = value.get(field).and_then(|v| v.as_u64()) {
        return Ok(number);
    }
    value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("row missing {field}"))?
        .parse::<u64>()
        .map_err(|_| format!("row field {field} is not a uint64"))
}

fn parse_ceremony_row(value: &serde_json::Value) -> Result<CeremonyRow, String> {
    Ok(CeremonyRow {
        h: value
            .get("h")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "ceremony row missing h".to_string())? as u32,
        source_chain_id: value
            .get("source_chain_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "ceremony row missing source_chain_id".to_string())?
            .to_string(),
        schedule_version: value
            .get("schedule_version")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| {
                "ceremony row missing schedule_version: cannot prove the freeze names the coordinated schedule"
                    .to_string()
            })?,
        finalized: parse_abi_bool(value, "finalized")?,
        digest: value
            .get("declaration_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "ceremony row missing declaration_digest".to_string())?
            .to_string(),
        init_time_us: parse_leap_uint64(value, "init_time").map_err(|error| {
            format!(
                "ceremony row missing freeze instant ({error}): refusing to sign an undated freeze"
            )
        })?,
    })
}

fn parse_member_row(value: &serde_json::Value) -> Result<(String, MemberRow), String> {
    Ok((
        value
            .get("producer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "member row missing producer".to_string())?
            .to_string(),
        MemberRow {
            key: value
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "member row missing key".to_string())?
                .to_string(),
            voted: parse_abi_bool(value, "voted")?,
        },
    ))
}

async fn read_view(
    client: &reqwest::Client,
    config: &LoadedConfig,
) -> Result<CeremonyView, String> {
    let base = &config.inner.nodeos_url;
    let (head_num, lib_num, chain_id) = get_info(client, base).await?;
    if chain_id != config.inner.source_chain_id {
        return Err(format!(
            "node chain id does not match coordinated source chain: refusing to act"
        ));
    }
    let ceremony = get_table_rows(client, base, &config.inner.contract, "ceremony").await?;
    let singleton = ceremony.first().map(parse_ceremony_row).transpose()?;
    let members = get_table_rows(client, base, &config.inner.contract, "members").await?;
    let mut member = None;
    let mut frozen: Vec<(String, pulsevm_crypto::k1::K1PublicKey)> = Vec::new();
    let mut frozen_unreadable = false;
    for row in &members {
        let (producer, parsed) = parse_member_row(row)?;
        match pulsevm_crypto::k1::K1PublicKey::from_string(&parsed.key) {
            Ok(key) => frozen.push((producer.clone(), key)),
            Err(_) => frozen_unreadable = true,
        }
        // No early break: the freeze-vs-schedule comparison below needs the
        // full frozen set, not just this operator's row.
        if producer == config.inner.producer {
            member = Some(parsed);
        }
    }
    let live = read_live_schedule(client, base).await?;
    // The frozen ceremony must still name the live active schedule: same
    // members both ways, same schedule keys. An unreadable frozen key or a
    // set that drifted since the freeze refuses (stale freeze), while an
    // absent freeze has nothing to compare yet.
    let schedule_mismatch = singleton.is_some()
        && (frozen_unreadable || !schedule_matches_freeze(&frozen, &live.active));
    // Head timestamp only matters once a freeze exists (it bounds the vote
    // window); skip the extra block fetch while there is nothing to expire.
    let head_time_us = if singleton.is_some() {
        fetch_head_timestamp_us(client, base, head_num).await?
    } else {
        0
    };
    Ok(CeremonyView {
        head_num,
        lib_num,
        head_time_us,
        live_version: live.version,
        singleton,
        member,
        schedule_blocked: live.blocked,
        schedule_mismatch,
    })
}

// ---------------------------------------------------------------------------
// Vote construction (byte-identical to the manual `cvote` path)
// ---------------------------------------------------------------------------

fn varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Action data for `vote(name producer, signature sig)`: the producer name
/// followed by the K1 signature over the declaration digest (varuint34 type
/// tag 0 + 65 compact bytes). Layout mirrors `make_probe_tx cvote`.
fn vote_action_data(
    producer: &str,
    digest: &[u8; 32],
    key: &K1PrivateKey,
) -> Result<Vec<u8>, String> {
    let mut data = Name::from_str(producer)
        .map_err(|_| "producer is not a valid name".to_string())?
        .as_u64()
        .to_le_bytes()
        .to_vec();
    varuint(0, &mut data);
    data.extend_from_slice(&key.sign(digest).compact65());
    Ok(data)
}

fn tapos_from_head(head_num: u32, head_id_hex: &str) -> Result<(u16, u32), String> {
    let raw = hex::decode(head_id_hex).map_err(|_| "head block id is not hex".to_string())?;
    if raw.len() != 32 {
        return Err("head block id must be 32 bytes".to_string());
    }
    let prefix = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    Ok(((head_num & 0xffff) as u16, prefix))
}

fn build_vote_transaction(
    config: &LoadedConfig,
    chain_id: &Id,
    ref_num: u16,
    ref_prefix: u32,
    expiration: u32,
    digest: &[u8; 32],
) -> Result<pulsevm_core::transaction::SignedTransaction, String> {
    let data = vote_action_data(&config.inner.producer, digest, &config.vote_key)?;
    let active = Name::from_str("active").expect("active is a valid name");
    let header = TransactionHeader::new(
        pulsevm_database::TimePointSec::new(expiration),
        ref_num,
        ref_prefix,
        0u32.into(),
        0,
        0u32.into(),
    );
    let trx = Transaction::new(
        header,
        vec![],
        vec![Action::new(
            Name::from_str(&config.inner.contract).expect("contract is a valid name"),
            Name::from_str("vote").expect("vote is a valid action"),
            data,
            vec![PermissionLevel::new(
                Name::from_str(&config.payer_account)
                    .expect("payer is a valid name")
                    .as_u64(),
                active.as_u64(),
            )],
        )],
    );
    trx.sign(&config.payer_key, chain_id)
        .map_err(|error| format!("sign vote transaction: {error}"))
}

async fn submit_vote(
    client: &reqwest::Client,
    config: &LoadedConfig,
    digest: &[u8; 32],
) -> Result<String, String> {
    let info = post_json(
        client,
        &format!("{}/v1/chain/get_info", config.inner.nodeos_url),
        &serde_json::json!({}),
    )
    .await?;
    let head_num = info
        .get("head_block_num")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "get_info missing head_block_num".to_string())? as u32;
    let head_id = info
        .get("head_block_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "get_info missing head_block_id".to_string())?;
    let chain_id = Id::from_str(
        info.get("chain_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "get_info missing chain_id".to_string())?,
    )
    .map_err(|_| "chain id invalid".to_string())?;
    let (ref_num, ref_prefix) = tapos_from_head(head_num, head_id)?;
    let expiration = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("wall clock: {error}"))?
        .as_secs() as u32)
        .saturating_add(120);
    let signed =
        build_vote_transaction(config, &chain_id, ref_num, ref_prefix, expiration, digest)?;
    let signatures: Vec<String> = signed.signatures().iter().map(|s| s.to_string()).collect();
    let packed = PackedTransaction::from_signed_transaction(signed)
        .map_err(|error| format!("pack vote transaction: {error}"))?;
    let receipt = post_json(
        client,
        &format!("{}/v1/chain/push_transaction", config.inner.nodeos_url),
        &serde_json::json!({
            "signatures": signatures,
            "compression": 0,
            "packed_context_free_data": "",
            "packed_trx": hex::encode(packed.packed_trx_bytes()),
        }),
    )
    .await?;
    receipt
        .get("transaction_id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .ok_or_else(|| format!("push accepted without transaction id: {receipt}"))
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

fn write_json(path: &str, value: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| format!("serialize: {error}"))?;
    let temporary = format!("{path}.tmp-{}", std::process::id());
    std::fs::write(&temporary, bytes).map_err(|error| format!("write temporary file: {error}"))?;
    std::fs::rename(&temporary, path).map_err(|error| format!("publish {path}: {error}"))?;
    Ok(())
}

async fn fetch_block_id(
    client: &reqwest::Client,
    base: &str,
    height: u32,
) -> Result<String, String> {
    let block = post_json(
        client,
        &format!("{base}/v1/chain/get_block"),
        &serde_json::json!({ "block_num_or_id": height.to_string() }),
    )
    .await?;
    block
        .get("id")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .ok_or_else(|| format!("get_block {height} missing id"))
}

/// Leap block timestamp (`2026-10-23T13:50:31.500`, always UTC) to
/// microseconds since the Unix epoch. No chrono/time dependency: the
/// days-from-civil count is exact for the Gregorian calendar, and the
/// fractional part keeps millisecond precision (microsecond digits, if a
/// node ever renders them, are truncated, never rounded up).
fn parse_leap_timestamp_us(text: &str) -> Result<u64, String> {
    let (date, time) = text
        .split_once('T')
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let month: i64 = date_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let day: i64 = date_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let mut time_parts = time.split([':', '.']);
    let hour: i64 = time_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let minute: i64 = time_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    let second: i64 = time_parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad Leap timestamp: {text}"))?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(format!("bad Leap timestamp: {text}"));
    }
    // Days from civil (Howard Hinnant's algorithm); valid for all
    // non-negative years, which covers every chain timestamp.
    let year_adj = if month <= 2 { year - 1 } else { year };
    let era = year_adj.div_euclid(400);
    let year_of_era = year_adj.rem_euclid(400);
    // March-based month index in [0, 11] (Hinnant days-from-civil).
    let month_adj = (month + 9).rem_euclid(12);
    let day_of_year = (153 * month_adj + 2).div_euclid(5) + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era.div_euclid(4) - year_of_era.div_euclid(100) + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    let fraction_us: u64 = time_parts
        .next()
        .map(|fraction| {
            let digits = format!("{:0<6}", fraction.chars().take(6).collect::<String>());
            digits.parse::<u64>().unwrap_or(0)
        })
        .unwrap_or(0);
    let micros = days as u64 * 86_400_000_000
        + (hour as u64 * 3600 + minute as u64 * 60 + second as u64) * 1_000_000
        + fraction_us;
    Ok(micros)
}

/// Head block timestamp in microseconds: the expiry check's clock. Fetched
/// per poll only while a freeze exists (no freeze, no deadline to check).
async fn fetch_head_timestamp_us(
    client: &reqwest::Client,
    base: &str,
    head_num: u32,
) -> Result<u64, String> {
    let block = post_json(
        client,
        &format!("{base}/v1/chain/get_block"),
        &serde_json::json!({ "block_num_or_id": head_num.to_string() }),
    )
    .await?;
    let timestamp = block
        .get("timestamp")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("get_block {head_num} missing timestamp"))?;
    parse_leap_timestamp_us(timestamp)
}

#[derive(Debug, Deserialize)]
struct CoordinatorParams {
    halt_height: u32,
    halt_block_id: String,
    checkpoint_sha256: String,
    new_chain_id: String,
    source_chain_id: String,
    #[serde(default)]
    platform_chain_id: Option<String>,
}

async fn fetch_coordinator_params(
    client: &reqwest::Client,
    url: &str,
) -> Result<CoordinatorParams, String> {
    let response = client
        .get(format!("{url}/cutover/params"))
        .send()
        .await
        .map_err(|error| format!("GET coordinator params: {error}"))?;
    response
        .json()
        .await
        .map_err(|error| format!("coordinator params bad JSON: {error}"))
}

fn successor_from_genesis(genesis_path: &str) -> Result<String, String> {
    let bytes = std::fs::read(genesis_path)
        .map_err(|error| format!("read migration genesis {genesis_path}: {error}"))?;
    let genesis = pulsevm_database::GenesisState::from_bytes(&bytes)
        .map_err(|error| format!("parse migration genesis: {error}"))?;
    if genesis.migration_checkpoint_sha256.is_none() {
        return Err("migration genesis carries no checkpoint binding".to_string());
    }
    Ok(hex::encode(genesis.compute_chain_id()))
}

/// The unsigned confirmation template plus its signing digest, without
/// signing or delivering anything. Shared by the submit path and
/// `--print-digest`: an external agent signs exactly these bytes with its
/// own key management, so the digest below and a locally signed vote are
/// the same commitment.
async fn unsigned_confirmation(
    client: &reqwest::Client,
    config: &LoadedConfig,
) -> Result<(HaltConfirmation, [u8; 32]), String> {
    let height = config.inner.height;
    let local_block_id = fetch_block_id(client, &config.inner.nodeos_url, height).await?;
    // The voter's own observed pause head: the local head at confirmation
    // time. The confirmation quorum attests the highest such head, and the
    // restore gate requires the post-H proof to cover exactly it — so the
    // template carries what this node actually sees frozen, never a
    // coordinator-typed number.
    let (observed_head, _, _) = get_info(client, &config.inner.nodeos_url).await?;
    if observed_head < height {
        return Err(format!(
            "local head {observed_head} has not reached H={height}: nothing to confirm yet"
        ));
    }
    // Checkpoint and successor id: explicit config wins; the coordinator may
    // supply them, but anything it says must match what is configured and
    // what the local node reports for H.
    let mut checkpoint = config.inner.confirmation.checkpoint_sha256.clone();
    let mut new_chain = match &config.inner.confirmation.migration_genesis {
        Some(path) => Some(successor_from_genesis(path)?),
        None => None,
    };
    let mut platform = config.inner.confirmation.platform_chain_id.clone();
    if let Some(url) = config.inner.confirmation.coordinator_url.as_deref() {
        let params = fetch_coordinator_params(client, url).await?;
        if params.halt_height != height {
            return Err("coordinator params height does not match coordinated H".to_string());
        }
        if params.source_chain_id != config.inner.source_chain_id {
            return Err("coordinator params source chain does not match config".to_string());
        }
        if params.halt_block_id != local_block_id {
            return Err(
                "coordinator block id for H does not match this node's block H: refusing to sign"
                    .to_string(),
            );
        }
        if let Some(explicit) = checkpoint.as_deref() {
            if explicit != params.checkpoint_sha256 {
                return Err(
                    "coordinator checkpoint does not match configured checkpoint".to_string(),
                );
            }
        } else {
            checkpoint = Some(params.checkpoint_sha256);
        }
        if let Some(explicit) = new_chain.as_deref() {
            if explicit != params.new_chain_id {
                return Err(
                    "coordinator successor chain does not match migration genesis".to_string(),
                );
            }
        } else {
            new_chain = Some(params.new_chain_id);
        }
        // The platform id is the one value that must agree three ways
        // (config, coordinator, boot): wallets sign under it while the
        // ceremony commits to it, so any mismatch refuses loudly. Either
        // side may use hex or the base58 log rendering; bytes are compared.
        match (platform.as_deref(), params.platform_chain_id.as_deref()) {
            (Some(configured), Some(coordinated)) => {
                let configured_id = pulsevm_crypto::parse_chain_id(configured)
                    .map_err(|error| format!("configured platform chain id: {error}"))?;
                let coordinated_id = pulsevm_crypto::parse_chain_id(coordinated)
                    .map_err(|error| format!("coordinator platform chain id: {error}"))?;
                if configured_id != coordinated_id {
                    return Err(
                        "coordinator platform chain id does not match configured platform chain id"
                            .to_string(),
                    );
                }
                platform = Some(pulsevm_crypto::chain_id_hex(&configured_id));
            }
            (None, Some(coordinated)) => {
                let coordinated_id = pulsevm_crypto::parse_chain_id(coordinated)
                    .map_err(|error| format!("coordinator platform chain id: {error}"))?;
                platform = Some(pulsevm_crypto::chain_id_hex(&coordinated_id));
            }
            _ => {}
        }
    }
    let checkpoint = checkpoint.ok_or_else(|| {
        "no checkpoint: set confirmation.checkpoint_sha256 or coordinator_url".to_string()
    })?;
    let new_chain = new_chain.ok_or_else(|| {
        "no successor chain id: set confirmation.migration_genesis or coordinator_url".to_string()
    })?;
    // The platform id is mandatory: a confirmation that does not bind the
    // id wallets sign under is refused by the restore gate, so shipping one
    // is never useful. Fail here, loudly, instead of signing evidence the
    // gate must reject.
    let platform = platform.ok_or_else(|| {
        "no platform chain id configured: set confirmation.platform_chain_id or coordinator_url"
            .to_string()
    })?;
    let parsed = pulsevm_crypto::parse_chain_id(&platform)
        .map_err(|error| format!("configured platform chain id: {error}"))?;
    let platform = pulsevm_crypto::chain_id_hex(&parsed);
    // Confirmation-time schedule gate: the coordinated init params must
    // still equal the live schedule exactly (version, names, keys), and no
    // pending or proposed change may be staged. A rotation between the
    // vote and the confirmation refuses here — same policy as the
    // declaration-time vote refusal, re-checked because the chain moved.
    let live = read_live_schedule(client, &config.inner.nodeos_url).await?;
    let expected_members = read_roster(&config.inner.roster_file)?;
    verify_confirmation_schedule(config.inner.schedule_version, &expected_members, &live)?;
    // One shared library constructor builds every agent's template, so an
    // external signer over --print-digest bytes and a locally signed vote
    // are the same commitment by construction.
    HaltConfirmation::unsigned(
        &hex::encode(config.expected_digest),
        height,
        observed_head,
        &local_block_id,
        &checkpoint,
        &new_chain,
        &platform,
    )
    .map_err(|error| format!("confirmation template: {error}"))
}

async fn submit_confirmation(
    client: &reqwest::Client,
    config: &LoadedConfig,
) -> Result<String, String> {
    let height = config.inner.height;
    let (template, digest) = unsigned_confirmation(client, config).await?;
    let local_block_id = template.halt_block_id.clone();
    let checkpoint = template.checkpoint_sha256.clone();
    let new_chain = template.new_chain_id.clone();
    let platform = template.platform_chain_id.clone();
    let member_producer = config.inner.producer.clone();
    let signature = HaltSignature {
        producer: member_producer.clone(),
        key: config.vote_key.public_key().to_string(),
        signature: config.vote_key.sign(&digest).to_string(),
    };
    let confirmation = HaltConfirmation {
        signatures: vec![signature.clone()],
        ..template
    };
    // The confirmation only counts if the key belongs to the declared set;
    // fail here rather than shipping a signature the gate must reject.
    let members = read_roster(&config.inner.roster_file)?;
    if !members.iter().any(|member| {
        pulsevm_crypto::k1::K1PublicKey::from_string(&member.key)
            .is_ok_and(|key| key == config.vote_key.public_key())
    }) {
        return Err("signing key is not in the declared set".to_string());
    }
    let line = format!(
        "confirmation {} height {} declaration {} new-chain {}",
        hex::encode(digest),
        height,
        hex::encode(config.expected_digest),
        new_chain
    );
    if let Some(url) = config.inner.confirmation.coordinator_url.as_deref() {
        post_json(
            client,
            &format!("{url}/cutover/confirmations"),
            &serde_json::json!({
                "producer": member_producer,
                "halt_height": height,
                "pause_height": template.pause_height,
                "halt_block_id": local_block_id,
                "checkpoint_sha256": checkpoint,
                "new_chain_id": new_chain,
                "platform_chain_id": platform,
                "declaration_digest": hex::encode(config.expected_digest),
                "key": signature.key,
                "signature": signature.signature,
            }),
        )
        .await?;
        return Ok(format!("{line} delivered to coordinator"));
    }
    write_json(
        &config.inner.confirmation.out_file,
        &serde_json::to_value(&confirmation).map_err(|error| format!("serialize: {error}"))?,
    )?;
    Ok(format!(
        "{} written to {}",
        line, config.inner.confirmation.out_file
    ))
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

/// Status: one JSON line for cron and monitoring. Reuses the loop's own
/// `decide` and pause predicate, so the reported state is the state the
/// loop would act on. Never signs, never submits, never pauses.
async fn status(config: &LoadedConfig) -> ExitCode {
    let client = match build_client(config) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("xpr_cutover_voter status: {error}");
            return ExitCode::from(1);
        }
    };
    let view = match read_view(&client, config).await {
        Ok(view) => view,
        Err(error) => {
            eprintln!("xpr_cutover_voter status: {error}");
            return ExitCode::from(1);
        }
    };
    let (vote_state, vote_detail) = match decide(config, &view) {
        Decision::Vote => ("pending", String::new()),
        Decision::AlreadyVoted => ("on-chain", String::new()),
        Decision::Wait(reason) => ("waiting", reason),
        Decision::Refuse(reason) => ("refused", reason),
    };
    let freeze_match = view
        .singleton
        .as_ref()
        .map(|row| row.digest == hex::encode(config.expected_digest));
    let confirmation_ready = matches!(decide(config, &view), Decision::AlreadyVoted)
        || view.singleton.as_ref().is_some_and(|s| s.finalized);
    let confirmation_state = if vote_state == "on-chain" || confirmation_ready {
        if view.lib_num >= config.inner.height {
            "actionable"
        } else {
            "waiting-lib"
        }
    } else {
        "waiting-vote"
    };
    let pause_state = if !config.inner.stop_producer.at_h {
        "off"
    } else if should_pause_producer(
        &config.inner.stop_producer,
        view.head_num,
        config.inner.height,
        confirmation_state == "actionable",
    ) {
        "due"
    } else {
        "armed"
    };
    println!(
        "{}",
        serde_json::json!({
            "producer": config.inner.producer,
            "height": config.inner.height,
            "head": view.head_num,
            "lib": view.lib_num,
            "vote": vote_state,
            "vote_detail": vote_detail,
            "freeze_match": freeze_match,
            "schedule_blocked": view.schedule_blocked,
            "confirmation": confirmation_state,
            "pause": pause_state,
        })
    );
    ExitCode::SUCCESS
}

/// Preflight: the operator's go/no-go checklist before (and during) the
/// window. Every check reuses the exact code the loop runs on — config and
/// key loading, node reachability, the chain-id match, the frozen-table
/// read, the recomputed digest, and (when armed) the producer API — so a
/// GO means the loop would act, not that a different path was tested.
/// Prints one line per check plus a verdict; exits 0 on GO, 1 otherwise.
async fn preflight(config: &LoadedConfig) -> ExitCode {
    let mut failures = 0u32;
    macro_rules! check {
        ($name:expr, $result:expr $(,)?) => {
            match $result {
                Ok(detail) => println!("PREFLIGHT ok: {}: {detail}", $name),
                Err(error) => {
                    failures += 1;
                    println!("PREFLIGHT FAIL: {}: {error}", $name);
                }
            }
        };
    }
    // Config, names, and both key files already loaded by the caller: the
    // voter would have refused to start otherwise.
    println!(
        "PREFLIGHT ok: config and keys: producer {} contract {} height {}",
        config.inner.producer, config.inner.contract, config.inner.height
    );
    check![
        "stop config",
        validate_stop_config(&config.inner.stop_producer)
            .map(|()| "armed or off, never half".to_string()),
    ];
    let client = match build_client(config) {
        Ok(client) => client,
        Err(error) => {
            println!("PREFLIGHT FAIL: http client: {error}");
            println!("PREFLIGHT: NO-GO (1 check failed before the node was reached)");
            return ExitCode::from(1);
        }
    };
    let base = config.inner.nodeos_url.clone();
    let info = get_info(&client, &base).await;
    check![
        "node reachable, source chain matches",
        info.and_then(|(head, lib, chain_id)| {
            if chain_id != config.inner.source_chain_id {
                Err("node chain id does not match coordinated source chain".to_string())
            } else {
                Ok(format!("head {head} lib {lib}"))
            }
        }),
    ];
    match read_view(&client, config).await {
        Ok(view) => {
            match view.singleton {
                Some(row) if row.digest == hex::encode(config.expected_digest) => println!(
                    "PREFLIGHT ok: freeze on-chain: declaration {} matches the recomputed digest (finalized={})",
                    row.digest, row.finalized
                ),
                Some(row) => {
                    failures += 1;
                    println!(
                        "PREFLIGHT FAIL: freeze on-chain: frozen digest {} does not match the recomputed {}, refusing to sign",
                        row.digest,
                        hex::encode(config.expected_digest)
                    );
                }
                None => println!(
                    "PREFLIGHT WAIT: freeze on-chain: no ceremony row yet, re-run after init"
                ),
            }
            match view.member {
                Some(member) if !member.voted => println!(
                    "PREFLIGHT ok: member row: {} present, vote not yet on-chain",
                    config.inner.producer
                ),
                Some(_) => println!(
                    "PREFLIGHT ok: member row: {} present, vote already on-chain",
                    config.inner.producer
                ),
                None => println!(
                    "PREFLIGHT WAIT: member row: {} not in the frozen set, no vote possible",
                    config.inner.producer
                ),
            }
            if view.schedule_blocked {
                println!(
                    "PREFLIGHT WAIT: schedule: a change is staged, votes refuse until the freeze is re-taken"
                );
            } else if view.schedule_mismatch {
                println!(
                    "PREFLIGHT WAIT: schedule: frozen set does not match the live active schedule, votes refuse until the freeze is re-taken"
                );
            } else {
                println!("PREFLIGHT ok: schedule: frozen set matches the live active schedule");
            }
            println!(
                "PREFLIGHT ok: head vs H: head {} vs H {}",
                view.head_num, config.inner.height
            );
        }
        Err(error) => {
            failures += 1;
            println!("PREFLIGHT FAIL: ceremony tables: {error}");
        }
    }
    if let Some(api_url) = config.inner.stop_producer.producer_api_url.clone() {
        check![
            "producer api reachable",
            post_json(
                &client,
                &format!("{api_url}/v1/producer/paused"),
                &serde_json::json!({})
            )
            .await
            .map(|state| format!(
                "paused={}",
                state.get("paused").unwrap_or(&serde_json::Value::Null)
            )),
        ];
    }
    if failures == 0 {
        println!("PREFLIGHT: GO");
        ExitCode::SUCCESS
    } else {
        println!(
            "PREFLIGHT: NO-GO ({failures} check{s} failed)",
            s = if failures == 1 { "" } else { "s" }
        );
        ExitCode::from(1)
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage: xpr_cutover_voter --config voter.json [--dry-run] [--max-polls N] [--print-digest] [--preflight]\n\
         \n\
         The config carries the node URL, contract, producer, coordinated\n\
         height and source chain, the roster file, the vote/payer key files\n\
         (owner-only permissions), and the confirmation delivery. See\n\
         tools/xpr-cutover-voter/config.example.json. Keys never appear on\n\
         the command line and are never logged.\n\
         \n\
         --print-digest prints the currently actionable signing digest as\n\
         JSON and exits without signing: an external agent (or remote\n\
         signer) signs exactly those bytes and submits through its own\n\
         path, so key custody never moves.\n\
         \n\
         --preflight runs the operator go/no-go checklist (config, keys,\
         node, freeze, schedule, producer API) and exits 0 on GO.\n\
         \n\
         --status prints one JSON line for monitoring: head vs H, vote\
         state, confirmation readiness, schedule and pause state."
    );
    std::process::exit(2);
}

fn now_stamp() -> String {
    use std::time::{
        SystemTime,
        UNIX_EPOCH,
    };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn build_client(config: &LoadedConfig) -> Result<reqwest::Client, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HOST,
        reqwest::header::HeaderValue::from_str(&config.inner.host_header)
            .map_err(|error| format!("bad host_header: {error}"))?,
    );
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .default_headers(headers)
        .build()
        .map_err(|error| format!("http client: {error}"))
}

/// Pure JSON shapes for `--print-digest`, unit-tested below: the digest an
/// external signer signs must equal the voter's own signing digest.
fn declaration_digest_json(config: &LoadedConfig) -> serde_json::Value {
    serde_json::json!({
        "role": "declaration",
        "producer": config.inner.producer,
        "height": config.inner.height,
        "contract": config.inner.contract,
        "digest": hex::encode(config.expected_digest),
    })
}

fn confirmation_digest_json(
    producer: &str,
    template: &HaltConfirmation,
    digest: &[u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "role": "confirmation",
        "producer": producer,
        "height": template.halt_height,
        "pause_height": template.pause_height,
        "halt_block_id": template.halt_block_id,
        "checkpoint_sha256": template.checkpoint_sha256,
        "new_chain_id": template.new_chain_id,
        "platform_chain_id": template.platform_chain_id,
        "declaration_digest": template.declaration_digest,
        "digest": hex::encode(digest),
    })
}

/// Print the currently actionable digest without signing anything, for an
/// agent that holds the key its own way: declaration while the vote is
/// due, confirmation once H is final. Exits 0 after printing, 1 when
/// nothing is actionable (same policy as the submit path, so the agent
/// and the voter can never disagree on what to sign).
async fn print_digest(config: &LoadedConfig) -> Result<(), String> {
    let client = build_client(config)?;
    let view = read_view(&client, config).await?;
    match decide(config, &view) {
        Decision::Vote => {
            println!(
                "{}",
                serde_json::to_string_pretty(&declaration_digest_json(config))
                    .map_err(|error| format!("serialize: {error}"))?
            );
            return Ok(());
        }
        Decision::Refuse(reason) => {
            return Err(format!("nothing to sign: refusing ({reason})"));
        }
        Decision::Wait(_) | Decision::AlreadyVoted => {}
    }
    if view.lib_num < config.inner.height {
        return Err(format!(
            "nothing to sign: H={} is not final yet (LIB {})",
            config.inner.height, view.lib_num
        ));
    }
    let (template, digest) = unsigned_confirmation(&client, config).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&confirmation_digest_json(
            &config.inner.producer,
            &template,
            &digest
        ))
        .map_err(|error| format!("serialize: {error}"))?
    );
    Ok(())
}

/// Fail fast when the stop is half-configured: `at_h` without a producer
/// API URL would silently never pause, which is exactly the failure this
/// option exists to prevent.
fn validate_stop_config(stop: &StopConfig) -> Result<(), String> {
    if stop.at_h && stop.producer_api_url.is_none() {
        return Err(
            "stop_producer.at_h is set but stop_producer.producer_api_url is missing: refusing to run a halt that cannot fire"
                .to_string(),
        );
    }
    Ok(())
}

/// Pure pause predicate, unit-tested below. The pause fires only for the
/// round whose confirmation this voter delivered: H reached on the local
/// node, opt-in armed, and confirmation done. Pausing is reversible (the
/// operator can always resume), so observed head — not irreversibility —
/// is the right trigger; the votes were the careful part and they landed
/// before H.
fn should_pause_producer(
    stop: &StopConfig,
    head_num: u32,
    height: u32,
    confirmation_delivered: bool,
) -> bool {
    stop.at_h && stop.producer_api_url.is_some() && confirmation_delivered && head_num >= height
}

/// Pause the local producer via the Leap producer API, then prove it is
/// paused instead of trusting the first call. Both endpoints are POSTs.
async fn pause_producer(client: &reqwest::Client, api_url: &str) -> Result<(), String> {
    post_json(
        client,
        &format!("{api_url}/v1/producer/pause"),
        &serde_json::json!({}),
    )
    .await?;
    let state = post_json(
        client,
        &format!("{api_url}/v1/producer/paused"),
        &serde_json::json!({}),
    )
    .await?;
    if state.get("paused").and_then(|v| v.as_bool()) == Some(true) {
        Ok(())
    } else {
        Err(format!("producer pause unverified: {state}"))
    }
}

/// Blocks of lookahead that switch the loop to 1s polling: discovering H
/// a poll late is fine hours out, but near the halt every half-second
/// block counts and the pause must land promptly.
const FAST_POLL_LOOKAHEAD: u32 = 12;

/// Seconds between polls once the halt is near. Slow polling far out
/// keeps the loop quiet for weeks; fast polling near H catches the exact
/// block. After the pause is holding, slow polling resumes: there is
/// nothing left to discover, only the pause to re-assert.
fn poll_interval_secs(poll_secs: u64, head_num: u32, height: u32, pause_holding: bool) -> u64 {
    if pause_holding {
        poll_secs
    } else if head_num.saturating_add(FAST_POLL_LOOKAHEAD) >= height {
        1
    } else {
        poll_secs
    }
}

async fn run(config: &LoadedConfig, dry_run: bool, max_polls: u64) -> Result<(), String> {
    validate_stop_config(&config.inner.stop_producer)?;
    let client = build_client(config)?;
    let mut voted = false;
    let mut confirmation_delivered = false;
    let mut pause_holding = false;
    let mut pause_note = String::new();
    let mut last_note = String::new();
    let mut polls = 0u64;
    loop {
        polls += 1;
        if max_polls > 0 && polls > max_polls {
            log_line!("poll limit reached ({max_polls}), exiting");
            return Ok(());
        }
        let view = match read_view(&client, config).await {
            Ok(view) => view,
            Err(error) => {
                // Node hiccups must not kill the watcher: the window is
                // what matters, and a dead loop helps nobody.
                if last_note != error {
                    log_line!("node unreachable, retrying: {error}");
                    last_note = error;
                }
                tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                continue;
            }
        };
        match decide(config, &view) {
            Decision::Vote => {
                if dry_run {
                    log_line!(
                        "DRY RUN: would sign declaration {} and submit vote for {} at head {}",
                        hex::encode(config.expected_digest),
                        config.inner.producer,
                        view.head_num
                    );
                } else {
                    match submit_vote(&client, config, &config.expected_digest).await {
                        Ok(txid) => {
                            log_line!("vote submitted: {txid}");
                            voted = true;
                        }
                        Err(error) => {
                            log_line!("vote submission failed, retrying: {error}");
                        }
                    }
                }
            }
            Decision::AlreadyVoted => {
                voted = true;
                note_throttled(&mut last_note, &mut polls, "vote already on-chain");
            }
            Decision::Wait(reason) => {
                note_throttled(&mut last_note, &mut polls, &format!("waiting: {reason}"));
            }
            Decision::Refuse(reason) => {
                note_throttled(&mut last_note, &mut polls, &format!("refusing: {reason}"));
            }
        }
        // Confirmation needs H irreversible on this node. It is independent
        // of whether our vote landed: the confirmation quorum is over the
        // declared set, so a late voter still signs.
        let confirmed_ready = voted
            || matches!(decide(config, &view), Decision::AlreadyVoted)
            || view.singleton.as_ref().is_some_and(|s| s.finalized);
        if confirmed_ready && view.lib_num >= config.inner.height {
            if dry_run {
                log_line!(
                    "DRY RUN: would sign and deliver the confirmation for H={}",
                    config.inner.height
                );
                if should_pause_producer(
                    &config.inner.stop_producer,
                    view.head_num,
                    config.inner.height,
                    true,
                ) {
                    log_line!(
                        "DRY RUN: would pause the local producer at H={} via {}",
                        config.inner.height,
                        config
                            .inner
                            .stop_producer
                            .producer_api_url
                            .as_deref()
                            .unwrap_or("<missing>")
                    );
                }
                return Ok(());
            }
            match submit_confirmation(&client, config).await {
                Ok(line) => {
                    log_line!("{line}");
                    confirmation_delivered = true;
                }
                Err(error) => {
                    log_line!("confirmation failed, retrying: {error}");
                }
            }
        }
        // The halt half of the binary: once this voter's confirmation is
        // delivered and H is observed, the local producer must stay paused.
        // This never exits over a pause failure — the process stays alive
        // retrying, because a node restart clears Leap's in-memory pause
        // and only a live enforcer re-pauses it. To resume production
        // deliberately, stop this voter first: a manual resume while it
        // runs gets re-paused on the next poll.
        if !dry_run
            && should_pause_producer(
                &config.inner.stop_producer,
                view.head_num,
                config.inner.height,
                confirmation_delivered,
            )
        {
            if let Some(api_url) = config.inner.stop_producer.producer_api_url.clone() {
                match pause_producer(&client, &api_url).await {
                    Ok(()) => {
                        if !pause_holding {
                            log_line!(
                                "local producer paused at H={}, enforcing",
                                config.inner.height
                            );
                        }
                        pause_holding = true;
                    }
                    Err(error) => {
                        pause_holding = false;
                        note_throttled(
                            &mut pause_note,
                            &mut polls,
                            &format!("producer pause failed, retrying: {error}"),
                        );
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(poll_interval_secs(
            config.inner.poll_secs,
            view.head_num,
            config.inner.height,
            pause_holding,
        )))
        .await;
    }
}

/// Log state changes immediately, repeats at most every dozen polls.
fn note_throttled(last_note: &mut String, polls: &mut u64, note: &str) {
    if *last_note != note || *polls % 12 == 0 {
        log_line!("{note}");
        *last_note = note.to_string();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    use std::process::ExitCode;
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<String> = None;
    let mut dry_run = false;
    let mut max_polls = 0u64;
    let mut print_digest_only = false;
    let mut preflight_only = false;
    let mut status_only = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = args.next();
            }
            "--dry-run" => dry_run = true,
            "--max-polls" => {
                let value = args.next().unwrap_or_default();
                max_polls = value
                    .parse()
                    .unwrap_or_else(|_| panic!("--max-polls needs a number, got {value}"));
            }
            "--print-digest" => print_digest_only = true,
            "--preflight" => preflight_only = true,
            "--status" => status_only = true,
            _ => usage(),
        }
    }
    let Some(config_path) = config_path else {
        usage()
    };
    let config = match load_loaded_config(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("xpr_cutover_voter: {error}");
            return ExitCode::from(1);
        }
    };
    if print_digest_only {
        return match print_digest(&config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xpr_cutover_voter: {error}");
                ExitCode::from(1)
            }
        };
    }
    if preflight_only {
        return preflight(&config).await;
    }
    if status_only {
        return status(&config).await;
    }
    if dry_run {
        log_line!("dry run: evaluating only, nothing will be signed or submitted");
    }
    match run(&config, dry_run || config.inner.dry_run, max_polls).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xpr_cutover_voter: {error}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: the decision function is the safety policy, so it is tested branch
// by branch. Chain I/O stays behind read_view/submit_* and is covered by the
// rehearsal, not here.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> K1PrivateKey {
        K1PrivateKey::from_seed_string("cutover-voter-test").unwrap()
    }

    /// Coordinated schedule version the test freeze names.
    const TEST_SCHEDULE_VERSION: u32 = 7;

    fn test_loaded_config(height: u32) -> LoadedConfig {
        let key = super::tests::test_key();
        let member = HaltDeclarationMember {
            producer: "prod.a".to_string(),
            key: key.public_key().to_string(),
            weight: pulsevm_chain_types::HaltWeight(1),
        };
        let digest = HaltDeclaration {
            version: HaltDeclaration::VERSION,
            source_chain_id: "41".repeat(32),
            last_height: height,
            validator_set: vec![member],
            signatures: Vec::new(),
        }
        .digest()
        .unwrap();
        LoadedConfig {
            inner: Config {
                nodeos_url: "http://127.0.0.1:8888".to_string(),
                host_header: default_host_header(),
                contract: "cutover".to_string(),
                producer: "prod.a".to_string(),
                source_chain_id: "41".repeat(32),
                height,
                schedule_version: TEST_SCHEDULE_VERSION,
                roster_file: String::new(),
                vote_key_file: String::new(),
                payer_account: "prod.a".to_string(),
                payer_key_file: String::new(),
                poll_secs: 1,
                dry_run: true,
                enabled: true,
                confirmation: ConfirmationConfig {
                    coordinator_url: None,
                    out_file: String::new(),
                    migration_genesis: None,
                    checkpoint_sha256: None,
                    platform_chain_id: None,
                },
                stop_producer: StopConfig::default(),
            },
            vote_key: key,
            payer_key: PrivateKey::from_str(
                "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
            )
            .unwrap(),
            payer_account: "prod.a".to_string(),
            expected_digest: digest,
        }
    }

    fn view_with(
        config: &LoadedConfig,
        head: u32,
        head_time_us: u64,
        singleton: Option<CeremonyRow>,
        member: Option<MemberRow>,
    ) -> CeremonyView {
        CeremonyView {
            head_num: head,
            lib_num: head.saturating_sub(10),
            head_time_us,
            live_version: config.inner.schedule_version,
            singleton,
            member,
            schedule_blocked: false,
            schedule_mismatch: false,
        }
    }

    fn live_singleton(config: &LoadedConfig) -> CeremonyRow {
        CeremonyRow {
            h: config.inner.height,
            source_chain_id: config.inner.source_chain_id.clone(),
            schedule_version: config.inner.schedule_version,
            finalized: false,
            digest: hex::encode(config.expected_digest),
            init_time_us: 0,
        }
    }

    fn live_member(config: &LoadedConfig, voted: bool) -> MemberRow {
        MemberRow {
            key: config.vote_key.public_key().to_string(),
            voted,
        }
    }

    #[test]
    fn waits_without_a_frozen_ceremony() {
        let config = test_loaded_config(100);
        let view = view_with(&config, 90, 0, None, None);
        assert!(matches!(decide(&config, &view), Decision::Wait(_)));
    }

    #[test]
    fn refuses_a_foreign_freeze() {
        let config = test_loaded_config(100);
        // Wrong height.
        let mut bad = live_singleton(&config);
        bad.h = 101;
        let view = view_with(&config, 90, 0, Some(bad), Some(live_member(&config, false)));
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
        // Wrong digest (a freeze we did not coordinate).
        let mut bad = live_singleton(&config);
        bad.digest = "00".repeat(32);
        let view = view_with(&config, 90, 0, Some(bad), Some(live_member(&config, false)));
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
        // Wrong source chain.
        let mut bad = live_singleton(&config);
        bad.source_chain_id = "42".repeat(32);
        let view = view_with(&config, 90, 0, Some(bad), Some(live_member(&config, false)));
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn refuses_outsider_keys_and_finalized_sets() {
        let config = test_loaded_config(100);
        // Finalized without us.
        let mut done = live_singleton(&config);
        done.finalized = true;
        let view = view_with(
            &config,
            90,
            0,
            Some(done),
            Some(live_member(&config, false)),
        );
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
        // Producer not frozen.
        let view = view_with(&config, 90, 0, Some(live_singleton(&config)), None);
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
        // Frozen under a different key.
        let other = K1PrivateKey::from_seed_string("someone-else").unwrap();
        let view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(MemberRow {
                key: other.public_key().to_string(),
                voted: false,
            }),
        );
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn abi_bools_accept_both_renderings() {
        for (input, want) in [
            (serde_json::json!(true), true),
            (serde_json::json!(false), false),
            (serde_json::json!(1), true),
            (serde_json::json!(0), false),
            (serde_json::json!("true"), true),
            (serde_json::json!("0"), false),
        ] {
            let row = serde_json::json!({"finalized": input});
            assert_eq!(parse_abi_bool(&row, "finalized"), Ok(want));
        }
        let row = serde_json::json!({});
        assert!(parse_abi_bool(&row, "finalized").is_err());
    }

    #[test]
    fn member_keys_match_across_string_forms() {
        // Nodes render frozen keys in legacy EOS form while the signer
        // formats as PUB_K1_: the voter must parse-compare, never compare
        // strings, or it would refuse forever on real chain data.
        let config = test_loaded_config(100);
        let eos_form = "EOS5XoBbqs61hJNY4XtCa7aTDn2ZhXoAmKkrLvBWW2tdrpDGYTonz";
        assert_eq!(
            pulsevm_crypto::k1::K1PublicKey::from_string(eos_form).unwrap(),
            config.vote_key.public_key()
        );
        let view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(MemberRow {
                key: eos_form.to_string(),
                voted: false,
            }),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
    }

    #[test]
    fn refuses_while_a_schedule_change_is_staged() {
        let config = test_loaded_config(100);
        let mut view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
        view.schedule_blocked = true;
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn refuses_a_freeze_that_drifted_from_the_active_schedule() {
        let config = test_loaded_config(100);
        let mut view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
        view.schedule_mismatch = true;
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn refuses_a_freeze_under_the_wrong_schedule_version() {
        let config = test_loaded_config(100);
        // The frozen ceremony names another version than coordinated: even
        // with matching members, the freeze is not the coordinated one.
        let mut wrong_frozen = live_singleton(&config);
        wrong_frozen.schedule_version = TEST_SCHEDULE_VERSION + 1;
        let view = view_with(
            &config,
            90,
            0,
            Some(wrong_frozen),
            Some(live_member(&config, false)),
        );
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
        // The live schedule rotated past the coordinated version after the
        // freeze: the vote must wait for a re-taken freeze.
        let mut rotated = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        rotated.live_version = TEST_SCHEDULE_VERSION + 1;
        assert!(matches!(decide(&config, &rotated), Decision::Refuse(_)));
        // All three sides agree (frozen, coordinated, live): votes.
        let view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
    }

    #[test]
    fn confirmation_refuses_any_schedule_drift_or_staging() {
        let config = test_loaded_config(100);
        let key = config.vote_key.public_key();
        let members = vec![HaltDeclarationMember {
            producer: "prod.a".to_string(),
            key: key.to_string(),
            weight: pulsevm_chain_types::HaltWeight(1),
        }];
        let live = |blocked: bool, version: u32, active: Vec<(String, _)>| LiveSchedule {
            blocked,
            version,
            active,
        };
        let matching = vec![("prod.a".to_string(), key.clone())];
        // Exact match on version, names, and keys: confirms.
        verify_confirmation_schedule(
            TEST_SCHEDULE_VERSION,
            &members,
            &live(false, TEST_SCHEDULE_VERSION, matching.clone()),
        )
        .expect("exact init params must confirm");
        // A staged schedule — pending or proposed — blocks the
        // confirmation exactly like it blocks the vote.
        for staged in [
            serde_json::json!({"pending": {"producers": [{"producer_name": "prod.a"}]}}),
            serde_json::json!({"proposed": {"producers": [{"producer_name": "prod.a"}]}}),
        ] {
            let blocked = LiveSchedule {
                blocked: schedule_staged(&staged),
                version: TEST_SCHEDULE_VERSION,
                active: matching.clone(),
            };
            assert!(
                verify_confirmation_schedule(TEST_SCHEDULE_VERSION, &members, &blocked).is_err(),
                "a staged schedule must refuse the confirmation"
            );
        }
        // A live version past the coordinated one: the freeze is
        // superseded, even with matching members.
        assert!(
            verify_confirmation_schedule(
                TEST_SCHEDULE_VERSION,
                &members,
                &live(false, TEST_SCHEDULE_VERSION + 1, matching.clone()),
            )
            .is_err(),
            "a rotated live version must refuse the confirmation"
        );
        // A schedule-key rotation under the same version: stale freeze.
        let other = K1PrivateKey::from_seed_string("someone-else")
            .unwrap()
            .public_key();
        assert!(
            verify_confirmation_schedule(
                TEST_SCHEDULE_VERSION,
                &members,
                &live(
                    false,
                    TEST_SCHEDULE_VERSION,
                    vec![("prod.a".to_string(), other)]
                ),
            )
            .is_err(),
            "a rotated schedule key must refuse the confirmation"
        );
        // A standby joining changes the set: stale freeze.
        let mut grown = matching.clone();
        grown.push(("prod.b".to_string(), key));
        assert!(
            verify_confirmation_schedule(
                TEST_SCHEDULE_VERSION,
                &members,
                &live(false, TEST_SCHEDULE_VERSION, grown),
            )
            .is_err(),
            "a grown schedule must refuse the confirmation"
        );
    }

    #[test]
    fn freeze_matches_live_schedule_on_names_and_keys() {
        use pulsevm_crypto::k1::K1PrivateKey;
        let first = K1PrivateKey::from_seed_string("schedule-a")
            .unwrap()
            .public_key();
        let second = K1PrivateKey::from_seed_string("schedule-b")
            .unwrap()
            .public_key();
        let frozen = vec![
            ("prod.a".to_string(), first.clone()),
            ("prod.b".to_string(), second.clone()),
        ];
        // Same set, any order: matches.
        let active = vec![
            ("prod.b".to_string(), second.clone()),
            ("prod.a".to_string(), first.clone()),
        ];
        assert!(schedule_matches_freeze(&frozen, &active));
        // A schedule-key rotation on one member: stale freeze.
        let other = K1PrivateKey::from_seed_string("schedule-c")
            .unwrap()
            .public_key();
        let rotated = vec![
            ("prod.a".to_string(), first.clone()),
            ("prod.b".to_string(), other),
        ];
        assert!(!schedule_matches_freeze(&frozen, &rotated));
        // A standby joining (or a member leaving) changes the count: stale.
        let grown = vec![
            ("prod.a".to_string(), first.clone()),
            ("prod.b".to_string(), second.clone()),
            ("prod.c".to_string(), second.clone()),
        ];
        assert!(!schedule_matches_freeze(&frozen, &grown));
        assert!(!schedule_matches_freeze(&grown, &frozen));
    }

    #[test]
    fn active_producer_parses_leap_authority_shapes() {
        use pulsevm_crypto::k1::K1PrivateKey;
        let key = K1PrivateKey::from_seed_string("schedule-a")
            .unwrap()
            .public_key()
            .to_string();
        let authority = |tag: u64, threshold: u64, keys: Vec<serde_json::Value>| {
            serde_json::json!({
                "producer_name": "prod.a",
                "authority": [tag, {"threshold": threshold, "keys": keys}],
            })
        };
        let one = || vec![serde_json::json!({"key": key.clone(), "weight": 1})];
        // Leap 4 (tag 0) and Leap 5 (tag 1) authority forms with a single
        // threshold-1 key: both parse — the rehearsal serves tag 0.
        for tag in [0, 1] {
            let (name, parsed) =
                parse_active_producer(&authority(tag, 1, one())).expect("authority parses");
            assert_eq!(name, "prod.a");
            assert_eq!(parsed.to_string(), key);
        }
        // The legacy flat key form is gone: refuse, do not sign under a
        // schedule we misread.
        assert!(
            parse_active_producer(&serde_json::json!({
                "producer_name": "prod.a",
                "block_signing_key": key,
            }))
            .is_err(),
            "flat block_signing_key must refuse"
        );
        // Threshold 2 and multi-key authorities name no single key: refuse.
        // An unknown variant tag is a shape the voter must not guess at.
        assert!(
            parse_active_producer(&authority(
                1,
                2,
                vec![
                    serde_json::json!({"key": key, "weight": 1}),
                    serde_json::json!({"key": key, "weight": 1}),
                ]
            ))
            .is_err(),
            "threshold-2 authority must refuse"
        );
        assert!(
            parse_active_producer(&authority(
                1,
                1,
                vec![
                    serde_json::json!({"key": key, "weight": 1}),
                    serde_json::json!({"key": key, "weight": 1}),
                ]
            ))
            .is_err(),
            "multi-key authority must refuse"
        );
        assert!(
            parse_active_producer(&authority(7, 1, one())).is_err(),
            "unknown variant tag must refuse"
        );
    }

    #[test]
    fn schedule_staging_reads_leap_shapes() {
        // Empty slots (null or missing) are not a change.
        assert!(!schedule_staged(&serde_json::json!({})));
        assert!(!schedule_staged(
            &serde_json::json!({"pending": null, "proposed": null})
        ));
        assert!(!schedule_staged(
            &serde_json::json!({"pending": {"producers": []}, "proposed": null})
        ));
        // Any staged producers block the vote.
        assert!(schedule_staged(
            &serde_json::json!({"pending": {"producers": [{"producer_name": "eosio"}]}})
        ));
        assert!(schedule_staged(
            &serde_json::json!({"proposed": {"producers": [{"producer_name": "eosio"}]}})
        ));
        // Unknown shapes fail closed: a schedule we cannot read may be mid-rotation.
        assert!(schedule_staged(&serde_json::json!({"pending": {}})));
        assert!(schedule_staged(
            &serde_json::json!({"pending": {"version": 3}})
        ));
    }

    #[test]
    fn print_digest_shapes_carry_the_signing_digests() {
        let config = test_loaded_config(100);
        // The declaration shape carries exactly the digest the voter would
        // sign: an external agent signing these bytes makes the same
        // commitment as the voter.
        let shape = declaration_digest_json(&config);
        assert_eq!(shape["role"], "declaration");
        assert_eq!(shape["producer"], "prod.a");
        assert_eq!(shape["digest"], hex::encode(config.expected_digest));
        // The confirmation shape carries the template digest, including
        // the platform binding when configured.
        let template = HaltConfirmation {
            version: HaltConfirmation::VERSION,
            declaration_digest: hex::encode(config.expected_digest),
            halt_height: 100,
            pause_height: 103,
            halt_block_id: "09".repeat(32),
            checkpoint_sha256: "10".repeat(32),
            new_chain_id: "11".repeat(32),
            platform_chain_id: "12".repeat(32),
            signatures: Vec::new(),
        };
        let digest = template.digest().unwrap();
        let shape = confirmation_digest_json("prod.a", &template, &digest);
        assert_eq!(shape["role"], "confirmation");
        assert_eq!(shape["pause_height"], 103);
        assert_eq!(shape["digest"], hex::encode(digest));
        assert_eq!(shape["platform_chain_id"], "12".repeat(32));
        assert_eq!(
            shape["declaration_digest"],
            hex::encode(config.expected_digest)
        );
    }

    #[test]
    fn votes_once_inside_the_window_then_stops() {
        let config = test_loaded_config(100);
        let view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
        // Already on-chain: never sign twice.
        let view = view_with(
            &config,
            90,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, true)),
        );
        assert_eq!(decide(&config, &view), Decision::AlreadyVoted);
        // At or past H the contract must reject: refuse instead of spamming.
        let view = view_with(
            &config,
            100,
            0,
            Some(live_singleton(&config)),
            Some(live_member(&config, false)),
        );
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn refuses_an_expired_freeze() {
        use pulsevm_chain_types::CEREMONY_VOTE_WINDOW_US;
        // The window constant is seven days in microseconds, matching the
        // contract's vote_window_us (the contract is authoritative).
        assert_eq!(CEREMONY_VOTE_WINDOW_US, 7 * 24 * 3600 * 1_000_000);
        let config = test_loaded_config(100);
        let mut frozen = live_singleton(&config);
        frozen.init_time_us = 1_000_000_000_000_000;
        // Inside the window (boundary inclusive): vote.
        let view = view_with(
            &config,
            90,
            frozen.init_time_us + CEREMONY_VOTE_WINDOW_US,
            Some(frozen.clone()),
            Some(live_member(&config, false)),
        );
        assert_eq!(decide(&config, &view), Decision::Vote);
        // One microsecond past the window: refuse, do not spam a vote the
        // contract must reject.
        let view = view_with(
            &config,
            90,
            frozen.init_time_us + CEREMONY_VOTE_WINDOW_US + 1,
            Some(frozen),
            Some(live_member(&config, false)),
        );
        assert!(matches!(decide(&config, &view), Decision::Refuse(_)));
    }

    #[test]
    fn leap_timestamps_parse_to_microseconds() {
        // 2026-01-01T00:00:00Z is 1767225600 (2025 is not a leap year).
        assert_eq!(
            parse_leap_timestamp_us("2026-01-01T00:00:00.000").unwrap(),
            1_767_225_600_000_000
        );
        assert_eq!(
            parse_leap_timestamp_us("2026-10-23T13:50:31.500").unwrap()
                - parse_leap_timestamp_us("2026-10-23T13:50:31.000").unwrap(),
            500_000
        );
        // A second absolute vector in the March-based half of the year, so
        // the month remap is pinned on both sides of February.
        // 2026-03-01T00:00:00Z is 1772323200 (Jan 31 + Feb 28 past New Year).
        assert_eq!(
            parse_leap_timestamp_us("2026-03-01T00:00:00.000").unwrap(),
            1_772_323_200_000_000
        );
        assert!(parse_leap_timestamp_us("not-a-timestamp").is_err());
        assert!(parse_leap_timestamp_us("2026-13-01T00:00:00.000").is_err());
    }

    #[test]
    fn ceremony_row_requires_the_freeze_instant() {
        let row = serde_json::json!({
            "h": 100,
            "source_chain_id": "41".repeat(32),
            "schedule_version": 7,
            "finalized": false,
            "declaration_digest": "00".repeat(32),
            "init_time": "1700000000000000",
        });
        let parsed = parse_ceremony_row(&row).unwrap();
        assert_eq!(parsed.init_time_us, 1_700_000_000_000_000);
        assert_eq!(parsed.schedule_version, 7);
        // A row without the frozen version cannot pin the init params to
        // the live schedule: it must not parse.
        let mut unversioned = row.clone();
        unversioned
            .as_object_mut()
            .unwrap()
            .remove("schedule_version");
        assert!(parse_ceremony_row(&unversioned).is_err());
        // Undated freezes (rows frozen before the window existed) must not
        // be signed: the vote window cannot be proven without init_time.
        let mut undated = row.clone();
        undated.as_object_mut().unwrap().remove("init_time");
        assert!(parse_ceremony_row(&undated).is_err());
    }

    #[test]
    fn vote_action_data_matches_the_manual_path() {
        // Layout parity with `make_probe_tx cvote`: producer u64 LE, then
        // varuint type tag 0, then the 65-byte compact K1 signature over the
        // declaration digest. One signature serves both tallies.
        let key = super::tests::test_key();
        let digest = [0xABu8; 32];
        let data = vote_action_data("prod.a", &digest, &key).unwrap();
        let mut expected = pulsevm_core::name::Name::from_str("prod.a")
            .unwrap()
            .as_u64()
            .to_le_bytes()
            .to_vec();
        expected.push(0x00);
        expected.extend_from_slice(&key.sign(&digest).compact65());
        assert_eq!(data, expected);
        // And the embedded signature recovers to the member key.
        let mut compact = [0u8; 65];
        compact.copy_from_slice(&data[9..74]);
        let recovered = pulsevm_crypto::k1::K1Signature::from_compact65(&compact)
            .recover(&digest)
            .unwrap();
        assert_eq!(recovered, key.public_key());
    }

    #[test]
    fn tapos_derivation_matches_the_relay_math() {
        // ref prefix is bytes 8..12 of the head id, little-endian; ref num
        // is the low 16 bits of the head number (mirrors leap_tapos_push).
        let mut raw = [0xAAu8; 32];
        raw[8..12].copy_from_slice(&hex::decode("cb9ed679").unwrap());
        let head_id = hex::encode(raw);
        let (num, prefix) = tapos_from_head(0x0001_00b2, &head_id).unwrap();
        assert_eq!(num, 0xb2);
        assert_eq!(
            prefix,
            u32::from_le_bytes(hex::decode("cb9ed679").unwrap().try_into().unwrap())
        );
        assert!(tapos_from_head(1, "00").is_err());
    }

    #[test]
    fn config_validation_fails_closed() {
        assert!(load_loaded_config("/nonexistent/voter.json").is_err());
        // Disabled configs refuse to run even when everything else parses.
        let dir = std::env::temp_dir().join(format!("voter-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, content: &str| {
            let path = dir.join(name);
            std::fs::write(&path, content).unwrap();
            path.to_str().unwrap().to_string()
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_path = write(
                "key.wif",
                "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
            );
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_key_file(&key_path).is_err());
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_key_file(&key_path).is_ok());
        }
        let roster = write(
            "roster.json",
            r#"[{"producer":"prod.a","key":"PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV","weight":"1"}]"#,
        );
        let key = write(
            "vote.wif",
            "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bad_height = write(
            "bad.json",
            &format!(
                r#"{{"nodeos_url":"http://x","contract":"cutover","producer":"prod.a","source_chain_id":"{}","height":"nope","roster_file":"{roster}","vote_key_file":"{key}","payer_account":"prod.a","payer_key_file":"{key}"}}"#,
                "41".repeat(32),
            ),
        );
        assert!(load_loaded_config(&bad_height).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn armed_stop() -> StopConfig {
        StopConfig {
            at_h: true,
            producer_api_url: Some("http://127.0.0.1:8888".to_string()),
        }
    }

    #[test]
    fn pause_fires_only_for_a_delivered_confirmation_at_h() {
        // Off by default: an unconfigured voter never pauses, no matter
        // what the chain does.
        let off = StopConfig::default();
        assert!(!should_pause_producer(&off, 100, 100, true));
        assert!(!should_pause_producer(&off, 200, 100, true));
        // Armed but head short of H: the producer still has blocks to
        // build, pausing now would fork it off early.
        let armed = armed_stop();
        assert!(!should_pause_producer(&armed, 99, 100, true));
        // Armed at H but the confirmation is not delivered: pausing on a
        // superseded round's H would halt the wrong freeze.
        assert!(!should_pause_producer(&armed, 100, 100, false));
        // Delivered at H: stop before H+1.
        assert!(should_pause_producer(&armed, 100, 100, true));
        // Delivered past H (late confirmation): still stop — every block
        // past H built by this producer is a straggler.
        assert!(should_pause_producer(&armed, 103, 100, true));
    }

    /// Minimal Leap producer-API stub: answers pause/paused with canned
    /// bodies over sequential connections. std-only; the test drives the
    /// real `pause_producer` HTTP path against it.
    fn stub_producer_api(paused_reports: bool) -> String {
        use std::io::{
            Read,
            Write,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head_text = String::from_utf8_lossy(&head);
                let path = head_text
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                let content_len = head_text
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; content_len];
                stream.read_exact(&mut body).ok();
                let response_body = if path.ends_with("/v1/producer/paused") {
                    format!("{{\"paused\":{paused_reports}}}")
                } else {
                    "{}".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).ok();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn pause_producer_roundtrip_against_stub_api() {
        let client = reqwest::Client::builder().build().unwrap();
        let api = stub_producer_api(true);
        assert!(pause_producer(&client, &api).await.is_ok());
    }

    #[tokio::test]
    async fn pause_producer_rejects_an_unverified_pause() {
        // The pause call succeeds but the node reports still running:
        // trust the verification, not the call.
        let client = reqwest::Client::builder().build().unwrap();
        let api = stub_producer_api(false);
        assert!(pause_producer(&client, &api).await.is_err());
    }

    #[test]
    fn half_configured_stop_fails_fast() {
        // at_h without a URL would silently never pause: refuse to run.
        let half = StopConfig {
            at_h: true,
            producer_api_url: None,
        };
        assert!(validate_stop_config(&half).is_err());
        // Either fully armed or fully off validates.
        assert!(validate_stop_config(&StopConfig::default()).is_ok());
        assert!(validate_stop_config(&armed_stop()).is_ok());
    }

    #[test]
    fn poll_interval_is_slow_far_out_fast_near_h_slow_while_holding() {
        // Hours out: the configured cadence, quiet for weeks.
        assert_eq!(poll_interval_secs(30, 100, 10_000, false), 30);
        // Inside the lookahead: 1s polling so the pause lands promptly.
        assert_eq!(poll_interval_secs(30, 9_989, 10_000, false), 1);
        assert_eq!(poll_interval_secs(30, 10_000, 10_000, false), 1);
        // Past H (stragglers): still fast until the pause is confirmed.
        assert_eq!(poll_interval_secs(30, 10_005, 10_000, false), 1);
        // Pause holding: nothing left to discover, slow cadence resumes.
        assert_eq!(poll_interval_secs(30, 10_005, 10_000, true), 30);
    }
}
