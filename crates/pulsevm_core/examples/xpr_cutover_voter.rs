//! Automatic cutover voter: after upgrading, a BP's node signs for them.
//!
//! The operator installs the release, drops in a small config file (node
//! URL, contract, producer name, the two key files they already hold, the
//! coordinated height and source chain id), and starts the voter. It polls
//! the ceremony tables and:
//!
//! * signs the frozen declaration digest with the block-signing key and submits the on-chain `vote`
//!   once, inside the window;
//! * signs the confirmation digest over the agreed pause head P (fixed H+k, never a LIB wait — on a
//!   large committee LIB(H) arrives long after the agreed stop) and delivers it to the coordinator
//!   (or a file when no coordinator is configured).
//!
//! Guardrails (all enforced, all logged, never silent):
//!
//! * The frozen ceremony must match the config: same H, same source chain, and a declaration digest
//!   recomputed locally from the published roster. Anything else is refused, never signed.
//! * The signing key must belong to the frozen member row, and the row must not already show a
//!   vote. Outsider keys and double votes refuse.
//! * No vote at or after H; the confirmation quorum over H_ID stands in for Leap finality instead
//!   of waiting on LIB.
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
    /// The agreed pause head P (a fixed H+k the ceremony sets before the
    /// freeze): every producer stops at P and every confirmation signs P,
    /// never the signer's own observed tip. Required, and must sit strictly
    /// past `height`: without an agreed head, 15 voters pausing at 15
    /// different tips can never assemble one quorum digest. Missing or
    /// non-advancing values fail fast at startup so a half-configured voter
    /// never signs a divergent head.
    pause_height: Option<u32>,
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
    /// Opt-in local producer stop. When `at_pause` is set with a
    /// `producer_api_url`, the voter pauses its own producer once the local
    /// head has reached P (Leap `producer/pause`), whether or not its own
    /// confirmation was delivered: a producer whose submission failed must
    /// still stop, or its tail runs past the proof window unstaged. A
    /// contract cannot halt block production — only the producer can — so
    /// this is the half of the halt that lives in the binary. Off by
    /// default: a surprise pause is worse than a loud refusal to start.
    #[serde(default)]
    stop_producer: StopConfig,
}

/// Local producer stop at the agreed pause head P. Both fields are required
/// together: `at_pause` without a URL fails fast at startup instead of
/// silently never pausing. The stop is deliberately independent of
/// confirmation delivery — a failed submission must still halt the
/// producer, or its tail runs past the proof window. `at_h` is the removed
/// predecessor that stopped at H: any config still carrying it is refused
/// below instead of silently never pausing.
#[derive(Debug, Clone, Default, Deserialize)]
struct StopConfig {
    #[serde(default)]
    at_pause: bool,
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
    /// The published sha256 of the source producer schedule
    /// (`xpr_snapshot_schedule` prints it). It is known before H, so it is
    /// required at load: the live schedule is checked against it on every
    /// poll before H, and at signing the migration genesis must pin the same
    /// value. Never taken from the genesis, which does not exist yet.
    schedule_sha256: Option<String>,
    /// The checkpoint hash, the genesis and the platform id all come into
    /// being after the voter has started (conversion of the H snapshot, then
    /// chain creation), so a ceremony agent starts the voter without them and
    /// restarts it as each lands. That is allowed only when this is set: a
    /// config that omits them without it can never sign and refuses to load.
    /// The pause is never gated on these fields; signing requires all three.
    #[serde(default)]
    operator_fed: bool,
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
    /// The published source schedule hash pinned in the migration genesis
    /// this voter will sign. The live active schedule must hash to it.
    schedule_pin: [u8; 32],
    /// Why signing is blocked although the config loaded: an operator-fed
    /// value (checkpoint hash, genesis, platform id) was supplied after H and
    /// does not validate. The voter must keep running, because exiting here
    /// would end pause enforcement and a nodeos restart would resume
    /// production past P. Signing refuses until the operator fixes the value.
    fed_inputs_error: Option<String>,
    /// Remembers that this voter's own ceremony finalized, so the fallback
    /// pause still works after a restart while the chain reads fail.
    finalized_marker: std::path::PathBuf,
}

/// The marker sits next to the config and is bound to the declaration digest:
/// a different ceremony never inherits it.
fn finalized_marker_path(config_path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{config_path}.finalized"))
}

fn read_finalized_marker(path: &std::path::Path, digest: &[u8; 32]) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.trim() == hex::encode(digest))
        .unwrap_or(false)
}

fn write_finalized_marker(path: &std::path::Path, digest: &[u8; 32]) -> Result<(), String> {
    let tmp = path.with_extension("finalized.tmp");
    std::fs::write(&tmp, format!("{}\n", hex::encode(digest)))
        .map_err(|error| format!("write {}: {error}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|error| format!("rename {} to {}: {error}", tmp.display(), path.display()))
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
    contract: &str,
) -> Result<[u8; 32], String> {
    // The digest the BPs sign binds the ceremony contract's account: a vote
    // is a vote for that contract only.
    let unsigned = HaltDeclaration {
        version: HaltDeclaration::VERSION,
        source_chain_id: source_chain_id.to_string(),
        last_height: height,
        validator_set: members.to_vec(),
        ceremony_contract: Some(contract.to_string()),
        signatures: Vec::new(),
    };
    unsigned
        .digest()
        .map_err(|error| format!("declaration digest: {error}"))
}

fn parse_hash32(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| "is not hex".to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "must be 32 bytes of hex".to_string())
}

/// The confirmation inputs that only exist after H. Signing needs all of
/// them; the pause and the declaration vote need none.
fn missing_confirmation_inputs(confirmation: &ConfirmationConfig) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if confirmation.checkpoint_sha256.is_none() {
        missing.push("confirmation.checkpoint_sha256");
    }
    if confirmation.migration_genesis.is_none() {
        missing.push("confirmation.migration_genesis");
    }
    if confirmation.platform_chain_id.is_none() {
        missing.push("confirmation.platform_chain_id");
    }
    missing
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
    // The agreed pause head is mandatory and must sit strictly past H: a
    // voter that cannot name P would sign its own observed tip, and 15
    // such voters can never assemble one quorum digest.
    match inner.pause_height {
        Some(pause) if pause > inner.height => {}
        Some(pause) => {
            return Err(format!(
                "pause_height {pause} does not sit past height {}: agree a P strictly past H before the freeze",
                inner.height
            ));
        }
        None => {
            return Err(
                "pause_height (the agreed pause head P) is required and must sit past height: refusing to run without an agreed head"
                    .to_string(),
            );
        }
    }
    validate_stop_config(&inner.stop_producer)?;
    let vote_wif = read_key_file(&inner.vote_key_file)?;
    let vote_key = K1PrivateKey::from_string(&vote_wif)
        .map_err(|error| format!("vote key invalid: {error:?}"))?;
    let payer_wif = read_key_file(&inner.payer_key_file)?;
    let payer_key =
        PrivateKey::from_str(&payer_wif).map_err(|_| "payer key invalid".to_string())?;
    let payer_account = inner.payer_account.clone();
    let members = read_roster(&inner.roster_file)?;
    let expected_digest = expected_declaration_digest(
        &inner.source_chain_id,
        inner.height,
        &members,
        &inner.contract,
    )?;
    // The published schedule hash is the one pin known before H, so it is
    // always required. The checkpoint hash, the genesis and the platform id
    // exist only after H (conversion, then chain creation): each is validated
    // when present, and all three may be absent only for an operator-fed
    // config, which refuses to sign until they have landed. The pause never
    // depends on them.
    let schedule_hex = inner.confirmation.schedule_sha256.as_deref().ok_or_else(|| {
        "confirmation.schedule_sha256 is required: the published hash of the source producer schedule (xpr_snapshot_schedule prints it)"
            .to_string()
    })?;
    let schedule_pin = parse_hash32(schedule_hex)
        .map_err(|error| format!("confirmation.schedule_sha256: {error}"))?;
    let checkpoint = inner.confirmation.checkpoint_sha256.as_deref();
    let validate_present_inputs = || -> Result<(), String> {
        if let Some(checkpoint) = checkpoint {
            parse_hash32(checkpoint)
                .map_err(|error| format!("confirmation.checkpoint_sha256: {error}"))?;
        }
        if let Some(platform) = inner.confirmation.platform_chain_id.as_deref() {
            pulsevm_crypto::parse_chain_id(platform)
                .map_err(|error| format!("confirmation.platform_chain_id: {error}"))?;
        }
        if let Some(genesis_path) = inner.confirmation.migration_genesis.as_deref() {
            genesis_binding(genesis_path, checkpoint, &schedule_pin)?;
        }
        Ok(())
    };
    // An operator-fed value arrives after H, when the voter is already
    // enforcing the pause: a bad one must block signing, not stop the voter.
    // A config that is not operator-fed has nothing to protect and refuses.
    let fed_inputs_error = match validate_present_inputs() {
        Ok(()) => None,
        Err(error) if inner.confirmation.operator_fed => Some(error),
        Err(error) => return Err(error),
    };
    let missing = missing_confirmation_inputs(&inner.confirmation);
    if !missing.is_empty() && !inner.confirmation.operator_fed {
        return Err(format!(
            "{} not set: a config without them can never sign. A ceremony agent that supplies them after H must set confirmation.operator_fed = true; the voter then pauses on schedule and refuses to sign until all three are present",
            missing.join(", ")
        ));
    }
    Ok(LoadedConfig {
        inner,
        vote_key,
        payer_key,
        payer_account,
        expected_digest,
        schedule_pin,
        fed_inputs_error,
        finalized_marker: finalized_marker_path(path),
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
    /// Hash of the live active schedule in the form the genesis pins
    /// (`pack_schedule_hash`). A schedule version bump changes it.
    live_schedule_hash: [u8; 32],
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
        live_schedule_hash: live_schedule_hash(&live)?,
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

/// One block of the H+1..P window must carry nothing: a zero transaction
/// merkle root and no transactions. The gate refuses any other window, so a
/// voter that signed over one would attest a round that cannot restore.
fn window_block_is_empty(block: &serde_json::Value, number: u32) -> Result<(), String> {
    let mroot = block
        .get("transaction_mroot")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("get_block {number} missing transaction_mroot"))?;
    if mroot.len() != 64 || mroot.bytes().any(|byte| byte != b'0') {
        return Err(format!(
            "block {number} in the H..P window carries transactions (transaction_mroot {mroot})"
        ));
    }
    if block
        .get("transactions")
        .and_then(|v| v.as_array())
        .is_some_and(|transactions| !transactions.is_empty())
    {
        return Err(format!(
            "block {number} in the H..P window lists transactions"
        ));
    }
    Ok(())
}

/// Each block must name the previous one as its parent. The scan fetches by
/// number, so without this a reorg between two fetches could leave one block
/// uninspected while the final id still matched.
fn window_block_links(
    block: &serde_json::Value,
    number: u32,
    expected_previous: &str,
) -> Result<(), String> {
    let previous = block
        .get("previous")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("get_block {number} missing previous"))?;
    if !previous.eq_ignore_ascii_case(expected_previous) {
        return Err(format!(
            "block {number} does not link to the block scanned before it (previous {previous}, expected {expected_previous}): the chain reorganized during the scan"
        ));
    }
    Ok(())
}

/// Walk the blocks after `after` through `through` on the local node and
/// require every one to be empty and to link to the one before it.
async fn verify_window_empty(
    client: &reqwest::Client,
    base: &str,
    after: u32,
    through: u32,
) -> Result<String, String> {
    let mut last_id = None;
    let mut expected_previous = if through > after {
        Some(fetch_block_id(client, base, after).await?)
    } else {
        None
    };
    for number in after.saturating_add(1)..=through {
        let block = post_json(
            client,
            &format!("{base}/v1/chain/get_block"),
            &serde_json::json!({ "block_num_or_id": number.to_string() }),
        )
        .await?;
        window_block_is_empty(&block, number)?;
        if let Some(previous) = &expected_previous {
            window_block_links(&block, number, previous)?;
        }
        let id = block
            .get("id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| format!("get_block {number} missing id"))?
            .to_owned();
        expected_previous = Some(id.clone());
        last_id = Some(id);
    }
    // The id of the block coverage ends at: a fork that replaces blocks above
    // P changes it, so cached coverage keyed to it cannot go stale.
    match last_id {
        Some(id) => Ok(id),
        None => fetch_block_id(client, base, through).await,
    }
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
    /// The ceremony's agreed pause head P, when the coordinator publishes
    /// it: the voter requires it to equal the configured P rather than
    /// signing a coordinator-typed number.
    #[serde(default)]
    pause_height: Option<u32>,
    /// Id of block P, when the coordinator publishes it: it must equal this
    /// node's own block P, so the voter attests the branch it actually saw.
    #[serde(default)]
    pause_block_id: Option<String>,
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

/// Read the migration genesis this voter is about to sign and return the
/// successor (ceremony) chain id it commits to plus the published schedule
/// hash it pins. The voter signs only a genesis it has read itself: the
/// checkpoint pin must equal the voter's own checkpoint hash (from its own
/// conversion) and the schedule pin must be present.
fn genesis_binding(
    genesis_path: &str,
    own_checkpoint: Option<&str>,
    expected_schedule_pin: &[u8; 32],
) -> Result<(String, [u8; 32]), String> {
    let bytes = std::fs::read(genesis_path)
        .map_err(|error| format!("read migration genesis {genesis_path}: {error}"))?;
    let genesis = pulsevm_database::GenesisState::from_bytes(&bytes)
        .map_err(|error| format!("parse migration genesis: {error}"))?;
    let pinned_checkpoint = genesis
        .migration_checkpoint_sha256
        .ok_or_else(|| "migration genesis carries no checkpoint binding".to_string())?;
    if let Some(own_checkpoint) = own_checkpoint
        && !hex::encode(pinned_checkpoint).eq_ignore_ascii_case(own_checkpoint)
    {
        return Err(format!(
            "migration genesis pins checkpoint {} but this voter derived {own_checkpoint}: refusing to sign a genesis for a checkpoint it did not derive",
            hex::encode(pinned_checkpoint)
        ));
    }
    let schedule_pin = genesis.migration_schedule_sha256.ok_or_else(|| {
        "migration genesis carries no migration_schedule_sha256: the published source schedule hash must be pinned"
            .to_string()
    })?;
    if &schedule_pin != expected_schedule_pin {
        return Err(format!(
            "migration genesis pins schedule {} but confirmation.schedule_sha256 is {}: refusing a genesis for a schedule this voter was not told to expect",
            hex::encode(schedule_pin),
            hex::encode(expected_schedule_pin)
        ));
    }
    Ok((
        hex::encode(genesis.compute_ceremony_chain_id()),
        schedule_pin,
    ))
}

/// The hash of the live active schedule in the form operators publish and the
/// genesis pins (`pack_schedule_hash`).
fn live_schedule_hash(live: &LiveSchedule) -> Result<[u8; 32], String> {
    let mut members = Vec::with_capacity(live.active.len());
    for (name, key) in &live.active {
        let producer = pulsevm_name::Name::from_str(name)
            .map_err(|_| format!("live schedule producer {name} is not a name"))?;
        members.push((producer.as_u64(), key.compressed()));
    }
    Ok(pulsevm_database::pack_schedule_hash(live.version, &members))
}

/// The unsigned confirmation template plus its signing digest, without
/// signing or delivering anything. Shared by the submit path and
/// `--print-digest`: an external agent signs exactly these bytes with its
/// own key management, so the digest below and a locally signed vote are
/// the same commitment.
async fn unsigned_confirmation(
    client: &reqwest::Client,
    config: &LoadedConfig,
    expected: Option<(&str, u32, &str)>,
) -> Result<(HaltConfirmation, [u8; 32]), String> {
    let height = config.inner.height;
    // The agreed pause head P: the ceremony fixes P (a strict H+k) before
    // the freeze, every producer stops at P, and every signer confirms P —
    // never its own observed tip, so 15 voters pausing at 15 different
    // tips can never split the quorum digest. Startup validation already
    // pins P strictly past H; belt-and-suspenders here because this digest
    // is the quorum's binding commitment.
    let pause_height = config.inner.pause_height.ok_or_else(|| {
        "no agreed pause_height configured: refusing to sign a divergent head".to_string()
    })?;
    if pause_height <= height {
        return Err(format!(
            "agreed pause head {pause_height} does not sit past H={height}: nothing to confirm yet"
        ));
    }
    let local_block_id = fetch_block_id(client, &config.inner.nodeos_url, height).await?;
    // No voter attests a freeze it has not seen land: signing requires the
    // local head at or past the agreed pause head P. H_ID (fetched above)
    // is then observed in ancestry, not assumed. P itself comes from config
    // (cross-checked against the coordinator above), never from the local
    // tip: it is the stop the quorum agreed, and the quorum over H_ID
    // stands in for Leap finality, so no voter waits for LIB — on a large
    // committee LIB(H) arrives after the agreed stop, and waiting for it
    // would deadlock the halt.
    let (head_num, _, _) = get_info(client, &config.inner.nodeos_url).await?;
    if head_num < pause_height {
        return Err(format!(
            "local head {head_num} has not reached the agreed stop P={pause_height}: nothing to confirm yet"
        ));
    }
    // The confirmation commits to the id of block P, read from this node:
    // the quorum attests one specific branch, so a fabricated empty fork
    // under the real height cannot match what the producers signed.
    let local_pause_block_id =
        fetch_block_id(client, &config.inner.nodeos_url, pause_height).await?;
    // The id that was settled and scanned is the id that gets signed: a
    // reorg of P since then refuses instead of signing a branch nobody
    // verified.
    if let Some((expected_id, covered_through, covered_tip)) = expected {
        if expected_id != local_pause_block_id {
            return Err(format!(
                "block P={pause_height} changed from {expected_id} to {local_pause_block_id} since it was verified: refusing to sign"
            ));
        }
        // The emptiness scan must reach the head the node has now: a block
        // that arrived after the scan could carry a transaction nothing else
        // covers (the proof and the gate stop at P).
        let (head_now, _, _) = get_info(client, &config.inner.nodeos_url).await?;
        if head_now > covered_through {
            return Err(format!(
                "head {head_now} is past the scanned coverage {covered_through}: rescanning before signing"
            ));
        }
        // Coverage is by block id, not height: a same-height fork above P
        // between the scan and now would otherwise pass unseen.
        let tip_now = fetch_block_id(client, &config.inner.nodeos_url, covered_through).await?;
        if tip_now != covered_tip {
            return Err(format!(
                "block {covered_through} changed from {covered_tip} to {tip_now} since the scan: rescanning before signing"
            ));
        }
    }
    // Checkpoint and successor id: explicit config wins; the coordinator may
    // supply them, but anything it says must match what is configured and
    // what the local node reports for H.
    let checkpoint = config.inner.confirmation.checkpoint_sha256.clone();
    // The voter signs only a genesis it has read: the successor id is
    // derived from the configured genesis, never adopted from a coordinator.
    if let Some(error) = &config.fed_inputs_error {
        return Err(format!(
            "signing blocked (the pause is unaffected): a fed input is invalid: {error}"
        ));
    }
    let missing = missing_confirmation_inputs(&config.inner.confirmation);
    if !missing.is_empty() {
        return Err(format!(
            "signing blocked (the pause is unaffected): {} not set yet; the voter signs only a checkpoint it derived, a genesis it read and a platform id it was configured with",
            missing.join(", ")
        ));
    }
    let own_checkpoint = checkpoint.as_deref().ok_or_else(|| {
        "no checkpoint: set confirmation.checkpoint_sha256 from your own conversion".to_string()
    })?;
    let genesis_path = config.inner.confirmation.migration_genesis.as_deref().ok_or_else(|| {
        "confirmation.migration_genesis is required: the voter signs only a genesis it has read, not a successor id a coordinator supplies"
            .to_string()
    })?;
    let (new_chain, schedule_pin) =
        genesis_binding(genesis_path, Some(own_checkpoint), &config.schedule_pin)?;
    let mut platform = config.inner.confirmation.platform_chain_id.clone();
    if let Some(url) = config.inner.confirmation.coordinator_url.as_deref() {
        let params = fetch_coordinator_params(client, url).await?;
        if params.halt_height != height {
            return Err("coordinator params height does not match coordinated H".to_string());
        }
        // The agreed pause head must match two ways (config, coordinator):
        // a coordinator publishing a different P is running a different
        // freeze, and this voter must not sign it.
        if let Some(coordinated_p) = params.pause_height
            && coordinated_p != pause_height
        {
            return Err(format!(
                "coordinator pause head {coordinated_p} does not match the agreed pause head {pause_height}: refusing to sign"
            ));
        }
        if let Some(coordinated_id) = params.pause_block_id.as_deref()
            && coordinated_id != local_pause_block_id
        {
            return Err(
                "coordinator block id for P does not match this node's block P: refusing to sign"
                    .to_string(),
            );
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
        // The checkpoint hash must come from this operator's own
        // conversion of its own snapshot, never from the coordinator: a
        // signer that adopts the coordinator's hash attests a state it never
        // derived, and a bad coordinator could get the quorum to sign
        // altered balances.
        match checkpoint.as_deref() {
            Some(explicit) if explicit == params.checkpoint_sha256 => {}
            Some(_) => {
                return Err(
                    "coordinator checkpoint does not match configured checkpoint".to_string(),
                );
            }
            None => {
                return Err(
                    "confirmation.checkpoint_sha256 is not set: derive the checkpoint from your own Leap snapshot at H (xpr_import_check --leap-snapshot) and configure its sha; refusing to adopt the coordinator's"
                        .to_string(),
                );
            }
        }
        if new_chain != params.new_chain_id {
            return Err("coordinator successor chain does not match migration genesis".to_string());
        }
        // The platform id is the one value that must agree three ways
        // (config, coordinator, boot): wallets sign under it while the
        // ceremony commits to it, so any mismatch refuses loudly. It is
        // configured, never adopted from the coordinator. Either side may
        // use hex or the base58 log rendering; bytes are compared.
        if let (Some(configured), Some(coordinated)) =
            (platform.as_deref(), params.platform_chain_id.as_deref())
        {
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
    }
    let checkpoint = checkpoint.ok_or_else(|| {
        "no checkpoint: set confirmation.checkpoint_sha256 from your own conversion".to_string()
    })?;
    // The platform id is mandatory: a confirmation that does not bind the
    // id wallets sign under is refused by the restore gate, so shipping one
    // is never useful. Fail here, loudly, instead of signing evidence the
    // gate must reject.
    let platform = platform.ok_or_else(|| {
        "no platform chain id configured: set confirmation.platform_chain_id (it is never adopted from a coordinator)"
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
    // The committee this voter attests must be the published schedule the
    // genesis pins: a fact from outside the bundle that a forged committee,
    // however consistent, cannot match.
    if live_schedule_hash(&live)? != schedule_pin {
        return Err(
            "the live active schedule does not hash to the migration genesis's migration_schedule_sha256: refusing to sign"
                .to_string(),
        );
    }
    // One shared library constructor builds every agent's template, so an
    // external signer over --print-digest bytes and a locally signed vote
    // are the same commitment by construction.
    HaltConfirmation::unsigned(
        &hex::encode(config.expected_digest),
        height,
        pause_height,
        &local_pause_block_id,
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
    expected_pause_id: &str,
    covered_through: u32,
    covered_tip: &str,
) -> Result<String, String> {
    let height = config.inner.height;
    let (template, digest) = unsigned_confirmation(
        client,
        config,
        Some((expected_pause_id, covered_through, covered_tip)),
    )
    .await?;
    let local_block_id = template.halt_block_id.clone();
    let pause_block_id = template.pause_block_id.clone();
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
                "pause_block_id": pause_block_id,
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
    let confirmation_ready =
        matches!(decide(config, &view), Decision::AlreadyVoted) || own_finalized(config, &view);
    let pause_height = config.inner.pause_height.unwrap_or(config.inner.height);
    // The quorum over H_ID stands in for Leap finality: confirmation is
    // actionable once the agreed stop is locally observed, without waiting
    // for LIB (which on a large committee arrives after the stop). The
    // pause is independent of delivery — see should_pause_producer.
    let confirmation_state = if vote_state == "on-chain" || confirmation_ready {
        if view.head_num >= pause_height {
            "actionable"
        } else if view.head_num >= config.inner.height {
            "waiting-stop"
        } else {
            "waiting-head"
        }
    } else {
        "waiting-vote"
    };
    let pause_state = if !config.inner.stop_producer.at_pause {
        "off"
    } else if should_pause_producer(&config.inner.stop_producer, view.head_num, pause_height)
        && own_finalized(config, &view)
    {
        "due"
    } else {
        "armed"
    };
    println!(
        "{}",
        serde_json::json!({
            "producer": config.inner.producer,
            "height": config.inner.height,
            "pause_height": config.inner.pause_height,
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
    if let (Some(pause_height), Ok((head, lib, _))) = (config.inner.pause_height, info.as_ref()) {
        check![
            "stop window past finality",
            stop_window_covers_finality(config.inner.height, pause_height, *head, *lib),
        ];
    }
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
            if view.live_schedule_hash == config.schedule_pin {
                println!(
                    "PREFLIGHT ok: schedule pin: the live active schedule hashes to confirmation.schedule_sha256"
                );
            } else {
                failures += 1;
                println!(
                    "PREFLIGHT FAIL: schedule pin: the live active schedule does not hash to confirmation.schedule_sha256 (version bump?): publish the new hash and rebuild the genesis and ceremony id"
                );
            }
            let missing = missing_confirmation_inputs(&config.inner.confirmation);
            if let Some(error) = &config.fed_inputs_error {
                failures += 1;
                println!(
                    "PREFLIGHT FAIL: confirmation inputs: a fed value is invalid ({error}): the pause holds but signing is blocked until it is fixed"
                );
            } else if missing.is_empty() {
                println!(
                    "PREFLIGHT ok: confirmation inputs: checkpoint hash, migration genesis and platform id are set and bound to the pinned schedule"
                );
            } else if view.head_num < config.inner.height {
                println!(
                    "PREFLIGHT WAIT: confirmation inputs: {} not set yet; they exist only after H, the agent supplies them and restarts the voter (the pause does not need them)",
                    missing.join(", ")
                );
            } else {
                failures += 1;
                println!(
                    "PREFLIGHT FAIL: confirmation inputs: {} not set after H: the pause holds but signing is blocked until they are supplied",
                    missing.join(", ")
                );
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
            .and_then(|state| match paused_flag(&state) {
                Some(paused) => Ok(format!("paused={paused}")),
                None => Err(format!(
                    "the producer API's paused reply is neither a boolean nor {{\"paused\": bool}}: {state}"
                )),
            }),
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
        "pause_block_id": template.pause_block_id,
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
/// due, confirmation once H is final and the agreed pause head P is
/// observed. Exits 0 after printing, 1 when nothing is actionable (same
/// policy as the submit path, so the agent and the voter can never
/// disagree on what to sign).
async fn print_digest(config: &LoadedConfig) -> Result<(), String> {
    let client = build_client(config)?;
    let view = read_view(&client, config).await?;
    let pause_height = config.inner.pause_height.unwrap_or(config.inner.height);
    // Before the ceremony finalizes there is only the declaration to sign.
    if !own_finalized(config, &view) {
        return match decide(config, &view) {
            Decision::Vote => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&declaration_digest_json(config))
                        .map_err(|error| format!("serialize: {error}"))?
                );
                Ok(())
            }
            Decision::Refuse(reason) => Err(format!("nothing to sign: refusing ({reason})")),
            Decision::Wait(_) | Decision::AlreadyVoted => Err(
                "nothing to sign: the ceremony is not finalized on-chain yet, so there is no confirmation to sign"
                    .to_string(),
            ),
        };
    }
    // Finalized: the confirmation digest, under the same policy the signing
    // loop applies, so an external signer cannot be handed a digest the loop
    // itself would refuse.
    if view.head_num < pause_height {
        return Err(format!(
            "nothing to sign: the agreed stop P={pause_height} is not observed yet (head {})",
            view.head_num
        ));
    }
    if config.inner.stop_producer.at_pause
        && let Some(api_url) = config.inner.stop_producer.producer_api_url.as_deref()
    {
        let state = post_json(
            &client,
            &format!("{api_url}/v1/producer/paused"),
            &serde_json::json!({}),
        )
        .await?;
        if paused_flag(&state) != Some(true) {
            return Err("nothing to sign: the local producer is not paused".to_string());
        }
    }
    let mut settle: (Option<String>, u32) = (None, 0);
    let settled_id = loop {
        let id = fetch_block_id(&client, &config.inner.nodeos_url, pause_height).await?;
        if settle_step(&mut settle, &id) >= SETTLE_POLLS {
            break id;
        }
        tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
    };
    let (head_now, _, _) = get_info(&client, &config.inner.nodeos_url).await?;
    let covered = pause_height.max(head_now);
    let covered_tip = verify_window_empty(
        &client,
        &config.inner.nodeos_url,
        config.inner.height,
        covered,
    )
    .await
    .map_err(|error| format!("nothing to sign: {error}"))?;
    let (template, digest) =
        unsigned_confirmation(&client, config, Some((&settled_id, covered, &covered_tip))).await?;
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

/// Fail fast when the stop is half-configured or stale: `at_pause` without
/// a producer API URL would silently never pause, which is exactly the
/// failure this option exists to prevent — and `at_h` is the removed
/// predecessor (it stopped at H, not at the agreed P), so any config still
/// carrying it is refused instead of silently never pausing.
fn validate_stop_config(stop: &StopConfig) -> Result<(), String> {
    if stop.at_h {
        return Err(
            "stop_producer.at_h was removed: set stop_producer.at_pause (which stops at the agreed pause head P, not at H) and remove at_h"
                .to_string(),
        );
    }
    if stop.at_pause && stop.producer_api_url.is_none() {
        return Err(
            "stop_producer.at_pause is set but stop_producer.producer_api_url is missing: refusing to run a halt that cannot fire"
                .to_string(),
        );
    }
    Ok(())
}

/// One producer turn of slack on top of the finality estimate.
const STOP_WINDOW_SAFETY_BLOCKS: u32 = 12;

/// Whether the agreed stop P sits far enough past H for H to become
/// irreversible before every producer stops. A Leap snapshot of H is only
/// finalized once H is irreversible, so a stop inside the finality lag
/// leaves a pending snapshot that never completes (found live with a
/// four-producer schedule: LIB(H) arrives tens of blocks after H, and on a
/// 21-producer committee hundreds). The live head-minus-LIB gap is the
/// finality lag; require twice that plus one producer turn.
fn stop_window_covers_finality(
    height: u32,
    pause_height: u32,
    head: u32,
    lib: u32,
) -> Result<String, String> {
    let lag = head.saturating_sub(lib);
    let needed = lag
        .saturating_mul(2)
        .saturating_add(STOP_WINDOW_SAFETY_BLOCKS);
    let window = pause_height.saturating_sub(height);
    if window >= needed {
        Ok(format!(
            "P-H = {window} blocks covers the observed finality lag {lag} (need {needed})"
        ))
    } else {
        Err(format!(
            "agreed stop leaves only {window} blocks after H but the chain's finality lag is {lag} (head {head}, LIB {lib}): \
             H would still be reversible at P and its snapshot would never finalize; agree P >= H + {needed}"
        ))
    }
}

/// Pure signing predicate, unit-tested below. The confirmation is
/// actionable once the voter is ready (voted, already voted, or singleton
/// finalized) and the agreed stop is observed locally: no voter attests a
/// freeze it has not seen land. LIB is deliberately not an input: the
/// quorum over H_ID stands in for Leap finality, and on a large committee
/// LIB(H) arrives after the agreed stop — waiting for it would deadlock
/// the halt.
///
/// When this voter manages the producer pause, signing also waits until the
/// pause is confirmed held: a failed pause must not coexist with a signed
/// confirmation, or production can continue past the P the quorum attested.
fn should_sign_confirmation(
    confirmed_ready: bool,
    head_num: u32,
    pause_height: u32,
    pause_ok: bool,
) -> bool {
    confirmed_ready && head_num >= pause_height && pause_ok
}

/// Pure pause predicate, unit-tested below. The pause fires once the local
/// head has reached the agreed pause head P: opt-in armed, head at or past
/// P. Delivery of this voter's own confirmation is deliberately NOT a
/// precondition: a producer whose submission fails must still stop, or the
/// chain keeps building past the agreed head (on a 21-producer network the
/// LIB-gated signing the old predicate waited on arrives hundreds of
/// blocks late, so gating the stop on delivery never stops at all).
/// Delivery retries continue independently after the pause. Stopping at the
/// agreed P (not at H) keeps the H+1..P window exactly the quorum
/// attested; every scheduled producer stops at the same agreed P, so no
/// producer builds an unproven tail past it.
fn should_pause_producer(stop: &StopConfig, head_num: u32, pause_height: u32) -> bool {
    stop.at_pause && stop.producer_api_url.is_some() && head_num >= pause_height
}

/// The ceremony counts as finalized for this voter only when the on-chain
/// singleton is the declaration this voter itself expects: same digest, same
/// H, same source chain. Anyone could otherwise stand up a ceremony of their
/// own (a one-member schedule, one vote) that finalizes but that every honest
/// voter refuses, and arm every voter's pause for a round that can never
/// restore.
fn own_finalized(config: &LoadedConfig, view: &CeremonyView) -> bool {
    view.singleton.as_ref().is_some_and(|singleton| {
        singleton.finalized
            && singleton.digest == hex::encode(config.expected_digest)
            && singleton.h == config.inner.height
            && singleton.source_chain_id == config.inner.source_chain_id
    })
}

/// Marks an exit made because the published schedule pin went stale before
/// H; `main` turns it into a distinct exit code so supervisors can alarm.
const PIN_ABORT_PREFIX: &str = "schedule pin abort: ";
const EXIT_PIN_ABORT: u8 = 3;

/// Consecutive identical reads of P's block id required before signing: the
/// confirmation commits to P's id, and P is still reversible (LIB sits far
/// behind it), so a microfork around P would split the signers across two
/// ids. The id has to hold still for several polls first.
const SETTLE_POLLS: u32 = 4;

/// Record one read of P's block id and return how many consecutive polls it
/// has now been the same (1 on any change).
fn settle_step(state: &mut (Option<String>, u32), id: &str) -> u32 {
    if state.0.as_deref() == Some(id) {
        state.1 += 1;
    } else {
        *state = (Some(id.to_string()), 1);
    }
    state.1
}

/// Read the producer API's paused state. Leap 5.0.3 answers
/// `/v1/producer/paused` with a bare JSON boolean (HTTP 201); some builds and
/// wrappers answer `{"paused": bool}`. Accept both, and treat anything else
/// as unknown, which never counts as paused.
fn paused_flag(state: &serde_json::Value) -> Option<bool> {
    state
        .as_bool()
        .or_else(|| state.get("paused").and_then(|value| value.as_bool()))
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
    if paused_flag(&state) == Some(true) {
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
    // The agreed pause head is validated at startup, but the loop takes it
    // from the same config it signs with: no head, no quorum, no pause.
    let pause_height = config.inner.pause_height.ok_or_else(|| {
        "no agreed pause_height configured: refusing to run without an agreed head".to_string()
    })?;
    let client = build_client(config)?;
    let mut voted = false;
    let mut pause_holding = false;
    let mut window_checked = false;
    let mut window_verified: Option<(String, u32, String)> = None;
    // Restored from the marker so a restart does not drop the fallback pause
    // until one chain read succeeds.
    let mut finalized_seen =
        read_finalized_marker(&config.finalized_marker, &config.expected_digest);
    if finalized_seen {
        log_line!(
            "ceremony finalization restored from {}",
            config.finalized_marker.display()
        );
    }
    if let Some(error) = &config.fed_inputs_error {
        log_line!(
            "ALARM event=cutover.signing_inputs_invalid producer={} outcome=failure: {error}; the pause stays enforced and signing is blocked until the value is fixed and the voter restarted",
            config.inner.producer
        );
    }
    let mut settle: (Option<String>, u32) = (None, 0);
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
                // The pause must not queue behind the ceremony reads: one
                // slow table read or schedule fetch used to skip it for the
                // whole poll, and the producer kept building past P. Try the
                // pause from the head alone.
                if !dry_run
                    && let Some(api_url) = config.inner.stop_producer.producer_api_url.clone()
                    && let Ok((head, _, chain_id)) =
                        get_info(&client, &config.inner.nodeos_url).await
                    && chain_id == config.inner.source_chain_id
                    && finalized_seen
                    && should_pause_producer(&config.inner.stop_producer, head, pause_height)
                {
                    match pause_producer(&client, &api_url).await {
                        Ok(()) => pause_holding = true,
                        Err(pause_error) => {
                            pause_holding = false;
                            log_line!("producer pause failed, retrying: {pause_error}");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                continue;
            }
        };
        // The stop window must clear the finality lag, or H would still be
        // reversible when every producer stops and its snapshot would never
        // finalize. Enforced on the first successful read before H (not only
        // under --preflight, which an operator can skip). It runs on any
        // start before P, including a restart after H, so a voter that comes
        // back mid-window still checks. At or past P the window is spent and
        // refusing to run would stop the pause being re-asserted.
        if !window_checked && view.head_num < pause_height {
            window_checked = true;
            if let Err(error) = stop_window_covers_finality(
                config.inner.height,
                pause_height,
                view.head_num,
                view.lib_num,
            ) {
                if view.head_num < config.inner.height {
                    return Err(error);
                }
                // Past H the window is already running and the fleet agreed
                // P: exiting here would leave this producer unpaused at P.
                // Keep enforcing the pause; without an irreversible H there
                // is no snapshot, so no checkpoint hash and no signature.
                log_line!("WARNING after H: {error}");
            }
        }
        // The published schedule pin must still describe the live committee
        // while there is time to abort. XPR's schedule version moves, the pin
        // includes the version, and a stale pin would otherwise only show up
        // at signing, with the chain already paused. Before H this fails
        // loudly and nothing has been paused.
        if view.head_num < config.inner.height && view.live_schedule_hash != config.schedule_pin {
            // A schedule bump between finalization and H makes the voters that
            // polled in that gap exit here while the rest pause at P and then
            // cannot sign. There is no on-chain abort, so the alarm line and
            // the distinct exit code are the signal: page on either and tell
            // the coordinator out of band before P.
            log_line!(
                "ALARM event=cutover.schedule_pin_abort producer={} height={} head={} outcome=failure: the live schedule no longer hashes to the published pin; other voters may still pause at P, tell the coordinator now",
                config.inner.producer,
                config.inner.height,
                view.head_num
            );
            return Err(format!(
                "{PIN_ABORT_PREFIX}the live active schedule no longer hashes to confirmation.schedule_sha256 (a schedule version bump?): abort this round before H, publish the new hash, rebuild the genesis and ceremony id, and re-run the declaration"
            ));
        }
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
        // The pause comes first. It is awaited before anything that talks to
        // the coordinator: a dead or slow coordinator costs 15 s per call
        // and several calls per poll, which used to push the pause tens of
        // seconds past P. Stopping the producer must never queue behind
        // network I/O to an off-chain service.
        // The halt half of the binary: once the local head has reached the
        // agreed pause head, the local producer must stay paused — whether
        // or not this voter's confirmation has been delivered yet.
        // Delivery retries continue above independently (the coordinator is
        // off-chain, so a paused producer does not block them); the stop
        // must never wait for delivery, or a failed submission keeps the
        // chain building past the agreed head. Stopping at P (not at H)
        // keeps the H+1..P window exactly the quorum attested. This never
        // exits over a pause failure — the process stays alive retrying,
        // because a node restart clears Leap's in-memory pause and only a
        // live enforcer re-pauses it. To resume production deliberately,
        // stop this voter first: a manual resume while it runs gets
        // re-paused on the next poll.
        // The pause is the fleet's pact, and the pact only exists once the
        // declaration has a quorum. Without one, pausing would halt a live
        // chain for a round that cannot restore, so it waits for the
        // contract to show the ceremony finalized (remembered, so a later
        // read failure does not lose it).
        if own_finalized(config, &view) {
            if !finalized_seen
                && let Err(error) =
                    write_finalized_marker(&config.finalized_marker, &config.expected_digest)
            {
                log_line!("could not persist the finalization marker: {error}");
            }
            finalized_seen = true;
        }
        if !dry_run
            && finalized_seen
            && should_pause_producer(&config.inner.stop_producer, view.head_num, pause_height)
        {
            if let Some(api_url) = config.inner.stop_producer.producer_api_url.clone() {
                match pause_producer(&client, &api_url).await {
                    Ok(()) => {
                        if !pause_holding {
                            log_line!("local producer paused at P={}, enforcing", pause_height);
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
        // Confirmation needs the agreed stop observed on this node: the
        // quorum over the terminal id stands in for Leap finality, so no
        // voter waits for LIB (on a 21-producer network LIB(H) arrives
        // hundreds of blocks late — after the agreed stop). Signing is
        // independent of whether our vote landed (the confirmation quorum
        // is over the declared set, so a late voter still signs), but no
        // voter attests a freeze it has not seen land. The agreed pause
        // head P comes from config, cross-checked against the coordinator,
        // never from the local tip, so every signer commits to the same
        // digest.
        let confirmed_ready = voted
            || matches!(decide(config, &view), Decision::AlreadyVoted)
            || own_finalized(config, &view);
        let pause_ok =
            !should_pause_producer(&config.inner.stop_producer, view.head_num, pause_height)
                || pause_holding
                || dry_run;
        // Signing also needs the ceremony finalized: a voter whose own vote
        // landed in a round that never reached quorum has nothing to attest.
        let confirmed_ready = confirmed_ready && (finalized_seen || dry_run);
        if should_sign_confirmation(confirmed_ready, view.head_num, pause_height, pause_ok) {
            if dry_run {
                log_line!(
                    "DRY RUN: would sign and deliver the confirmation for H={} P={}",
                    config.inner.height,
                    pause_height
                );
                if should_pause_producer(&config.inner.stop_producer, view.head_num, pause_height) {
                    log_line!(
                        "DRY RUN: would pause the local producer at P={} via {}",
                        pause_height,
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
            // Delivery is not the stop precondition (the pause below fires
            // on head >= P regardless), so a failed submission retries
            // here on every poll until the coordinator has it — including
            // after the local producer has paused, since the coordinator
            // is off-chain.
            // Nothing may have landed in H+1..P: the gate refuses any other
            // window, and by now XPR is already paused, so signing over a
            // dirty window would only waste the round. Checked once; a
            // violation refuses to sign and is logged every poll so the
            // operator sees it.
            // P must hold still before it is signed: see SETTLE_POLLS.
            let settled_id = match fetch_block_id(&client, &config.inner.nodeos_url, pause_height)
                .await
            {
                Ok(id) => {
                    let steady = settle_step(&mut settle, &id);
                    if steady < SETTLE_POLLS {
                        note_throttled(
                            &mut last_note,
                            &mut polls,
                            &format!(
                                "waiting for block P={pause_height} to settle ({steady}/{SETTLE_POLLS})"
                            ),
                        );
                        tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                        continue;
                    }
                    id
                }
                Err(error) => {
                    settle = (None, 0);
                    note_throttled(
                        &mut last_note,
                        &mut polls,
                        &format!("cannot read block P to settle it: {error}"),
                    );
                    tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                    continue;
                }
            };
            // Nothing may have landed from H+1 through the point production
            // actually stopped: the gate refuses a dirty H+1..P, and blocks
            // past P (a pause that lands late) carry traffic nothing else
            // covers. The head is read now, after the pause is confirmed
            // held, not taken from the start of the poll. Coverage is cached
            // against the id of the last block scanned (not just P's), so a
            // fork that replaces blocks above P restarts the scan.
            let (head_after_pause, _, _) = match get_info(&client, &config.inner.nodeos_url).await {
                Ok(info) => info,
                Err(error) => {
                    note_throttled(
                        &mut last_note,
                        &mut polls,
                        &format!("cannot read the head after the pause: {error}"),
                    );
                    tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                    continue;
                }
            };
            let scan_to = pause_height.max(head_after_pause);
            let cached = match &window_verified {
                Some((id, through, tip)) if *id == settled_id => {
                    match fetch_block_id(&client, &config.inner.nodeos_url, *through).await {
                        Ok(current) if current == *tip => Some(*through),
                        _ => None,
                    }
                }
                _ => None,
            };
            let (covered_through, covered_tip) = match cached {
                Some(through) if through >= scan_to => {
                    // `cached` already matched the stored tip id.
                    let tip = window_verified
                        .as_ref()
                        .map(|(_, _, tip)| tip.clone())
                        .unwrap_or_default();
                    (through, tip)
                }
                _ => {
                    let scan_from = cached.unwrap_or(config.inner.height);
                    match verify_window_empty(&client, &config.inner.nodeos_url, scan_from, scan_to)
                        .await
                    {
                        Ok(tip) => {
                            window_verified = Some((settled_id.clone(), scan_to, tip.clone()));
                            log_line!(
                                "H+1..{scan_to} (P={pause_height}) verified empty on the local node"
                            );
                            (scan_to, tip)
                        }
                        Err(error) => {
                            window_verified = None;
                            note_throttled(
                                &mut last_note,
                                &mut polls,
                                &format!("refusing to sign: {error}"),
                            );
                            tokio::time::sleep(Duration::from_secs(config.inner.poll_secs)).await;
                            continue;
                        }
                    }
                }
            };
            match submit_confirmation(&client, config, &settled_id, covered_through, &covered_tip)
                .await
            {
                Ok(line) => {
                    log_line!("{line}");
                }
                Err(error) => {
                    log_line!("confirmation failed, retrying: {error}");
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
            if error.starts_with(PIN_ABORT_PREFIX) {
                ExitCode::from(EXIT_PIN_ABORT)
            } else {
                ExitCode::from(1)
            }
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
            ceremony_contract: Some("cutover".to_string()),
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
                pause_height: Some(height + 3),
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
                    schedule_sha256: None,
                    operator_fed: true,
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
            schedule_pin: [0x5C; 32],
            fed_inputs_error: None,
            finalized_marker: std::path::PathBuf::from("/nonexistent/voter.finalized"),
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
            live_schedule_hash: config.schedule_pin,
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

    // Only the voter's own declaration counts as finalized: a ceremony anyone
    // stood up (other digest, height or chain) must never arm the pause.
    #[test]
    fn only_our_own_finalized_ceremony_arms_anything() {
        let config = test_loaded_config(100);
        let finalized = |edit: &dyn Fn(&mut CeremonyRow)| {
            let mut row = live_singleton(&config);
            row.finalized = true;
            edit(&mut row);
            view_with(&config, 90, 0, Some(row), Some(live_member(&config, false)))
        };
        assert!(own_finalized(&config, &finalized(&|_| {})));
        assert!(!own_finalized(
            &config,
            &finalized(&|row| row.digest = "00".repeat(32))
        ));
        assert!(!own_finalized(&config, &finalized(&|row| row.h = 101)));
        assert!(!own_finalized(
            &config,
            &finalized(&|row| row.source_chain_id = "42".repeat(32))
        ));
        // Not finalized at all.
        let mut open = live_singleton(&config);
        open.finalized = false;
        let view = view_with(
            &config,
            90,
            0,
            Some(open),
            Some(live_member(&config, false)),
        );
        assert!(!own_finalized(&config, &view));
        // No singleton.
        assert!(!own_finalized(
            &config,
            &view_with(&config, 90, 0, None, None)
        ));
    }

    #[test]
    fn the_voter_signs_only_a_genesis_it_read_for_its_own_checkpoint() {
        let dir = std::env::temp_dir().join(format!("voter-genesis-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, checkpoint: Option<&str>, schedule: Option<&str>| {
            let mut genesis: serde_json::Value = serde_json::from_str(
                r#"{
                "initial_timestamp": "2023-01-01T00:00:00",
                "initial_key": "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX",
                "initial_configuration": {
                    "max_block_net_usage": 1048576, "target_block_net_usage_pct": 1000,
                    "max_transaction_net_usage": 524288, "base_per_transaction_net_usage": 12,
                    "net_usage_leeway": 500, "context_free_discount_net_usage_num": 20,
                    "context_free_discount_net_usage_den": 100, "max_block_cpu_usage": 3000000000,
                    "target_block_cpu_usage_pct": 2500, "max_transaction_cpu_usage": 1000000000,
                    "min_transaction_cpu_usage": 100000, "max_transaction_lifetime": 3600,
                    "deferred_trx_expiration_window": 600, "max_transaction_delay": 3888000,
                    "max_inline_action_size": 4096, "max_inline_action_depth": 6,
                    "max_authority_depth": 6, "max_action_return_value_size": 256
                }
            }"#,
            )
            .unwrap();
            if let Some(checkpoint) = checkpoint {
                genesis["migration_checkpoint_sha256"] = checkpoint.into();
            }
            if let Some(schedule) = schedule {
                genesis["migration_schedule_sha256"] = schedule.into();
            }
            let path = dir.join(name);
            std::fs::write(&path, genesis.to_string()).unwrap();
            path.to_string_lossy().into_owned()
        };
        let own = "ab".repeat(32);
        let pin = "cd".repeat(32);
        let good = write("good.json", Some(&own), Some(&pin));
        let pin_bytes = [0xcd; 32];
        let (chain_id, schedule) = genesis_binding(&good, Some(&own), &pin_bytes).unwrap();
        assert_eq!(chain_id.len(), 64);
        assert_eq!(hex::encode(schedule), pin);
        // A genesis pinning a checkpoint this voter did not derive.
        let foreign = write("foreign.json", Some(&"ee".repeat(32)), Some(&pin));
        let error = genesis_binding(&foreign, Some(&own), &pin_bytes).unwrap_err();
        assert!(error.contains("did not derive"), "{error}");
        // No schedule pin, and no checkpoint pin at all.
        let unpinned = write("unpinned.json", Some(&own), None);
        assert!(
            genesis_binding(&unpinned, Some(&own), &pin_bytes)
                .unwrap_err()
                .contains("migration_schedule_sha256")
        );
        let bare = write("bare.json", None, None);
        assert!(
            genesis_binding(&bare, Some(&own), &pin_bytes)
                .unwrap_err()
                .contains("no checkpoint binding")
        );
        // A genesis pinning a different schedule than the one this voter was
        // configured to expect is refused, whatever its checkpoint says.
        let other_pin = write("other-pin.json", Some(&own), Some(&"ee".repeat(32)));
        assert!(
            genesis_binding(&other_pin, Some(&own), &pin_bytes)
                .unwrap_err()
                .contains("not told to expect")
        );
        // Without an own checkpoint yet (operator-fed, pre-conversion) the
        // genesis is still read and its schedule pin still checked.
        assert!(genesis_binding(&good, None, &pin_bytes).is_ok());
        assert!(genesis_binding(&other_pin, None, &pin_bytes).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
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
            pause_block_id: "08".repeat(32),
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
        // No agreed pause head: a voter that cannot name P would sign its
        // own observed tip, so startup refuses without one.
        let no_pause = write(
            "no-pause.json",
            &format!(
                r#"{{"nodeos_url":"http://x","contract":"cutover","producer":"prod.a","source_chain_id":"{}","height":100,"roster_file":"{roster}","vote_key_file":"{key}","payer_account":"prod.a","payer_key_file":"{key}"}}"#,
                "41".repeat(32),
            ),
        );
        assert!(load_loaded_config(&no_pause).is_err());
        // A pause head at or below H stages no proof: startup refuses it
        // instead of signing a divergent head.
        for bad_pause in [100u32, 99] {
            let bad_p = write(
                &format!("bad-p-{bad_pause}.json"),
                &format!(
                    r#"{{"nodeos_url":"http://x","contract":"cutover","producer":"prod.a","source_chain_id":"{}","height":100,"pause_height":{bad_pause},"roster_file":"{roster}","vote_key_file":"{key}","payer_account":"prod.a","payer_key_file":"{key}"}}"#,
                    "41".repeat(32),
                ),
            );
            assert!(load_loaded_config(&bad_p).is_err());
        }
        // A config that can never sign must not start: the confirmation's
        // outside facts are checked at load, not at signing time.
        let own = "ab".repeat(32);
        let genesis = write(
            "genesis.json",
            &format!(
                r#"{{"initial_timestamp":"2023-01-01T00:00:00","initial_key":"PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX","initial_configuration":{{"max_block_net_usage":1048576,"target_block_net_usage_pct":1000,"max_transaction_net_usage":524288,"base_per_transaction_net_usage":12,"net_usage_leeway":500,"context_free_discount_net_usage_num":20,"context_free_discount_net_usage_den":100,"max_block_cpu_usage":3000000000,"target_block_cpu_usage_pct":2500,"max_transaction_cpu_usage":1000000000,"min_transaction_cpu_usage":100000,"max_transaction_lifetime":3600,"deferred_trx_expiration_window":600,"max_transaction_delay":3888000,"max_inline_action_size":4096,"max_inline_action_depth":6,"max_authority_depth":6,"max_action_return_value_size":256}},"migration_checkpoint_sha256":"{own}","migration_schedule_sha256":"{}"}}"#,
                "cd".repeat(32)
            ),
        );
        let platform = "51".repeat(32);
        // A roster whose key is real (the earlier cases never got that far).
        let real_key =
            K1PrivateKey::from_string("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")
                .unwrap()
                .public_key()
                .to_string();
        let roster = write(
            "roster-real.json",
            &format!(r#"[{{"producer":"prod.a","key":"{real_key}","weight":"1"}}]"#),
        );
        let with = |confirmation: String| {
            write(
                "full.json",
                &format!(
                    r#"{{"nodeos_url":"http://x","contract":"cutover","producer":"prod.a","source_chain_id":"{}","height":100,"pause_height":120,"schedule_version":7,"roster_file":"{roster}","vote_key_file":"{key}","payer_account":"prod.a","payer_key_file":"{key}","confirmation":{{{confirmation}}}}}"#,
                    "41".repeat(32),
                ),
            )
        };
        let pin = "cd".repeat(32);
        let complete = format!(
            r#""schedule_sha256":"{pin}","migration_genesis":"{genesis}","checkpoint_sha256":"{own}","platform_chain_id":"{platform}""#
        );
        let good = load_loaded_config(&with(complete.clone())).expect("a complete config loads");
        assert_eq!(hex::encode(good.schedule_pin), pin);
        // The published schedule hash is the one pin known before H: it is
        // required, and it is what the pre-H check compares against.
        let error = load_loaded_config(&with(String::new()))
            .err()
            .expect("no schedule pin refuses");
        assert!(error.contains("schedule_sha256 is required"), "{error}");
        let error = load_loaded_config(&with(r#""schedule_sha256":"zz""#.to_string()))
            .err()
            .expect("a malformed pin refuses");
        assert!(error.contains("schedule_sha256"), "{error}");
        // An operator-fed config starts before H with none of the post-H
        // inputs: this is how the ceremony agent actually runs the voter.
        let fed = load_loaded_config(&with(format!(
            r#""schedule_sha256":"{pin}","operator_fed":true"#
        )))
        .expect(
            "an operator-fed config loads before the checkpoint, genesis and platform id exist",
        );
        assert_eq!(hex::encode(fed.schedule_pin), pin);
        assert_eq!(
            missing_confirmation_inputs(&fed.inner.confirmation).len(),
            3
        );
        // Without the opt-in the same config is a config that can never sign.
        let error = load_loaded_config(&with(format!(r#""schedule_sha256":"{pin}""#)))
            .err()
            .expect("an unsignable config must refuse to load");
        assert!(
            error.contains("checkpoint_sha256")
                && error.contains("migration_genesis")
                && error.contains("platform_chain_id")
                && error.contains("operator_fed"),
            "{error}"
        );
        // Whatever is present is validated, even when operator-fed: a
        // genesis for a checkpoint this operator did not derive, one pinning
        // another schedule, and malformed values all refuse.
        let refusals = [
            (
                format!(
                    r#""schedule_sha256":"{pin}","operator_fed":true,"migration_genesis":"{genesis}","checkpoint_sha256":"{}","platform_chain_id":"{platform}""#,
                    "ee".repeat(32)
                ),
                "did not derive",
            ),
            (
                format!(
                    r#""schedule_sha256":"{}","operator_fed":true,"migration_genesis":"{genesis}","checkpoint_sha256":"{own}""#,
                    "ee".repeat(32)
                ),
                "not told to expect",
            ),
            (
                format!(
                    r#""schedule_sha256":"{pin}","operator_fed":true,"checkpoint_sha256":"12""#
                ),
                "checkpoint_sha256",
            ),
            (
                format!(
                    r#""schedule_sha256":"{pin}","operator_fed":true,"platform_chain_id":"nope""#
                ),
                "platform_chain_id",
            ),
        ];
        for (confirmation, expected) in refusals {
            // Not operator-fed: nothing is running yet, so a bad value refuses.
            let strict = confirmation.replace(r#""operator_fed":true,"#, "");
            let error = load_loaded_config(&with(strict))
                .err()
                .expect("a bad confirmation input must refuse to load");
            assert!(error.contains(expected), "{error} (wanted {expected})");
            // Operator-fed: the value arrives after H, with the pause already
            // enforced. Refusing to start would end that enforcement, so the
            // voter loads, remembers why, and refuses only to sign.
            let loaded = load_loaded_config(&with(confirmation))
                .expect("an operator-fed bad value must not stop the voter");
            let reason = loaded.fed_inputs_error.expect("the reason is recorded");
            assert!(reason.contains(expected), "{reason} (wanted {expected})");
        }
        assert!(good.fed_inputs_error.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_window_block_must_link_to_the_one_scanned_before_it() {
        let block = serde_json::json!({ "previous": "AB12" });
        assert!(window_block_links(&block, 5, "ab12").is_ok());
        let error = window_block_links(&block, 5, "cd34").unwrap_err();
        assert!(error.contains("reorganized"), "{error}");
        let error = window_block_links(&serde_json::json!({}), 5, "ab12").unwrap_err();
        assert!(error.contains("missing previous"), "{error}");
    }

    #[test]
    fn the_finalized_marker_survives_a_restart_and_is_bound_to_its_digest() {
        let dir = std::env::temp_dir().join(format!("voter-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("voter.json.finalized");
        let digest = [7u8; 32];
        assert!(
            !read_finalized_marker(&path, &digest),
            "absent means not finalized"
        );
        write_finalized_marker(&path, &digest).unwrap();
        assert!(read_finalized_marker(&path, &digest));
        assert!(
            !read_finalized_marker(&path, &[8u8; 32]),
            "another ceremony must not inherit it"
        );
        std::fs::write(&path, "not a digest").unwrap();
        assert!(!read_finalized_marker(&path, &digest));
        assert!(write_finalized_marker(&dir.join("missing/dir/m"), &digest).is_err());
        assert_eq!(
            finalized_marker_path("/etc/voter.json"),
            std::path::PathBuf::from("/etc/voter.json.finalized")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn armed_stop() -> StopConfig {
        StopConfig {
            at_pause: true,
            at_h: false,
            producer_api_url: Some("http://127.0.0.1:8888".to_string()),
        }
    }

    #[test]
    fn signs_once_agreed_stop_is_observed_without_waiting_for_lib() {
        // Not ready (no vote yet): never sign, even past P.
        assert!(!should_sign_confirmation(false, 210, 105, true));
        // Ready but the agreed stop not yet observed (only H seen): never
        // attest a freeze that has not landed.
        assert!(!should_sign_confirmation(true, 100, 105, true));
        assert!(!should_sign_confirmation(true, 104, 105, true));
        // Ready and the stop observed: sign. LIB is not an input — on a
        // 21-producer network LIB(H) arrives hundreds of blocks after H,
        // and waiting for it would deadlock the halt past the agreed stop.
        assert!(should_sign_confirmation(true, 105, 105, true));
        assert!(should_sign_confirmation(true, 150, 105, true));
    }

    #[test]
    fn p_must_hold_still_before_it_is_signed() {
        let mut state = (None, 0);
        assert_eq!(settle_step(&mut state, "aa"), 1);
        assert_eq!(settle_step(&mut state, "aa"), 2);
        // A microfork flips P's id: the count starts over.
        assert_eq!(settle_step(&mut state, "bb"), 1);
        assert_eq!(settle_step(&mut state, "bb"), 2);
        assert_eq!(settle_step(&mut state, "bb"), 3);
        assert_eq!(settle_step(&mut state, "bb"), SETTLE_POLLS);
    }

    #[test]
    fn window_blocks_must_be_empty() {
        let empty = serde_json::json!({
            "transaction_mroot": "0".repeat(64),
            "transactions": []
        });
        assert!(window_block_is_empty(&empty, 101).is_ok());
        let busy = serde_json::json!({
            "transaction_mroot": "ab".repeat(32),
            "transactions": [{"trx": {}}]
        });
        let error = window_block_is_empty(&busy, 102).unwrap_err();
        assert!(error.contains("102"), "{error}");
        // A zero root with a listed transaction is still refused.
        let listed = serde_json::json!({
            "transaction_mroot": "0".repeat(64),
            "transactions": [{"trx": {}}]
        });
        assert!(window_block_is_empty(&listed, 103).is_err());
        // A node that omits the root cannot be trusted to have checked it.
        assert!(window_block_is_empty(&serde_json::json!({}), 104).is_err());
    }

    #[test]
    fn never_signs_while_the_pause_is_not_held() {
        // A pause error must not coexist with a signed confirmation.
        assert!(!should_sign_confirmation(true, 150, 105, false));
        assert!(should_sign_confirmation(true, 150, 105, true));
    }

    #[test]
    fn pause_fires_at_p_without_waiting_for_delivery() {
        // Off by default: an unconfigured voter never pauses, no matter
        // what the chain does.
        let off = StopConfig::default();
        assert!(!should_pause_producer(&off, 100, 103));
        assert!(!should_pause_producer(&off, 200, 103));
        // Armed but head short of P: the producer still has blocks to
        // build, pausing now would stop it early.
        let armed = armed_stop();
        assert!(!should_pause_producer(&armed, 102, 103));
        // Armed at P: stop even when this voter's own confirmation has
        // not been delivered — a failed submission must never keep the
        // chain building past the agreed head. Delivery retries continue
        // independently.
        assert!(should_pause_producer(&armed, 103, 103));
        // Past P (late pause): still stop.
        assert!(should_pause_producer(&armed, 105, 103));
        // No producer API configured: never pause — there is nothing to
        // pause through, and a silent no-op halt is worse than none.
        let no_api = StopConfig {
            at_pause: true,
            at_h: false,
            producer_api_url: None,
        };
        assert!(!should_pause_producer(&no_api, 200, 103));
    }

    #[test]
    fn stop_window_must_cover_the_finality_lag() {
        // Single producer: LIB trails head by one, a short window is fine.
        assert!(stop_window_covers_finality(100, 120, 90, 89).is_ok());
        // Exactly the requirement (2 * lag + one producer turn) passes.
        assert!(stop_window_covers_finality(100, 100 + 2 * 40 + 12, 90, 50).is_ok());
        // One block short fails and names the needed P.
        let error = stop_window_covers_finality(100, 100 + 2 * 40 + 11, 90, 50).unwrap_err();
        assert!(error.contains("agree P >= H + 92"), "{error}");
        // A 21-producer-sized lag (about 170 blocks) rejects the old H+5.
        assert!(stop_window_covers_finality(1000, 1005, 5000, 4830).is_err());
        // Garbage heights never panic: LIB ahead of head and P before H.
        assert!(stop_window_covers_finality(100, 90, 10, 20).is_err());
    }

    /// Minimal Leap producer-API stub: answers pause/paused with canned
    /// bodies over sequential connections. std-only; the test drives the
    /// real `pause_producer` HTTP path against it.
    fn stub_producer_api(paused_reports: bool) -> String {
        stub_producer_api_shaped(paused_reports, false)
    }

    /// `bare` answers like Leap 5.0.3 (`true`/`false`), otherwise the object
    /// form `{"paused": ...}`.
    fn stub_producer_api_shaped(paused_reports: bool, bare: bool) -> String {
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
                    if bare {
                        paused_reports.to_string()
                    } else {
                        format!("{{\"paused\":{paused_reports}}}")
                    }
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
    async fn pause_producer_accepts_leaps_bare_boolean_paused_reply() {
        // Real nodeos 5.0.3 answers /v1/producer/paused with a bare boolean.
        let client = reqwest::Client::builder().build().unwrap();
        assert!(
            pause_producer(&client, &stub_producer_api_shaped(true, true))
                .await
                .is_ok()
        );
        // A bare `false` is an unverified pause, never a verified one.
        assert!(
            pause_producer(&client, &stub_producer_api_shaped(false, true))
                .await
                .is_err()
        );
    }

    #[test]
    fn paused_flag_reads_both_shapes_and_nothing_else() {
        assert_eq!(paused_flag(&serde_json::json!(true)), Some(true));
        assert_eq!(paused_flag(&serde_json::json!(false)), Some(false));
        assert_eq!(
            paused_flag(&serde_json::json!({"paused": true})),
            Some(true)
        );
        assert_eq!(
            paused_flag(&serde_json::json!({"paused": false})),
            Some(false)
        );
        assert_eq!(paused_flag(&serde_json::json!({})), None);
        assert_eq!(paused_flag(&serde_json::json!("true")), None);
        assert_eq!(paused_flag(&serde_json::json!(null)), None);
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
        // at_pause without a URL would silently never pause: refuse to run.
        let half = StopConfig {
            at_pause: true,
            at_h: false,
            producer_api_url: None,
        };
        assert!(validate_stop_config(&half).is_err());
        // The removed at_h predecessor is refused even when fully armed:
        // it stopped at H, and silently never pausing is worse than noise.
        let stale = StopConfig {
            at_pause: true,
            at_h: true,
            producer_api_url: Some("http://127.0.0.1:8888".to_string()),
        };
        assert!(validate_stop_config(&stale).is_err());
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
