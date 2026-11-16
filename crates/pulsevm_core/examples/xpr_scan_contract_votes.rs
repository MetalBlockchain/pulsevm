//! Scan a Leap node's blocks for cutover-contract votes and capture the
//! ceremony singleton into a verifier-ready evidence fragment.
//!
//! The exporter runs this over the declaration window once the tally is
//! finalized, then attaches the fragment to the migration manifest as
//! `halt_contract_ceremony`. The offline verifier replays the tally from
//! the fragment (digest link, windows, membership, recomputed weights,
//! strict quorum) instead of trusting the recorded inclusion block alone.
//!
//! Usage:
//!   xpr_scan_contract_votes --api URL --contract NAME --from BLOCK --to BLOCK
//!     --singleton-block BLOCK --out fragment.json [--host-header VALUE]
//!
//! `--singleton-block` is the block at which the exporter read the
//! `ceremony` singleton (it must predate H; the tally only completes before
//! the cutover). Votes are lifted from `cutover::vote` actions in
//! [`--from`, `--to`]; every vote must predate H as well — the verifier
//! enforces both windows. `--host-header` overrides the HTTP Host header:
//! Leap validates it against its listening address, so port-mapped fixture
//! nodes need the in-container value (e.g. `0.0.0.0:8888`).

use std::{
    collections::HashMap,
    env,
    fs,
    process::ExitCode,
    str::FromStr as _,
};

use pulsevm_chain_types::{
    HaltContractCeremony,
    HaltContractVote,
    HaltWeight,
};
use pulsevm_core::{
    name::Name,
    transaction::Transaction,
};
use pulsevm_crypto::k1::K1Signature;
use pulsevm_serialization::Read as _;
use serde::Deserialize;

fn usage() -> ExitCode {
    eprintln!(
        "Usage: xpr_scan_contract_votes --api URL --contract NAME --from BLOCK --to BLOCK --singleton-block BLOCK --out fragment.json [--declare-out declaration.json] [--host-header VALUE]"
    );
    ExitCode::from(2)
}

fn bool_from_int_or_bool<'de, D: serde::Deserializer<'de>>(input: D) -> Result<bool, D::Error> {
    struct Flag;
    impl<'de> serde::de::Visitor<'de> for Flag {
        type Value = bool;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a boolean or 0/1")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<bool, E> {
            Ok(value)
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<bool, E> {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                other => Err(E::custom(format!("bad boolean integer {other}"))),
            }
        }
    }
    input.deserialize_any(Flag)
}

/// Leap renders uint64 table fields as decimal strings; accept a JSON
/// number too so fixture rows stay writable by hand. Missing stays 0 so
/// rows frozen before the window existed still decode (the window only
/// ever constrains live freezes).
fn u64_from_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrNumber;
    impl<'de> serde::de::Visitor<'de> for StringOrNumber {
        type Value = u64;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a decimal uint64 string or a JSON number")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<u64, E> {
            value
                .parse::<u64>()
                .map_err(|_| E::custom(format!("not a uint64: {value}")))
        }
    }
    deserializer.deserialize_any(StringOrNumber)
}

#[derive(Debug, Deserialize)]
struct CeremonyRow {
    h: u32,
    source_chain_id: String,
    total_weight: HaltWeight,
    voted_weight: HaltWeight,
    #[serde(deserialize_with = "bool_from_int_or_bool")]
    finalized: bool,
    declaration_digest: String,
    #[serde(default, deserialize_with = "u64_from_string_or_number")]
    init_time: u64,
}

#[derive(Debug, Deserialize)]
struct MemberRow {
    producer: String,
    key: String,
    weight: HaltWeight,
}

fn parse_varuint32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    let mut value: u32 = 0;
    let mut shift = 0;
    loop {
        if *pos >= bytes.len() {
            return Err("vote action data ends inside the signature type".to_string());
        }
        let byte = bytes[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        if shift >= 35 {
            return Err("vote signature type overflows u32".to_string());
        }
    }
}

async fn post(
    client: &reqwest::Client,
    host_header: Option<&str>,
    api: &str,
    path: &str,
    body: &str,
) -> Result<serde_json::Value, String> {
    let mut request = client
        .post(format!("{api}{path}"))
        .header("Content-Type", "application/json");
    if let Some(host) = host_header {
        request = request.header("Host", host);
    }
    let response = request
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("{path} unreachable: {e}"))?;
    let status = response.status();
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("{path} returned non-JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!("{path} failed: {value}"));
    }
    Ok(value)
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut api: Option<String> = None;
    let mut contract: Option<String> = None;
    let mut from: Option<u32> = None;
    let mut to: Option<u32> = None;
    let mut singleton_block: Option<u32> = None;
    let mut out: Option<String> = None;
    let mut declare_out: Option<String> = None;
    let mut host_header: Option<String> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next();
        match (arg.as_str(), value) {
            ("--api", Some(value)) => api = Some(value),
            ("--contract", Some(value)) => contract = Some(value),
            ("--from", Some(value)) => from = value.parse().ok(),
            ("--to", Some(value)) => to = value.parse().ok(),
            ("--singleton-block", Some(value)) => singleton_block = value.parse().ok(),
            ("--out", Some(value)) => out = Some(value),
            ("--declare-out", Some(value)) => declare_out = Some(value),
            ("--host-header", Some(value)) => host_header = Some(value),
            _ => return usage(),
        }
    }
    let (Some(api), Some(contract), Some(from), Some(to), Some(singleton_block), Some(out)) =
        (api, contract, from, to, singleton_block, out)
    else {
        return usage();
    };
    if from > to {
        eprintln!("xpr_scan_contract_votes: --from must not exceed --to");
        return ExitCode::from(1);
    }
    match run(
        &api,
        &contract,
        from,
        to,
        singleton_block,
        &out,
        declare_out.as_deref(),
        host_header.as_deref(),
    )
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xpr_scan_contract_votes: FAIL: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(
    api: &str,
    contract: &str,
    from: u32,
    to: u32,
    singleton_block: u32,
    out: &str,
    declare_out: Option<&str>,
    host_header: Option<&str>,
) -> Result<(), String> {
    let client = reqwest::Client::new();

    // Frozen roster keys and weights: the vote action carries (producer,
    // signature) but no key, so each vote's key comes from the frozen
    // members table, and the declaration members below reuse the frozen
    // weights bit-for-bit.
    let members: Vec<MemberRow> = post(
        &client,
        host_header,
        api,
        "/v1/chain/get_table_rows",
        &format!(
            "{{\"json\":true,\"code\":\"{contract}\",\"scope\":\"{contract}\",\"table\":\"members\",\"limit\":1000}}"
        ),
    )
    .await?
    .get("rows")
    .ok_or_else(|| "members table has no rows field".to_string())
    .and_then(|rows| serde_json::from_value(rows.clone()).map_err(|e| e.to_string()))?;
    let frozen: HashMap<String, (String, HaltWeight)> = members
        .into_iter()
        .map(|row| (row.producer, (row.key, row.weight)))
        .collect();

    // A node can serve a block while it is still being built, so a single
    // pass can miss transactions that a later pass sees. Merge rounds keyed
    // by (block, producer) until the set is stable; conflicting signatures
    // for one slot fail closed (equivocation is malformed evidence).
    // Round 1 establishes the set, so stability needs at least two passes.
    let mut merged: HashMap<(u32, String), HaltContractVote> = HashMap::new();
    let mut versions: HashMap<u32, u32> = HashMap::new();
    let mut stable_rounds = 0;
    let mut uninspectable: std::collections::BTreeSet<(u32, String)> =
        std::collections::BTreeSet::new();
    for round in 1..=4 {
        let pass = scan_once(&client, host_header, api, contract, from, to, &frozen).await?;
        uninspectable.extend(pass.uninspectable);
        let found = pass.votes;
        let mut fresh = 0;
        for (vote, version) in found {
            versions.insert(vote.block, version);
            match merged.get(&(vote.block, vote.producer.clone())) {
                Some(known) if known.signature == vote.signature => {}
                Some(_) => {
                    return Err(format!(
                        "block {} carries conflicting votes from {}",
                        vote.block, vote.producer
                    ));
                }
                None => {
                    merged.insert((vote.block, vote.producer.clone()), vote);
                    fresh += 1;
                }
            }
        }
        eprintln!(
            "scan round {round}: +{fresh} vote(s), {} total",
            merged.len()
        );
        if fresh == 0 {
            stable_rounds += 1;
            if stable_rounds == 2 {
                break;
            }
        } else {
            stable_rounds = 0;
        }
    }
    if stable_rounds < 2 {
        return Err("vote set never stabilized across scan rounds".to_string());
    }
    let mut votes: Vec<HaltContractVote> = merged.into_values().collect();
    votes.sort_by(|left, right| {
        left.block
            .cmp(&right.block)
            .then_with(|| left.producer.cmp(&right.producer))
    });

    // Rotation-window exactness, enforced at export: every vote must sit
    // under one schedule version, or the schedule rotated mid-ceremony and
    // the freeze no longer names the active set. The rehearsal additionally
    // requires this version to equal H's header version before attaching.
    let mut vote_versions: Vec<u32> = votes
        .iter()
        .filter_map(|vote| versions.get(&vote.block).copied())
        .collect();
    vote_versions.sort_unstable();
    vote_versions.dedup();
    let schedule_version = match vote_versions.as_slice() {
        [] => None,
        [only] => Some(*only),
        _ => {
            return Err(format!(
                "schedule rotated across the vote window (versions {vote_versions:?}); restart the ceremony"
            ));
        }
    };
    let ceremony: CeremonyRow = post(
        &client,
        host_header,
        api,
        "/v1/chain/get_table_rows",
        &format!(
            "{{\"json\":true,\"code\":\"{contract}\",\"scope\":\"{contract}\",\"table\":\"ceremony\",\"limit\":1}}"
        ),
    )
    .await?
    .get("rows")
    .and_then(|rows| rows.as_array())
    .and_then(|rows| rows.first())
    .ok_or_else(|| "ceremony singleton is empty; run init first".to_string())
    .and_then(|row| serde_json::from_value(row.clone()).map_err(|e| e.to_string()))?;
    if ceremony.h == 0 {
        return Err("ceremony singleton not initialized".to_string());
    }
    if !uninspectable.is_empty() {
        let found_weight: u128 = votes
            .iter()
            .map(|vote| vote.producer.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|producer| frozen.get(producer))
            .map(|(_, weight)| weight.0)
            .sum();
        let uninspectable: Vec<(u32, String)> = uninspectable.into_iter().collect();
        check_uninspectable_receipts_hide_no_vote(
            found_weight,
            ceremony.voted_weight.0,
            &uninspectable,
        )?;
        eprintln!(
            "note: {} deferred transaction(s) ran in the window and cannot be inspected; the votes found account for the contract's full counted weight, so none is hiding a vote",
            uninspectable.len()
        );
    }

    let fragment = HaltContractCeremony {
        contract: contract.to_string(),
        declaration_digest: ceremony.declaration_digest.clone(),
        total_weight: ceremony.total_weight,
        voted_weight: ceremony.voted_weight,
        finalized: ceremony.finalized,
        finalized_block: singleton_block,
        init_time: ceremony.init_time,
        votes,
    };
    fs::write(
        out,
        serde_json::to_string_pretty(&fragment).expect("fragment serializes"),
    )
    .map_err(|e| format!("cannot write {out}: {e}"))?;

    if let Some(declare_path) = declare_out {
        let members: Vec<pulsevm_chain_types::HaltDeclarationMember> = frozen
            .into_iter()
            .map(
                |(producer, (key, weight))| pulsevm_chain_types::HaltDeclarationMember {
                    producer,
                    key,
                    weight,
                },
            )
            .collect();
        let declaration = pulsevm_chain_types::HaltDeclaration::from_contract_votes(
            &ceremony.source_chain_id,
            ceremony.h,
            members,
            contract,
            &fragment.votes,
        )
        .map_err(|e| format!("declaration build rejected: {e}"))?;
        let built = declaration
            .digest()
            .map_err(|e| format!("declaration digest: {e}"))?;
        if hex::encode(built) != ceremony.declaration_digest {
            return Err("rebuilt declaration digest does not match the frozen ceremony".into());
        }
        fs::write(
            declare_path,
            serde_json::to_string_pretty(&declaration).expect("declaration serializes"),
        )
        .map_err(|e| format!("cannot write {declare_path}: {e}"))?;
    }

    println!(
        "scanned [{from},{to}]: {} vote(s), ceremony H={} finalized={} schedule_version={}",
        fragment.votes.len(),
        ceremony.h,
        fragment.finalized,
        schedule_version
            .map(|version| version.to_string())
            .unwrap_or_else(|| "none (no votes)".to_string()),
    );
    Ok(())
}

/// What one pass over the window found.
struct ScanPass {
    votes: Vec<(HaltContractVote, u32)>,
    /// Receipts of deferred transactions that ran and are reported by id only,
    /// as `(block, transaction id)`.
    uninspectable: Vec<(u32, String)>,
}

/// How a block's receipt can be read.
#[derive(Debug, PartialEq, Eq)]
enum ReceiptBody<'a> {
    /// The packed transaction, as for an ordinary input transaction.
    Packed(&'a str),
    /// A deferred transaction retired as expired: it never ran.
    Expired,
    /// A deferred transaction that ran. Leap reports it as a bare id.
    Uninspectable(String),
}

/// Read one receipt of a `get_block` reply, or `None` if it has neither a
/// packed transaction nor an id (a node that pruned the history).
fn classify_receipt(entry: &serde_json::Value) -> Option<ReceiptBody<'_>> {
    let trx = entry.get("trx").unwrap_or(entry);
    if let Some(packed) = trx.get("packed_trx").and_then(serde_json::Value::as_str) {
        return Some(ReceiptBody::Packed(packed));
    }
    let id = trx.as_str()?;
    let expired = entry.get("status").and_then(serde_json::Value::as_str) == Some("expired");
    Some(if expired {
        ReceiptBody::Expired
    } else {
        ReceiptBody::Uninspectable(id.to_string())
    })
}

/// A vote cannot be found inside a receipt that carries no actions. The votes
/// that were found must therefore account for all the weight the contract
/// counted; if they do not, one of those receipts may hold the missing vote and
/// the scan cannot tell, so it stops instead of exporting a short vote set.
fn check_uninspectable_receipts_hide_no_vote(
    found_weight: u128,
    counted_weight: u128,
    uninspectable: &[(u32, String)],
) -> Result<(), String> {
    if uninspectable.is_empty() || found_weight >= counted_weight {
        return Ok(());
    }
    let first = &uninspectable[0];
    Err(format!(
        "{} deferred transaction(s) ran in the window and are reported by id only (first: {} in block {}), and the votes found carry weight {found_weight} of the {counted_weight} the contract counted: a vote may be inside one that cannot be inspected",
        uninspectable.len(),
        first.1,
        first.0
    ))
}

/// One scan pass over [from, to]: every `cutover::vote` action plus the
/// schedule version of each block that carried one.
async fn scan_once(
    client: &reqwest::Client,
    host_header: Option<&str>,
    api: &str,
    contract: &str,
    from: u32,
    to: u32,
    frozen: &HashMap<String, (String, HaltWeight)>,
) -> Result<ScanPass, String> {
    let contract_name =
        Name::from_str(contract).map_err(|e| format!("bad contract name {contract}: {e:?}"))?;
    let vote_name = Name::from_str("vote").map_err(|e| format!("bad vote action name: {e:?}"))?;
    let mut found = Vec::new();
    let mut uninspectable = Vec::new();
    let mut block_num = from;
    while block_num <= to {
        let block = post(
            client,
            host_header,
            api,
            "/v1/chain/get_block",
            &format!("{{\"block_num_or_id\":{block_num}}}"),
        )
        .await?;
        let version = block
            .get("schedule_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(|| format!("block {block_num} carries no schedule version"))?;
        let transactions = block
            .get("transactions")
            .and_then(|transactions| transactions.as_array())
            .ok_or_else(|| format!("block {block_num} has no transactions array"))?;
        for entry in transactions {
            let packed = match classify_receipt(entry) {
                Some(ReceiptBody::Packed(packed)) => packed,
                // A deferred transaction retired as expired never ran, so
                // it carried no action of anyone's.
                Some(ReceiptBody::Expired) => continue,
                // One that ran is reported by id alone, and its actions are
                // not in the block. Note it: the tally check in `main` decides
                // whether a vote could be hiding there.
                Some(ReceiptBody::Uninspectable(id)) => {
                    uninspectable.push((block_num, id));
                    continue;
                }
                None => {
                    return Err(format!(
                        "block {block_num} transaction is not in packed form; history may be pruned"
                    ));
                }
            };
            let bytes = hex::decode(packed)
                .map_err(|e| format!("block {block_num} packed_trx invalid: {e}"))?;
            let mut pos = 0;
            let transaction = Transaction::read(&bytes, &mut pos)
                .map_err(|e| format!("block {block_num} transaction unpacks: {e:?}"))?;
            for action in &transaction.actions {
                if action.account.as_u64() != contract_name.as_u64()
                    || action.name.as_u64() != vote_name.as_u64()
                {
                    continue;
                }
                let data = action.data.as_ref();
                if data.len() < 8 {
                    return Err(format!(
                        "block {block_num} vote action data too short for a producer name"
                    ));
                }
                let producer = Name::new(u64::from_le_bytes(
                    data[..8].try_into().expect("8 name bytes"),
                ))
                .to_string();
                let mut at = 8;
                let signature_type = parse_varuint32(data, &mut at)?;
                if signature_type != 0 {
                    return Err(format!(
                        "block {block_num} vote from {producer} uses signature type {signature_type}; only K1 (0) is supported"
                    ));
                }
                if data.len() != at + 65 {
                    return Err(format!(
                        "block {block_num} vote from {producer} has {} trailing bytes; want exactly a 65-byte K1 signature",
                        data.len().saturating_sub(at)
                    ));
                }
                let compact: [u8; 65] = data[at..at + 65].try_into().expect("65 signature bytes");
                let (key, _) = frozen.get(&producer).ok_or_else(|| {
                    format!("block {block_num} vote from {producer} names no frozen member")
                })?;
                found.push((
                    HaltContractVote {
                        producer,
                        block: block_num,
                        schedule_version: version,
                        key: key.clone(),
                        signature: K1Signature::from_compact65(&compact).to_string(),
                    },
                    version,
                ));
            }
        }
        block_num = block_num.saturating_add(1);
        if block_num == u32::MAX {
            break;
        }
    }
    Ok(ScanPass {
        votes: found,
        uninspectable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The receipts a Leap block carries. An ordinary one holds the packed
    // transaction; a deferred one holds a bare id. The scan halted a ceremony on
    // the second kind.
    #[test]
    fn receipts_are_read_by_what_they_carry() {
        let input = json!({"status": "executed", "trx": {"id": "aa", "packed_trx": "0102"}});
        assert_eq!(classify_receipt(&input), Some(ReceiptBody::Packed("0102")));

        let expired = json!({"status": "expired", "cpu_usage_us": 0, "trx": "bb"});
        assert_eq!(classify_receipt(&expired), Some(ReceiptBody::Expired));

        let ran = json!({"status": "executed", "trx": "cc"});
        assert_eq!(
            classify_receipt(&ran),
            Some(ReceiptBody::Uninspectable("cc".to_string()))
        );
        let soft = json!({"status": "soft_fail", "trx": "dd"});
        assert_eq!(
            classify_receipt(&soft),
            Some(ReceiptBody::Uninspectable("dd".to_string()))
        );

        // Neither a packed transaction nor an id: history that was pruned.
        let pruned = json!({"status": "executed", "trx": {"id": "ee"}});
        assert_eq!(classify_receipt(&pruned), None);
        assert_eq!(classify_receipt(&json!({"status": "executed"})), None);
    }

    #[test]
    fn a_receipt_that_cannot_be_read_cannot_hide_a_counted_vote() {
        let ran = vec![(886316u32, "cc".to_string())];
        // Nothing uninspectable: nothing to check.
        assert!(check_uninspectable_receipts_hide_no_vote(1, 3, &[]).is_ok());
        // Every counted vote was found, so nothing is hiding.
        assert!(check_uninspectable_receipts_hide_no_vote(3, 3, &ran).is_ok());
        // A counted vote was not found: it may be in the receipt that cannot be
        // read, so the scan stops and names it.
        let error = check_uninspectable_receipts_hide_no_vote(2, 3, &ran).unwrap_err();
        assert!(
            error.contains("886316") && error.contains("cc") && error.contains("2 of the 3"),
            "{error}"
        );
    }
}
