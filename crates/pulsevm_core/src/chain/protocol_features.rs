//! Consensus protocol versions and feature gates.
//!
//! A protocol version is selected solely from the block height and the upgrade
//! bytes supplied at VM initialization. Those bytes are consensus-critical
//! out-of-band input: every validator must load the same schedule even though
//! MetalGo supplies it from each node's chain configuration.
//!
//! Unreleased implementations are additionally hidden behind temporary Cargo
//! features named `protocol_feature_*` and collected by the `nightly` feature.
//! Cargo features control which rules the binary contains; the height schedule
//! controls when contained rules become active. A feature is compiled into
//! stable builds before its activation is scheduled.
//!
//! See `docs/protocol-features.md` for the schedule lifecycle, rollout rules,
//! and feature-development checklist.

use pulsevm_crypto::Digest;
use serde::{
    Deserialize,
    Serialize,
};
use thiserror::Error;

/// The protocol-version type used by consensus code.
pub type ProtocolVersion = u32;

/// Protocol version used before the first scheduled upgrade.
///
/// See `docs/protocol-features.md` section 1.
pub const GENESIS_PROTOCOL_VERSION: ProtocolVersion = 1;

/// Oldest protocol version this binary can execute.
///
/// See `docs/protocol-features.md` section 1.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = 1;

/// Newest protocol version compiled into a normal production build.
const STABLE_PROTOCOL_VERSION: ProtocolVersion = GENESIS_PROTOCOL_VERSION;

/// Newest protocol version compiled by the aggregate `nightly` Cargo feature.
///
/// Advance this only after every unfinished implementation assigned to the new
/// version is present and its `protocol_feature_*` Cargo flag is included by
/// `nightly`. It may equal the stable version when no future feature exists.
const NIGHTLY_PROTOCOL_VERSION: ProtocolVersion = STABLE_PROTOCOL_VERSION;

/// Newest protocol version this particular binary can execute.
///
/// A normal build advertises [`STABLE_PROTOCOL_VERSION`]. A build compiled with
/// `--features nightly` advertises [`NIGHTLY_PROTOCOL_VERSION`]. Neither build
/// activates a version merely by containing it; activation still comes from the
/// height schedule.
///
/// See `docs/protocol-features.md` sections 1 and 9.
pub const PROTOCOL_VERSION: ProtocolVersion = if cfg!(feature = "nightly") {
    NIGHTLY_PROTOCOL_VERSION
} else {
    STABLE_PROTOCOL_VERSION
};

/// A consensus-affecting behavior with a fixed activation version.
///
/// Add new variants here and map each one to its first protocol version. Query
/// them through [`ProtocolExecutionContext::feature_enabled`] at the exact
/// consensus boundary where behavior changes. Multiple features may
/// intentionally activate in the same protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolFeature {
    /// The protocol rules present at chain launch. This anchor keeps the first
    /// real breaking change on the same code path as every later feature.
    Baseline,
}

/// A block height and protocol version that this binary has proved it can run.
///
/// The fields are intentionally private. Consensus code obtains a context from
/// [`ProtocolUpgradeSchedule::execution_context`] instead of constructing one
/// from an unchecked numeric version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolExecutionContext {
    block_height: u32,
    protocol_version: ProtocolVersion,
}

impl ProtocolExecutionContext {
    pub const fn block_height(self) -> u32 {
        self.block_height
    }

    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn feature_enabled(self, feature: ProtocolFeature) -> bool {
        feature.enabled(self.protocol_version)
    }
}

/// Protocol information committed to a state-sync summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolScheduleCommitment {
    pub protocol_version: ProtocolVersion,
    pub activated_schedule_hash: [u8; 32],
}

impl ProtocolFeature {
    /// First protocol version in which this feature is enabled.
    const fn protocol_version(self) -> ProtocolVersion {
        match self {
            Self::Baseline => GENESIS_PROTOCOL_VERSION,
        }
    }

    /// Whether this feature is active under `protocol_version`.
    const fn enabled(self, protocol_version: ProtocolVersion) -> bool {
        protocol_version >= self.protocol_version()
    }
}

/// One height-triggered transition in the chain-wide upgrade schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUpgrade {
    /// Version that becomes active at `activation_height`.
    pub protocol_version: ProtocolVersion,
    /// First block height evaluated under this version.
    pub activation_height: u32,
}

impl ProtocolUpgrade {
    const DIGEST_DOMAIN: &'static [u8] = b"pulsevm-protocol-upgrade-v1\0";

    /// Stable identifier stored in chainbase's existing protocol-state object.
    /// It commits to both the permanent version and its activation boundary.
    pub fn feature_digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(Self::DIGEST_DOMAIN.len() + 8);
        bytes.extend_from_slice(Self::DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.extend_from_slice(&self.activation_height.to_le_bytes());
        *Digest::hash(&bytes).as_bytes()
    }

    pub fn activation_record(self) -> ([u8; 32], u32) {
        (self.feature_digest(), self.activation_height)
    }
}

/// JSON payload accepted in MetalGo/rpcchainvm's `upgrade_bytes` field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolUpgradeSchedule {
    #[serde(default)]
    pub(crate) protocol_upgrades: Vec<ProtocolUpgrade>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolVersionError {
    #[error("invalid protocol upgrade bytes: {0}")]
    InvalidUpgradeBytes(String),
    #[error("protocol upgrade schedule has more than {0} entries")]
    TooManyUpgrades(usize),
    #[error("protocol upgrade activation heights must be strictly increasing and at least 2")]
    NonIncreasingActivationHeights,
    #[error(
        "protocol versions must be strictly increasing from genesis version {GENESIS_PROTOCOL_VERSION}"
    )]
    NonIncreasingProtocolVersions,
    #[error("invalid canonical protocol upgrade prefix: {0}")]
    InvalidCanonicalPrefix(String),
    #[error(
        "protocol version {protocol_version} is unsupported by this binary (supported {MIN_SUPPORTED_PROTOCOL_VERSION}..={PROTOCOL_VERSION})"
    )]
    UnsupportedProtocolVersion { protocol_version: ProtocolVersion },
}

impl ProtocolUpgradeSchedule {
    const MAX_UPGRADES: usize = 1_024;
    const PREFIX_MAGIC: &'static [u8; 8] = b"PVMUPG01";

    /// Decode and validate the consensus upgrade schedule.
    ///
    /// Empty bytes (MetalGo's default for chains without upgrades) select the
    /// genesis protocol version forever.
    pub fn from_upgrade_bytes(bytes: &[u8]) -> Result<Self, ProtocolVersionError> {
        let schedule = if bytes.iter().all(u8::is_ascii_whitespace) {
            Self::default()
        } else {
            serde_json::from_slice(bytes)
                .map_err(|e| ProtocolVersionError::InvalidUpgradeBytes(e.to_string()))?
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(&self) -> Result<(), ProtocolVersionError> {
        if self.protocol_upgrades.len() > Self::MAX_UPGRADES {
            return Err(ProtocolVersionError::TooManyUpgrades(Self::MAX_UPGRADES));
        }

        // Block 1 is created from genesis before any scheduled execution. Keep
        // it permanently under the genesis protocol and begin upgrades at the
        // first post-genesis block.
        let mut previous_height = 1;
        let mut previous_version = GENESIS_PROTOCOL_VERSION;

        for upgrade in &self.protocol_upgrades {
            if upgrade.activation_height <= previous_height {
                return Err(ProtocolVersionError::NonIncreasingActivationHeights);
            }
            if upgrade.protocol_version <= previous_version {
                return Err(ProtocolVersionError::NonIncreasingProtocolVersions);
            }
            previous_height = upgrade.activation_height;
            previous_version = upgrade.protocol_version;
        }
        Ok(())
    }

    /// Protocol version selected for a block height.
    pub fn protocol_version(&self, block_height: u32) -> ProtocolVersion {
        self.protocol_upgrades
            .iter()
            .take_while(|upgrade| block_height >= upgrade.activation_height)
            .last()
            .map_or(GENESIS_PROTOCOL_VERSION, |upgrade| upgrade.protocol_version)
    }

    /// Reject execution when the schedule has activated rules unknown to this
    /// binary. Future upgrades are allowed in the schedule before activation.
    pub fn execution_context(
        &self,
        block_height: u32,
    ) -> Result<ProtocolExecutionContext, ProtocolVersionError> {
        let protocol_version = self.protocol_version(block_height);
        if !(MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&protocol_version) {
            return Err(ProtocolVersionError::UnsupportedProtocolVersion { protocol_version });
        }
        Ok(ProtocolExecutionContext {
            block_height,
            protocol_version,
        })
    }

    /// Entries active at `block_height`, in canonical schedule order.
    pub fn activated_upgrades(&self, block_height: u32) -> &[ProtocolUpgrade] {
        let end = self
            .protocol_upgrades
            .partition_point(|upgrade| upgrade.activation_height <= block_height);
        &self.protocol_upgrades[..end]
    }

    /// A representation-independent digest of the entire validated schedule.
    pub fn schedule_hash(&self) -> [u8; 32] {
        Self::hash_upgrades(&self.protocol_upgrades)
    }

    /// The protocol version and activated schedule prefix at a state height.
    pub fn commitment(&self, block_height: u32) -> ProtocolScheduleCommitment {
        ProtocolScheduleCommitment {
            protocol_version: self.protocol_version(block_height),
            activated_schedule_hash: Self::hash_upgrades(self.activated_upgrades(block_height)),
        }
    }

    /// Canonical bytes for the schedule prefix active at `block_height`.
    /// These bytes define the hash committed in state summaries; their format
    /// is deliberately independent of JSON layout. Individual entry digests are
    /// persisted in chainbase's protocol-state object.
    pub fn activated_prefix_bytes(&self, block_height: u32) -> Vec<u8> {
        Self::encode_upgrades(self.activated_upgrades(block_height))
    }

    /// Decode the canonical prefix representation used for commitments.
    pub fn from_canonical_prefix_bytes(bytes: &[u8]) -> Result<Self, ProtocolVersionError> {
        if bytes.len() < Self::PREFIX_MAGIC.len() + 4
            || &bytes[..Self::PREFIX_MAGIC.len()] != Self::PREFIX_MAGIC
        {
            return Err(ProtocolVersionError::InvalidCanonicalPrefix(
                "missing PVMUPG01 header".into(),
            ));
        }
        let count_offset = Self::PREFIX_MAGIC.len();
        let count = u32::from_le_bytes(
            bytes[count_offset..count_offset + 4]
                .try_into()
                .expect("length checked"),
        ) as usize;
        if count > Self::MAX_UPGRADES {
            return Err(ProtocolVersionError::TooManyUpgrades(Self::MAX_UPGRADES));
        }
        let expected_len = Self::PREFIX_MAGIC.len() + 4 + count * 8;
        if bytes.len() != expected_len {
            return Err(ProtocolVersionError::InvalidCanonicalPrefix(format!(
                "expected {expected_len} bytes for {count} entries, got {}",
                bytes.len()
            )));
        }
        let mut protocol_upgrades = Vec::with_capacity(count);
        let mut pos = count_offset + 4;
        for _ in 0..count {
            let protocol_version =
                u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("length checked"));
            let activation_height =
                u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().expect("length checked"));
            protocol_upgrades.push(ProtocolUpgrade {
                protocol_version,
                activation_height,
            });
            pos += 8;
        }
        let schedule = Self { protocol_upgrades };
        schedule.validate()?;
        Ok(schedule)
    }

    /// The first transition strictly after `block_height`.
    pub fn next_upgrade(&self, block_height: u32) -> Option<ProtocolUpgrade> {
        self.protocol_upgrades
            .iter()
            .copied()
            .find(|upgrade| upgrade.activation_height > block_height)
    }

    fn hash_upgrades(upgrades: &[ProtocolUpgrade]) -> [u8; 32] {
        *Digest::hash(&Self::encode_upgrades(upgrades)).as_bytes()
    }

    fn encode_upgrades(upgrades: &[ProtocolUpgrade]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::PREFIX_MAGIC.len() + 4 + upgrades.len() * 8);
        bytes.extend_from_slice(Self::PREFIX_MAGIC);
        bytes.extend_from_slice(&(upgrades.len() as u32).to_le_bytes());
        for upgrade in upgrades {
            bytes.extend_from_slice(&upgrade.protocol_version.to_le_bytes());
            bytes.extend_from_slice(&upgrade.activation_height.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_maximum_matches_compiled_feature_track() {
        // These are deliberate release declarations, not values derived from
        // the condition under test. Change them only with the corresponding
        // stable/nightly implementation and boundary-test updates.
        assert_eq!(STABLE_PROTOCOL_VERSION, 1);
        assert_eq!(NIGHTLY_PROTOCOL_VERSION, 1);
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn permanent_feature_version_mappings_are_stable() {
        assert_eq!(ProtocolFeature::Baseline.protocol_version(), 1);
    }

    #[test]
    fn empty_upgrade_bytes_use_genesis_version() {
        let schedule = ProtocolUpgradeSchedule::from_upgrade_bytes(b"").unwrap();
        assert_eq!(schedule.protocol_version(1), GENESIS_PROTOCOL_VERSION);
        assert!(
            schedule
                .execution_context(1)
                .unwrap()
                .feature_enabled(ProtocolFeature::Baseline)
        );
    }

    #[test]
    fn version_changes_exactly_at_activation_height() {
        let bytes = br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":100}]}"#;
        let schedule = ProtocolUpgradeSchedule::from_upgrade_bytes(bytes).unwrap();

        assert_eq!(schedule.protocol_version(99), GENESIS_PROTOCOL_VERSION);
        assert_eq!(schedule.protocol_version(100), 2);
    }

    #[test]
    fn future_unsupported_version_is_rejected_only_after_activation() {
        let schedule = ProtocolUpgradeSchedule {
            protocol_upgrades: vec![ProtocolUpgrade {
                protocol_version: PROTOCOL_VERSION + 1,
                activation_height: 100,
            }],
        };
        schedule.validate().unwrap();

        assert!(schedule.execution_context(99).is_ok());
        assert_eq!(
            schedule.execution_context(100),
            Err(ProtocolVersionError::UnsupportedProtocolVersion {
                protocol_version: PROTOCOL_VERSION + 1,
            })
        );
    }

    #[test]
    fn malformed_or_ambiguous_schedules_are_rejected() {
        let cases = vec![
            br#"{"unknown":[]}"#.to_vec(),
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":100},{"protocol_version":3,"activation_height":99}]}"#.to_vec(),
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":100},{"protocol_version":2,"activation_height":200}]}"#.to_vec(),
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":0}]}"#.to_vec(),
        ];
        for bytes in cases {
            assert!(ProtocolUpgradeSchedule::from_upgrade_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn whitespace_and_empty_object_use_genesis_version() {
        for bytes in [b" \n\t".as_slice(), br#"{}"#.as_slice()] {
            let schedule = ProtocolUpgradeSchedule::from_upgrade_bytes(bytes).unwrap();
            assert_eq!(schedule, ProtocolUpgradeSchedule::default());
        }
    }

    #[test]
    fn valid_multi_upgrade_schedule_allows_version_gaps() {
        let schedule = ProtocolUpgradeSchedule::from_upgrade_bytes(
            br#"{"protocol_upgrades":[{"protocol_version":3,"activation_height":10},{"protocol_version":7,"activation_height":20}]}"#,
        )
        .unwrap();
        assert_eq!(schedule.protocol_version(9), 1);
        assert_eq!(schedule.protocol_version(10), 3);
        assert_eq!(schedule.protocol_version(19), 3);
        assert_eq!(schedule.protocol_version(20), 7);
        assert_eq!(schedule.protocol_version(21), 7);
        assert_eq!(schedule.next_upgrade(10).unwrap().protocol_version, 7);
        assert_eq!(schedule.next_upgrade(20), None);
    }

    #[test]
    fn genesis_height_and_duplicate_height_are_rejected() {
        for bytes in [
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":1}]}"#.as_slice(),
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":10},{"protocol_version":3,"activation_height":10}]}"#.as_slice(),
        ] {
            assert_eq!(
                ProtocolUpgradeSchedule::from_upgrade_bytes(bytes),
                Err(ProtocolVersionError::NonIncreasingActivationHeights)
            );
        }
    }

    #[test]
    fn entry_shape_and_numeric_errors_are_rejected() {
        let cases: &[&[u8]] = &[
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":10,"unknown":true}]}"#,
            br#"{"protocol_upgrades":[{"activation_height":10}]}"#,
            br#"{"protocol_upgrades":[{"protocol_version":-2,"activation_height":10}]}"#,
            br#"{"protocol_upgrades":[{"protocol_version":2.5,"activation_height":10}]}"#,
            br#"{"protocol_upgrades":[{"protocol_version":4294967296,"activation_height":10}]}"#,
            br#"not-json"#,
        ];
        for bytes in cases {
            assert!(matches!(
                ProtocolUpgradeSchedule::from_upgrade_bytes(bytes),
                Err(ProtocolVersionError::InvalidUpgradeBytes(_))
            ));
        }
    }

    #[test]
    fn schedule_entry_limit_is_exact() {
        let upgrades = (0..ProtocolUpgradeSchedule::MAX_UPGRADES)
            .map(|i| ProtocolUpgrade {
                protocol_version: i as u32 + 2,
                activation_height: i as u32 + 2,
            })
            .collect::<Vec<_>>();
        let schedule = ProtocolUpgradeSchedule {
            protocol_upgrades: upgrades,
        };
        schedule.validate().unwrap();

        let mut oversized = schedule;
        oversized.protocol_upgrades.push(ProtocolUpgrade {
            protocol_version: ProtocolUpgradeSchedule::MAX_UPGRADES as u32 + 2,
            activation_height: ProtocolUpgradeSchedule::MAX_UPGRADES as u32 + 2,
        });
        assert_eq!(
            oversized.validate(),
            Err(ProtocolVersionError::TooManyUpgrades(
                ProtocolUpgradeSchedule::MAX_UPGRADES
            ))
        );
    }

    #[test]
    fn canonical_hash_ignores_json_formatting_and_prefix_tracks_height() {
        let compact = ProtocolUpgradeSchedule::from_upgrade_bytes(
            br#"{"protocol_upgrades":[{"protocol_version":2,"activation_height":10},{"protocol_version":3,"activation_height":20}]}"#,
        )
        .unwrap();
        let formatted = ProtocolUpgradeSchedule::from_upgrade_bytes(
            br#"{ "protocol_upgrades" : [ { "activation_height": 10, "protocol_version": 2 }, { "activation_height": 20, "protocol_version": 3 } ] }"#,
        )
        .unwrap();
        assert_eq!(compact.schedule_hash(), formatted.schedule_hash());
        assert_eq!(compact.commitment(9).protocol_version, 1);
        assert_ne!(
            compact.commitment(9).activated_schedule_hash,
            compact.commitment(10).activated_schedule_hash
        );
        assert_eq!(
            compact.commitment(20).activated_schedule_hash,
            compact.schedule_hash()
        );
        assert_eq!(
            ProtocolUpgradeSchedule::from_canonical_prefix_bytes(
                &compact.activated_prefix_bytes(u32::MAX)
            )
            .unwrap(),
            compact
        );
    }

    #[test]
    fn activation_record_digest_is_stable() {
        let upgrade = ProtocolUpgrade {
            protocol_version: 2,
            activation_height: 100,
        };
        assert_eq!(
            hex::encode(upgrade.feature_digest()),
            "25629ec6598353f6a5f172578688a3df34c0c38669d902c6969e8f42e2b1a0ef"
        );
        assert_eq!(upgrade.activation_record().1, 100);
    }

    #[test]
    fn canonical_prefix_rejects_corruption_and_trailing_bytes() {
        let empty = ProtocolUpgradeSchedule::default().activated_prefix_bytes(1);
        for bytes in [
            b"PVMUPG0".to_vec(),
            [empty.clone(), vec![0]].concat(),
            b"NOTUPG01\0\0\0\0".to_vec(),
        ] {
            assert!(ProtocolUpgradeSchedule::from_canonical_prefix_bytes(&bytes).is_err());
        }
    }
}
