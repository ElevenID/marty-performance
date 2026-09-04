//! Side-effect-free validation for the pre-launch host-stability observation.

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

use super::artifact_store::{CampaignArtifactStore, FixedArtifactRole};

const REQUIRED_DURATION_NS: u64 = 2_700_000_000_000;
const MAXIMUM_ATTESTATION_DURATION_NS: u64 = 43_200_000_000_000;
const SAMPLE_INTERVAL_SECONDS: u32 = 5;
const MAXIMUM_SAMPLE_GAP_NS: u64 = 10_000_000_000;
const THROTTLE_FLAGS: &[&str] = &[
    "none",
    "thermal",
    "power_limit",
    "frequency_cap",
    "platform_reported_unknown",
];
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FirstQuietWindowWire {
    schema: String,
    campaign_id: String,
    created_at_utc_rfc3339_nanoseconds: String,
    plan_fingerprint: ArtifactFingerprint,
    manifest_fingerprint: ArtifactFingerprint,
    monitor_binary_fingerprint: ArtifactFingerprint,
    controller_binary_fingerprint: ArtifactFingerprint,
    controller_configuration_fingerprint: ArtifactFingerprint,
    monitor_configuration_fingerprint: ArtifactFingerprint,
    external_anchor_channel_configuration_fingerprint: ArtifactFingerprint,
    source_commit: String,
    source_tree: String,
    source_archive_fingerprint: ArtifactFingerprint,
    cargo_lock_fingerprint: ArtifactFingerprint,
    rustc_verbose_version: String,
    target_triple: String,
    build_profile: String,
    host_identity_fingerprint: ArtifactFingerprint,
    boot_identity_pseudonym: String,
    hardware_profile_fingerprint: ArtifactFingerprint,
    validity_thresholds_fingerprint: ArtifactFingerprint,
    first_quiet_window_attestation_fingerprint: ArtifactFingerprint,
    baseline_unrelated_process_set_fingerprint: ArtifactFingerprint,
    started_at_utc_rfc3339_nanoseconds: String,
    started_at_monotonic_nanoseconds: u64,
    ended_at_utc_rfc3339_nanoseconds: String,
    ended_at_monotonic_nanoseconds: u64,
    sample_interval_seconds: u32,
    maximum_sample_gap_seconds: u32,
    samples: Vec<FirstQuietWindowSampleWire>,
    invalidating_events: Vec<String>,
    validity_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FirstQuietWindowSampleWire {
    sample_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    boot_identity_pseudonym: String,
    total_cpu_percent: f64,
    monitor_cpu_percent: f64,
    unrelated_cpu_percent: f64,
    available_memory_bytes: u64,
    cpu_frequency_hz: u64,
    maximum_temperature_millidegrees_celsius: i64,
    throttle_flags: Vec<String>,
    unrelated_process_set_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FirstQuietWindowAttestationWire {
    schema: String,
    campaign_id: String,
    target_role: String,
    target_identity_pseudonym: String,
    starts_at_rfc3339_nanoseconds: String,
    expires_at_rfc3339_nanoseconds: String,
    change_reference_pseudonym: String,
    production_traffic_drained: bool,
    public_ingress_disabled: bool,
    synthetic_data_only: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnrelatedProcessSetWire {
    schema: String,
    campaign_id: String,
    boot_identity_pseudonym: String,
    identity_scheme: String,
    entry_count: u32,
    opaque_process_instances: Vec<UnrelatedProcessInstanceWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnrelatedProcessInstanceWire {
    process_instance_pseudonym: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HardwareProfileWire {
    schema: String,
    campaign_id: String,
    operating_system_family: String,
    operating_system_version: Option<String>,
    kernel_version: Option<String>,
    architecture: String,
    cpu_vendor: Option<String>,
    cpu_model: Option<String>,
    physical_core_count: Option<u32>,
    logical_cpu_count: u32,
    host_available_parallelism: u32,
    numa_node_count: Option<u32>,
    total_memory_bytes: u64,
    nominal_cpu_frequency_hz: Option<u64>,
    virtualization_kind: String,
    power_policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidityThresholdsWire {
    schema: String,
    campaign_id: String,
    maximum_total_cpu_percent: f64,
    maximum_monitor_cpu_percent: f64,
    maximum_unrelated_cpu_percent: f64,
    minimum_available_memory_bytes: u64,
    minimum_cpu_frequency_hz: u64,
    maximum_temperature_millidegrees_celsius: i64,
    forbidden_throttle_flags: Vec<String>,
    maximum_unrelated_process_count: u32,
    unrelated_process_set_policy: String,
    require_all_observations: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostIdentityWire {
    schema: String,
    campaign_id: String,
    identity_scheme: String,
    host_identity_pseudonym: String,
    boot_identity_pseudonym: String,
}

/// Narrow, validated threshold capability shared by both quiet-window validators.
pub(super) struct ValidatedThresholdPolicy {
    fingerprint: ArtifactFingerprint,
    policy: HostStabilityPolicy,
}

/// One host observation evaluated by the shared validity predicate.
pub(super) struct HostObservation<'a> {
    pub(super) total_cpu_percent: f64,
    pub(super) monitor_cpu_percent: f64,
    pub(super) benchmark_cpu_percent: f64,
    pub(super) unrelated_cpu_percent: f64,
    pub(super) available_memory_bytes: u64,
    pub(super) cpu_frequency_hz: u64,
    pub(super) maximum_temperature_millidegrees_celsius: i64,
    pub(super) throttle_flags: &'a [String],
}

/// Validated timing-window interval and privacy-preserving target identity.
pub(super) struct ValidatedTestWindow {
    fingerprint: ArtifactFingerprint,
    starts_at_utc_nanoseconds: i128,
    expires_at_utc_nanoseconds: i128,
    target_role: String,
    target_identity_pseudonym: String,
    change_reference_pseudonym: String,
}

/// Validated host/boot pseudonyms without exposing the wire representation.
pub(super) struct ValidatedHostIdentity {
    fingerprint: ArtifactFingerprint,
    host_identity_pseudonym: String,
    boot_identity_pseudonym: String,
}

/// Validated content-addressed unrelated-process set.
pub(super) struct ValidatedProcessSet {
    fingerprint: ArtifactFingerprint,
    process_identity_pseudonyms: Vec<String>,
}

pub(super) struct PersistedFirstQuietWindowPreimages {
    attestation_bytes: Vec<u8>,
    attestation_fingerprint: ArtifactFingerprint,
    baseline_process_set_bytes: Vec<u8>,
    baseline_process_set_fingerprint: ArtifactFingerprint,
    hardware_bytes: Vec<u8>,
    hardware_fingerprint: ArtifactFingerprint,
    thresholds_bytes: Vec<u8>,
    thresholds_fingerprint: ArtifactFingerprint,
}

fn persist_preimages(
    store: &CampaignArtifactStore,
    attestation_bytes: Vec<u8>,
    baseline_process_set_bytes: Vec<u8>,
    hardware_bytes: Vec<u8>,
    thresholds_bytes: Vec<u8>,
) -> Result<PersistedFirstQuietWindowPreimages> {
    for bytes in [
        &attestation_bytes,
        &baseline_process_set_bytes,
        &hardware_bytes,
        &thresholds_bytes,
    ] {
        anyhow::ensure!(
            bytes.len() <= MAX_ARTIFACT_BYTES,
            "first quiet window: preimage byte limit"
        );
    }
    let maximum =
        u64::try_from(MAX_ARTIFACT_BYTES).context("first quiet window: compiled byte limit")?;
    let attestation_fingerprint = store.write_fixed_preimage(
        FixedArtifactRole::FirstQuietAttestation,
        &attestation_bytes,
        maximum,
    )?;
    let baseline_process_set_fingerprint = store.write_fixed_preimage(
        FixedArtifactRole::BaselineUnrelatedProcessSet,
        &baseline_process_set_bytes,
        maximum,
    )?;
    let hardware_fingerprint =
        store.write_fixed_preimage(FixedArtifactRole::HardwareProfile, &hardware_bytes, maximum)?;
    let thresholds_fingerprint = store.write_fixed_preimage(
        FixedArtifactRole::ValidityThresholds,
        &thresholds_bytes,
        maximum,
    )?;
    Ok(PersistedFirstQuietWindowPreimages {
        attestation_bytes,
        attestation_fingerprint,
        baseline_process_set_bytes,
        baseline_process_set_fingerprint,
        hardware_bytes,
        hardware_fingerprint,
        thresholds_bytes,
        thresholds_fingerprint,
    })
}

pub(super) struct FirstQuietWindowBindings {
    pub(super) campaign_id: String,
    pub(super) plan_fingerprint: ArtifactFingerprint,
    pub(super) manifest_fingerprint: ArtifactFingerprint,
    pub(super) monitor_binary_fingerprint: ArtifactFingerprint,
    pub(super) controller_binary_fingerprint: ArtifactFingerprint,
    pub(super) controller_configuration_fingerprint: ArtifactFingerprint,
    pub(super) monitor_configuration_fingerprint: ArtifactFingerprint,
    pub(super) external_anchor_channel_configuration_fingerprint: ArtifactFingerprint,
    pub(super) source_commit: String,
    pub(super) source_tree: String,
    pub(super) source_archive_fingerprint: ArtifactFingerprint,
    pub(super) cargo_lock_fingerprint: ArtifactFingerprint,
    pub(super) rustc_verbose_version: String,
    pub(super) target_triple: String,
    pub(super) build_profile: String,
    pub(super) host_identity_fingerprint: ArtifactFingerprint,
    pub(super) boot_identity_pseudonym: String,
    pub(super) hardware_profile_fingerprint: ArtifactFingerprint,
    pub(super) validity_thresholds_fingerprint: ArtifactFingerprint,
    pub(super) baseline_unrelated_process_set_fingerprint: ArtifactFingerprint,
    pub(super) target_role: String,
    pub(super) target_identity_pseudonym: String,
    pub(super) change_reference_pseudonym: String,
}

#[derive(Debug)]
pub(super) struct ValidatedFirstQuietWindow {
    campaign_id: String,
    source_commit: String,
    source_tree: String,
    source_archive_fingerprint: ArtifactFingerprint,
    cargo_lock_fingerprint: ArtifactFingerprint,
    target_triple: String,
    build_profile: String,
    controller_binary_fingerprint: ArtifactFingerprint,
    rustc_verbose_version: String,
    evidence_fingerprint: ArtifactFingerprint,
    attestation_fingerprint: ArtifactFingerprint,
    baseline_process_set_fingerprint: ArtifactFingerprint,
    process_set_fingerprints: Vec<ArtifactFingerprint>,
    ended_at_monotonic_nanoseconds: u64,
    ended_at_utc_rfc3339_nanoseconds: String,
}

impl ValidatedFirstQuietWindow {
    pub(super) fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub(super) fn evidence_fingerprint(&self) -> &ArtifactFingerprint {
        &self.evidence_fingerprint
    }

    pub(super) fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub(super) fn source_tree(&self) -> &str {
        &self.source_tree
    }

    pub(super) fn source_archive_fingerprint(&self) -> &ArtifactFingerprint {
        &self.source_archive_fingerprint
    }

    pub(super) fn cargo_lock_fingerprint(&self) -> &ArtifactFingerprint {
        &self.cargo_lock_fingerprint
    }

    pub(super) fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub(super) fn build_profile(&self) -> &str {
        &self.build_profile
    }

    pub(super) fn controller_binary_fingerprint(&self) -> &ArtifactFingerprint {
        &self.controller_binary_fingerprint
    }

    pub(super) fn rustc_verbose_version(&self) -> &str {
        &self.rustc_verbose_version
    }

    pub(super) fn ended_at_monotonic_nanoseconds(&self) -> u64 {
        self.ended_at_monotonic_nanoseconds
    }

    pub(super) fn ended_at_utc_rfc3339_nanoseconds(&self) -> &str {
        &self.ended_at_utc_rfc3339_nanoseconds
    }

    /// Constructs an opaque test-only input for the fixed-build composition test.
    #[cfg(test)]
    pub(super) fn for_fixed_build_test(
        campaign_id: String,
        source_commit: String,
        source_tree: String,
        source_archive_fingerprint: ArtifactFingerprint,
        cargo_lock_fingerprint: ArtifactFingerprint,
        target_triple: String,
    ) -> Self {
        Self {
            campaign_id,
            source_commit,
            source_tree,
            source_archive_fingerprint,
            cargo_lock_fingerprint,
            target_triple,
            build_profile: "bench".to_owned(),
            controller_binary_fingerprint: ArtifactFingerprint {
                sha256: "A".repeat(64),
                byte_length: 1,
            },
            rustc_verbose_version: "rustc 1.95.0 (fixed-build-test)\n".to_owned(),
            evidence_fingerprint: ArtifactFingerprint {
                sha256: "B".repeat(64),
                byte_length: 1,
            },
            attestation_fingerprint: ArtifactFingerprint {
                sha256: "C".repeat(64),
                byte_length: 1,
            },
            baseline_process_set_fingerprint: ArtifactFingerprint {
                sha256: "D".repeat(64),
                byte_length: 1,
            },
            process_set_fingerprints: vec![ArtifactFingerprint {
                sha256: "E".repeat(64),
                byte_length: 1,
            }],
            ended_at_monotonic_nanoseconds: 100,
            ended_at_utc_rfc3339_nanoseconds: "2026-08-29T12:45:00.000000000Z".to_owned(),
        }
    }
}

#[derive(Debug)]
struct SemanticallyValidatedFirstQuietWindow {
    wire: FirstQuietWindowWire,
    capability: ValidatedFirstQuietWindow,
}

struct FirstQuietWindowObservation {
    pub(super) boot_identity_pseudonym: String,
    pub(super) first_quiet_window_attestation_fingerprint: ArtifactFingerprint,
    pub(super) started_at_monotonic_nanoseconds: u64,
    pub(super) ended_at_monotonic_nanoseconds: u64,
    pub(super) sample_interval_seconds: u32,
    pub(super) maximum_sample_gap_seconds: u32,
    pub(super) samples: Vec<FirstQuietWindowSample>,
    pub(super) invalidating_events: Vec<String>,
    pub(super) validity_status: String,
}

struct FirstQuietWindowSample {
    pub(super) sample_ordinal: u64,
    pub(super) monotonic_nanoseconds: u64,
    pub(super) boot_identity_pseudonym: String,
    pub(super) total_cpu_percent: f64,
    pub(super) monitor_cpu_percent: f64,
    pub(super) unrelated_cpu_percent: f64,
    pub(super) available_memory_bytes: u64,
    pub(super) cpu_frequency_hz: u64,
    pub(super) maximum_temperature_millidegrees_celsius: i64,
    pub(super) throttle_flags: Vec<String>,
    pub(super) unrelated_process_set_fingerprint: ArtifactFingerprint,
}

struct FirstQuietWindowAttestation {
    pub(super) fingerprint: ArtifactFingerprint,
    pub(super) started_at_monotonic_nanoseconds: u64,
    pub(super) expires_at_monotonic_nanoseconds: u64,
}

struct HostStabilityPolicy {
    total_memory_bytes: u64,
    maximum_total_cpu_percent: f64,
    maximum_monitor_cpu_percent: f64,
    maximum_unrelated_cpu_percent: f64,
    minimum_available_memory_bytes: u64,
    minimum_cpu_frequency_hz: u64,
    maximum_temperature_millidegrees_celsius: i64,
    forbidden_throttle_flags: Vec<String>,
    maximum_unrelated_process_count: u32,
    unrelated_process_set_policy: String,
    require_all_observations: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "linear validation order is security-significant and covered by error-precedence tests"
)]
fn validate_first_quiet_window_semantics(
    evidence_bytes: &[u8],
    bindings: &FirstQuietWindowBindings,
    preimages: &PersistedFirstQuietWindowPreimages,
) -> Result<SemanticallyValidatedFirstQuietWindow> {
    anyhow::ensure!(
        evidence_bytes.len() <= MAX_ARTIFACT_BYTES,
        "first quiet window: evidence byte limit"
    );
    let wire: FirstQuietWindowWire = serde_json::from_slice(evidence_bytes)
        .map_err(|_| anyhow::anyhow!("first quiet window: evidence schema"))?;
    require_canonical(
        evidence_bytes,
        &wire,
        "first quiet window: evidence canonical bytes",
    )?;
    let evidence_fingerprint = fingerprint_bytes(evidence_bytes)?;
    anyhow::ensure!(
        wire.schema == "marty.performance/sd-jwt-issuance-first-quiet-window/v1",
        "first quiet window: evidence schema literal"
    );
    anyhow::ensure!(
        wire.campaign_id == bindings.campaign_id
            && wire.plan_fingerprint == bindings.plan_fingerprint
            && wire.manifest_fingerprint == bindings.manifest_fingerprint
            && wire.monitor_binary_fingerprint == bindings.monitor_binary_fingerprint
            && wire.controller_binary_fingerprint == bindings.controller_binary_fingerprint
            && wire.controller_configuration_fingerprint
                == bindings.controller_configuration_fingerprint
            && wire.monitor_configuration_fingerprint == bindings.monitor_configuration_fingerprint
            && wire.external_anchor_channel_configuration_fingerprint
                == bindings.external_anchor_channel_configuration_fingerprint
            && wire.source_commit == bindings.source_commit
            && wire.source_tree == bindings.source_tree
            && wire.source_archive_fingerprint == bindings.source_archive_fingerprint
            && wire.cargo_lock_fingerprint == bindings.cargo_lock_fingerprint
            && wire.rustc_verbose_version == bindings.rustc_verbose_version
            && wire.target_triple == bindings.target_triple
            && wire.build_profile == bindings.build_profile
            && wire.host_identity_fingerprint == bindings.host_identity_fingerprint
            && wire.boot_identity_pseudonym == bindings.boot_identity_pseudonym
            && wire.hardware_profile_fingerprint == bindings.hardware_profile_fingerprint
            && wire.validity_thresholds_fingerprint == bindings.validity_thresholds_fingerprint
            && wire.baseline_unrelated_process_set_fingerprint
                == bindings.baseline_unrelated_process_set_fingerprint,
        "first quiet window: global preimage binding"
    );
    anyhow::ensure!(
        wire.first_quiet_window_attestation_fingerprint == preimages.attestation_fingerprint
            && wire.baseline_unrelated_process_set_fingerprint
                == preimages.baseline_process_set_fingerprint
            && wire.hardware_profile_fingerprint == preimages.hardware_fingerprint
            && wire.validity_thresholds_fingerprint == preimages.thresholds_fingerprint,
        "first quiet window: persisted preimage binding"
    );
    anyhow::ensure!(
        fingerprint_bytes(&preimages.attestation_bytes)? == preimages.attestation_fingerprint
            && fingerprint_bytes(&preimages.baseline_process_set_bytes)?
                == preimages.baseline_process_set_fingerprint
            && fingerprint_bytes(&preimages.hardware_bytes)? == preimages.hardware_fingerprint
            && fingerprint_bytes(&preimages.thresholds_bytes)? == preimages.thresholds_fingerprint,
        "first quiet window: persisted preimage actual bytes"
    );
    let attestation_bytes = preimages.attestation_bytes.as_slice();
    anyhow::ensure!(
        attestation_bytes.len() <= MAX_ARTIFACT_BYTES,
        "first quiet window: attestation byte limit"
    );
    anyhow::ensure!(
        fingerprint_bytes(attestation_bytes)? == wire.first_quiet_window_attestation_fingerprint,
        "first quiet window: attestation actual bytes"
    );
    let attestation: FirstQuietWindowAttestationWire = serde_json::from_slice(attestation_bytes)
        .map_err(|_| anyhow::anyhow!("first quiet window: attestation schema"))?;
    require_canonical(
        attestation_bytes,
        &attestation,
        "first quiet window: attestation canonical bytes",
    )?;
    anyhow::ensure!(
        valid_test_window_conditions(
            &attestation,
            &bindings.campaign_id,
            Some((
                &bindings.target_role,
                &bindings.target_identity_pseudonym,
                &bindings.change_reference_pseudonym,
            )),
            false,
        ),
        "first quiet window: attestation conditions"
    );
    let start_utc = utc_nanos(&wire.started_at_utc_rfc3339_nanoseconds)?;
    let end_utc = utc_nanos(&wire.ended_at_utc_rfc3339_nanoseconds)?;
    let created_utc = utc_nanos(&wire.created_at_utc_rfc3339_nanoseconds)?;
    let attestation_start = utc_nanos(&attestation.starts_at_rfc3339_nanoseconds)?;
    let attestation_expiry = utc_nanos(&attestation.expires_at_rfc3339_nanoseconds)?;
    let monotonic_duration = wire
        .ended_at_monotonic_nanoseconds
        .checked_sub(wire.started_at_monotonic_nanoseconds)
        .context("first quiet window: monotonic order")?;
    let utc_duration = end_utc
        .checked_sub(start_utc)
        .context("first quiet window: UTC order")?;
    anyhow::ensure!(
        u64::try_from(utc_duration) == Ok(monotonic_duration),
        "first quiet window: authoritative UTC monotonic mapping"
    );
    anyhow::ensure!(
        attestation_start <= start_utc && attestation_expiry > end_utc,
        "first quiet window: attestation UTC containment"
    );
    anyhow::ensure!(
        created_utc >= end_utc
            && (1..=i128::from(MAXIMUM_ATTESTATION_DURATION_NS))
                .contains(&(attestation_expiry - attestation_start)),
        "first quiet window: UTC interval"
    );
    let hardware: HardwareProfileWire = serde_json::from_slice(&preimages.hardware_bytes)
        .map_err(|_| anyhow::anyhow!("first quiet window: hardware schema"))?;
    require_canonical(
        &preimages.hardware_bytes,
        &hardware,
        "first quiet window: hardware canonical bytes",
    )?;
    let thresholds: ValidityThresholdsWire = serde_json::from_slice(&preimages.thresholds_bytes)
        .map_err(|_| anyhow::anyhow!("first quiet window: thresholds schema"))?;
    require_canonical(
        &preimages.thresholds_bytes,
        &thresholds,
        "first quiet window: thresholds canonical bytes",
    )?;
    anyhow::ensure!(
        hardware.schema == "marty.performance/sd-jwt-issuance-hardware-profile/v1"
            && hardware.campaign_id == bindings.campaign_id,
        "first quiet window: hardware binding"
    );
    anyhow::ensure!(
        thresholds.schema == "marty.performance/sd-jwt-issuance-validity-thresholds/v1"
            && thresholds.campaign_id == bindings.campaign_id,
        "first quiet window: thresholds binding"
    );
    let policy = validated_threshold_policy_from_wire(
        thresholds,
        hardware.total_memory_bytes,
        &preimages.thresholds_fingerprint,
    )
    .map_err(|_| anyhow::anyhow!("first quiet window: policy"))?;
    for sample in &wire.samples {
        let sample_utc = utc_nanos(&sample.utc_rfc3339_nanoseconds)
            .map_err(|_| anyhow::anyhow!("first quiet window: sample"))?;
        let sample_delta = sample
            .monotonic_nanoseconds
            .checked_sub(wire.started_at_monotonic_nanoseconds)
            .ok_or_else(|| anyhow::anyhow!("first quiet window: sample"))?;
        anyhow::ensure!(
            sample_utc
                .checked_sub(start_utc)
                .and_then(|value| u64::try_from(value).ok())
                == Some(sample_delta)
                && (start_utc..=end_utc).contains(&sample_utc)
                && sample_utc < attestation_expiry,
            "first quiet window: sample"
        );
    }
    let observation = FirstQuietWindowObservation {
        boot_identity_pseudonym: wire.boot_identity_pseudonym.clone(),
        first_quiet_window_attestation_fingerprint: wire
            .first_quiet_window_attestation_fingerprint
            .clone(),
        started_at_monotonic_nanoseconds: wire.started_at_monotonic_nanoseconds,
        ended_at_monotonic_nanoseconds: wire.ended_at_monotonic_nanoseconds,
        sample_interval_seconds: wire.sample_interval_seconds,
        maximum_sample_gap_seconds: wire.maximum_sample_gap_seconds,
        samples: wire
            .samples
            .iter()
            .map(|sample| FirstQuietWindowSample {
                sample_ordinal: sample.sample_ordinal,
                monotonic_nanoseconds: sample.monotonic_nanoseconds,
                boot_identity_pseudonym: sample.boot_identity_pseudonym.clone(),
                total_cpu_percent: sample.total_cpu_percent,
                monitor_cpu_percent: sample.monitor_cpu_percent,
                unrelated_cpu_percent: sample.unrelated_cpu_percent,
                available_memory_bytes: sample.available_memory_bytes,
                cpu_frequency_hz: sample.cpu_frequency_hz,
                maximum_temperature_millidegrees_celsius: sample
                    .maximum_temperature_millidegrees_celsius,
                throttle_flags: sample.throttle_flags.clone(),
                unrelated_process_set_fingerprint: sample.unrelated_process_set_fingerprint.clone(),
            })
            .collect(),
        invalidating_events: wire.invalidating_events.clone(),
        validity_status: wire.validity_status.clone(),
    };
    observation
        .validate(
            &FirstQuietWindowAttestation {
                fingerprint: wire.first_quiet_window_attestation_fingerprint.clone(),
                started_at_monotonic_nanoseconds: wire.started_at_monotonic_nanoseconds,
                expires_at_monotonic_nanoseconds: wire
                    .ended_at_monotonic_nanoseconds
                    .checked_add(1)
                    .context("first quiet window: attestation monotonic projection")?,
            },
            &policy,
        )
        .map_err(|_| anyhow::anyhow!("first quiet window: sample"))?;
    let process_set_bytes = preimages.baseline_process_set_bytes.as_slice();
    anyhow::ensure!(
        process_set_bytes.len() <= MAX_ARTIFACT_BYTES,
        "first quiet window: process set byte limit"
    );
    anyhow::ensure!(
        fingerprint_bytes(process_set_bytes)?
            == bindings.baseline_unrelated_process_set_fingerprint,
        "first quiet window: process set actual bytes"
    );
    let set: UnrelatedProcessSetWire = serde_json::from_slice(process_set_bytes)
        .map_err(|_| anyhow::anyhow!("first quiet window: process set schema"))?;
    require_canonical(
        process_set_bytes,
        &set,
        "first quiet window: process set canonical bytes",
    )?;
    anyhow::ensure!(
        valid_process_set_semantics(
            &set,
            &bindings.campaign_id,
            &bindings.boot_identity_pseudonym,
            policy.maximum_unrelated_process_count(),
        ),
        "first quiet window: process set policy"
    );
    for sample in &wire.samples {
        anyhow::ensure!(
            sample.unrelated_process_set_fingerprint
                == bindings.baseline_unrelated_process_set_fingerprint,
            "first quiet window: exact baseline process set"
        );
    }
    let capability = ValidatedFirstQuietWindow {
        campaign_id: wire.campaign_id.clone(),
        source_commit: bindings.source_commit.clone(),
        source_tree: bindings.source_tree.clone(),
        source_archive_fingerprint: bindings.source_archive_fingerprint.clone(),
        cargo_lock_fingerprint: bindings.cargo_lock_fingerprint.clone(),
        target_triple: bindings.target_triple.clone(),
        build_profile: bindings.build_profile.clone(),
        controller_binary_fingerprint: bindings.controller_binary_fingerprint.clone(),
        rustc_verbose_version: bindings.rustc_verbose_version.clone(),
        evidence_fingerprint,
        attestation_fingerprint: wire.first_quiet_window_attestation_fingerprint.clone(),
        baseline_process_set_fingerprint: wire.baseline_unrelated_process_set_fingerprint.clone(),
        process_set_fingerprints: vec![bindings.baseline_unrelated_process_set_fingerprint.clone()],
        ended_at_monotonic_nanoseconds: wire.ended_at_monotonic_nanoseconds,
        ended_at_utc_rfc3339_nanoseconds: wire.ended_at_utc_rfc3339_nanoseconds.clone(),
    };
    Ok(SemanticallyValidatedFirstQuietWindow { wire, capability })
}

pub(super) fn validate_retained_first_quiet_window(
    evidence_bytes: &[u8],
    bindings: &FirstQuietWindowBindings,
    preimages: &PersistedFirstQuietWindowPreimages,
    store: &CampaignArtifactStore,
) -> Result<ValidatedFirstQuietWindow> {
    let validated = validate_first_quiet_window_semantics(evidence_bytes, bindings, preimages)?;
    let retained_fingerprint = store
        .write_first_quiet_window(
            &validated.wire,
            u64::try_from(MAX_ARTIFACT_BYTES).context("first quiet window: compiled byte limit")?,
        )
        .map_err(|_| anyhow::anyhow!("first quiet window: publication"))?;
    anyhow::ensure!(
        retained_fingerprint == validated.capability.evidence_fingerprint,
        "first quiet window: publication"
    );
    Ok(validated.capability)
}

fn require_canonical<T: Serialize>(bytes: &[u8], value: &T, error: &'static str) -> Result<()> {
    let mut canonical = BoundedCanonical::default();
    let mut serializer = serde_json::Serializer::pretty(&mut canonical);
    value.serialize(&mut serializer).context(error)?;
    canonical.write_all(b"\n").context(error)?;
    anyhow::ensure!(canonical.0 == bytes, "{error}");
    Ok(())
}

#[derive(Default)]
struct BoundedCanonical(Vec<u8>);

impl Write for BoundedCanonical {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("canonical byte count overflow"))?;
        if next > MAX_ARTIFACT_BYTES {
            return Err(std::io::Error::other("canonical byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fingerprint_bytes(bytes: &[u8]) -> Result<ArtifactFingerprint> {
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(Sha256::digest(bytes)),
        byte_length: u64::try_from(bytes.len()).context("first quiet window: byte length")?,
    })
}

fn validated_threshold_policy_from_wire(
    wire: ValidityThresholdsWire,
    total_memory_bytes: u64,
    fingerprint: &ArtifactFingerprint,
) -> Result<ValidatedThresholdPolicy> {
    let policy = HostStabilityPolicy {
        total_memory_bytes,
        maximum_total_cpu_percent: wire.maximum_total_cpu_percent,
        maximum_monitor_cpu_percent: wire.maximum_monitor_cpu_percent,
        maximum_unrelated_cpu_percent: wire.maximum_unrelated_cpu_percent,
        minimum_available_memory_bytes: wire.minimum_available_memory_bytes,
        minimum_cpu_frequency_hz: wire.minimum_cpu_frequency_hz,
        maximum_temperature_millidegrees_celsius: wire.maximum_temperature_millidegrees_celsius,
        forbidden_throttle_flags: wire.forbidden_throttle_flags,
        maximum_unrelated_process_count: wire.maximum_unrelated_process_count,
        unrelated_process_set_policy: wire.unrelated_process_set_policy,
        require_all_observations: wire.require_all_observations,
    };
    validate_policy(&policy)?;
    Ok(ValidatedThresholdPolicy {
        fingerprint: fingerprint.clone(),
        policy,
    })
}

fn valid_test_window_conditions(
    wire: &FirstQuietWindowAttestationWire,
    campaign_id: &str,
    expected_identity: Option<(&str, &str, &str)>,
    require_distinct_identity_aliases: bool,
) -> bool {
    wire.schema == "marty.performance/sd-jwt-issuance-test-window/v1"
        && wire.campaign_id == campaign_id
        && matches!(
            wire.target_role.as_str(),
            "isolated_production_gateway" | "dedicated_performance_gateway"
        )
        && expected_identity.is_none_or(|(role, target, change)| {
            wire.target_role == role
                && wire.target_identity_pseudonym == target
                && wire.change_reference_pseudonym == change
        })
        && valid_uppercase_hex_256(&wire.target_identity_pseudonym)
        && valid_uppercase_hex_256(&wire.change_reference_pseudonym)
        && (!require_distinct_identity_aliases
            || wire.target_identity_pseudonym != wire.change_reference_pseudonym)
        && wire.production_traffic_drained
        && wire.public_ingress_disabled
        && wire.synthetic_data_only
}

fn valid_process_set_semantics(
    wire: &UnrelatedProcessSetWire,
    campaign_id: &str,
    boot_identity_pseudonym: &str,
    maximum_unrelated_process_count: u32,
) -> bool {
    wire.schema == "marty.performance/sd-jwt-issuance-unrelated-process-set/v1"
        && wire.campaign_id == campaign_id
        && wire.boot_identity_pseudonym == boot_identity_pseudonym
        && wire.identity_scheme == "hmac_sha256_campaign_ephemeral_process_set_v1"
        && usize::try_from(wire.entry_count) == Ok(wire.opaque_process_instances.len())
        && wire.entry_count <= maximum_unrelated_process_count
        && wire
            .opaque_process_instances
            .windows(2)
            .all(|pair| pair[0].process_instance_pseudonym < pair[1].process_instance_pseudonym)
        && wire
            .opaque_process_instances
            .iter()
            .all(|entry| valid_uppercase_hex_256(&entry.process_instance_pseudonym))
}

pub(super) fn validate_threshold_policy_bytes(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
    total_memory_bytes: u64,
) -> Result<ValidatedThresholdPolicy> {
    anyhow::ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES && fingerprint_bytes(bytes)?.eq(expected_fingerprint),
        "validity thresholds: actual bytes"
    );
    let wire: ValidityThresholdsWire = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("validity thresholds: schema"))?;
    require_canonical(bytes, &wire, "validity thresholds: canonical bytes")?;
    anyhow::ensure!(
        wire.schema == "marty.performance/sd-jwt-issuance-validity-thresholds/v1"
            && wire.campaign_id == campaign_id,
        "validity thresholds: binding"
    );
    validated_threshold_policy_from_wire(wire, total_memory_bytes, expected_fingerprint)
        .map_err(|_| anyhow::anyhow!("validity thresholds: policy"))
}

impl ValidatedThresholdPolicy {
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    fn maximum_unrelated_process_count(&self) -> u32 {
        self.policy.maximum_unrelated_process_count
    }

    fn valid_cpu_observation(observation: &HostObservation<'_>) -> bool {
        let cpu = [
            observation.total_cpu_percent,
            observation.monitor_cpu_percent,
            observation.benchmark_cpu_percent,
            observation.unrelated_cpu_percent,
        ];
        let component_total = observation.monitor_cpu_percent
            + observation.benchmark_cpu_percent
            + observation.unrelated_cpu_percent;
        cpu.iter()
            .all(|value| value.is_finite() && (0.0..=100.0).contains(value))
            && observation.monitor_cpu_percent <= observation.total_cpu_percent
            && observation.benchmark_cpu_percent <= observation.total_cpu_percent
            && observation.unrelated_cpu_percent <= observation.total_cpu_percent
            && component_total.is_finite()
            && component_total <= observation.total_cpu_percent
    }

    fn observation_satisfies_policy(&self, observation: &HostObservation<'_>) -> bool {
        observation.total_cpu_percent <= self.policy.maximum_total_cpu_percent
            && observation.monitor_cpu_percent <= self.policy.maximum_monitor_cpu_percent
            && observation.unrelated_cpu_percent <= self.policy.maximum_unrelated_cpu_percent
            && observation.available_memory_bytes <= self.policy.total_memory_bytes
            && (self.policy.minimum_available_memory_bytes == 0
                || observation.available_memory_bytes >= self.policy.minimum_available_memory_bytes)
            && (1..=10_000_000_000).contains(&observation.cpu_frequency_hz)
            && (self.policy.minimum_cpu_frequency_hz == 0
                || observation.cpu_frequency_hz >= self.policy.minimum_cpu_frequency_hz)
            && (-100_000..=200_000).contains(&observation.maximum_temperature_millidegrees_celsius)
            && observation.maximum_temperature_millidegrees_celsius
                <= self.policy.maximum_temperature_millidegrees_celsius
    }

    fn valid_throttle_flags(observation: &HostObservation<'_>) -> bool {
        sorted_unique_known_flags(observation.throttle_flags)
    }

    fn throttle_flags_are_allowed(&self, observation: &HostObservation<'_>) -> bool {
        !observation.throttle_flags.iter().any(|flag| {
            matches!(flag.as_str(), "thermal" | "power_limit")
                || self
                    .policy
                    .forbidden_throttle_flags
                    .binary_search(flag)
                    .is_ok()
        })
    }

    pub(super) fn validate_observation(&self, observation: &HostObservation<'_>) -> Result<()> {
        anyhow::ensure!(
            Self::valid_cpu_observation(observation),
            "host observation: CPU"
        );
        anyhow::ensure!(
            self.observation_satisfies_policy(observation),
            "host observation: policy"
        );
        anyhow::ensure!(
            Self::valid_throttle_flags(observation) && self.throttle_flags_are_allowed(observation),
            "host observation: throttle"
        );
        Ok(())
    }
}

pub(super) fn validate_process_set_bytes(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
    boot_identity_pseudonym: &str,
    thresholds: &ValidatedThresholdPolicy,
) -> Result<ValidatedProcessSet> {
    anyhow::ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES && fingerprint_bytes(bytes)?.eq(expected_fingerprint),
        "unrelated process set: actual bytes"
    );
    let wire: UnrelatedProcessSetWire = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("unrelated process set: schema"))?;
    require_canonical(bytes, &wire, "unrelated process set: canonical bytes")?;
    anyhow::ensure!(
        valid_process_set_semantics(
            &wire,
            campaign_id,
            boot_identity_pseudonym,
            thresholds.maximum_unrelated_process_count(),
        ),
        "unrelated process set: semantics"
    );
    Ok(ValidatedProcessSet {
        fingerprint: expected_fingerprint.clone(),
        process_identity_pseudonyms: wire
            .opaque_process_instances
            .into_iter()
            .map(|entry| entry.process_instance_pseudonym)
            .collect(),
    })
}

impl ValidatedProcessSet {
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    pub(super) fn process_identity_pseudonyms(&self) -> &[String] {
        &self.process_identity_pseudonyms
    }
}

fn validate_test_window_common(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
) -> Result<ValidatedTestWindow> {
    anyhow::ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES && fingerprint_bytes(bytes)?.eq(expected_fingerprint),
        "test window: actual bytes"
    );
    let wire: FirstQuietWindowAttestationWire =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("test window: schema"))?;
    require_canonical(bytes, &wire, "test window: canonical bytes")?;
    let start = utc_nanos(&wire.starts_at_rfc3339_nanoseconds)
        .map_err(|_| anyhow::anyhow!("test window: UTC"))?;
    let expiry = utc_nanos(&wire.expires_at_rfc3339_nanoseconds)
        .map_err(|_| anyhow::anyhow!("test window: UTC"))?;
    anyhow::ensure!(
        valid_test_window_conditions(&wire, campaign_id, None, true)
            && (1..=i128::from(MAXIMUM_ATTESTATION_DURATION_NS)).contains(&(expiry - start)),
        "test window: semantics"
    );
    Ok(ValidatedTestWindow {
        fingerprint: expected_fingerprint.clone(),
        starts_at_utc_nanoseconds: start,
        expires_at_utc_nanoseconds: expiry,
        target_role: wire.target_role,
        target_identity_pseudonym: wire.target_identity_pseudonym,
        change_reference_pseudonym: wire.change_reference_pseudonym,
    })
}

pub(super) fn validate_initial_test_window_bytes(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
) -> Result<ValidatedTestWindow> {
    validate_test_window_common(bytes, expected_fingerprint, campaign_id)
}

pub(super) fn validate_test_window_bytes(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
    expected_target_role: &str,
    expected_target_identity_pseudonym: &str,
    expected_change_reference_pseudonym: &str,
) -> Result<ValidatedTestWindow> {
    let validated = validate_test_window_common(bytes, expected_fingerprint, campaign_id)?;
    anyhow::ensure!(
        validated.target_role == expected_target_role
            && validated.target_identity_pseudonym == expected_target_identity_pseudonym
            && validated.change_reference_pseudonym == expected_change_reference_pseudonym,
        "test window: identity binding"
    );
    Ok(validated)
}

impl ValidatedTestWindow {
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    pub(super) fn starts_at_utc_nanoseconds(&self) -> i128 {
        self.starts_at_utc_nanoseconds
    }

    pub(super) fn expires_at_utc_nanoseconds(&self) -> i128 {
        self.expires_at_utc_nanoseconds
    }

    pub(super) fn target_role(&self) -> &str {
        &self.target_role
    }

    pub(super) fn target_identity_pseudonym(&self) -> &str {
        &self.target_identity_pseudonym
    }

    pub(super) fn change_reference_pseudonym(&self) -> &str {
        &self.change_reference_pseudonym
    }
}

pub(super) fn validate_host_identity_bytes(
    bytes: &[u8],
    expected_fingerprint: &ArtifactFingerprint,
    campaign_id: &str,
    boot_identity_pseudonym: &str,
) -> Result<ValidatedHostIdentity> {
    anyhow::ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES && fingerprint_bytes(bytes)?.eq(expected_fingerprint),
        "host identity: actual bytes"
    );
    let wire: HostIdentityWire =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("host identity: schema"))?;
    require_canonical(bytes, &wire, "host identity: canonical bytes")?;
    anyhow::ensure!(
        wire.schema == "marty.performance/sd-jwt-issuance-host-identity/v1"
            && wire.campaign_id == campaign_id
            && wire.identity_scheme == "campaign_random_256_v1"
            && valid_uppercase_hex_256(&wire.host_identity_pseudonym)
            && valid_uppercase_hex_256(&wire.boot_identity_pseudonym)
            && wire.host_identity_pseudonym != wire.boot_identity_pseudonym
            && wire.boot_identity_pseudonym == boot_identity_pseudonym,
        "host identity: semantics"
    );
    Ok(ValidatedHostIdentity {
        fingerprint: expected_fingerprint.clone(),
        host_identity_pseudonym: wire.host_identity_pseudonym,
        boot_identity_pseudonym: wire.boot_identity_pseudonym,
    })
}

impl ValidatedHostIdentity {
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    pub(super) fn boot_identity_pseudonym(&self) -> &str {
        &self.boot_identity_pseudonym
    }

    pub(super) fn host_identity_pseudonym(&self) -> &str {
        &self.host_identity_pseudonym
    }
}

pub(super) fn utc_nanos(value: &str) -> Result<i128> {
    anyhow::ensure!(
        super::valid_utc_rfc3339_nanoseconds(value),
        "first quiet window: UTC grammar"
    );
    let parsed =
        chrono::DateTime::parse_from_rfc3339(value).context("first quiet window: UTC grammar")?;
    Ok(
        i128::from(parsed.timestamp()) * 1_000_000_000
            + i128::from(parsed.timestamp_subsec_nanos()),
    )
}

impl FirstQuietWindowObservation {
    pub(super) fn validate(
        &self,
        attestation: &FirstQuietWindowAttestation,
        policy: &ValidatedThresholdPolicy,
    ) -> Result<()> {
        anyhow::ensure!(self.validity_status == "valid", "quiet window is not valid");
        anyhow::ensure!(
            self.invalidating_events.is_empty(),
            "quiet window has invalidating events"
        );
        anyhow::ensure!(
            self.sample_interval_seconds == SAMPLE_INTERVAL_SECONDS
                && self.maximum_sample_gap_seconds == 10,
            "quiet window cadence contract changed"
        );
        let duration = self
            .ended_at_monotonic_nanoseconds
            .checked_sub(self.started_at_monotonic_nanoseconds)
            .context("quiet window monotonic interval is reversed")?;
        anyhow::ensure!(
            duration >= REQUIRED_DURATION_NS,
            "quiet window is too short"
        );
        anyhow::ensure!(
            duration <= MAXIMUM_ATTESTATION_DURATION_NS,
            "quiet window exceeds bounded attestation duration"
        );
        anyhow::ensure!(
            attestation.started_at_monotonic_nanoseconds <= self.started_at_monotonic_nanoseconds
                && attestation.expires_at_monotonic_nanoseconds
                    > self.ended_at_monotonic_nanoseconds,
            "quiet window is not contained by its attestation"
        );
        anyhow::ensure!(
            self.first_quiet_window_attestation_fingerprint == attestation.fingerprint,
            "quiet window attestation fingerprint changed"
        );
        anyhow::ensure!(
            valid_fingerprint(&attestation.fingerprint),
            "quiet window attestation fingerprint is invalid"
        );
        let attestation_duration = attestation
            .expires_at_monotonic_nanoseconds
            .checked_sub(attestation.started_at_monotonic_nanoseconds)
            .context("quiet-window attestation interval is reversed")?;
        anyhow::ensure!(
            attestation_duration > 0 && attestation_duration <= MAXIMUM_ATTESTATION_DURATION_NS,
            "quiet-window attestation duration is invalid"
        );
        anyhow::ensure!(
            !self.samples.is_empty(),
            "quiet window sample count is invalid"
        );
        validate_policy(&policy.policy)?;
        let mut previous = None;
        for (index, sample) in self.samples.iter().enumerate() {
            let ordinal = u64::try_from(index).context("sample ordinal overflow")?;
            anyhow::ensure!(
                sample.sample_ordinal == ordinal,
                "sample ordinals are not contiguous"
            );
            anyhow::ensure!(
                sample.monotonic_nanoseconds >= self.started_at_monotonic_nanoseconds
                    && sample.monotonic_nanoseconds <= self.ended_at_monotonic_nanoseconds
                    && sample.monotonic_nanoseconds < attestation.expires_at_monotonic_nanoseconds,
                "sample is outside the quiet window"
            );
            if let Some(previous) = previous {
                let gap = sample
                    .monotonic_nanoseconds
                    .checked_sub(previous)
                    .context("sample monotonic order is reversed")?;
                anyhow::ensure!(
                    gap > 0 && gap <= MAXIMUM_SAMPLE_GAP_NS,
                    "sample gap is invalid"
                );
            }
            previous = Some(sample.monotonic_nanoseconds);
            validate_sample(sample, &self.boot_identity_pseudonym, policy)?;
        }
        let first = self
            .samples
            .first()
            .context("quiet window has no samples")?;
        let last = self.samples.last().context("quiet window has no samples")?;
        anyhow::ensure!(
            first.monotonic_nanoseconds - self.started_at_monotonic_nanoseconds
                <= MAXIMUM_SAMPLE_GAP_NS
                && self.ended_at_monotonic_nanoseconds - last.monotonic_nanoseconds
                    <= MAXIMUM_SAMPLE_GAP_NS,
            "samples do not cover the full quiet window"
        );
        Ok(())
    }
}

fn validate_policy(policy: &HostStabilityPolicy) -> Result<()> {
    for value in [
        policy.maximum_total_cpu_percent,
        policy.maximum_monitor_cpu_percent,
        policy.maximum_unrelated_cpu_percent,
    ] {
        anyhow::ensure!(
            value.is_finite() && (0.0..=100.0).contains(&value),
            "invalid CPU threshold"
        );
    }
    anyhow::ensure!(
        policy.maximum_monitor_cpu_percent <= policy.maximum_total_cpu_percent
            && policy.maximum_unrelated_cpu_percent <= policy.maximum_total_cpu_percent
            && (1..=1_152_921_504_606_846_976).contains(&policy.total_memory_bytes)
            && policy.minimum_available_memory_bytes <= policy.total_memory_bytes
            && (policy.minimum_cpu_frequency_hz == 0
                || (1..=10_000_000_000).contains(&policy.minimum_cpu_frequency_hz))
            && (0..=200_000).contains(&policy.maximum_temperature_millidegrees_celsius)
            && policy.maximum_unrelated_process_count <= 4_096
            && policy.unrelated_process_set_policy == "exact_baseline_match_v1"
            && policy.require_all_observations,
        "invalid host-stability thresholds"
    );
    anyhow::ensure!(
        (policy.forbidden_throttle_flags.is_empty()
            || sorted_unique_known_flags(&policy.forbidden_throttle_flags))
            && !policy
                .forbidden_throttle_flags
                .iter()
                .any(|flag| flag == "none"),
        "invalid forbidden throttle flags"
    );
    Ok(())
}

fn validate_sample(
    sample: &FirstQuietWindowSample,
    boot_identity: &str,
    policy: &ValidatedThresholdPolicy,
) -> Result<()> {
    let observation = HostObservation {
        total_cpu_percent: sample.total_cpu_percent,
        monitor_cpu_percent: sample.monitor_cpu_percent,
        benchmark_cpu_percent: 0.0,
        unrelated_cpu_percent: sample.unrelated_cpu_percent,
        available_memory_bytes: sample.available_memory_bytes,
        cpu_frequency_hz: sample.cpu_frequency_hz,
        maximum_temperature_millidegrees_celsius: sample.maximum_temperature_millidegrees_celsius,
        throttle_flags: &sample.throttle_flags,
    };
    anyhow::ensure!(
        ValidatedThresholdPolicy::valid_cpu_observation(&observation),
        "invalid quiet-window CPU observation"
    );
    anyhow::ensure!(
        policy.observation_satisfies_policy(&observation),
        "quiet-window observation violates host-stability policy"
    );
    anyhow::ensure!(
        sample.boot_identity_pseudonym == boot_identity && valid_uppercase_hex_256(boot_identity),
        "boot identity changed during quiet window"
    );
    anyhow::ensure!(
        ValidatedThresholdPolicy::valid_throttle_flags(&observation),
        "invalid throttle flags"
    );
    anyhow::ensure!(
        policy.throttle_flags_are_allowed(&observation),
        "forbidden throttle flag observed"
    );
    anyhow::ensure!(
        valid_fingerprint(&sample.unrelated_process_set_fingerprint),
        "invalid unrelated-process-set fingerprint"
    );
    Ok(())
}

fn valid_fingerprint(value: &ArtifactFingerprint) -> bool {
    valid_uppercase_hex_256(&value.sha256) && value.byte_length > 0
}

fn valid_uppercase_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
}

fn sorted_unique_known_flags(flags: &[String]) -> bool {
    !flags.is_empty()
        && flags.windows(2).all(|pair| pair[0] < pair[1])
        && flags
            .iter()
            .all(|flag| THROTTLE_FLAGS.contains(&flag.as_str()))
        && (flags.len() == 1 || !flags.iter().any(|flag| flag == "none"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn error<T>(result: Result<T>) -> String {
        result
            .err()
            .expect("expected validation failure")
            .to_string()
    }

    fn rewrite_evidence(evidence: &mut Vec<u8>, mutate: impl FnOnce(&mut FirstQuietWindowWire)) {
        let mut wire: FirstQuietWindowWire = serde_json::from_slice(evidence).unwrap();
        mutate(&mut wire);
        *evidence = bytes(&wire);
    }

    fn rebind_attestation(
        evidence: &mut Vec<u8>,
        preimages: &mut PersistedFirstQuietWindowPreimages,
        mutate: impl FnOnce(&mut FirstQuietWindowAttestationWire),
    ) {
        let mut value: FirstQuietWindowAttestationWire =
            serde_json::from_slice(&preimages.attestation_bytes).unwrap();
        mutate(&mut value);
        preimages.attestation_bytes = bytes(&value);
        preimages.attestation_fingerprint =
            fingerprint_bytes(&preimages.attestation_bytes).unwrap();
        rewrite_evidence(evidence, |wire| {
            wire.first_quiet_window_attestation_fingerprint =
                preimages.attestation_fingerprint.clone();
        });
    }

    fn rebind_thresholds(
        evidence: &mut Vec<u8>,
        bindings: &mut FirstQuietWindowBindings,
        preimages: &mut PersistedFirstQuietWindowPreimages,
        mutate: impl FnOnce(&mut ValidityThresholdsWire),
    ) {
        let mut value: ValidityThresholdsWire =
            serde_json::from_slice(&preimages.thresholds_bytes).unwrap();
        mutate(&mut value);
        preimages.thresholds_bytes = bytes(&value);
        preimages.thresholds_fingerprint = fingerprint_bytes(&preimages.thresholds_bytes).unwrap();
        bindings.validity_thresholds_fingerprint = preimages.thresholds_fingerprint.clone();
        rewrite_evidence(evidence, |wire| {
            wire.validity_thresholds_fingerprint = preimages.thresholds_fingerprint.clone();
        });
    }

    fn rebind_hardware(
        evidence: &mut Vec<u8>,
        bindings: &mut FirstQuietWindowBindings,
        preimages: &mut PersistedFirstQuietWindowPreimages,
        mutate: impl FnOnce(&mut HardwareProfileWire),
    ) {
        let mut value: HardwareProfileWire =
            serde_json::from_slice(&preimages.hardware_bytes).unwrap();
        mutate(&mut value);
        preimages.hardware_bytes = bytes(&value);
        preimages.hardware_fingerprint = fingerprint_bytes(&preimages.hardware_bytes).unwrap();
        bindings.hardware_profile_fingerprint = preimages.hardware_fingerprint.clone();
        rewrite_evidence(evidence, |wire| {
            wire.hardware_profile_fingerprint = preimages.hardware_fingerprint.clone();
        });
    }

    fn rebind_process_set(
        evidence: &mut Vec<u8>,
        bindings: &mut FirstQuietWindowBindings,
        preimages: &mut PersistedFirstQuietWindowPreimages,
        mutate: impl FnOnce(&mut UnrelatedProcessSetWire),
    ) {
        let mut value: UnrelatedProcessSetWire =
            serde_json::from_slice(&preimages.baseline_process_set_bytes).unwrap();
        mutate(&mut value);
        preimages.baseline_process_set_bytes = bytes(&value);
        preimages.baseline_process_set_fingerprint =
            fingerprint_bytes(&preimages.baseline_process_set_bytes).unwrap();
        bindings.baseline_unrelated_process_set_fingerprint =
            preimages.baseline_process_set_fingerprint.clone();
        rewrite_evidence(evidence, |wire| {
            wire.baseline_unrelated_process_set_fingerprint =
                preimages.baseline_process_set_fingerprint.clone();
            for sample in &mut wire.samples {
                sample.unrelated_process_set_fingerprint =
                    preimages.baseline_process_set_fingerprint.clone();
            }
        });
    }

    fn fingerprint() -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: "A".repeat(64),
            byte_length: 1,
        }
    }

    fn policy() -> ValidatedThresholdPolicy {
        ValidatedThresholdPolicy {
            fingerprint: fingerprint(),
            policy: HostStabilityPolicy {
                total_memory_bytes: 16_000,
                maximum_total_cpu_percent: 20.0,
                maximum_monitor_cpu_percent: 2.0,
                maximum_unrelated_cpu_percent: 5.0,
                minimum_available_memory_bytes: 8_000,
                minimum_cpu_frequency_hz: 1_000,
                maximum_temperature_millidegrees_celsius: 80_000,
                forbidden_throttle_flags: vec!["power_limit".into(), "thermal".into()],
                maximum_unrelated_process_count: 4,
                unrelated_process_set_policy: "exact_baseline_match_v1".into(),
                require_all_observations: true,
            },
        }
    }

    fn observation() -> FirstQuietWindowObservation {
        let start = 1_000;
        FirstQuietWindowObservation {
            boot_identity_pseudonym: "B".repeat(64),
            first_quiet_window_attestation_fingerprint: fingerprint(),
            started_at_monotonic_nanoseconds: start,
            ended_at_monotonic_nanoseconds: start + REQUIRED_DURATION_NS,
            sample_interval_seconds: 5,
            maximum_sample_gap_seconds: 10,
            samples: (0..=270)
                .map(|ordinal| FirstQuietWindowSample {
                    sample_ordinal: ordinal,
                    monotonic_nanoseconds: start + ordinal * 10_000_000_000,
                    boot_identity_pseudonym: "B".repeat(64),
                    total_cpu_percent: 10.0,
                    monitor_cpu_percent: 1.0,
                    unrelated_cpu_percent: 2.0,
                    available_memory_bytes: 10_000,
                    cpu_frequency_hz: 2_000,
                    maximum_temperature_millidegrees_celsius: 50_000,
                    throttle_flags: vec!["none".into()],
                    unrelated_process_set_fingerprint: fingerprint(),
                })
                .collect(),
            invalidating_events: Vec::new(),
            validity_status: "valid".into(),
        }
    }

    fn attestation() -> FirstQuietWindowAttestation {
        FirstQuietWindowAttestation {
            fingerprint: fingerprint(),
            started_at_monotonic_nanoseconds: 999,
            expires_at_monotonic_nanoseconds: 1_001 + REQUIRED_DURATION_NS,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one explicit complete 32-field golden fixture keeps all equality bindings visible"
    )]
    fn complete_fixture() -> (
        Vec<u8>,
        FirstQuietWindowBindings,
        PersistedFirstQuietWindowPreimages,
    ) {
        let campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001".to_owned();
        let boot = "B".repeat(64);
        let process_set = UnrelatedProcessSetWire {
            schema: "marty.performance/sd-jwt-issuance-unrelated-process-set/v1".into(),
            campaign_id: campaign_id.clone(),
            boot_identity_pseudonym: boot.clone(),
            identity_scheme: "hmac_sha256_campaign_ephemeral_process_set_v1".into(),
            entry_count: 1,
            opaque_process_instances: vec![UnrelatedProcessInstanceWire {
                process_instance_pseudonym: "D".repeat(64),
            }],
        };
        let process_bytes = bytes(&process_set);
        let process_fingerprint = fingerprint_bytes(&process_bytes).unwrap();
        let attestation = FirstQuietWindowAttestationWire {
            schema: "marty.performance/sd-jwt-issuance-test-window/v1".into(),
            campaign_id: campaign_id.clone(),
            target_role: "dedicated_performance_gateway".into(),
            target_identity_pseudonym: "E".repeat(64),
            starts_at_rfc3339_nanoseconds: "2026-08-29T12:00:00.000000000Z".into(),
            expires_at_rfc3339_nanoseconds: "2026-08-30T00:00:00.000000000Z".into(),
            change_reference_pseudonym: "F".repeat(64),
            production_traffic_drained: true,
            public_ingress_disabled: true,
            synthetic_data_only: true,
        };
        let attestation_bytes = bytes(&attestation);
        let attestation_fingerprint = fingerprint_bytes(&attestation_bytes).unwrap();
        let common = fingerprint();
        let controller = fingerprint_bytes(b"distinct controller binary").unwrap();
        let start = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:00:00.000000000Z").unwrap();
        let samples = (0..=270)
            .map(|ordinal| {
                let utc = start + chrono::Duration::seconds(i64::try_from(ordinal * 10).unwrap());
                FirstQuietWindowSampleWire {
                    sample_ordinal: ordinal,
                    utc_rfc3339_nanoseconds: utc.format("%Y-%m-%dT%H:%M:%S.000000000Z").to_string(),
                    monotonic_nanoseconds: 1_000 + ordinal * 10_000_000_000,
                    boot_identity_pseudonym: boot.clone(),
                    total_cpu_percent: 10.0,
                    monitor_cpu_percent: 1.0,
                    unrelated_cpu_percent: 2.0,
                    available_memory_bytes: 10_000,
                    cpu_frequency_hz: 2_000,
                    maximum_temperature_millidegrees_celsius: 50_000,
                    throttle_flags: vec!["none".into()],
                    unrelated_process_set_fingerprint: process_fingerprint.clone(),
                }
            })
            .collect();
        let mut wire = FirstQuietWindowWire {
            schema: "marty.performance/sd-jwt-issuance-first-quiet-window/v1".into(),
            campaign_id: campaign_id.clone(),
            created_at_utc_rfc3339_nanoseconds: "2026-08-29T12:45:00.000000000Z".into(),
            plan_fingerprint: common.clone(),
            manifest_fingerprint: common.clone(),
            monitor_binary_fingerprint: common.clone(),
            controller_binary_fingerprint: controller.clone(),
            controller_configuration_fingerprint: common.clone(),
            monitor_configuration_fingerprint: common.clone(),
            external_anchor_channel_configuration_fingerprint: common.clone(),
            source_commit: "1".repeat(40),
            source_tree: "2".repeat(40),
            source_archive_fingerprint: common.clone(),
            cargo_lock_fingerprint: common.clone(),
            rustc_verbose_version: "rustc synthetic".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            build_profile: "bench".into(),
            host_identity_fingerprint: common.clone(),
            boot_identity_pseudonym: boot.clone(),
            hardware_profile_fingerprint: common.clone(),
            validity_thresholds_fingerprint: common.clone(),
            first_quiet_window_attestation_fingerprint: attestation_fingerprint.clone(),
            baseline_unrelated_process_set_fingerprint: process_fingerprint.clone(),
            started_at_utc_rfc3339_nanoseconds: "2026-08-29T12:00:00.000000000Z".into(),
            started_at_monotonic_nanoseconds: 1_000,
            ended_at_utc_rfc3339_nanoseconds: "2026-08-29T12:45:00.000000000Z".into(),
            ended_at_monotonic_nanoseconds: 1_000 + REQUIRED_DURATION_NS,
            sample_interval_seconds: 5,
            maximum_sample_gap_seconds: 10,
            samples,
            invalidating_events: Vec::new(),
            validity_status: "valid".into(),
        };
        let hardware_bytes = bytes(&HardwareProfileWire {
            schema: "marty.performance/sd-jwt-issuance-hardware-profile/v1".into(),
            campaign_id: campaign_id.clone(),
            operating_system_family: "linux".into(),
            operating_system_version: None,
            kernel_version: None,
            architecture: "x86_64".into(),
            cpu_vendor: None,
            cpu_model: None,
            physical_core_count: Some(4),
            logical_cpu_count: 8,
            host_available_parallelism: 8,
            numa_node_count: Some(1),
            total_memory_bytes: 16_000,
            nominal_cpu_frequency_hz: Some(2_000),
            virtualization_kind: "bare_metal".into(),
            power_policy: "performance".into(),
        });
        let hardware_fingerprint = fingerprint_bytes(&hardware_bytes).unwrap();
        let thresholds_bytes = bytes(&ValidityThresholdsWire {
            schema: "marty.performance/sd-jwt-issuance-validity-thresholds/v1".into(),
            campaign_id: campaign_id.clone(),
            maximum_total_cpu_percent: 20.0,
            maximum_monitor_cpu_percent: 2.0,
            maximum_unrelated_cpu_percent: 5.0,
            minimum_available_memory_bytes: 8_000,
            minimum_cpu_frequency_hz: 1_000,
            maximum_temperature_millidegrees_celsius: 80_000,
            forbidden_throttle_flags: Vec::new(),
            maximum_unrelated_process_count: 4,
            unrelated_process_set_policy: "exact_baseline_match_v1".into(),
            require_all_observations: true,
        });
        let thresholds_fingerprint = fingerprint_bytes(&thresholds_bytes).unwrap();
        wire.hardware_profile_fingerprint = hardware_fingerprint.clone();
        wire.validity_thresholds_fingerprint = thresholds_fingerprint.clone();
        let bindings = FirstQuietWindowBindings {
            campaign_id,
            plan_fingerprint: common.clone(),
            manifest_fingerprint: common.clone(),
            monitor_binary_fingerprint: common.clone(),
            controller_binary_fingerprint: controller,
            controller_configuration_fingerprint: common.clone(),
            monitor_configuration_fingerprint: common.clone(),
            external_anchor_channel_configuration_fingerprint: common.clone(),
            source_commit: "1".repeat(40),
            source_tree: "2".repeat(40),
            source_archive_fingerprint: common.clone(),
            cargo_lock_fingerprint: common.clone(),
            rustc_verbose_version: "rustc synthetic".into(),
            target_triple: "x86_64-unknown-linux-gnu".into(),
            build_profile: "bench".into(),
            host_identity_fingerprint: common.clone(),
            boot_identity_pseudonym: boot,
            hardware_profile_fingerprint: hardware_fingerprint.clone(),
            validity_thresholds_fingerprint: thresholds_fingerprint.clone(),
            baseline_unrelated_process_set_fingerprint: process_fingerprint.clone(),
            target_role: "dedicated_performance_gateway".into(),
            target_identity_pseudonym: "E".repeat(64),
            change_reference_pseudonym: "F".repeat(64),
        };
        let preimages = PersistedFirstQuietWindowPreimages {
            attestation_bytes,
            attestation_fingerprint,
            baseline_process_set_bytes: process_bytes,
            baseline_process_set_fingerprint: process_fingerprint,
            hardware_bytes,
            hardware_fingerprint,
            thresholds_bytes,
            thresholds_fingerprint,
        };
        (bytes(&wire), bindings, preimages)
    }

    #[cfg(not(windows))]
    #[test]
    fn complete_canonical_retained_artifact_issues_bound_capability() {
        let (evidence, bindings, preimages) = complete_fixture();
        let temporary = tempfile::tempdir().unwrap();
        let store = CampaignArtifactStore::create_new(&temporary.path().join("campaign")).unwrap();
        store.initialize_fixed_layout().unwrap();
        let preimages = persist_preimages(
            &store,
            preimages.attestation_bytes,
            preimages.baseline_process_set_bytes,
            preimages.hardware_bytes,
            preimages.thresholds_bytes,
        )
        .unwrap();
        let capability =
            validate_retained_first_quiet_window(&evidence, &bindings, &preimages, &store).unwrap();
        assert_eq!(capability.campaign_id, bindings.campaign_id);
        assert_eq!(
            capability.evidence_fingerprint,
            fingerprint_bytes(&evidence).unwrap()
        );
        assert_eq!(
            capability.ended_at_monotonic_nanoseconds,
            1_000 + REQUIRED_DURATION_NS
        );
        assert_eq!(capability.process_set_fingerprints.len(), 1);
    }

    #[test]
    fn complete_semantics_execute_without_platform_writer() {
        let (evidence, bindings, preimages) = complete_fixture();
        let pending =
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages).unwrap();
        assert_eq!(pending.capability.campaign_id(), bindings.campaign_id);
        assert_eq!(
            pending.capability.evidence_fingerprint(),
            &fingerprint_bytes(&evidence).unwrap()
        );
        assert_eq!(
            pending.capability.controller_binary_fingerprint(),
            &bindings.controller_binary_fingerprint
        );
        assert_eq!(
            pending.capability.rustc_verbose_version(),
            bindings.rustc_verbose_version
        );
    }

    #[test]
    fn shared_threshold_validator_checks_bounds_hash_canonical_bytes_and_binding() {
        let (_, bindings, preimages) = complete_fixture();
        let hardware: HardwareProfileWire =
            serde_json::from_slice(&preimages.hardware_bytes).unwrap();
        let capability = validate_threshold_policy_bytes(
            &preimages.thresholds_bytes,
            &preimages.thresholds_fingerprint,
            &bindings.campaign_id,
            hardware.total_memory_bytes,
        )
        .unwrap();
        assert_eq!(capability.fingerprint(), &preimages.thresholds_fingerprint);
        assert_eq!(capability.maximum_unrelated_process_count(), 4);

        let oversized = vec![b' '; MAX_ARTIFACT_BYTES + 1];
        assert_eq!(
            error(validate_threshold_policy_bytes(
                &oversized,
                &fingerprint(),
                &bindings.campaign_id,
                hardware.total_memory_bytes,
            )),
            "validity thresholds: actual bytes"
        );
        assert_eq!(
            error(validate_threshold_policy_bytes(
                &preimages.thresholds_bytes,
                &fingerprint(),
                &bindings.campaign_id,
                hardware.total_memory_bytes,
            )),
            "validity thresholds: actual bytes"
        );

        let mut noncanonical = preimages.thresholds_bytes.clone();
        noncanonical.push(b' ');
        let noncanonical_fingerprint = fingerprint_bytes(&noncanonical).unwrap();
        assert_eq!(
            error(validate_threshold_policy_bytes(
                &noncanonical,
                &noncanonical_fingerprint,
                &bindings.campaign_id,
                hardware.total_memory_bytes,
            )),
            "validity thresholds: canonical bytes"
        );

        let mut wrong_campaign: ValidityThresholdsWire =
            serde_json::from_slice(&preimages.thresholds_bytes).unwrap();
        wrong_campaign.campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d999".into();
        let wrong_campaign = bytes(&wrong_campaign);
        let wrong_campaign_fingerprint = fingerprint_bytes(&wrong_campaign).unwrap();
        assert_eq!(
            error(validate_threshold_policy_bytes(
                &wrong_campaign,
                &wrong_campaign_fingerprint,
                &bindings.campaign_id,
                hardware.total_memory_bytes,
            )),
            "validity thresholds: binding"
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one shared-validator matrix keeps every capability and sanitized rejection boundary visible"
    )]
    #[test]
    fn shared_preimage_validators_issue_only_bound_capabilities() {
        let (_, bindings, preimages) = complete_fixture();
        let hardware: HardwareProfileWire =
            serde_json::from_slice(&preimages.hardware_bytes).unwrap();
        let thresholds = validate_threshold_policy_bytes(
            &preimages.thresholds_bytes,
            &preimages.thresholds_fingerprint,
            &bindings.campaign_id,
            hardware.total_memory_bytes,
        )
        .unwrap();

        let window = validate_initial_test_window_bytes(
            &preimages.attestation_bytes,
            &preimages.attestation_fingerprint,
            &bindings.campaign_id,
        )
        .unwrap();
        assert_eq!(window.fingerprint(), &preimages.attestation_fingerprint);
        assert_eq!(window.target_role(), bindings.target_role);
        assert_eq!(
            window.target_identity_pseudonym(),
            bindings.target_identity_pseudonym
        );
        assert_eq!(
            window.change_reference_pseudonym(),
            bindings.change_reference_pseudonym
        );
        validate_test_window_bytes(
            &preimages.attestation_bytes,
            &preimages.attestation_fingerprint,
            &bindings.campaign_id,
            &bindings.target_role,
            &bindings.target_identity_pseudonym,
            &bindings.change_reference_pseudonym,
        )
        .unwrap();

        let host_wire = HostIdentityWire {
            schema: "marty.performance/sd-jwt-issuance-host-identity/v1".into(),
            campaign_id: bindings.campaign_id.clone(),
            identity_scheme: "campaign_random_256_v1".into(),
            host_identity_pseudonym: "C".repeat(64),
            boot_identity_pseudonym: bindings.boot_identity_pseudonym.clone(),
        };
        let host_bytes = bytes(&host_wire);
        let host_fingerprint = fingerprint_bytes(&host_bytes).unwrap();
        let host = validate_host_identity_bytes(
            &host_bytes,
            &host_fingerprint,
            &bindings.campaign_id,
            &bindings.boot_identity_pseudonym,
        )
        .unwrap();
        assert_eq!(host.fingerprint(), &host_fingerprint);
        assert_eq!(host.host_identity_pseudonym(), "C".repeat(64));
        assert_eq!(
            host.boot_identity_pseudonym(),
            bindings.boot_identity_pseudonym
        );

        let process_set = validate_process_set_bytes(
            &preimages.baseline_process_set_bytes,
            &preimages.baseline_process_set_fingerprint,
            &bindings.campaign_id,
            &bindings.boot_identity_pseudonym,
            &thresholds,
        )
        .unwrap();
        assert_eq!(
            process_set.fingerprint(),
            &preimages.baseline_process_set_fingerprint
        );
        assert_eq!(process_set.process_identity_pseudonyms(), &["D".repeat(64)]);

        assert_eq!(
            error(validate_initial_test_window_bytes(
                &preimages.attestation_bytes,
                &fingerprint(),
                &bindings.campaign_id,
            )),
            "test window: actual bytes"
        );
        let mut noncanonical_window = preimages.attestation_bytes.clone();
        noncanonical_window.push(b' ');
        let noncanonical_window_fingerprint = fingerprint_bytes(&noncanonical_window).unwrap();
        assert_eq!(
            error(validate_initial_test_window_bytes(
                &noncanonical_window,
                &noncanonical_window_fingerprint,
                &bindings.campaign_id,
            )),
            "test window: canonical bytes"
        );
        assert_eq!(
            error(validate_test_window_bytes(
                &preimages.attestation_bytes,
                &preimages.attestation_fingerprint,
                &bindings.campaign_id,
                "isolated_production_gateway",
                &bindings.target_identity_pseudonym,
                &bindings.change_reference_pseudonym,
            )),
            "test window: identity binding"
        );
        let mut colliding_aliases: FirstQuietWindowAttestationWire =
            serde_json::from_slice(&preimages.attestation_bytes).unwrap();
        colliding_aliases.change_reference_pseudonym =
            colliding_aliases.target_identity_pseudonym.clone();
        let colliding_aliases = bytes(&colliding_aliases);
        let colliding_aliases_fingerprint = fingerprint_bytes(&colliding_aliases).unwrap();
        assert_eq!(
            error(validate_initial_test_window_bytes(
                &colliding_aliases,
                &colliding_aliases_fingerprint,
                &bindings.campaign_id,
            )),
            "test window: semantics"
        );

        let mut noncanonical_host = host_bytes.clone();
        noncanonical_host.push(b' ');
        let noncanonical_host_fingerprint = fingerprint_bytes(&noncanonical_host).unwrap();
        assert_eq!(
            error(validate_host_identity_bytes(
                &noncanonical_host,
                &noncanonical_host_fingerprint,
                &bindings.campaign_id,
                &bindings.boot_identity_pseudonym,
            )),
            "host identity: canonical bytes"
        );
        assert_eq!(
            error(validate_host_identity_bytes(
                &host_bytes,
                &host_fingerprint,
                &bindings.campaign_id,
                &"9".repeat(64),
            )),
            "host identity: semantics"
        );

        let mut noncanonical_set = preimages.baseline_process_set_bytes.clone();
        noncanonical_set.push(b' ');
        let noncanonical_set_fingerprint = fingerprint_bytes(&noncanonical_set).unwrap();
        assert_eq!(
            error(validate_process_set_bytes(
                &noncanonical_set,
                &noncanonical_set_fingerprint,
                &bindings.campaign_id,
                &bindings.boot_identity_pseudonym,
                &thresholds,
            )),
            "unrelated process set: canonical bytes"
        );
        assert_eq!(
            error(validate_process_set_bytes(
                &preimages.baseline_process_set_bytes,
                &preimages.baseline_process_set_fingerprint,
                &bindings.campaign_id,
                &"9".repeat(64),
                &thresholds,
            )),
            "unrelated process set: semantics"
        );
    }

    #[test]
    fn shared_observation_predicate_checks_nonzero_benchmark_cpu() {
        let thresholds = policy();
        let flags = vec!["none".to_owned()];
        let valid = || HostObservation {
            total_cpu_percent: 10.0,
            monitor_cpu_percent: 1.0,
            benchmark_cpu_percent: 6.0,
            unrelated_cpu_percent: 2.0,
            available_memory_bytes: 10_000,
            cpu_frequency_hz: 2_000,
            maximum_temperature_millidegrees_celsius: 50_000,
            throttle_flags: &flags,
        };
        thresholds.validate_observation(&valid()).unwrap();

        let mut non_finite = valid();
        non_finite.benchmark_cpu_percent = f64::NAN;
        assert_eq!(
            thresholds
                .validate_observation(&non_finite)
                .unwrap_err()
                .to_string(),
            "host observation: CPU"
        );
        let mut out_of_range = valid();
        out_of_range.benchmark_cpu_percent = 101.0;
        assert!(thresholds.validate_observation(&out_of_range).is_err());
        let mut above_total = valid();
        above_total.benchmark_cpu_percent = 11.0;
        assert!(thresholds.validate_observation(&above_total).is_err());
        let mut component_sum = valid();
        component_sum.benchmark_cpu_percent = 8.0;
        assert!(thresholds.validate_observation(&component_sum).is_err());

        let boundary = HostObservation {
            total_cpu_percent: 10.0,
            monitor_cpu_percent: 0.0,
            benchmark_cpu_percent: 10.0,
            unrelated_cpu_percent: 0.0,
            available_memory_bytes: 10_000,
            cpu_frequency_hz: 2_000,
            maximum_temperature_millidegrees_celsius: 50_000,
            throttle_flags: &flags,
        };
        thresholds.validate_observation(&boundary).unwrap();
    }

    #[test]
    fn shared_refactor_preserves_legacy_first_window_acceptance_and_error_precedence() {
        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rebind_attestation(&mut evidence, &mut preimages, |value| {
            value.change_reference_pseudonym = value.target_identity_pseudonym.clone();
        });
        bindings.change_reference_pseudonym = bindings.target_identity_pseudonym.clone();
        validate_first_quiet_window_semantics(&evidence, &bindings, &preimages).unwrap();

        let (mut evidence, bindings, mut preimages) = complete_fixture();
        preimages.attestation_bytes.push(b' ');
        preimages.attestation_fingerprint =
            fingerprint_bytes(&preimages.attestation_bytes).unwrap();
        rewrite_evidence(&mut evidence, |wire| {
            wire.first_quiet_window_attestation_fingerprint =
                preimages.attestation_fingerprint.clone();
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: attestation canonical bytes"
        );

        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rebind_hardware(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d999".into();
        });
        preimages.thresholds_bytes.push(b' ');
        preimages.thresholds_fingerprint = fingerprint_bytes(&preimages.thresholds_bytes).unwrap();
        bindings.validity_thresholds_fingerprint = preimages.thresholds_fingerprint.clone();
        rewrite_evidence(&mut evidence, |wire| {
            wire.validity_thresholds_fingerprint = preimages.thresholds_fingerprint.clone();
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: thresholds canonical bytes"
        );

        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        preimages.baseline_process_set_bytes.push(b' ');
        preimages.baseline_process_set_fingerprint =
            fingerprint_bytes(&preimages.baseline_process_set_bytes).unwrap();
        bindings.baseline_unrelated_process_set_fingerprint =
            preimages.baseline_process_set_fingerprint.clone();
        rewrite_evidence(&mut evidence, |wire| {
            wire.baseline_unrelated_process_set_fingerprint =
                preimages.baseline_process_set_fingerprint.clone();
            for sample in &mut wire.samples {
                sample.unrelated_process_set_fingerprint =
                    preimages.baseline_process_set_fingerprint.clone();
            }
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: process set canonical bytes"
        );
    }

    #[test]
    fn fixed_build_projection_getters_preserve_independently_distinct_values() {
        let fingerprint = |seed: char| ArtifactFingerprint {
            sha256: seed.to_string().repeat(64),
            byte_length: u64::from(seed as u32),
        };
        let capability = ValidatedFirstQuietWindow {
            campaign_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
            source_commit: "1".repeat(40),
            source_tree: "2".repeat(40),
            source_archive_fingerprint: fingerprint('A'),
            cargo_lock_fingerprint: fingerprint('B'),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            build_profile: "bench".to_owned(),
            controller_binary_fingerprint: fingerprint('C'),
            rustc_verbose_version: "rustc 1.95.0 (getter-test)\n".to_owned(),
            evidence_fingerprint: fingerprint('D'),
            attestation_fingerprint: fingerprint('E'),
            baseline_process_set_fingerprint: fingerprint('F'),
            process_set_fingerprints: vec![fingerprint('0')],
            ended_at_monotonic_nanoseconds: 987_654_321,
            ended_at_utc_rfc3339_nanoseconds: "2026-08-29T12:45:00.123456789Z".to_owned(),
        };
        assert_eq!(
            capability.campaign_id(),
            "123e4567-e89b-42d3-a456-426614174000"
        );
        assert_eq!(capability.source_commit(), "1".repeat(40));
        assert_eq!(capability.source_tree(), "2".repeat(40));
        assert_eq!(capability.source_archive_fingerprint(), &fingerprint('A'));
        assert_eq!(capability.cargo_lock_fingerprint(), &fingerprint('B'));
        assert_eq!(capability.target_triple(), "x86_64-unknown-linux-gnu");
        assert_eq!(capability.build_profile(), "bench");
        assert_eq!(
            capability.controller_binary_fingerprint(),
            &fingerprint('C')
        );
        assert_eq!(
            capability.rustc_verbose_version(),
            "rustc 1.95.0 (getter-test)\n"
        );
        assert_eq!(capability.evidence_fingerprint(), &fingerprint('D'));
        assert_eq!(capability.ended_at_monotonic_nanoseconds(), 987_654_321);
        assert_eq!(
            capability.ended_at_utc_rfc3339_nanoseconds(),
            "2026-08-29T12:45:00.123456789Z"
        );
    }

    #[test]
    fn complete_boundary_has_named_error_precedence() {
        let (mut evidence, bindings, preimages) = complete_fixture();
        evidence.extend_from_slice(b" ");
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: evidence canonical bytes"
        );
        let (evidence, mut bindings, preimages) = complete_fixture();
        bindings.source_tree = "9".repeat(40);
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: global preimage binding"
        );
    }

    #[test]
    fn retained_hardware_and_threshold_mutations_fail_at_actual_bytes_binding() {
        for mutate in [
            |preimages: &mut PersistedFirstQuietWindowPreimages| {
                preimages.hardware_bytes.push(b' ');
            },
            |preimages: &mut PersistedFirstQuietWindowPreimages| {
                preimages.thresholds_bytes.push(b' ');
            },
        ] {
            let (evidence, bindings, mut preimages) = complete_fixture();
            mutate(&mut preimages);
            assert_eq!(
                validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                    .unwrap_err()
                    .to_string(),
                "first quiet window: persisted preimage actual bytes"
            );
        }
    }

    #[test]
    fn retained_actual_bytes_precede_attestation_semantics() {
        let (evidence, bindings, mut preimages) = complete_fixture();
        let mut attestation: FirstQuietWindowAttestationWire =
            serde_json::from_slice(&preimages.attestation_bytes).unwrap();
        attestation.synthetic_data_only = false;
        preimages.attestation_bytes = bytes(&attestation);
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: persisted preimage actual bytes"
        );
    }

    #[test]
    fn independent_preimage_fingerprint_faults_precede_later_phases() {
        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        preimages.hardware_fingerprint.sha256 = "9".repeat(64);
        rebind_thresholds(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.require_all_observations = false;
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: persisted preimage binding"
        );

        let (mut evidence, bindings, mut preimages) = complete_fixture();
        preimages.thresholds_fingerprint.sha256 = "8".repeat(64);
        rewrite_evidence(&mut evidence, |wire| {
            wire.samples[0].sample_ordinal = 9;
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: persisted preimage binding"
        );
    }

    #[test]
    fn adjacent_phase_faults_freeze_sanitized_precedence() {
        let (mut evidence, mut bindings, preimages) = complete_fixture();
        evidence.push(b' ');
        bindings.source_tree = "9".repeat(40);
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: evidence canonical bytes"
        );

        let (evidence, mut bindings, mut preimages) = complete_fixture();
        bindings.source_tree = "9".repeat(40);
        preimages.attestation_fingerprint.sha256 = "9".repeat(64);
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: global preimage binding"
        );

        let (mut evidence, bindings, mut preimages) = complete_fixture();
        rebind_attestation(&mut evidence, &mut preimages, |value| {
            value.synthetic_data_only = false;
        });
        rewrite_evidence(&mut evidence, |wire| {
            wire.started_at_utc_rfc3339_nanoseconds = "invalid".into();
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: attestation conditions"
        );

        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rewrite_evidence(&mut evidence, |wire| {
            wire.started_at_utc_rfc3339_nanoseconds = "invalid".into();
        });
        rebind_thresholds(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.require_all_observations = false;
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: UTC grammar"
        );

        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rebind_thresholds(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.require_all_observations = false;
        });
        rewrite_evidence(&mut evidence, |wire| wire.samples[0].sample_ordinal = 9);
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: policy"
        );

        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rewrite_evidence(&mut evidence, |wire| {
            wire.samples[0].utc_rfc3339_nanoseconds = "invalid".into();
        });
        rebind_process_set(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.entry_count = 2;
        });
        assert_eq!(
            validate_first_quiet_window_semantics(&evidence, &bindings, &preimages)
                .unwrap_err()
                .to_string(),
            "first quiet window: sample"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn publication_collision_is_sanitized_and_issues_no_capability() {
        let (evidence, bindings, preimages) = complete_fixture();
        let temporary = tempfile::tempdir().unwrap();
        let store = CampaignArtifactStore::create_new(&temporary.path().join("campaign")).unwrap();
        store.initialize_fixed_layout().unwrap();
        let preimages = persist_preimages(
            &store,
            preimages.attestation_bytes,
            preimages.baseline_process_set_bytes,
            preimages.hardware_bytes,
            preimages.thresholds_bytes,
        )
        .unwrap();
        let wire: FirstQuietWindowWire = serde_json::from_slice(&evidence).unwrap();
        store
            .write_first_quiet_window(&wire, u64::try_from(MAX_ARTIFACT_BYTES).unwrap())
            .unwrap();
        assert_eq!(
            validate_retained_first_quiet_window(&evidence, &bindings, &preimages, &store)
                .unwrap_err()
                .to_string(),
            "first quiet window: publication"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn process_set_policy_fault_precedes_publication_collision() {
        let (mut evidence, mut bindings, mut preimages) = complete_fixture();
        rebind_process_set(&mut evidence, &mut bindings, &mut preimages, |value| {
            value.entry_count = 2;
        });
        let temporary = tempfile::tempdir().unwrap();
        let store = CampaignArtifactStore::create_new(&temporary.path().join("campaign")).unwrap();
        store.initialize_fixed_layout().unwrap();
        let preimages = persist_preimages(
            &store,
            preimages.attestation_bytes,
            preimages.baseline_process_set_bytes,
            preimages.hardware_bytes,
            preimages.thresholds_bytes,
        )
        .unwrap();
        let wire: FirstQuietWindowWire = serde_json::from_slice(&evidence).unwrap();
        store
            .write_first_quiet_window(&wire, u64::try_from(MAX_ARTIFACT_BYTES).unwrap())
            .unwrap();
        assert_eq!(
            validate_retained_first_quiet_window(&evidence, &bindings, &preimages, &store)
                .unwrap_err()
                .to_string(),
            "first quiet window: process set policy"
        );
    }

    #[test]
    fn exact_boundary_window_is_accepted_without_side_effects() {
        observation().validate(&attestation(), &policy()).unwrap();
    }

    #[test]
    fn duration_cadence_order_and_attestation_fail_closed() {
        let mut value = observation();
        value.ended_at_monotonic_nanoseconds -= 1;
        assert!(value.validate(&attestation(), &policy()).is_err());
        let mut value = observation();
        value.samples[1].sample_ordinal = 2;
        assert!(value.validate(&attestation(), &policy()).is_err());
        let mut value = observation();
        value.samples[1].monotonic_nanoseconds += 1;
        assert!(value.validate(&attestation(), &policy()).is_err());
        let mut expired = attestation();
        expired.expires_at_monotonic_nanoseconds = observation().ended_at_monotonic_nanoseconds;
        assert!(observation().validate(&expired, &policy()).is_err());
        let mut uncovered = observation();
        uncovered.samples.truncate(1);
        assert!(uncovered.validate(&attestation(), &policy()).is_err());
        let mut mismatched = attestation();
        mismatched.fingerprint.sha256 = "C".repeat(64);
        assert!(observation().validate(&mismatched, &policy()).is_err());
    }

    #[test]
    fn identity_metrics_thresholds_flags_and_status_fail_closed() {
        let mut value = observation();
        value.samples[0].boot_identity_pseudonym = "C".repeat(64);
        assert!(value.validate(&attestation(), &policy()).is_err());
        let mut value = observation();
        value.samples[0].total_cpu_percent = f64::NAN;
        assert!(value.validate(&attestation(), &policy()).is_err());
        let mut value = observation();
        value.samples[0].throttle_flags = vec!["thermal".into()];
        let mut empty_forbidden = policy();
        empty_forbidden.policy.forbidden_throttle_flags.clear();
        assert!(value.validate(&attestation(), &empty_forbidden).is_err());
        let mut power_limited = observation();
        power_limited.samples[0].throttle_flags = vec!["power_limit".into()];
        assert!(power_limited
            .validate(&attestation(), &empty_forbidden)
            .is_err());
        let mut value = observation();
        value.invalidating_events.push("sentinel".into());
        assert!(value.validate(&attestation(), &policy()).is_err());
    }
}
