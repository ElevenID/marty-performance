//! Frozen, deterministic planning for SD-JWT issuance qualification.
#![allow(
    dead_code,
    unused_imports,
    reason = "temporary until the analyzer pipeline commit wires the promoted layers"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

use anyhow::{Context, Result};
use chrono::{NaiveDate, NaiveTime};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(windows)]
use fs_at::OpenOptions as AtOpenOptions;
use marty_perf_schema::{
    ArtifactFingerprint, SdJwtIssuanceArtifactIndexProtocol, SdJwtIssuanceBootstrapProtocol,
    SdJwtIssuanceCriterionHomeProtocol, SdJwtIssuanceCriterionProtocol,
    SdJwtIssuanceDiscoveryProtocol, SdJwtIssuanceEffectProtocol,
    SdJwtIssuanceEvidenceFieldProtocol, SdJwtIssuanceEvidenceJsonType,
    SdJwtIssuanceEvidenceRecordProtocol, SdJwtIssuanceFirstQuietWindowProtocol,
    SdJwtIssuanceGlobalPreimageProtocol, SdJwtIssuanceGlobalRoundProtocol,
    SdJwtIssuanceInvocationDescriptorProtocol, SdJwtIssuanceLaunchBarrierProtocol,
    SdJwtIssuanceObservationBounds, SdJwtIssuanceQualificationManifest,
    SdJwtIssuanceQualificationPlan, SdJwtIssuanceRouteArtifactProtocol,
    SdJwtIssuanceRunValidityCompletionProtocol, SdJwtIssuanceRunValidityLimits,
    SdJwtIssuanceRunValidityProtocol, SdJwtIssuanceRunValidityRecordProtocols,
    MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use uuid::{Uuid, Variant, Version};

const MANIFEST_SCHEMA: &str = "sd_jwt_issuance_qualification_manifest_v1";
const PLAN_SCHEMA: &str = "marty.performance/sd-jwt-issuance-plan/v3";
const BENCHMARK_GROUP_ID: &str = "sd_jwt_issuance";
const ROUTE_SCHEMA: &str = "sd_jwt_issuance_route_v2";
const WORK_ESTIMATOR_VERSION: &str = "issuance_work_bytes_v1";
const STATIC_PARTITION_RULE_VERSION: &str = "contiguous_ceil_chunks_v1";
const FIXTURE_CASE_COUNT: usize = 33;
const BENCHMARK_ID_COUNT: usize = 132;
const PAIRED_CELL_COUNT: usize = 66;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const QUIET_WINDOW_SECONDS: u64 = 45 * 60;
const PROCESSES_PER_SUPERBLOCK: u32 = 8;
const MAX_EXTERNAL_ANCHOR_V1_BYTES: u64 = 16 * 1024;
const MAX_SOURCE_ARCHIVE_V1_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES: u64 = 1024 * 1024;
const MAX_SOURCE_ARCHIVE_V1_ENTRIES: u32 = 65_536;
const MAX_SOURCE_ARCHIVE_PATH_V1_BYTES: u32 = 1_024;
const MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES: u32 = 255;
const MAX_SOURCE_ARCHIVE_PATH_SEGMENTS: u32 = 256;
const MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES: u32 = 131_072;
const MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FIXED_BUILD_INPUT_ENTRIES: u32 = 65_536;
const MAX_FIXED_BUILD_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TOTAL_EVIDENCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const FIXED_BUILD_ROOT_WINDOWS: &str = "M:/marty-cdla-build-v1";
const FIXED_BUILD_ROOT_NON_WINDOWS: &str = "/marty-cdla-build-v1";
const FIXED_BUILD_INPUT_ARCHIVE_MAGIC: &[u8] = b"MARTY-SD-JWT-BUILD-INPUT-ARCHIVE-V1\n";
const SOURCE_ARCHIVE_MAGIC: &[u8] = b"MARTY-SD-JWT-SOURCE-ARCHIVE-V1\n";

const SUPERBLOCK_ORDERS: [&str; 20] = [
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
];
const ABBA_EXPANSION: [&str; 8] = [
    "serial", "adaptive", "adaptive", "serial", "adaptive", "serial", "serial", "adaptive",
];
const BAAB_EXPANSION: [&str; 8] = [
    "adaptive", "serial", "serial", "adaptive", "serial", "adaptive", "adaptive", "serial",
];

pub(crate) fn write_plan(manifest_path: &Path, output_path: &Path) -> Result<()> {
    anyhow::ensure!(
        output_path.is_absolute(),
        "qualification plan output path must be absolute"
    );
    let (manifest, manifest_bytes) = load_manifest(manifest_path)?;
    let plan = plan_for_manifest(&manifest, &manifest_bytes)?;
    let mut encoded = serde_json::to_vec_pretty(&plan).context("serialize qualification plan")?;
    encoded.push(b'\n');
    anyhow::ensure!(
        u64::try_from(encoded.len()).context("qualification plan byte length overflow")?
            <= MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
        "qualification plan exceeds the compiled V3 pre-parse limit"
    );

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .with_context(|| format!("create qualification plan {}", output_path.display()))?;
    output
        .write_all(&encoded)
        .with_context(|| format!("write qualification plan {}", output_path.display()))?;
    output
        .flush()
        .with_context(|| format!("flush qualification plan {}", output_path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync qualification plan {}", output_path.display()))?;
    println!(
        "Frozen {} paired cells and {} fresh processes in {}.",
        plan.paired_cell_count,
        plan.total_processes,
        output_path.display()
    );
    Ok(())
}

fn load_manifest(path: &Path) -> Result<(SdJwtIssuanceQualificationManifest, Vec<u8>)> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect issuance qualification manifest {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "issuance qualification manifest must be a file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_MANIFEST_BYTES,
        "issuance qualification manifest exceeds {MAX_MANIFEST_BYTES} bytes"
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(MAX_MANIFEST_BYTES + 1).context("manifest read cap overflow")?,
    );
    fs::File::open(path)
        .with_context(|| format!("open issuance qualification manifest {}", path.display()))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read issuance qualification manifest {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).context("manifest byte length overflow")? <= MAX_MANIFEST_BYTES,
        "issuance qualification manifest changed beyond the size limit while reading"
    );
    validate_canonical_json_bytes(&bytes)?;
    let manifest: SdJwtIssuanceQualificationManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse issuance qualification manifest {}", path.display()))?;
    validate_manifest(&manifest)?;

    let mut canonical = serde_json::to_vec_pretty(&manifest)
        .context("serialize canonical qualification manifest")?;
    canonical.push(b'\n');
    anyhow::ensure!(
        bytes == canonical,
        "issuance qualification manifest is not the canonical v1 byte representation"
    );
    Ok((manifest, bytes))
}

fn validate_canonical_json_bytes(bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(!bytes.is_empty(), "qualification manifest is empty");
    anyhow::ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "qualification manifest must not contain a UTF-8 BOM"
    );
    anyhow::ensure!(
        std::str::from_utf8(bytes).is_ok(),
        "qualification manifest must be UTF-8"
    );
    anyhow::ensure!(
        !bytes.contains(&b'\r'),
        "qualification manifest must use LF line endings"
    );
    anyhow::ensure!(
        bytes.ends_with(b"\n") && !bytes.ends_with(b"\n\n"),
        "qualification manifest must end in exactly one LF"
    );
    Ok(())
}

fn validate_manifest(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    validate_manifest_contract(manifest)?;
    let expected_cases = expected_qualification_cases();
    validate_cases(manifest, &expected_cases)?;
    validate_paired_matrix(manifest, &expected_cases)
}

fn validate_manifest_contract(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    anyhow::ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "unexpected manifest schema"
    );
    anyhow::ensure!(
        manifest.benchmark_group_id == BENCHMARK_GROUP_ID,
        "unexpected Criterion benchmark group"
    );
    anyhow::ensure!(
        manifest.fixture_case_count == FIXTURE_CASE_COUNT
            && manifest.cases.len() == FIXTURE_CASE_COUNT,
        "qualification manifest must contain exactly {FIXTURE_CASE_COUNT} cases"
    );
    anyhow::ensure!(
        manifest.benchmark_id_count == BENCHMARK_ID_COUNT
            && manifest.criterion_ids.len() == BENCHMARK_ID_COUNT,
        "qualification manifest must contain exactly {BENCHMARK_ID_COUNT} Criterion IDs"
    );
    anyhow::ensure!(
        manifest.paired_cell_count == PAIRED_CELL_COUNT
            && manifest.paired_cells.len() == PAIRED_CELL_COUNT,
        "qualification manifest must contain exactly {PAIRED_CELL_COUNT} paired cells"
    );
    anyhow::ensure!(
        manifest.route_schema == ROUTE_SCHEMA,
        "unexpected route schema"
    );
    anyhow::ensure!(
        manifest.work_estimator_version == WORK_ESTIMATOR_VERSION,
        "unexpected work-estimator version"
    );
    anyhow::ensure!(
        manifest.static_partition_rule_version == STATIC_PARTITION_RULE_VERSION,
        "unexpected static-partition version"
    );
    anyhow::ensure!(
        (1..=64).contains(&manifest.worker_cap),
        "worker cap is outside the supported qualification range"
    );
    anyhow::ensure!(
        manifest.mechanical_benchmark_thresholds.min_jobs == 2
            && manifest
                .mechanical_benchmark_thresholds
                .min_estimated_work_bytes
                == 1,
        "unexpected mechanical benchmark thresholds"
    );
    anyhow::ensure!(
        manifest.qualified_issuance_thresholds.is_none(),
        "production issuance thresholds must remain unqualified"
    );
    Ok(())
}

#[derive(Debug)]
struct ExpectedQualificationCase {
    fixture_id: String,
    disclosure_count: usize,
    benchmark_suffix: String,
}

fn expected_qualification_cases() -> Vec<ExpectedQualificationCase> {
    const DISCLOSURE_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
    const CORE_PAYLOADS: [(&str, &str); 4] = [
        ("small", "s"),
        ("medium_nested", "mn"),
        ("large_64_kib", "l64"),
        ("mixed_nested", "mx"),
    ];
    const DECOY_PAYLOADS: [(&str, &str); 2] = [("small", "s"), ("mixed_nested", "mx")];

    let mut cases = Vec::with_capacity(FIXTURE_CASE_COUNT);
    for (payload_label, payload_code) in CORE_PAYLOADS {
        for disclosure_count in DISCLOSURE_COUNTS {
            cases.push(ExpectedQualificationCase {
                fixture_id: format!("payload_{payload_label}__decoys_off__n_{disclosure_count:04}"),
                disclosure_count,
                benchmark_suffix: format!("p_{payload_code}__d_0__n_{disclosure_count:04}"),
            });
        }
    }
    for (payload_label, payload_code) in DECOY_PAYLOADS {
        for disclosure_count in DISCLOSURE_COUNTS {
            cases.push(ExpectedQualificationCase {
                fixture_id: format!("payload_{payload_label}__decoys_on__n_{disclosure_count:04}"),
                disclosure_count,
                benchmark_suffix: format!("p_{payload_code}__d_1__n_{disclosure_count:04}"),
            });
        }
    }
    for (fixture_id, disclosure_count) in [
        ("al_nested_obj_n0007", 7),
        ("al_array_dag_n0008", 8),
        ("tl_imbalanced_n0008", 8),
    ] {
        cases.push(ExpectedQualificationCase {
            fixture_id: fixture_id.to_owned(),
            disclosure_count,
            benchmark_suffix: format!("f_{fixture_id}"),
        });
    }
    debug_assert_eq!(cases.len(), FIXTURE_CASE_COUNT);
    cases
}

fn validate_cases(
    manifest: &SdJwtIssuanceQualificationManifest,
    expected_cases: &[ExpectedQualificationCase],
) -> Result<()> {
    let mut fixture_ids = BTreeSet::new();
    for (case, expected) in manifest.cases.iter().zip(expected_cases) {
        anyhow::ensure!(
            valid_identifier(&case.fixture_id),
            "invalid qualification fixture identifier"
        );
        anyhow::ensure!(
            fixture_ids.insert(case.fixture_id.as_str()),
            "duplicate qualification fixture identifier"
        );
        anyhow::ensure!(
            (1..=512).contains(&case.disclosure_count),
            "fixture disclosure count is outside the qualification matrix"
        );
        anyhow::ensure!(
            case.fixture_id == expected.fixture_id
                && case.disclosure_count == expected.disclosure_count,
            "qualification cases do not match the exact frozen matrix"
        );
    }
    Ok(())
}

fn validate_paired_matrix(
    manifest: &SdJwtIssuanceQualificationManifest,
    expected_cases: &[ExpectedQualificationCase],
) -> Result<()> {
    let criterion_prefix = format!("{}/", manifest.benchmark_group_id);
    let mut criterion_ids = BTreeSet::new();
    for id in &manifest.criterion_ids {
        anyhow::ensure!(
            id.starts_with(&criterion_prefix) && valid_criterion_id(id),
            "invalid full Criterion benchmark ID"
        );
        anyhow::ensure!(
            criterion_ids.insert(id.as_str()),
            "duplicate full Criterion benchmark ID"
        );
    }

    let mut paired_ids = BTreeSet::new();
    for (case_ordinal, (case, expected_case)) in
        manifest.cases.iter().zip(expected_cases).enumerate()
    {
        for (stage_ordinal, expected_stage) in ["executor_assembly", "full_issuance"]
            .into_iter()
            .enumerate()
        {
            let cell = &manifest.paired_cells[case_ordinal * 2 + stage_ordinal];
            let stage_code = if expected_stage == "executor_assembly" {
                "ea"
            } else {
                "fi"
            };
            let expected_serial_id = format!(
                "{}/v2__s_{stage_code}__r_so__{}",
                manifest.benchmark_group_id, expected_case.benchmark_suffix
            );
            let expected_adaptive_id = format!(
                "{}/v2__s_{stage_code}__r_ac__{}",
                manifest.benchmark_group_id, expected_case.benchmark_suffix
            );
            anyhow::ensure!(
                cell.fixture_id == case.fixture_id && cell.stage == expected_stage,
                "paired cells must follow case order and executor/full stage order"
            );
            anyhow::ensure!(
                cell.serial_id == expected_serial_id && cell.adaptive_id == expected_adaptive_id,
                "paired cell Criterion IDs do not exactly encode their fixture, stage, and route"
            );
            anyhow::ensure!(
                criterion_ids.contains(cell.serial_id.as_str())
                    && criterion_ids.contains(cell.adaptive_id.as_str()),
                "paired cell references an unknown Criterion ID"
            );
            anyhow::ensure!(
                paired_ids.insert(cell.serial_id.as_str())
                    && paired_ids.insert(cell.adaptive_id.as_str()),
                "Criterion ID is reused across paired cells"
            );
        }
    }
    anyhow::ensure!(
        paired_ids == criterion_ids,
        "paired cells do not cover the complete Criterion ID set"
    );
    let expected_registration_order = manifest.paired_cells.chunks_exact(2).flat_map(|stages| {
        [
            stages[0].serial_id.as_str(),
            stages[1].serial_id.as_str(),
            stages[0].adaptive_id.as_str(),
            stages[1].adaptive_id.as_str(),
        ]
    });
    anyhow::ensure!(
        manifest
            .criterion_ids
            .iter()
            .map(String::as_str)
            .eq(expected_registration_order),
        "Criterion IDs do not follow canonical case, route, and stage registration order"
    );
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_criterion_id(value: &str) -> bool {
    (1..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

fn evidence_fields<const N: usize>(
    values: [(&str, SdJwtIssuanceEvidenceJsonType, bool); N],
) -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    values
        .map(
            |(name, json_type, nullable)| SdJwtIssuanceEvidenceFieldProtocol {
                name: name.to_owned(),
                json_type,
                nullable,
            },
        )
        .to_vec()
}

fn record_protocol(
    schema: &str,
    fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    cardinality: &str,
    semantic_rule: &str,
) -> SdJwtIssuanceEvidenceRecordProtocol {
    SdJwtIssuanceEvidenceRecordProtocol {
        schema: schema.to_owned(),
        fields,
        cardinality: cardinality.to_owned(),
        semantic_rule: semantic_rule.to_owned(),
    }
}

fn genesis_header_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-genesis/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
            (
                "fixed_binary_build_receipt_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("monitor_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_configuration_fingerprint", ArtifactFingerprint, false),
            ("monitor_configuration_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("host_identity_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
            ("hardware_profile_fingerprint", ArtifactFingerprint, false),
            ("validity_thresholds_fingerprint", ArtifactFingerprint, false),
            ("first_quiet_window_evidence_fingerprint", ArtifactFingerprint, false),
            ("initial_test_window_attestation_fingerprint", ArtifactFingerprint, false),
            ("baseline_unrelated_process_set_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_as_segment_0_record_0",
        "campaign_id_is_unique_uuid_v4_segment_ordinal_and_record_ordinal_are_0_all_fingerprints_resolve_through_fixed_role_paths_and_bind_create_new_actual_bytes_source_archive_reconstructs_exact_commit_and_tree_and_Cargo_lock_fixed_binary_build_receipt_cryptographically_links_the_installed_fixed_binary_to_those_source_toolchain_command_and_build_inputs_and_initial_timing_window_attestation_exists_after_shutdown_checks",
    )
}

fn continuation_header_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-continuation/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("previous_segment_fingerprint", ArtifactFingerprint, false),
            ("genesis_header_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
        ]),
        "exactly_one_as_record_0_of_each_segment_after_0",
        "same_campaign_genesis_and_boot_segment_ordinal_equals_predecessor_plus_1_previous_fingerprint_binds_entire_synced_predecessor",
    )
}

fn sample_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, String, StringArray, F64, I64, U32, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-sample/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("sample_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("boot_identity_pseudonym", String, false),
            ("timing_state", String, false),
            ("global_round_ordinal", U32, true),
            ("cell_ordinal", U32, true),
            ("expansion_position", U32, true),
            ("timing_process_id", String, true),
            ("total_cpu_percent", F64, false),
            ("monitor_cpu_percent", F64, false),
            ("benchmark_cpu_percent", F64, false),
            ("unrelated_cpu_percent", F64, false),
            ("available_memory_bytes", U64, false),
            ("cpu_frequency_hz", U64, false),
            ("maximum_temperature_millidegrees_celsius", I64, false),
            ("throttle_flags", StringArray, false),
            ("unrelated_process_set_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
        ]),
        "zero_based_sample_ordinal_contiguous_across_campaign_at_declared_cadence",
        "timing_state_is_exactly_idle_launching_or_process_idle_requires_all_four_process_context_fields_null_launching_requires_all_four_nonnull_and_matching_active_synced_intent_before_start_process_requires_all_four_nonnull_and_matching_active_start_and_remains_process_after_child_exit_through_route_Criterion_receipt_and_finish_sync_total_monitor_benchmark_and_unrelated_CPU_percent_are_finite_in_observation_bounds_each_subcategory_is_at_most_total_and_checked_finite_monitor_plus_benchmark_plus_unrelated_is_at_most_total_available_memory_is_at_most_bound_hardware_total_frequency_and_temperature_are_in_observation_bounds_throttle_flags_are_sorted_unique_protocol_literals_and_none_is_the_only_value_when_no_flag_is_active_every_sample_applies_the_bound_validity_thresholds_exactly_total_monitor_and_unrelated_CPU_are_at_most_their_declared_maxima_available_memory_is_at_least_the_enabled_nonzero_minimum_frequency_is_at_least_the_enabled_nonzero_minimum_temperature_is_at_most_the_declared_maximum_no_forbidden_throttle_flag_is_present_and_the_referenced_unrelated_process_set_entry_count_is_at_most_the_declared_maximum",
    )
}

fn process_intent_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-intent/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_before_creation_of_each_of_10560_scheduled_processes",
        "static_token_descriptor_and_empty_Criterion_home_inventory_are_create_new_synced_and_match_coordinate_controller_configuration_and_fixed_binary_token_fingerprint_is_bound_by_descriptor_and_intent_and_intent_record_is_flushed_and_durably_synced_before_spawn",
    )
}

fn process_start_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-start/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("full_benchmark_id", String, false),
            ("process_intent_record_fingerprint", ArtifactFingerprint, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_ready_frame_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_after_spawned_child_reports_blocked_and_before_release_for_each_process",
        "same_coordinate_id_descriptor_token_and_full_benchmark_id_as_durably_synced_intent_process_identity_pseudonym_equals_the_exact_value_in_the_token_bound_by_intent_and_matching_ready_frame_controller_checks_actual_child_PID_only_in_memory_against_the_spawned_OS_handle_and_exclusive_pipes_without_retaining_it_child_validated_static_token_emitted_bounded_ready_frame_and_has_stdin_read_as_next_operation_controller_persisted_and_synced_exact_ready_bytes_checked_subtraction_of_start_monotonic_nanoseconds_minus_matching_intent_monotonic_nanoseconds_is_at_most_30000000000_which_conservatively_proves_spawn_to_ready_within_30_seconds_underflow_overflow_or_greater_delta_rejects_start_record_binds_ready_and_is_flushed_and_durably_synced_before_controller_persists_syncs_and_sends_release_no_second_start_before_matching_finish",
    )
}

fn process_finish_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, I32, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-finish/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("full_benchmark_id", String, false),
            ("exit_code", I32, false),
            ("termination_reason", String, false),
            ("elapsed_monotonic_nanoseconds", U64, false),
            ("stdout_after_ready_bytes", U64, false),
            ("stderr_bytes", U64, false),
            ("launch_barrier_receipt_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_final_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_artifact_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_fingerprint", ArtifactFingerprint, false),
            ("artifacts_flushed_and_synced", Boolean, false),
        ]),
        "exactly_one_after_each_matching_process_start",
        "same_coordinates_ids_process_identity_pseudonym_and_descriptor_as_intent_and_start_exit_code_0_termination_reason_exactly_exited_elapsed_monotonic_nanoseconds_equals_checked_finish_monotonic_nanoseconds_minus_matching_start_monotonic_nanoseconds_and_is_greater_than_0_and_at_most_300000000000_release_prepared_monotonic_is_between_matching_start_and_finish_inclusive_underflow_overflow_or_mismatch_rejects_controller_observed_stdout_after_ready_bytes_and_stderr_bytes_checked_add_without_overflow_and_sum_at_most_maximum_process_output_bytes_raw_output_was_drain_discarded_barrier_receipt_proves_release_after_synced_start_unique_home_was_empty_before_release_and_final_inventory_contains_one_fresh_matching_full_id_benchmark_object_with_new_benchmark_json_and_sibling_estimates_json_created_between_start_and_finish_no_unrelated_id_and_all_bound_artifacts_are_flushed_and_synced",
    )
}

fn attestation_transition_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("previous_attestation_fingerprint", ArtifactFingerprint, false),
            ("next_attestation_fingerprint", ArtifactFingerprint, false),
            ("next_starts_at_rfc3339_nanoseconds", String, false),
            ("next_expires_at_rfc3339_nanoseconds", String, false),
        ]),
        "exactly_one_for_each_actual_attestation_after_the_genesis_attestation",
        "next_create_new_attestation_exists_and_was_created_after_shutdown_recheck_before_previous_expiry_same_target_and_conditions_no_time_gap_and_duration_at_most_43200_seconds",
    )
}

fn segment_footer_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-segment-footer/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("records_before_footer", U32, false),
            ("bytes_before_footer", U64, false),
            ("records_before_footer_fingerprint", ArtifactFingerprint, false),
            ("first_monotonic_nanoseconds", U64, false),
            ("last_monotonic_nanoseconds", U64, false),
            ("sample_count", U32, false),
            ("process_intent_count", U32, false),
            ("process_start_count", U32, false),
            ("process_finish_count", U32, false),
            ("attestation_transition_count", U32, false),
            ("closed_reason", String, false),
        ]),
        "exactly_one_as_the_last_record_of_every_segment",
        "record_ordinal_equals_records_before_footer_counts_cover_every_prior_record_first_monotonic_equals_header_monotonic_last_monotonic_equals_footer_monotonic_closed_reason_is_one_protocol_literal_and_matches_the_exact_run_validity_segment_close_reason_rule_and_entire_segment_is_flushed_and_durably_synced_before_successor_or_completion",
    )
}

fn record_protocols() -> SdJwtIssuanceRunValidityRecordProtocols {
    SdJwtIssuanceRunValidityRecordProtocols {
        genesis_header: genesis_header_protocol(),
        continuation_header: continuation_header_protocol(),
        sample: sample_protocol(),
        process_intent: process_intent_protocol(),
        process_start: process_start_protocol(),
        process_finish: process_finish_protocol(),
        attestation_transition: attestation_transition_protocol(),
        segment_footer: segment_footer_protocol(),
    }
}

fn first_quiet_window_protocol() -> SdJwtIssuanceFirstQuietWindowProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, QuietWindowSampleArray, String, StringArray, U32, U64,
    };
    SdJwtIssuanceFirstQuietWindowProtocol {
        schema: "marty.performance/sd-jwt-issuance-first-quiet-window/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_before_correctness_and_build"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("created_at_utc_rfc3339_nanoseconds", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            ("monitor_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_configuration_fingerprint", ArtifactFingerprint, false),
            ("monitor_configuration_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("host_identity_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
            ("hardware_profile_fingerprint", ArtifactFingerprint, false),
            ("validity_thresholds_fingerprint", ArtifactFingerprint, false),
            (
                "first_quiet_window_attestation_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("baseline_unrelated_process_set_fingerprint", ArtifactFingerprint, false),
            ("started_at_utc_rfc3339_nanoseconds", String, false),
            ("started_at_monotonic_nanoseconds", U64, false),
            ("ended_at_utc_rfc3339_nanoseconds", String, false),
            ("ended_at_monotonic_nanoseconds", U64, false),
            ("sample_interval_seconds", U32, false),
            ("maximum_sample_gap_seconds", U32, false),
            ("samples", QuietWindowSampleArray, false),
            ("invalidating_events", StringArray, false),
            ("validity_status", String, false),
        ]),
        sample_fields: evidence_fields([
            ("sample_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("boot_identity_pseudonym", String, false),
            ("total_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("monitor_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("unrelated_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("available_memory_bytes", U64, false),
            ("cpu_frequency_hz", U64, false),
            (
                "maximum_temperature_millidegrees_celsius",
                SdJwtIssuanceEvidenceJsonType::I64,
                false,
            ),
            ("throttle_flags", StringArray, false),
            ("unrelated_process_set_fingerprint", ArtifactFingerprint, false),
        ]),
        validity_rule: "campaign_plan_manifest_source_commit_tree_archive_Cargo_lock_host_and_boot_pseudonyms_hardware_monitor_controller_configuration_thresholds_and_first_window_target_pseudonym_and_conditions_match_genesis_except_the_first_window_attestation_has_its_own_disjoint_fixed_role_and_need_not_equal_the_initial_timing_window_attestation_the_first_window_attestation_start_is_at_or_before_the_first_window_start_and_its_expiry_is_strictly_after_every_first_window_sample_and_the_first_window_end_zero_based_samples_are_contiguous_controller_observed_target_5_second_cadence_no_gap_over_10_seconds_ended_minus_started_at_least_2700000000000_monotonic_nanoseconds_CPU_percent_memory_frequency_temperature_throttle_and_process_set_observations_satisfy_the_same_exact_observation_bounds_cross-field_rules_and_bound_validity_threshold_predicate_as_timing_samples_with_checked_finite_monitor_plus_unrelated_at_most_total_validity_status_exactly_valid_and_empty_invalidating_events".to_owned(),
    }
}

fn invocation_descriptor_protocol() -> SdJwtIssuanceInvocationDescriptorProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, NameValueArray, String, StringArray, U32,
    };
    SdJwtIssuanceInvocationDescriptorProtocol {
        schema: "marty.performance/sd-jwt-issuance-invocation/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_before_process_intent"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
            ("executable_relative_path", String, false),
            ("full_benchmark_id", String, false),
            ("argv", StringArray, false),
            ("standard_input_mode", String, false),
            ("standard_output_mode", String, false),
            ("standard_error_mode", String, false),
            ("environment", NameValueArray, false),
            ("working_directory", String, false),
            ("criterion_home", String, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_path", String, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
        ]),
        environment_entry_fields: evidence_fields([
            ("name", String, false),
            ("value_kind", String, false),
            ("portable_value", String, true),
        ]),
        environment_allowlist: [
            "CRITERION_HOME",
            "MARTY_PERF_START_BARRIER",
            "NO_COLOR",
            "RUST_BACKTRACE",
            "SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID",
            "SD_JWT_ISSUANCE_ROUTE_NDJSON",
            "SystemRoot",
            "TEMP",
            "TMP",
            "WINDIR",
        ]
        .map(str::to_owned)
        .to_vec(),
        environment_value_kind_literals: [
            "literal",
            "campaign_relative_path",
            "windows_host_runtime_path",
        ]
        .map(str::to_owned)
        .to_vec(),
        environment_mapping_rule: "entries_are_in_allowlist_order_with_exact_table_CRITERION_HOME_campaign_relative_path_criterion/rNN_cNN_eN_MARTY_PERF_START_BARRIER_campaign_relative_path_barriers/rNN_cNN_eN.token_NO_COLOR_literal_1_RUST_BACKTRACE_literal_0_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_literal_exact_full_benchmark_id_SD_JWT_ISSUANCE_ROUTE_NDJSON_campaign_relative_path_routes/rNN_cNN_eN.ndjson_TEMP_campaign_relative_path_tmp/rNN_cNN_eN_TMP_campaign_relative_path_tmp/rNN_cNN_eN_and_on_windows_only_SystemRoot_and_WINDIR_windows_host_runtime_path_with_null_portable_value_non_windows_has_exactly_8_entries_and_windows_has_exactly_10_each_name_appears_once_no_other_name_kind_or_value_is_valid".to_owned(),
        semantic_rule: "descriptor_matches_controller_configuration_coordinate_fixed_binary_and_manifest_full_id_executable_relative_path_is_bin/fixed-benchmark_on_unix_or_bin/fixed-benchmark.exe_on_windows_selected_only_by_target_triple_argv_is_exact_ordered_Criterion_0.5.1_logical_vector_--bench_--exact_full_benchmark_id_--sample-size_50_--nresamples_100000_--warm-up-time_15_--measurement-time_10_--confidence-level_0.95_--save-baseline_base_--noplot_with_no_other_argument_standard_input_mode_is_controller_single_writer_release_frame_pipe_standard_output_mode_persists_only_exact_ready_frame_then_continuously_bounded_drains_and_discards_all_later_stdout_while_retaining_only_byte_count_standard_error_mode_concurrently_bounded_drains_and_discards_all_bytes_while_retaining_only_byte_count_working_directory_is_dot_for_campaign_root_parent_environment_is_cleared_then_only_explicit_allowlist_entries_are_added_in_protocol_order_case_fold_duplicates_forbidden_NO_COLOR_is_literal_1_RUST_BACKTRACE_is_literal_0_and_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_is_literal_exact_full_id_CRITERION_HOME_is_criterion/rNN_cNN_eN_MARTY_PERF_START_BARRIER_is_barriers/rNN_cNN_eN.token_SD_JWT_ISSUANCE_ROUTE_NDJSON_is_routes/rNN_cNN_eN.ndjson_TEMP_and_TMP_are_both_tmp/rNN_cNN_eN_SystemRoot_and_WINDIR_are_present_only_on_windows_as_host_role_with_null_portable_value_and_absent_on_non_windows_no_raw_absolute_inherited_digest_diagnostic_or_secret_value_is_retained_controller_derives_actual_absolute_campaign_paths_from_trusted_campaign_root_initial_inventory_is_canonical_empty_array".to_owned(),
        resolution_rule: "descriptor_at_invocations/rNN_cNN_eN.json_criterion_home_at_criterion/rNN_cNN_eN_token_at_barriers/rNN_cNN_eN.token_ready_at_barrier-ready/rNN_cNN_eN.json_release_at_barrier-releases/rNN_cNN_eN.json_receipt_at_barrier-receipts/rNN_cNN_eN.json_and_inventories_at_inventories/rNN_cNN_eN-initial.json_and_-final.json_under_campaign_root_compute_paths_from_coordinates_reject_absolute_parent_symlink_hardlink_or_reparse_escape_and_reject_missing_extra_or_mismatched_preimage".to_owned(),
    }
}

fn launch_barrier_protocol() -> SdJwtIssuanceLaunchBarrierProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    SdJwtIssuanceLaunchBarrierProtocol {
        token_schema: "marty.performance/sd-jwt-issuance-launch-token/v1".to_owned(),
        token_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("nonce_uppercase_hex_256", String, false),
            ("process_identity_pseudonym", String, false),
        ]),
        nonce_rule: "exactly_64_ASCII_uppercase_hex_characters_from_an_independently_sampled_32_byte_CSPRNG_value_unique_across_all_10560_tokens_and_distinct_from_every_process_host_boot_target_change_and_anchor_challenge_pseudonym_or_nonce".to_owned(),
        process_identity_pseudonym_rule: "exactly_64_ASCII_uppercase_hex_characters_from_an_independently_sampled_32_byte_CSPRNG_value_unique_across_all_10560_processes_and_distinct_from_every_launch_nonce_host_boot_target_change_and_anchor_challenge_pseudonym_or_nonce".to_owned(),
        ready_frame_schema: "marty.performance/sd-jwt-issuance-launch-ready/v1".to_owned(),
        ready_frame_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        release_frame_schema: "marty.performance/sd-jwt-issuance-launch-release/v1".to_owned(),
        release_frame_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("ready_frame_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("prepared_at_utc_rfc3339_nanoseconds", String, false),
            ("prepared_at_monotonic_nanoseconds", U64, false),
        ]),
        receipt_schema: "marty.performance/sd-jwt-issuance-launch-receipt/v1".to_owned(),
        receipt_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("ready_frame_fingerprint", ArtifactFingerprint, false),
            ("release_frame_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        artifact_format: "token_and_receipt_are_create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_ready_and_release_are_create_new_exact_canonical_compact_json_lf_frame_bytes_flush_and_durable_sync".to_owned(),
        transport_rule: "custom_benchmark_process_entry_before_any_Criterion_construction_validates_synced_token_then_writes_ready_as_exact_first_stdout_frame_plus_LF_flushes_and_makes_blocking_stdin_read_its_next_operation_controller_uses_one_bounded_reader_for_ready_and_all_later_stdout_and_concurrently_drains_bounded_stderr_persists_only_exact_ready_bytes_then_discards_later_stdout_and_all_stderr_while_retaining_only_separate_numeric_byte_counts_controller_checks_actual_child_PID_only_in_memory_against_spawned_handle_and_exclusive_pipe_ownership_controller_is_only_stdin_writer_all_duplicate_write_handles_are_closed_and_after_synced_release_artifact_uses_write_all_flush_close_child_reads_to_EOF_and_rejects_early_EOF_partial_extra_second_or_noncanonical_frame_and_does_not_enter_Criterion_on_any_error_broken_pipe_early_exit_conservative_intent_to_start_delta_over_30_seconds_or_output_over_limit_invalidates_campaign".to_owned(),
        semantic_rule: "controller_precomputes_canonical_token_identity_nonce_and_process_identity_pseudonym_under_their_exact_independent_random_grammar_uniqueness_and_nonreuse_rules_then_create_new_writes_flushes_and_durably_syncs_token_before_descriptor_and_intent_child_validates_token_emits_and_flushes_the_same_token_bound_pseudonym_in_ready_frame_then_waits_only_for_stdin_controller_create_new_persists_and_durably_syncs_exact_ready_frame_then_durably_syncs_matching_process_start_binding_ready_controller_create_new_persists_and_durably_syncs_release_frame_binding_token_ready_start_and_pseudonym_then_sends_same_exact_frame_child_validates_release_and_identity_then_create_new_writes_and_syncs_canonical_receipt_before_any_Criterion_construction_setup_or_timing_token_ready_start_release_receipt_and_finish_all_equal_the_same_pseudonym_causal_fingerprints_not_child_clocks_or_raw_PID_prove_order".to_owned(),
    }
}

fn criterion_home_protocol() -> SdJwtIssuanceCriterionHomeProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactInventoryEntryArray, String, U32, U64,
    };
    SdJwtIssuanceCriterionHomeProtocol {
        inventory_schema: "marty.performance/sd-jwt-issuance-criterion-home-inventory/v1"
            .to_owned(),
        inventory_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("phase", String, false),
            ("collected_at_utc_rfc3339_nanoseconds", String, false),
            ("collected_at_monotonic_nanoseconds", U64, false),
            ("criterion_home", String, false),
            ("entries", ArtifactInventoryEntryArray, false),
        ]),
        entry_fields: evidence_fields([
            ("relative_path", String, false),
            ("file_kind", String, false),
            ("fingerprint", ArtifactFingerprint, false),
        ]),
        opaque_artifact_rule: "every_Criterion_owned_file_is_an_opaque_bounded_byte_string_hashed_exactly_as_written_without_Marty_canonical_byte_requirements_all_files_are_streamed_and_bound_by_the_final_inventory".to_owned(),
        benchmark_json_projection_rule: "parse_only_the_selected_new/benchmark.json_with_Criterion_0.5.1_shape_require_exact_ordered_keys_group_id_function_id_value_str_throughput_full_id_directory_name_title_throughput_is_exact_single_variant_Bytes_u64_object_and_require_group_function_full_id_directory_name_title_equal_manifest_selected_ID_mapping_reject_unknown_duplicate_missing_wrong_type_nonfinite_or_trailing_data".to_owned(),
        estimates_json_projection_rule: "parse_only_the_sibling_new/estimates.json_with_Criterion_0.5.1_Estimates_shape_exact_ordered_keys_mean_median_median_abs_dev_slope_std_dev_each_nonnull_estimate_has_exact_ordered_confidence_interval_point_estimate_standard_error_and_confidence_interval_has_exact_ordered_confidence_level_lower_bound_upper_bound_all_numbers_finite_each_interval_ordered_and_confidence_level_0.95_slope_is_nullable_and_when_nonnull_has_same_estimate_shape_selected_value_is_positive_median.point_estimate".to_owned(),
        freshness_rule: "controller_create_directory_fail_if_exists_at_unique_coordinate_home_reject_link_or_reparse_initial_inventory_phase_initial_is_synced_before_intent_and_has_zero_entries_final_inventory_phase_final_is_collected_after_successful_child_exit_in_ascending_utf8_relative_path_order_contains_exactly_eight_regular_files_for_one_manifest_matching_ID_base_and_new_each_have_benchmark.json_estimates.json_sample.json_tukey.json_corresponding_base_and_new_files_are_byte_equal_every_file_was_created_from_that_lifecycle_no_unrelated_benchmark_id_and_finish_binds_both_inventories_and_selected_new_artifacts".to_owned(),
    }
}

fn route_artifact_protocol() -> SdJwtIssuanceRouteArtifactProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        Boolean, RouteReadyBatchArray, RouteStaticChunkArray, String, U64,
    };
    SdJwtIssuanceRouteArtifactProtocol {
        record_schema: "sd_jwt_issuance_route_v2".to_owned(),
        artifact_format: "create_new_utf8_exactly_one_serde_json_1.0.151_canonical_compact_record_plus_one_LF_no_BOM_CR_or_extra_bytes_flush_and_durable_sync".to_owned(),
        record_fields: evidence_fields([
            ("schema", String, false),
            ("benchmark_id", String, false),
            ("fixture_id", String, false),
            ("stage", String, false),
            ("requested", String, false),
            ("effective", String, false),
            ("executor_batches", U64, true),
            ("serial_batches", U64, true),
            ("native_batches", U64, true),
            ("budget_fallback_batches", U64, true),
            ("max_native_worker_count", U64, false),
            ("worker_cap", U64, false),
            ("host_available_parallelism", U64, false),
            ("work_estimator_version", String, false),
            ("static_partition_rule_version", String, false),
            ("ready_batches", RouteReadyBatchArray, true),
        ]),
        ready_batch_fields: evidence_fields([
            ("ordinal", U64, false),
            ("job_count", U64, false),
            ("estimated_work_bytes", U64, true),
            ("work_estimate_status", String, false),
            ("work_gate_evaluated", Boolean, false),
            ("parallelism_gate_evaluated", Boolean, false),
            ("budget_gate_evaluated", Boolean, false),
            ("available_parallelism", U64, true),
            ("selected_worker_count", U64, true),
            ("leased_worker_count", U64, true),
            ("budget_acquisition_result", String, false),
            ("selected_mode", String, false),
            ("selection_reason", String, false),
            ("static_chunk_size", U64, true),
            ("static_chunks", RouteStaticChunkArray, true),
        ]),
        static_chunk_fields: evidence_fields([
            ("ordinal", U64, false),
            ("job_count", U64, false),
            ("estimated_work_bytes", U64, false),
        ]),
        stage_literals: ["executor_assembly", "full_issuance"]
            .map(str::to_owned)
            .to_vec(),
        requested_literals: ["serial_oracle", "adaptive_candidate"]
            .map(str::to_owned)
            .to_vec(),
        effective_literals: [
            "serial_oracle",
            "bounded_native",
            "mixed_native_and_serial",
            "ready_batch_serial_fallback",
            "budget_serial_fallback",
            "target_serial_fallback",
        ]
        .map(str::to_owned)
        .to_vec(),
        work_estimate_status_literals: ["not_evaluated", "available", "overflow"]
            .map(str::to_owned)
            .to_vec(),
        budget_acquisition_result_literals: ["not_evaluated", "acquired", "unavailable"]
            .map(str::to_owned)
            .to_vec(),
        selected_mode_literals: ["serial", "native_parallel"]
            .map(str::to_owned)
            .to_vec(),
        selection_reason_literals: [
            "below_min_jobs",
            "work_estimate_overflow",
            "below_min_estimated_work_bytes",
            "insufficient_available_parallelism",
            "worker_budget_unavailable",
            "bounded_native",
        ]
        .map(str::to_owned)
        .to_vec(),
        selected_record_rule: "fixed_binary_constructs_all_132_manifest_route_records_in_exact_registration_order_validates_the_full_unique_set_then_requires_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_equal_the_descriptor_and_exact_Criterion_filter_and_retains_only_that_one_matching_record_the_manifest_serial_ID_requires_requested_serial_oracle_and_the_manifest_adaptive_ID_requires_requested_adaptive_candidate_reject_missing_duplicate_extra_or_route-swapped_match".to_owned(),
        record_invariant_rule: "deny_unknown_duplicate_missing_wrong_type_nonfinite_checked_integer_overflow_or_trailing_data_schema_fixture_stage_and_benchmark_id_equal_the_exact_manifest_case_cell_and_full_ID_requested_is_exactly_serial_oracle_for_that_cell_serial_ID_or_adaptive_candidate_for_that_cell_adaptive_ID_versions_equal_issuance_work_bytes_v1_and_contiguous_ceil_chunks_v1_worker_cap_equals_manifest_and_locked_fixed_binary_host_available_parallelism_is_at_least_1_and_equals_bound_hardware_profile_serial_oracle_requires_effective_serial_oracle_all_four_batch_counts_and_ready_batches_null_and_max_native_worker_count_0_adaptive_target_fallback_requires_effective_target_serial_fallback_the_same_five_nullable_values_null_max_0_and_worker_cap_1_and_worker_cap_1_requires_this_exact_target_fallback_branch_other_adaptive_requires_worker_cap_at_least_2_ready_batches_array_and_four_nonnull_counts_let_E_equal_array_length_N_equal_count_selected_mode_native_parallel_S_equal_E_minus_N_F_equal_count selection_reason worker_budget_unavailable_and_M_equal_max_nonnull_leased_worker_count_or_0_require_executor_batches_E_native_batches_N_serial_batches_S_budget_fallback_batches_F_max_native_worker_count_M_E_equal_S_plus_N_F_at_most_S_and_M_at_most_worker_cap_effective_is_mixed_native_and_serial_if_N_positive_and_S_positive_else_bounded_native_if_N_positive_else_budget_serial_fallback_if_F_positive_else_ready_batch_serial_fallback_empty_array_is_ready_batch_serial_fallback_and_no_adaptive_record_may_use_serial_oracle".to_owned(),
        ready_batch_invariant_rule: "for_each_zero_based_ordinal_J_job_count_is_positive_X_is_estimated_work_bytes_A_is_available_parallelism_W_is_selected_worker_count_cap_is_record_worker_cap_and_thresholds_are_Jmin_2_and_Xmin_1_every_status_result_mode_and_reason_is_from_its_protocol_literal_array_and_only_exact_mode_reason_pairs_serial_below_min_jobs_serial_work_estimate_overflow_serial_below_min_estimated_work_bytes_serial_insufficient_available_parallelism_serial_worker_budget_unavailable_or_native_parallel_bounded_native_are_valid_below_min_jobs_iff_J_below_2_X_null_status_not_evaluated_work_gate_false_A_W_null_parallelism_gate_false_budget_gate_false_result_not_evaluated_mode_serial_lease_chunk_size_chunks_null_work_estimate_overflow_requires_J_at_least_2_X_null_status_overflow_work_gate_true_and_same_remaining_unevaluated_serial_fields_below_min_estimated_work_bytes_requires_J_at_least_2_X_present_below_1_status_available_work_gate_true_and_same_remaining_unevaluated_serial_fields_otherwise_X_at_least_1_status_available_work_gate_true_A_present_at_least_1_parallelism_gate_true_W_equals_min_A_cap_J_and_A_equals_record_host_available_parallelism_if_W_below_2_reason_insufficient_available_parallelism_budget_unevaluated_and_serial_static_null_if_W_at_least_2_and_acquisition_fails_reason_worker_budget_unavailable_budget_gate_true_result_unavailable_and_serial_lease_and_static_null_if_W_at_least_2_and_acquisition_succeeds_reason_bounded_native_budget_gate_true_result_acquired_mode_native_parallel_leased_worker_count_W_and_static_fields_present_equivalently_work_gate_iff_status_not_not_evaluated_X_present_iff_status_available_parallelism_gate_iff_A_and_W_present_budget_gate_iff_result_not_not_evaluated_native_parallel_iff_reason_bounded_native_and_lease_chunk_size_chunks_present_iff_native".to_owned(),
        static_chunk_invariant_rule: "native_only_with_J_job_count_W_selected_workers_X_estimated_work_bytes_C_equal_checked_ceil_J_div_W_and_K_equal_checked_ceil_J_div_C_static_chunk_size_equals_C_exactly_K_nonempty_chunks_K_at_most_W_ordinals_are_contiguous_0_through_K_minus_1_each_nonfinal_job_count_equals_C_final_job_count_equals_J_minus_C_times_K_minus_1_and_is_between_1_and_C_checked_sum_job_count_equals_J_checked_sum_estimated_work_bytes_equals_X_record_max_native_worker_count_uses_leased_W_not_K_analyzer_validation_is_limited_to_these_retained_count_ordinal_and_sum_equations_because_per_job_work_is_not_retained_while_locked_fixed_binary_source_tests_validate_each_chunk_estimate_against_its_exact_contiguous_job_slice_and_the_artifact_fingerprint_binds_the_emitted_values".to_owned(),
    }
}

fn artifact_index_protocol() -> SdJwtIssuanceArtifactIndexProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, CoordinateArtifactArray, String, U32,
    };
    SdJwtIssuanceArtifactIndexProtocol {
        criterion_schema: "marty.performance/sd-jwt-issuance-criterion-artifact-index/v1"
            .to_owned(),
        route_schema: "marty.performance/sd-jwt-issuance-route-artifact-index/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_JSON_plus_one_LF_flush_and_durable_sync_before_terminal_segment_footer"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("artifact_kind", String, false),
            ("entry_count", U32, false),
            ("entries", CoordinateArtifactArray, false),
        ]),
        entry_fields: evidence_fields([
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("relative_path", String, false),
            ("fingerprint", ArtifactFingerprint, false),
        ]),
        criterion_artifact_kind: "criterion_0_5_1_new_estimates_json".to_owned(),
        route_artifact_kind: "sd_jwt_issuance_route_v2".to_owned(),
        criterion_path_rule: "exact_ASCII_forward_slash_formatter_criterion/rRR_cCC_eE/sd_jwt_issuance/FUNCTION_ID/new/estimates.json_where_RR_is_two_digit_round_00_through_19_CC_is_two_digit_cell_00_through_65_E_is_one_digit_expansion_0_through_7_and_FUNCTION_ID_is_full_benchmark_id_after_removing_exactly_one_sd_jwt_issuance/ prefix_require_string_equality_to_formatter_and_reject_backslash_dot_or_dotdot_segment_absolute_path_alternate_padding_case_separator_escape_alias_or_extra_prefix".to_owned(),
        route_path_rule: "exact_ASCII_forward_slash_formatter_routes/rRR_cCC_eE.ndjson_with_the_same_coordinate_digits_require_string_equality_to_formatter_and_reject_backslash_dot_or_dotdot_segment_absolute_path_alternate_padding_case_separator_escape_alias_or_extra_suffix".to_owned(),
        validity_rule: "each_index_artifact_kind_equals_its_exact_protocol_literal_entry_count_is_10560_and_entries_are_exactly_unique_in_zero-based_array_position_order_array_position_equals_checked_formula_global_round_ordinal_times_66_plus_cell_ordinal_then_times_8_plus_expansion_position_with_round_0_through_19_cell_0_through_65_and_expansion_0_through_7_timing_process_id_equals_rRR-cCC-eE_full_benchmark_id_equals_the_schedule-selected_manifest_serial_or_adaptive_ID_relative_path_equals_the_kind-specific_exact_formatter_every_fingerprint_matches_process_completion_and_exact_opaque_Criterion_or_typed_route_file_bytes_and_completion_set_fingerprint_binds_the_entire_canonical_synced_index_artifact_reject_missing_extra_duplicate_gap_reorder_or_alias".to_owned(),
    }
}

fn terminal_observation_receipt_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        ("channel_id", String, false),
        ("log_id", String, false),
        ("campaign_append_ordinal", U64, false),
        ("channel_clock_session_id", String, false),
        ("channel_monotonic_nanoseconds", U64, false),
        ("observed_at_utc_rfc3339_nanoseconds", String, false),
        ("channel_receipt_id", String, false),
        ("challenge_uppercase_hex_256", String, false),
        ("terminal_segment_fingerprint", ArtifactFingerprint, false),
        ("terminal_footer_monotonic_nanoseconds", U64, false),
        ("controller_request_monotonic_nanoseconds", U64, false),
        ("signing_key_id", String, false),
        ("signature_uppercase_hex_512", String, false),
    ])
}

fn terminal_observation_evidence_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        (
            "terminal_observation_receipt_fingerprint",
            ArtifactFingerprint,
            false,
        ),
        (
            "controller_receipt_observed_monotonic_nanoseconds",
            U64,
            false,
        ),
    ])
}

fn completion_anchor_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        ("channel_id", String, false),
        ("log_id", String, false),
        ("campaign_append_ordinal", U64, false),
        ("channel_clock_session_id", String, false),
        ("channel_monotonic_nanoseconds", U64, false),
        ("published_at_utc_rfc3339_nanoseconds", String, false),
        ("channel_receipt_id", String, false),
        ("challenge_uppercase_hex_256", String, false),
        ("completion_fingerprint", ArtifactFingerprint, false),
        ("terminal_segment_fingerprint", ArtifactFingerprint, false),
        (
            "terminal_observation_evidence_fingerprint",
            ArtifactFingerprint,
            false,
        ),
        ("signing_key_id", String, false),
        ("signature_uppercase_hex_512", String, false),
    ])
}

fn external_anchor_channel_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-external-anchor-channel/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("channel_id", String, false),
            ("channel_kind", String, false),
            ("endpoint_role", String, false),
            ("log_id", String, false),
            ("connector_authentication_policy", String, false),
            ("receipt_verification_scheme", String, false),
            ("signing_key_id", String, false),
            ("trust_root_fingerprint", ArtifactFingerprint, false),
            ("clock_policy", String, false),
            ("maximum_receipt_bytes", U64, false),
        ]),
        "exactly_one_at_configuration/external-anchor-channel.json_and_bound_by_first_window_genesis_and_completion",
        "channel_id_equals_marty-sd-jwt-issuance-anchor-v1_channel_kind_equals_signed_create_only_log_v1_endpoint_role_equals_preconfigured_primary_anchor_connector_log_id_equals_sd-jwt-issuance-qualification-v1_connector_authentication_policy_equals_out_of_band_trust_root_authenticated_transport_v1_receipt_verification_scheme_equals_ed25519_rfc8032_canonical_json_v1_signing_key_id_equals_marty-sd-jwt-issuance-anchor-ed25519-v1_trust_root_fingerprint_has_byte_length_32_and_SHA256_of_exact_32_raw_Ed25519_public_key_bytes_resolved_only_by_exact_channel_log_and_key_ID_match_in_the_analyzer_out_of_band_preconfigured_read_only_trust_store_and_never_to_a_campaign_file_clock_policy_equals_signed_nonrollback_monotonic_session_si_nanoseconds_v1_under_which_one_session_ID_identifies_one_nonrestarting_channel_monotonic_origin_each_tick_is_one_SI_nanosecond_the_counter_never_rolls_back_or_slows_relative_to_elapsed_time_and_restart_changes_the_session_ID_maximum_receipt_bytes_is_exactly_16384_raw_endpoint_credentials_access_tokens_private_keys_and_transport_diagnostics_are_never_campaign_artifacts",
    )
}

fn completion_protocol() -> SdJwtIssuanceRunValidityCompletionProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactFingerprintArray, ProcessCompletionArray, String, U32, U64,
    };
    SdJwtIssuanceRunValidityCompletionProtocol {
        schema: "marty.performance/sd-jwt-issuance-validity-completion/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_after_terminal_segment_sync"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("created_at_utc_rfc3339_nanoseconds", String, false),
            ("created_at_monotonic_nanoseconds", U64, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("genesis_header_fingerprint", ArtifactFingerprint, false),
            ("ordered_segment_fingerprints", ArtifactFingerprintArray, false),
            ("terminal_segment_fingerprint", ArtifactFingerprint, false),
            (
                "terminal_observation_evidence_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("ordered_test_window_attestation_fingerprints", ArtifactFingerprintArray, false),
            ("first_monotonic_nanoseconds", U64, false),
            ("last_monotonic_nanoseconds", U64, false),
            ("segment_count", U32, false),
            ("sample_count", U64, false),
            ("process_intent_count", U32, false),
            ("process_start_count", U32, false),
            ("process_finish_count", U32, false),
            ("attestation_transition_count", U32, false),
            ("process_completions", ProcessCompletionArray, false),
            ("criterion_artifact_set_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_set_fingerprint", ArtifactFingerprint, false),
            ("first_quiet_window_evidence_fingerprint", ArtifactFingerprint, false),
            ("invalidating_event_count", U32, false),
            ("validity_status", String, false),
        ]),
        process_completion_fields: evidence_fields([
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("process_intent_record_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("process_finish_record_fingerprint", ArtifactFingerprint, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_receipt_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_final_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_artifact_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_fingerprint", ArtifactFingerprint, false),
        ]),
        validity_rule: "created_after_terminal_footer_and_signed_ordinal_0_terminal_observation_receipt_and_its_create_new_synced_controller_observation_wrapper_then_create_new_written_flushed_and_durably_synced_before_signed_ordinal_1_completion_anchor_and_within_total_campaign_limit_validity_status_exactly_valid_invalidating_event_count_0_external_anchor_channel_configuration_matches_genesis_and_typed_fixed_role_ordered_segments_are_complete_chain_terminal_equals_last_first_and_last_monotonic_equal_genesis_and_terminal_footer_genesis_fixed_binary_build_receipt_fingerprint_resolves_the_exact_v2_receipt_whose_inventory_and_archive_fingerprints_resolve_build/input-inventory.json_and_build/input-files.bia_and_the_inventory_archive_fingerprint_matches_so_every_member_byte_mode_and_path_is_offline_recomputable_terminal_observation_evidence_fingerprint_binds_the_exact_wrapper_and_signed_ordinal_0_receipt_attestations_are_complete_actual_chain_process_intent_start_finish_counts_each_10560_process_completions_have_exactly_10560_unique_round_major_cell_major_expansion_entries_with_matching_synced_intent_ready_start_release_receipt_successful_finish_fresh_home_and_artifacts_and_criterion_and_route_artifact_set_fingerprints_bind_the_exact_two_canonical_synced_index_artifacts_whose_entries_match_process_completions".to_owned(),
        terminal_observation_receipt_schema:
            "marty.performance/sd-jwt-issuance-terminal-observation-receipt/v1".to_owned(),
        terminal_observation_receipt_fields: terminal_observation_receipt_fields(),
        terminal_observation_evidence_schema:
            "marty.performance/sd-jwt-issuance-terminal-observation-evidence/v1".to_owned(),
        terminal_observation_evidence_fields: terminal_observation_evidence_fields(),
        external_anchor_schema: "marty.performance/sd-jwt-issuance-completion-anchor/v1".to_owned(),
        external_anchor_fields: completion_anchor_fields(),
        external_anchor_format: "two_offline_verifiable_Ed25519_signed_create-only_log_receipts_are_retained_at_anchors/terminal-observation-receipt.json_and_anchors/completion-anchor.json_as_utf8_canonical_pretty_JSON_plus_one_LF_with_the_Marty_owned_terminal_observation_wrapper_at_anchors/terminal-observation-evidence.json_each_create_new_flushed_and_durably_synced_and_each_signed_receipt_independently_verifiable_without_network_access".to_owned(),
        external_anchor_channel: external_anchor_channel_protocol(),
        external_anchor_channel_id: "marty-sd-jwt-issuance-anchor-v1".to_owned(),
        external_anchor_log_id: "sd-jwt-issuance-qualification-v1".to_owned(),
        external_anchor_connector_policy:
            "out_of_band_trust_root_authenticated_transport_v1".to_owned(),
        external_anchor_signature_scheme: "ed25519_rfc8032_canonical_json_v1".to_owned(),
        external_anchor_signing_key_id:
            "marty-sd-jwt-issuance-anchor-ed25519-v1".to_owned(),
        external_anchor_signed_preimage_rule: "strict_RFC8032_Ed25519_over_exact_ASCII_domain_then_u64_big_endian_unsigned_JSON_byte_length_then_canonical_compact_unsigned_JSON_without_LF_and_with_every_field_preceding_signature_in_protocol_order_terminal_domain_is_MARTY-SD-JWT-TERMINAL-OBSERVATION-V1_then_0x00_completion_domain_is_MARTY-SD-JWT-COMPLETION-ANCHOR-V1_then_0x00_signature_is_exactly_128_ASCII_uppercase_hex_characters_channel_clock_session_ID_is_exactly_64_ASCII_uppercase_hex_characters_unique_to_one_nonrestarting_channel_clock_session_challenge_is_an_independently_sampled_32_byte_CSPRNG_value_encoded_as_exactly_64_ASCII_uppercase_hex_characters_unique_across_both_receipts_and_all_other_campaign_nonces_or_pseudonyms_mutation_of_any_field_domain_length_key_or_signature_rejects".to_owned(),
        external_anchor_receipt_id_rule:
            "ASCII_[A-Za-z0-9._:-]_length_1_through_128_nonsecret_locator".to_owned(),
        external_anchor_replay_rule: "the_pinned_channel_create-only_uniqueness_and_non-equivocation_guarantee_for_each_exact_channel_id_log_id_campaign_id_campaign_append_ordinal_tuple_is_an_explicit_out-of-band_trusted-service_assumption_and_an_offline_bundle_cannot_discover_a_conflicting_receipt_withheld_by_that_trusted_channel_analyzer_rejects_every_same-tuple_pair_with_different_exact_canonical_signed_receipt_bytes_present_in_the_bundle_ordinals_are_exactly_0_for_terminal_observation_and_1_for_completion_only_exact_byte-for-byte_same_signed_receipt_retrieval_is_idempotent_same_locator_with_different_signed_bytes_is_a_conflict_both_ordinals_use_the_same_bound_channel_log_key_and_channel_clock_session_and_ordinal_1_binds_the_local_evidence_wrapper_whose_fingerprint_binds_ordinal_0_no_cross-log_channel_campaign_session_or_ordinal_replay_is_valid_and_no_one-time_downstream_activation_is_inferred".to_owned(),
        external_anchor_rule: "before_UTF8_or_JSON_parsing_analyzer_reads_each_signed_receipt_at_most_hardcoded_MAX_SD_JWT_ISSUANCE_COMPLETION_ANCHOR_V1_BYTES_16384_plus_one_and_rejects_larger_input_independently_of_plan_fields_then_offline_verifies_exact_canonical_bytes_signature_trust_root_channel_log_campaign_key_receipt_ID_challenge_channel_clock_session_and_ordinal_0_or_1_semantics_terminal_observation_receipt_terminal_fingerprint_and_footer_monotonic_match_the_synced_terminal_segment_controller_request_monotonic_is_between_terminal_footer_and_controller_receipt_observed_monotonic_inclusive_wrapper_binds_exact_ordinal_0_receipt_and_controller_observation_completion_binds_wrapper_and_is_durably_synced_before_ordinal_1_ordinal_1_binds_completion_terminal_and_wrapper_both_receipts_have_the_same_channel_clock_session_ID_and_ordinal_1_channel_monotonic_is_not_before_ordinal_0_timing_uses_only_same-clock_durations_A_is_checked_controller_receipt_observed_monotonic_minus_terminal_footer_monotonic_B_is_checked_ordinal_1_channel_monotonic_nanoseconds_minus_ordinal_0_channel_monotonic_nanoseconds_checked_A_plus_B_must_be_at_most_maximum_anchor_publication_delay_seconds_300000000000_nanoseconds_underflow_overflow_session_change_or_one_nanosecond_over_rejects_channel_UTC_is_retained_only_as_authenticated_audit_metadata_and_is_not_used_for_duration_controller_UTC_is_not_compared_to_channel_UTC_the_limit_proves_channel_publication_not_local_ordinal_1_receipt_delivery_or_sync_and_network_access_is_neither_used_nor_permitted_during_offline_analysis".to_owned(),
    }
}

fn controller_configuration_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-controller-config/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("artifact_layout_version", String, false),
            ("process_schedule_version", String, false),
            ("child_environment_policy_version", String, false),
            ("launch_transport_version", String, false),
            ("stdout_retention_policy", String, false),
            ("stderr_retention_policy", String, false),
            ("external_anchor_channel_id", String, false),
            ("external_anchor_policy_version", String, false),
            ("maximum_spawn_to_ready_seconds", U32, false),
            ("maximum_timing_process_seconds", U32, false),
            ("maximum_process_output_bytes", U64, false),
            ("maximum_anchor_publication_delay_seconds", U32, false),
            ("synthetic_data_only", Boolean, false),
            ("source_export_approved", Boolean, false),
        ]),
        "exactly_one_at_configuration/controller.json",
        "artifact_layout_version_equals_sd_jwt_issuance_artifact_layout_v1_process_schedule_version_equals_global_round_manifest_cell_expansion_v1_child_environment_policy_version_equals_cleared_allowlist_v1_launch_transport_version_equals_stdio_ready_release_v1_stdout_retention_policy_equals_persist_ready_only_drain_discard_rest_v1_stderr_retention_policy_equals_bounded_drain_discard_v1_external_anchor_channel_id_equals_marty-sd-jwt-issuance-anchor-v1_external_anchor_policy_version_equals_signed_offline_receipts_v1_all_limits_including_maximum_anchor_publication_delay_seconds_equal_the_plan_synthetic_data_only_and_source_export_approved_are_true_no_path_endpoint_credential_or_free_form_diagnostic_field_is_permitted",
    )
}

fn monitor_configuration_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, U32};
    record_protocol(
        "marty.performance/sd-jwt-issuance-monitor-config/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("sample_interval_seconds", U32, false),
            ("maximum_sample_gap_seconds", U32, false),
            ("controller_clock_authoritative", Boolean, false),
            ("cpu_backend", String, false),
            ("memory_backend", String, false),
            ("frequency_backend", String, false),
            ("temperature_backend", String, false),
            ("throttle_backend", String, false),
            ("process_scope_policy", String, false),
            ("process_identity_scheme", String, false),
            ("process_identity_key_persisted", Boolean, false),
            ("raw_process_metadata_retained", Boolean, false),
        ]),
        "exactly_one_at_configuration/monitor.json",
        "intervals_equal_the_plan_controller_clock_authoritative_is_true_cpu_backend_equals_controller_observed_total_cpu_percent_v1_memory_backend_equals_controller_observed_available_memory_bytes_v1_frequency_backend_equals_controller_observed_cpu_frequency_hz_v1_temperature_backend_equals_controller_observed_maximum_temperature_millidegrees_celsius_v1_throttle_backend_equals_controller_observed_throttle_flags_v1_no_backend_value_is_a_device_or_filesystem_path_process_scope_policy_equals_exact_baseline_match_v1_process_identity_scheme_equals_hmac_sha256_campaign_ephemeral_process_set_v1_and_both_process_identity_key_persisted_and_raw_process_metadata_retained_are_false",
    )
}

fn host_identity_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::String;
    record_protocol(
        "marty.performance/sd-jwt-issuance-host-identity/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("identity_scheme", String, false),
            ("host_identity_pseudonym", String, false),
            ("boot_identity_pseudonym", String, false),
        ]),
        "exactly_one_at_profiles/host-identity.json",
        "identity_scheme_is_campaign_random_256_v1_each_pseudonym_is_an_independent_64_character_uppercase_hex_CSPRNG_value_unique_to_this_campaign_and_is_not_a_hostname_machine_or_boot_ID_serial_account_network_value_or_hash_of_any_guessable_identifier_controller_detects_underlying_host_or_boot_change_without_persisting_the_raw_values",
    )
}

fn hardware_profile_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-hardware-profile/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("operating_system_family", String, false),
            ("operating_system_version", String, true),
            ("kernel_version", String, true),
            ("architecture", String, false),
            ("cpu_vendor", String, true),
            ("cpu_model", String, true),
            ("physical_core_count", U32, true),
            ("logical_cpu_count", U32, false),
            ("host_available_parallelism", U32, false),
            ("numa_node_count", U32, true),
            ("total_memory_bytes", U64, false),
            ("nominal_cpu_frequency_hz", U64, true),
            ("virtualization_kind", String, false),
            ("power_policy", String, false),
        ]),
        "exactly_one_at_profiles/hardware.json",
        "operating_system_family_architecture_virtualization_kind_and_power_policy_each_equal_one_value_from_their_protocol_literal_array_operating_system_version_kernel_version_cpu_vendor_and_cpu_model_are_null_or_printable_ASCII_length_1_through_128_physical_core_count_and_numa_node_count_when_present_are_1_through_65536_logical_cpu_count_and_host_available_parallelism_are_1_through_observation_bounds_maximum_logical_cpu_count_and_host_available_parallelism_is_at_most_logical_cpu_count_total_memory_bytes_is_1_through_observation_bounds_maximum_total_memory_bytes_nominal_cpu_frequency_when_present_is_within_observation_bounds_frequency_range_hostname_username_IP_MAC_device_CPU_disk_or_cloud_instance_serial_and_filesystem_path_fields_are_forbidden",
    )
}

fn validity_thresholds_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{Boolean, String, StringArray, F64, I64, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-thresholds/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("maximum_total_cpu_percent", F64, false),
            ("maximum_monitor_cpu_percent", F64, false),
            ("maximum_unrelated_cpu_percent", F64, false),
            ("minimum_available_memory_bytes", U64, false),
            ("minimum_cpu_frequency_hz", U64, false),
            ("maximum_temperature_millidegrees_celsius", I64, false),
            ("forbidden_throttle_flags", StringArray, false),
            ("maximum_unrelated_process_count", U32, false),
            ("unrelated_process_set_policy", String, false),
            ("require_all_observations", Boolean, false),
        ]),
        "exactly_one_at_profiles/validity-thresholds.json",
        "maximum_total_monitor_and_unrelated_CPU_percent_are_finite_in_inclusive_observation_bounds_and_monitor_and_unrelated_are_each_at_most_total_minimum_available_memory_bytes_is_0_to_bound_hardware_total_memory_where_0_disables_the_cutoff_minimum_cpu_frequency_hz_is_0_or_within_observation_bounds_frequency_range_where_0_disables_the_cutoff_maximum_temperature_millidegrees_celsius_is_0_through_observation_bounds_maximum_temperature_forbidden_throttle_flags_are_sorted_unique_values_from_the_protocol_throttle_flag_literals_and_must_not_include_none_maximum_unrelated_process_count_is_0_through_observation_bounds_maximum_unrelated_process_count_unrelated_process_set_policy_is_exact_baseline_match_v1_and_require_all_observations_is_true",
    )
}

fn unrelated_process_set_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ProcessIdentityArray, String, U32};
    record_protocol(
        "marty.performance/sd-jwt-issuance-unrelated-process-set/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("boot_identity_pseudonym", String, false),
            ("identity_scheme", String, false),
            ("entry_count", U32, false),
            ("opaque_process_instances", ProcessIdentityArray, false),
        ]),
        "exactly_one_baseline_and_one_content_addressed_document_for_each_distinct_sampled_set",
        "identity_scheme_is_hmac_sha256_campaign_ephemeral_process_set_v1_entry_count_equals_array_length_and_is_at_most_4096_each_process_instance_pseudonym_is_exactly_64_ASCII_uppercase_hex_characters_entries_are_sorted_unique_and_match_the_baseline_under_exact_baseline_match_v1_controller_samples_one_independent_32_byte_CSPRNG_process_set_key_that_is_never_reused_as_any_target_or_other_key_and_derives_each_pseudonym_as_HMAC-SHA256_over_ASCII_marty.unrelated-process-instance.v1_then_0x00_then_u64_big_endian_total_tuple_byte_length_then_raw_tuple_bytes_where_the_tuple_is_u64be_operating_system_family_UTF8_byte_length_then_exact_operating_system_family_UTF8_then_u64be_PID_then_u64be_process_start_unix_nanoseconds_then_32_raw_SHA256_bytes_of_the_executable_file_controller_never_retains_the_key_tuple_PID_start_time_image_name_executable_path_or_digest_argv_environment_account_or_container_endpoint",
    )
}

fn test_window_attestation_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{Boolean, String};
    record_protocol(
        "marty.performance/sd-jwt-issuance-test-window/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("target_role", String, false),
            ("target_identity_pseudonym", String, false),
            ("starts_at_rfc3339_nanoseconds", String, false),
            ("expires_at_rfc3339_nanoseconds", String, false),
            ("change_reference_pseudonym", String, false),
            ("production_traffic_drained", Boolean, false),
            ("public_ingress_disabled", Boolean, false),
            ("synthetic_data_only", Boolean, false),
        ]),
        "exactly_one_first_quiet_window_role_and_between_1_and_16_disjoint_actual_timing_window_roles",
        "target_role_is_one_of_the_protocol_literal_array_controller_samples_one_independent_32_byte_CSPRNG_target_key_never_reused_as_the_process_set_key_or_any_other_key_target_identity_pseudonym_is_exactly_64_ASCII_uppercase_hex_characters_of_HMAC-SHA256_over_ASCII_marty.test-window-target.v1_then_0x00_then_u64_big_endian_length_then_normalized_origin_UTF8_normalized_origin_is_the_RFC6454_ASCII_serialization_of_an_absolute_HTTPS_origin_with_lowercase_scheme_and_IDNA2008_A-label_host_RFC5952_bracketed_IPv6_default_port_443_removed_nondefault_port_in_unpadded_decimal_and_no_userinfo_path_beyond_slash_query_or_fragment_all_actual_attestations_match_the_same_target_pseudonym_and_conditions_times_use_the_plan_UTC_format_duration_is_positive_and_at_most_43200_seconds_change_reference_pseudonym_is_an_independently_sampled_32_byte_CSPRNG_value_encoded_as_exactly_64_ASCII_uppercase_hex_characters_unique_to_the_campaign_and_distinct_from_every_other_pseudonym_nonce_or_HMAC_output_all_three_condition_booleans_are_true_raw_target_origin_change_ticket_operator_identity_and_authorization_material_remain_outside_exportable_campaign_evidence_and_the_trusted_controller_is_the_only_authority_linking_those_raw_values_to_their_pseudonyms",
    )
}

fn fixed_binary_build_input_inventory_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactInventoryEntryArray, String, StringArray, U32, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("target_triple", String, false),
            ("entry_count", U32, false),
            ("total_byte_length", U64, false),
            ("archive_fingerprint", ArtifactFingerprint, false),
            ("executable_path_directories", StringArray, false),
            ("entries", ArtifactInventoryEntryArray, false),
        ]),
        "exactly_one_at_build/input-inventory.json_created_before_the_build_receipt",
        "entry_count_equals_entries_length_and_is_1_through_maximum_fixed_binary_build_input_entries_checked_sum_of_entry_fingerprint_byte_lengths_equals_total_byte_length_archive_fingerprint_byte_length_equals_checked_magic_length_plus_8_times_entry_count_plus_total_byte_length_and_is_at_most_maximum_build_input_bytes_every_role_path_mode_and_cardinality_matches_the_closed_rules_executable_path_directories_reconstructs_PATH_exactly_entries_are_strictly_sorted_unique_by_role_then_unsigned_ASCII_relative_path_and_completely_inventory_every_file_in_the_staged_read_only_Cargo_home_dependency_sources_and_configuration_fingerprinted_Cargo_and_rustc_distribution_target_linker_archiver_dynamic_tool_dependencies_Windows_runtime_tree_and_every_executable_PATH_directory_each_entry_fingerprint_matches_the_corresponding_retained_archive_member_bytes_no_unknown_role_alias_absolute_parent_backslash_case-fold_collision_link_device_reparse_uninventoried_config_or_extra_readable_build_input_is_permitted",
    )
}

fn fixed_binary_build_receipt_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, Boolean, NameValueArray, String, StringArray, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-fixed-binary-build/v2",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("cargo_binary_fingerprint", ArtifactFingerprint, false),
            ("cargo_verbose_version", String, false),
            ("rustc_binary_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("rustc_reported_sysroot", String, false),
            ("build_input_inventory_fingerprint", ArtifactFingerprint, false),
            ("build_input_archive_fingerprint", ArtifactFingerprint, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("materialized_build_root", String, false),
            ("working_directory", String, false),
            ("logical_argv", StringArray, false),
            ("enabled_features", StringArray, false),
            ("build_environment_policy", String, false),
            ("build_environment", NameValueArray, false),
            ("offline_dependency_resolution_argv", StringArray, false),
            ("offline_dependency_resolution_succeeded", Boolean, false),
            ("build_started_monotonic_nanoseconds", U64, false),
            ("build_finished_monotonic_nanoseconds", U64, false),
            ("produced_binary_fingerprint", ArtifactFingerprint, false),
            ("installed_fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_at_build/fixed-benchmark.json_created_after_first_quiet_window_and_before_genesis",
        "all_source_toolchain_target_controller_build_input_inventory_and_build_input_archive_values_are_transitively_bound_by_genesis_and_fixed_role_preimages_and_the_inventory_archive_fingerprints_equal_each_other_target_triple_has_ASCII_length_1_through_128_and_every_byte_is_alphanumeric_hyphen_underscore_or_dot_build_profile_equals_bench_materialized_build_root_equals_the_exact_platform_canonical_root_working_directory_equals_ROOT/worktree_enabled_features_equals_exact_single_item_issuance_bench_cargo_and_rustc_verbose_versions_are_exact_command_stdout_valid_UTF8_at_most_4096_bytes_with_only_printable_ASCII_and_LF_and_no_endpoint_credential_or_diagnostic_suffix_rustc_reported_sysroot_equals_ROOT/inputs/toolchain_from_executing_the_inventoried_rustc_--print_sysroot_under_the_exact_cleared_build_environment_build_environment_policy_equals_trusted_controller_inventoried_inputs_cleared_offline_sandbox_v1_and_build_environment_equals_the_exact_platform_mapping_including_the_concrete_derived_target_linker_name_and_exact_SystemRoot_WINDIR_PATH_and_SOURCE_DATE_EPOCH_values_logical_argv_is_exactly_cargo_build_--frozen_--offline_--profile_bench_--no-default-features_--features_issuance_bench_--bench_sd_jwt_issuance_--target_target_triple_--message-format_json-render-diagnostics_with_the_record_target_triple_substituted_at_that_position_offline_dependency_resolution_argv_is_exactly_cargo_metadata_--frozen_--offline_--locked_--format-version_1_and_succeeded_is_true_for_a_real_prebuild_probe_under_the_same_materialized_tree_cleared_environment_and_read_sandbox_controller_mounts_one_private_create-new_campaign_directory_at_the_exact_canonical_root_securely_materializes_only_the_verified_source_archive_under_ROOT/worktree_and_the_verified_build_input_archive_under_ROOT/inputs_preserving_the_Rust_distribution_toolchain/bin_and_toolchain/lib_layout_clears_environment_then_adds_only_the_closed_table_disables_network_and_incremental_compilation_forces_the_fingerprinted_rustc_target_linker_archiver_sysroot_dependency_sources_Cargo_configuration_dynamic_tool_and_staged_Windows_runtime_inputs_rejects_RUSTC_WRAPPER_RUSTC_WORKSPACE_WRAPPER_RUSTFLAGS_CARGO_ENCODED_RUSTFLAGS_or_any_unlisted_variable_and_sandboxes_reads_to_worktree_and_inventoried_inputs_and_writes_to_ROOT/target_and_ROOT/tmp_all_Cargo_generated_absolute_environment_values_including_CARGO_MANIFEST_DIR_and_OUT_DIR_are_deterministically_derived_from_ROOT_source_target_profile_and_package_metadata_and_any_other_observed_generated_value_rejects_controller_runs_only_the_probes_and_build_command_accepts_exactly_one_Cargo_compiler-artifact_executable_for_bench_sd_jwt_issuance_hashes_it_before_installation_copies_it_create_new_to_the_target-selected_fixed_binary_path_and_requires_produced_installed_and_genesis_fixed_binary_fingerprints_equal_build_started_is_after_the_first_quiet_window_end_build_finished_equals_or_follows_start_and_precedes_genesis_monotonic_checked_subtraction_and_all_archive_member_tool_dependency_configuration_environment_path_source_and_binary_fingerprints_bind_actual_bytes",
    )
}

fn fixed_build_input_inventory_entry_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String};
    evidence_fields([
        ("role", String, false),
        ("relative_path", String, false),
        ("file_mode", String, false),
        ("fingerprint", ArtifactFingerprint, false),
    ])
}

fn fixed_build_input_mode_literals() -> Vec<String> {
    ["100644", "100755"].map(str::to_owned).to_vec()
}

fn test_window_target_role_literals() -> Vec<String> {
    [
        "isolated_production_gateway",
        "dedicated_performance_gateway",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn fixed_build_input_role_literals() -> Vec<String> {
    [
        "cargo_configuration",
        "cargo_dependency_source",
        "cargo_executable",
        "executable_path_input",
        "rustc_executable",
        "rustc_sysroot_file",
        "target_archiver_executable",
        "target_linker_executable",
        "tool_dynamic_dependency",
        "windows_runtime_input",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn fixed_build_environment_entry_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::String;
    evidence_fields([
        ("name", String, false),
        ("value_kind", String, false),
        ("resolved_value", String, false),
    ])
}

fn fixed_build_environment_allowlist() -> Vec<String> {
    [
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_<TARGET_TRIPLE_ENV>_LINKER",
        "PATH",
        "RUSTC",
        "SOURCE_DATE_EPOCH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "WINDIR",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn observation_bounds() -> SdJwtIssuanceObservationBounds {
    SdJwtIssuanceObservationBounds {
        minimum_cpu_percent: 0.0,
        maximum_cpu_percent: 100.0,
        minimum_cpu_frequency_hz: 1,
        maximum_cpu_frequency_hz: 10_000_000_000,
        minimum_temperature_millidegrees_celsius: -100_000,
        maximum_temperature_millidegrees_celsius: 200_000,
        maximum_total_memory_bytes: 1_152_921_504_606_846_976,
        maximum_logical_cpu_count: 65_536,
        maximum_unrelated_process_count: 4_096,
    }
}

fn global_preimage_protocol() -> SdJwtIssuanceGlobalPreimageProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, SourceArchiveEntryArray, String, U32,
    };

    SdJwtIssuanceGlobalPreimageProtocol {
        artifact_format: "each_typed_preimage_is_create_new_utf8_canonical_pretty_JSON_plus_one_LF_flushed_and_durably_synced_before_its_first_fingerprint_reference_unknown_duplicate_missing_wrong_type_nonfinite_out_of_range_or_trailing_data_rejects".to_owned(),
        resolution_rule: "plan_manifest_and_Cargo_lock_resolve_inputs/qualification-plan.json_inputs/qualification-manifest.json_and_inputs/Cargo.lock_target_triple_selects_exactly_one_fixed-benchmark_fixed-benchmark.exe_controller_controller.exe_monitor_or_monitor.exe_under_bin_controller_monitor_and_external_anchor_channel_configurations_resolve_configuration/controller.json_configuration/monitor.json_and_configuration/external-anchor-channel.json_source_archive_resolves_source/exact-tree.sar_fixed_binary_build_receipt_complete_build_input_inventory_and_retained_build_input_archive_resolve_build/fixed-benchmark.json_build/input-inventory.json_and_build/input-files.bia_host_hardware_threshold_and_baseline_process_set_resolve_profiles/host-identity.json_profiles/hardware.json_profiles/validity-thresholds.json_and_profiles/baseline-unrelated-process-set.json_first_quiet_window_attestation_resolves_attestations/first-quiet-window.json_actual_timing_window_attestations_resolve_disjoint_attestations/timing-window-0000.json_through_timing-window-0015.json_and_each_observed_process_set_resolves_observations/unrelated-process-sets/UPPERCASE_SHA256.json_all_paths_are_fixed_roles_or_valid_ordinals_and_reject_absolute_parent_backslash_empty_link_hardlink_reparse_missing_duplicate_or_extra_resolution_trust_root_fingerprint_is_the_only_nonfile_reference_and_resolves_exclusively_against_the_analyzer_out_of_band_trust_store".to_owned(),
        controller_configuration: controller_configuration_protocol(),
        monitor_configuration: monitor_configuration_protocol(),
        host_identity: host_identity_protocol(),
        hardware_profile: hardware_profile_protocol(),
        observation_bounds: observation_bounds(),
        operating_system_family_literals: ["windows", "linux", "macos"]
            .map(str::to_owned)
            .to_vec(),
        architecture_literals: ["x86_64", "aarch64"]
            .map(str::to_owned)
            .to_vec(),
        virtualization_kind_literals: [
            "bare_metal",
            "virtual_machine",
            "containerized_host",
            "unknown",
        ]
        .map(str::to_owned)
        .to_vec(),
        power_policy_literals: [
            "performance",
            "balanced",
            "platform_default",
            "custom_locked",
        ]
        .map(str::to_owned)
        .to_vec(),
        throttle_flag_literals: [
            "none",
            "thermal",
            "power_limit",
            "frequency_cap",
            "platform_reported_unknown",
        ]
        .map(str::to_owned)
        .to_vec(),
        validity_thresholds: validity_thresholds_protocol(),
        unrelated_process_set: unrelated_process_set_protocol(),
        process_identity_fields: evidence_fields([(
            "process_instance_pseudonym",
            String,
            false,
        )]),
        test_window_attestation: test_window_attestation_protocol(),
        test_window_target_role_literals: test_window_target_role_literals(),
        fixed_binary_build_receipt: fixed_binary_build_receipt_protocol(),
        fixed_binary_build_input_inventory: fixed_binary_build_input_inventory_protocol(),
        fixed_binary_build_input_inventory_entry_fields:
            fixed_build_input_inventory_entry_fields(),
        fixed_binary_build_input_role_literals: fixed_build_input_role_literals(),
        fixed_binary_build_input_role_rule: "cargo_executable_and_rustc_executable_each_have_exactly_one_entry_at_toolchain/bin/cargo_or_cargo.exe_and_toolchain/bin/rustc_or_rustc.exe_rustc_sysroot_file_has_at_least_one_entry_under_toolchain_and_completes_the_same_distribution_whose_inventoried_rustc_reports_ROOT/inputs/toolchain_target_linker_executable_and_target_archiver_executable_each_have_exactly_one_entry_under_tools/linker_and_tools/archiver_cargo_dependency_source_has_at_least_one_entry_under_cargo-home/registry/src_or_cargo-home/git/checkouts_cargo_configuration_has_exactly_one_entry_at_cargo-home/config.toml_executable_path_input_is_zero_or_more_under_one_declared_executable_path_directory_tool_dynamic_dependency_is_zero_or_more_beside_its_consuming_inventoried_tool_or_under_tools/runtime_windows_runtime_input_is_absent_on_non-Windows_and_at_least_one_under_windows-runtime/SystemRoot_on_Windows_every_file_read_by_the_build_has_exactly_one_entry_and_no_role_alias_cross-root_or_uninventoried_input_is_valid".to_owned(),
        fixed_binary_build_input_path_rule: "entry_relative_paths_use_the_same_portable_ASCII_segment_grammar_bounds_and_exact_.git_component_prohibition_as_source_archive_paths_are_strictly_sorted_unique_by_role_then_unsigned_path_bytes_and_are_relative_to_the_canonical_materialized_build_ROOT/inputs_directory_executable_path_directories_is_the_exact_ordered_unique_array_toolchain/bin_tools/linker_tools/archiver_tools/runtime_each_directory_contains_an_inventoried_executable_PATH_is_reconstructed_by_joining_ROOT/inputs_to_these_entries_in_exact_array_order_CARGO_HOME_resolves_the_same_ROOT/inputs/cargo-home_tree_and_RUSTC_resolves_the_same_ROOT/inputs/toolchain/bin_member_whose_reported_sysroot_is_ROOT/inputs/toolchain_on_Windows_SystemRoot_and_WINDIR_resolve_the_same_staged_ROOT/inputs/windows-runtime/SystemRoot_tree_no_member_is_materialized_twice_and_unknown_absolute_parent_backslash_drive_ADS_device_case-fold_file-directory-prefix_or_target-filesystem_alias_paths_reject".to_owned(),
        fixed_binary_build_input_mode_literals: fixed_build_input_mode_literals(),
        fixed_binary_build_input_archive_format: "one_exact_build/input-files.bia_binary_stream_beginning_with_exact_ASCII_bytes_MARTY-SD-JWT-BUILD-INPUT-ARCHIVE-V1_plus_LF_then_for_each_build/input-inventory.json_entry_in_its_exact_canonical_order_one_unsigned_64_bit_big_endian_content_length_and_exact_file_bytes_then_immediate_EOF_no_paths_modes_alignment_padding_unused_metadata_or_trailing_byte_the_separate_inventory_is_the_only_manifest".to_owned(),
        fixed_binary_build_input_archive_rule: "controller_and_analyzer_open_the_archive_create-new_or_no-follow_read-only_verify_its_outer_SHA256_and_length_against_both_inventory.archive_fingerprint_and_build_receipt.build_input_archive_fingerprint_before_parsing_then_stream_a_second_pass_over_the_same_immutable_handle_without_buffering_the_archive_or_allocating_from_unverified_lengths_complete_archive_length_including_magic_and_framing_is_at_most_maximum_build_input_bytes_entry_count_is_at_most_maximum_fixed_binary_build_input_entries_every_length_equals_the_corresponding_inventory_fingerprint.byte_length_checked_member_SHA256_matches_that_fingerprint_checked_member_sum_equals_inventory.total_byte_length_file_mode_is_exactly_100644_or_100755_and_executed_tools_are_100755_members_and_inventory_are_one-to-one_in_identical_order_and_missing_extra_reordered_duplicate_link_device_or_trailing_members_reject_secure_materialization_preserves_portable_logical_mode_as_read-only_data_or_read-only_executable_without_host_ACL_metadata_and_all_build_reads_are_confined_to_the_verified_materialization".to_owned(),
        maximum_fixed_binary_build_input_entries: MAX_FIXED_BUILD_INPUT_ENTRIES,
        fixed_binary_build_environment_entry_fields: fixed_build_environment_entry_fields(),
        fixed_binary_build_environment_allowlist: fixed_build_environment_allowlist(),
        fixed_binary_build_environment_mapping_rule: "entries_are_in_allowlist_order_with_exact_name_value_kind_and_nonnull_resolved_value_CARGO_HOME_canonical_absolute_path_ROOT/inputs/cargo-home_CARGO_INCREMENTAL_literal_0_CARGO_NET_OFFLINE_literal_true_CARGO_TARGET_DIR_canonical_absolute_path_ROOT/target_the_wire_name_for_the_target_linker_is_the_concrete_CARGO_TARGET_plus_underscore_plus_target_triple_ASCII_uppercase_with_each_hyphen_underscore_or_dot_replaced_by_underscore_plus_underscore_LINKER_any_other_target_byte_and_any_template_brace_rejects_and_its_value_is_the_unique_inventoried_absolute_target_linker_member_below_ROOT/inputs/tools/linker_PATH_ordered_absolute_path_list_is_ROOT/inputs_joined_to_executable_path_directories_in_exact_inventory_order_RUSTC_inventoried_absolute_path_ROOT/inputs/toolchain/bin/RUSTC_FILE_SOURCE_DATE_EPOCH_literal_exact_canonical_unsigned_decimal_sole_validated_commit_committer_Unix_timestamp_TEMP_and_TMP_canonical_absolute_path_ROOT/tmp_and_on_Windows_only_SystemRoot_and_WINDIR_are_both_canonical_absolute_path_ROOT/inputs/windows-runtime/SystemRoot_non-Windows_has_exactly_10_entries_and_Windows_has_exactly_12_each_name_appears_once_ROOT_equals_the_exact_platform_fixed_binary_build_root_no_other_name_kind_value_duplicate_case-fold_alias_wrapper_flag_config_ambient_live_SystemRoot_or_unrecorded_resolved_path_is_valid".to_owned(),
        fixed_binary_build_root_windows: FIXED_BUILD_ROOT_WINDOWS.to_owned(),
        fixed_binary_build_root_non_windows: FIXED_BUILD_ROOT_NON_WINDOWS.to_owned(),
        fixed_binary_build_rule: "trusted_controller_receipt_complete_build_input_inventory_and_retained_build_input_archive_are_part_of_the_anchored_genesis_chain_and_are_the_only_v2_link_from_verified_source_archive_Cargo_lock_exact_retained_dependency_sources_Cargo_configuration_Rust_distribution_sysroot_Cargo_rustc_linker_archiver_dynamic_tool_and_staged_Windows_runtime_bytes_exact_canonical_materialized_build_root_generated_Cargo_environment_values_real_offline_dependency_probe_build_command_working_directory_sandbox_and_typed_cleared_offline_environment_to_the_actual_installed_fixed_binary_analyzer_reconstructs_the_exact_retained_tree_from_verified_archive_members_repeats_rustc_--print_sysroot_and_exact_cargo_metadata_--frozen_--offline_--locked_--format-version_1_under_the_same_typed_cleared_environment_working_directory_and_read_sandbox_and_requires_success_the_exact_reported_sysroot_and_the_same_resolved_dependency_graph_before_accepting_the_receipt_stale_extra_ambient_relocated_substituted_unretained_or_differently_built_binary_invalidates_the_campaign".to_owned(),
        source_archive_manifest_schema:
            "marty.performance/sd-jwt-issuance-source-archive-manifest/v1".to_owned(),
        source_archive_manifest_fields: evidence_fields([
            ("schema", String, false),
            ("git_object_format", String, false),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("entry_count", U32, false),
            ("entries", SourceArchiveEntryArray, false),
        ]),
        source_archive_entry_fields: evidence_fields([
            ("repository_relative_path", String, false),
            ("git_mode", String, false),
            ("git_object_id", String, false),
            ("artifact_fingerprint", ArtifactFingerprint, false),
        ]),
        maximum_source_archive_bytes: MAX_SOURCE_ARCHIVE_V1_BYTES,
        maximum_source_archive_manifest_bytes: MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES,
        maximum_source_archive_commit_bytes: MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES,
        maximum_source_archive_entries: MAX_SOURCE_ARCHIVE_V1_ENTRIES,
        maximum_source_archive_path_bytes: MAX_SOURCE_ARCHIVE_PATH_V1_BYTES,
        maximum_source_archive_path_segment_bytes: MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES,
        maximum_source_archive_path_segments: MAX_SOURCE_ARCHIVE_PATH_SEGMENTS,
        maximum_source_archive_derived_directory_nodes:
            MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES,
        maximum_source_archive_derived_component_bytes:
            MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
        source_archive_format: "one_exact_source/exact-tree.sar_binary_stream_beginning_with_exact_ASCII_bytes_MARTY-SD-JWT-SOURCE-ARCHIVE-V1_plus_LF_then_unsigned_64_bit_big_endian_manifest_byte_length_including_its_terminal_LF_then_exact_canonical_pretty_JSON_plus_LF_manifest_bytes_then_unsigned_64_bit_big_endian_raw_commit_content_length_then_exact_raw_Git_commit_content_then_for_each_manifest_entry_in_order_one_unsigned_64_bit_big_endian_content_length_and_exact_regular_file_bytes_then_immediate_EOF_no_alignment_padding_unused_header_metadata_or_trailing_byte_analyzer_reads_at_most_hardcoded_16777216_plus_one_into_one_bounded_immutable_buffer_verifies_the_outer_archive_fingerprint_before_any_UTF8_or_JSON_parse_then_parses_that_same_buffer_every_u64_length_uses_checked_conversion_and_subtraction_and_must_fit_remaining_bytes_and_its_4194304_manifest_1048576_commit_or_remaining_archive_cap_before_allocation".to_owned(),
        source_archive_rule: "manifest_schema_and_fields_are_exact_git_object_format_equals_sha1_source_commit_and_source_tree_are_40_lowercase_hex_entry_count_equals_entries_length_and_is_1_through_65536_repository_relative_paths_use_the_portable_ASCII_grammar_bytes_A_to_Z_a_to_z_0_to_9_dot_underscore_at_plus_hyphen_preserved_byte-for-byte_1_through_1024_bytes_with_1_through_256_forward-slash-separated_segments_each_1_through_255_bytes_no_component_ASCII-case-folds_to_exact_.git_and_no_absolute_drive_ADS_empty_dot_dotdot_backslash_control_trailing_dot_or_Windows_reserved_device_segment_entries_are_strictly_ascending_by_unsigned_bytes_and_a_single_bounded_component_trie_rejects_file_or_directory_duplicates_ASCII_case-fold_aliases_at_every_component_and_file-directory_prefix_conflicts_derived_directory_node_count_is_at_most_131072_and_checked_sum_of_each_cloned_unique_directory_or_file_component_byte_length_is_at_most_4194304_secure_materialization_uses_create-new_directory-handle-relative_no-follow_opens_verifies_every_opened_handle_remains_beneath_the_empty_build_root_and_rejects_any_target-filesystem_lossy_round_trip_case_fold_normalization_or_other_alias_collision_git_mode_is_exactly_100644_or_100755_git_object_id_is_40_lowercase_hex_SHA1_and_matches_Git_blob_header_plus_the_corresponding_length-prefixed_file_bytes_each_SHA256_and_length_fingerprint_matches_those_file_bytes_archive_has_no_extra_duplicate_link_device_ref_reflog_config_remote_hook_credential_parent-commit_or_history-object_record_while_parent_identifiers_inside_the_retained_commit_are_allowed_analyzer_builds_the_bounded_parent-to-children_trie_in_one_path_pass_hashes_each_node_once_in_reverse_creation_order_using_canonical_Git_tree_entry_order_and_recomputes_every_intermediate_tree_and_root_source_tree_without_recursion_quadratic_prefix_scans_or_unbounded_derived_strings_parses_only_the_header_prefix_of_the_sole_raw_commit_bytewise_while_leaving_identity_encoding_headers_and_message_bytes_opaque_recomputes_the_complete_unchanged_raw_Git_object_ID_as_source_commit_requires_exactly_one_first_ASCII_tree_header_equal_source_tree_and_exactly_one_committer_header_whose_final_ASCII_tokens_are_a_nonnegative_no-leading-zero_u64_Unix_timestamp_and_valid_plus-or-minus_HHMM_offset_that_define_SOURCE_DATE_EPOCH_missing_duplicate_malformed_or_negative_committer_time_rejects_and_requires_inputs/Cargo.lock_bytes_equal_the_archive_entry_for_Cargo.lock_controller_configuration_source_export_approved_must_be_true".to_owned(),
        privacy_rule: "all_operational_typed_preimages_use_deny_unknown_fields_exact_literal_domains_and_bounded_string_grammars_and_retain_no_raw_or_unsalted_digest_of_hostname_machine_or_boot_ID_username_account_IP_MAC_serial_cloud_instance_ID_PID_process_start_time_image_name_executable_or_account_home_path_command_line_target_origin_endpoint_change_ticket_access_credential_secret_token_private_key_or_unbounded_or_untyped_free_form_diagnostic_text_campaign_ephemeral_identity_keys_and_raw_inputs_are_memory_only_and_destroyed_after_completion_the_fixed_nonpersonal_build_root_exact_staged_Windows_runtime_paths_bounded_typed_hardware_source_commit_toolchain_and_binary_fingerprints_anchor_channel_log_key_IDs_and_authenticated_timestamps_are_explicit_nonsecret_stable-metadata_exceptions_and_can_link_campaigns_the_retained_build_input_archive_is_a_separate_explicit_exception_limited_to_approved_public_dependency_Cargo_configuration_toolchain_linker_archiver_dynamic_runtime_and_staged_Windows_runtime_bytes_and_portable_nonpersonal_paths_and_must_contain_no_credential_private_source_secret_or_operational_capture_data_source_archive_bytes_are_another_explicit_exception_because_the_export_approved_exact_source_commit_can_intentionally_contain_repository_relative_paths_public_URLs_author_and_committer_metadata_and_timestamps_parent_identifiers_and_public_synthetic_test_key_material_but_no_extra_history_objects_or_operational_capture_data_child_output_after_ready_is_bounded_drained_and_discarded_and_only_counts_are_retained".to_owned(),
    }
}

fn run_validity_limits() -> SdJwtIssuanceRunValidityLimits {
    SdJwtIssuanceRunValidityLimits {
        maximum_plan_bytes: MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
        maximum_segment_seconds: 12 * 60 * 60,
        maximum_segment_bytes: 64 * 1024 * 1024,
        maximum_line_bytes: 64 * 1024,
        maximum_records_per_segment: 65_536,
        maximum_segment_count: 16,
        maximum_completion_manifest_bytes: 32 * 1024 * 1024,
        maximum_external_anchor_bytes: MAX_EXTERNAL_ANCHOR_V1_BYTES,
        maximum_auxiliary_preimage_bytes: MAX_SOURCE_ARCHIVE_V1_BYTES,
        maximum_route_artifact_bytes: 1024 * 1024,
        maximum_total_route_artifact_bytes: 128 * 1024 * 1024,
        maximum_criterion_home_bytes: 1024 * 1024,
        maximum_total_criterion_home_bytes: 512 * 1024 * 1024,
        maximum_build_input_bytes: MAX_FIXED_BUILD_INPUT_BYTES,
        maximum_launch_frame_bytes: 64 * 1024,
        maximum_spawn_to_ready_seconds: 30,
        maximum_process_output_bytes: 1024 * 1024,
        maximum_total_evidence_bytes: MAX_TOTAL_EVIDENCE_BYTES,
        maximum_total_records: 1_000_000,
        maximum_campaign_seconds: 7 * 24 * 60 * 60,
        maximum_timing_process_seconds: 5 * 60,
        maximum_anchor_publication_delay_seconds: 5 * 60,
        maximum_test_window_attestations: 16,
        exact_global_rounds: 20,
        exact_cells_per_round: 66,
        exact_expansion_positions_per_cell: 8,
        exact_timing_processes: 10_560,
        validation_rule: "before_UTF8_or_JSON_analyzer_opens_fixed_inputs/qualification-plan.json_without_following_links_reads_at_most_compiled_MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES_1048576_plus_one_rejects_larger_then_parses_exact_deny-unknown_V3_and_requires_canonical_pretty_JSON_plus_LF_before_using_any_plan-declared_limit_manifest_uses_its_independent_compiled_4194304_cap_stream_other_files_without_unbounded_buffering_check_each_declared_and_actual_size_before_allocation_or_hashing_the_build_input_archive_is_opened_without_following_links_outer-hashed_under_the_compiled_2147483648_byte_cap_then_rewound_on_the_same_immutable_handle_and_stream-framed_against_the_bound_inventory_without_member-sized_allocation_maximum_auxiliary_preimage_bytes_is_only_the_fallback_for_controller_monitor_anchor-channel_host-hardware-threshold-test-window-process-set-invocation-barrier-and-inventory_JSON_without_another_dedicated_cap_and_never_overrides_the_dedicated_segment_completion_anchor_route_Criterion_source-archive_or_build-input-archive_cap_each_dedicated_cap_has_precedence_route_Criterion_build-input-archive_segment_and_all_other_subtotals_are_part_of_total_evidence_bytes_and_reject_when_any_individual_subtotal_or_aggregate_limit_would_be_exceeded".to_owned(),
    }
}

fn run_validity_protocol() -> SdJwtIssuanceRunValidityProtocol {
    SdJwtIssuanceRunValidityProtocol {
        schema: "marty.performance/sd-jwt-issuance-run-validity/v1".to_owned(),
        artifact_format: "create_new_utf8_ndjson_segments_one_compact_json_record_per_lf_line_keys_in_protocol_order_no_bom_no_cr_record_fingerprints_cover_exact_line_including_lf_each_segment_flushed_and_durably_synced_before_successor".to_owned(),
        canonicalization_rule: "for_Marty_owned_typed_JSON_only_deserialize_with_Cargo_lock_serde_json_1.0.151_into_exact_versioned_deny_unknown_struct_reject_duplicate_missing_unknown_wrong_type_nonfinite_and_trailing_data_then_require_byte_equality_with_serde_json_to_vec_for_segment_NDJSON_or_to_vec_pretty_two_space_indent_for_pretty_artifacts_plus_one_LF_nested_artifact_fingerprint_key_order_sha256_then_byte_length_route_bytes_follow_route_artifact_rule_Criterion_Cargo_lock_binary_source_archive_members_and_fixed_build_input_archive_members_are_opaque_and_only_stream_hashed_while_the_source_archive_manifest_and_fixed_build_input_inventory_are_typed".to_owned(),
        utc_format_rule: "exactly_30_ascii_bytes_yyyy-mm-ddThh:mm:ss.nnnnnnnnnZ_valid_utc_calendar_time_uppercase_T_and_Z_exactly_9_fractional_digits_no_offset_or_leap_second".to_owned(),
        monotonic_clock_rule: "one_nonrestarting_controller_process_creates_one_std_time_Instant_origin_before_campaign_genesis_and_authoritatively_observes_and_stamps_every_segment_first_window_monitor_child_and_completion_event_as_checked_u64_elapsed_nanoseconds_from_that_origin_monitor_and_child_never_supply_comparable_monotonic_values_controller_restart_origin_loss_overflow_or_detected_suspend_or_UTC_vs_monotonic_discontinuity_invalidates_campaign".to_owned(),
        artifact_inventory_rule: "create_new_campaign_root_has_fixed_role_inputs_bin_build_configuration_source_profiles_observations_tmp_segments_attestations_invocations_criterion_barriers_barrier-ready_barrier-releases_barrier-receipts_inventories_routes_indexes_and_anchors_directories_plus_first-quiet-window.json_and_completion.json_build_receipt_inventory_and_retained_input_archive_are_build/fixed-benchmark.json_build/input-inventory.json_and_build/input-files.bia_signed_anchor_receipts_and_wrapper_are_anchors/terminal-observation-receipt.json_anchors/terminal-observation-evidence.json_and_anchors/completion-anchor.json_process_paths_are_r00..19_c00..65_e0..7_with_token_ready_release_receipt_invocation_initial_and_final_inventory_unique_per_coordinate_route_suffix_ndjson_and_temp_directory_exactly_tmp/rNN_cNN_eN_segments_are_segment-0000..0015.ndjson_first_window_attestation_is_attestations/first-quiet-window.json_and_the_disjoint_actual_chain_is_attestations/timing-window-0000.json_through_timing-window-0015.json_indexes_are_criterion-artifacts.json_and_route-artifacts.json_all_paths_computed_only_from_fixed_roles_or_valid_ordinals_ordered_arrays_map_by_ordinal_and_validator_rejects_missing_extra_duplicate_absolute_parent_backslash_symlink_hardlink_or_reparse_escape_in_governed_paths".to_owned(),
        global_preimages: global_preimage_protocol(),
        threat_model: "trusted_nonrestarting_controller_and_create_new_filesystem_during_capture_controller_is_the_authority_that_checks_raw_operator_test_window_authorization_raw_target_origin_and_change_reference_then_exports_only_independent_domain-separated_pseudonyms_later_offline_analysis_proves_alias_continuity_but_intentionally_cannot_independently_recover_or_reauthenticate_those_raw_mappings_unkeyed_local_sha256_is_tamper_evidence_not_authenticity_terminal_and_completion_heads_are_authenticated_by_two_retained_strict_Ed25519_create-only-log_receipts_verified_offline_against_the_bound_out-of-band_public_key".to_owned(),
        coverage: "monitor_first_sample_at_or_before_second_quiet_window_start_through_after_last_criterion_and_route_artifact_sync".to_owned(),
        pre_timing_quiet_seconds: 2_700,
        sample_interval_seconds: 5,
        maximum_sample_gap_seconds: 10,
        limits: run_validity_limits(),
        segment_chain_rule: "exactly_one_genesis_segment_ordinal_0_without_predecessor_each_continuation_ordinal_equals_prior_plus_1_and_binds_entire_prior_segment_uppercase_sha256_and_byte_length_and_0_less_than_next_first_monotonic_minus_prior_last_monotonic_less_than_or_equal_10000000000_nanoseconds".to_owned(),
        record_ordinal_rule: "within_each_segment_header_is_record_0_every_following_record_ordinal_equals_prior_plus_1_and_footer_is_unique_last_record_without_gap_or_duplicate".to_owned(),
        event_ordinal_rule: "zero_based_contiguous_across_process_intent_process_start_process_finish_and_attestation_transition_records_in_physical_campaign_order".to_owned(),
        segment_close_reason_literals: [
            "next_event_would_exceed_duration_limit",
            "next_record_would_exceed_byte_limit",
            "next_record_would_exceed_record_limit",
            "campaign_complete",
        ]
        .map(str::to_owned)
        .to_vec(),
        segment_close_reason_rule: "before_each_non-footer_record_controller_canonically_encodes_the_candidate_and_checked-tests_it_plus_the_required_footer_against_duration_byte_and_record_limits_using_precedence_duration_then_bytes_then_records_if_a_limit_would_be_exceeded_controller_writes_no_candidate_and_closes_with_the_corresponding_exact_literal_campaign_complete_is_valid_only_after_all_10560_finishes_final_monitor_sample_and_required_attestation_transition_state_and_only_on_the_unique_terminal_segment_no_other_reason_or_early_close_is_valid".to_owned(),
        process_schedule_rule: "exactly_20_by_66_by_8_coordinates_in_zero_based_global_round_then_manifest_cell_then_expansion_order_each_has_create_new_synced_static_token_with_exact_unique_nonreused_64-uppercase-hex_nonce_and_process_identity_pseudonym_descriptor_and_empty_home_then_durably_synced_PID_free_intent_then_spawned_child_ready_and_blocked_before_any_Criterion_construction_controller_checks_raw_PID_only_in_memory_then_durably_synced_ready_artifact_and_pseudonymous_start_then_create_new_synced_release_artifact_and_exact_stdin_release_then_synced_receipt_Criterion_and_route_artifacts_and_one_matching_successful_finish_before_any_other_intent_no_overlap_skip_duplicate_retry_or_resume".to_owned(),
        attestation_chain_rule: "attestation_intervals_are_start_inclusive_and_expiry_exclusive_first_quiet_attestation_contains_the_entire_first_quiet_interval_initial_actual_attestation_starts_at_or_before_the_second_quiet_window_start_and_every_genesis_or_continuation_header_sample_process_intent_start_release_finish_artifact_sync_terminal_footer_and_terminal_observation_request_time_is_strictly_before_the_expiry_of_the_exact_referenced_active_attestation_genesis_binds_only_current_actual_attestation_each_renewal_is_create_new_after_shutdown_recheck_and_recorded_before_prior_expiry_with_predecessor_fingerprint_same_target_conditions_next_start_at_or_before_prior_expiry_so_no_one_nanosecond_gap_each_duration_is_positive_and_at_most_43200_seconds_expired_future_unreferenced_or_uncovered_attestation_rejects_completion_binds_ordered_actual_chain".to_owned(),
        first_quiet_window: first_quiet_window_protocol(),
        invocation_descriptor: invocation_descriptor_protocol(),
        launch_barrier: launch_barrier_protocol(),
        criterion_home: criterion_home_protocol(),
        route_artifact: route_artifact_protocol(),
        artifact_indexes: artifact_index_protocol(),
        records: record_protocols(),
        completion: completion_protocol(),
        invalidating_events: [
            "monitor_started_after_second_quiet_window_start_or_clean_pre_timing_coverage_under_2700_seconds",
            "monitor_restart_or_state_loss",
            "sample_gap_exceeds_maximum",
            "campaign_id_host_identity_or_boot_identity_change",
            "reboot_suspend_resume_or_monotonic_discontinuity",
            "hardware_toolchain_binary_controller_monitor_or_configuration_change",
            "first_quiet_window_missing_invalid_mismatched_or_under_2700_seconds",
            "invocation_descriptor_missing_noncanonical_unresolvable_or_not_allowlisted",
            "criterion_home_not_unique_create_new_empty_or_fresh_for_exact_process",
            "launch_token_ready_release_or_receipt_missing_reused_noncanonical_unsynced_oversize_out_of_order_or_mismatched",
            "launch_spawn_to_ready_timeout_pipe_ownership_EOF_broken_pipe_early_exit_or_output_bound_failure",
            "timing_process_overlap_chronology_coordinate_invocation_or_environment_mismatch",
            "timing_process_nonzero_exit_abnormal_termination_or_timeout",
            "criterion_home_or_selected_route_artifact_write_flush_sync_shape_size_or_coordinate_mismatch",
            "global_fingerprint_preimage_or_artifact_index_missing_invalid_or_mismatched",
            "validity_evidence_write_flush_or_sync_failure",
            "unexpected_process_set_or_predeclared_load_bound_exceeded",
            "operating_system_reported_thermal_or_power_throttle",
            "predeclared_temperature_frequency_or_memory_bound_exceeded",
            "test_window_attestation_missing_gap_condition_change_or_invalid_renewal",
            "record_missing_duplicate_out_of_order_unknown_or_noncanonical",
            "resource_cardinality_or_duration_bound_exceeded",
            "required_observation_unavailable_or_nonfinite",
            "completion_manifest_missing_invalid_unsynced_or_not_externally_anchored",
        ]
        .map(str::to_owned)
        .to_vec(),
        invalidation_rule: "any_event_gap_write_failure_or_missing_terminal_commitment_invalidates_entire_campaign_no_round_deletion_resume_or_partial_analysis".to_owned(),
    }
}

fn global_round_protocol() -> Result<SdJwtIssuanceGlobalRoundProtocol> {
    let cells_per_round =
        u32::try_from(PAIRED_CELL_COUNT).context("global-round cell count overflow")?;
    let processes_per_round = cells_per_round
        .checked_mul(PROCESSES_PER_SUPERBLOCK)
        .context("global-round process count overflow")?;
    Ok(SdJwtIssuanceGlobalRoundProtocol {
        execution_nesting: "global_round_then_manifest_cell_then_expansion_position".to_owned(),
        ordinal_alignment: "shared_campaign_cluster_across_all_cells".to_owned(),
        cells_per_round,
        processes_per_round,
        concurrent_timing_processes: 1,
        run_validity: run_validity_protocol(),
    })
}

fn bootstrap_protocol(draws_per_replicate: u32) -> SdJwtIssuanceBootstrapProtocol {
    SdJwtIssuanceBootstrapProtocol {
        replicates: 100_000,
        confidence_level: 0.95,
        rng: "splitmix64".to_owned(),
        seed: 2_453_812_215,
        seed_is_initial_state: true,
        rng_state_transition: "state=wrapping_add(state,0x9E3779B97F4A7C15);z=wrapping_mul(state^(state>>30),0xBF58476D1CE4E5B9);z=wrapping_mul(z^(z>>27),0x94D049BB133111EB);output=z^(z>>31)".to_owned(),
        draws_per_replicate,
        sampling_method: "with_replacement".to_owned(),
        uniform_index_rule: "accept_x_below_18446744073709551600_then_x_mod_20".to_owned(),
        stream_scope: "single_continuous_stream_across_all_replicates".to_owned(),
        consumption_order: "replicate_major_then_accepted_draw_major".to_owned(),
        rejected_output_rule: "rejected_output_consumes_state_and_retries_current_draw".to_owned(),
        quantile_method: "type_7".to_owned(),
        resampling_unit: "whole_global_round".to_owned(),
        common_index_scope: "all_paired_cells_and_effects_d_s_p_o".to_owned(),
        simultaneous_band: "type_7_q_0.95_of_replicate_max_abs_bootstrap_minus_observed_over_66_cells_d_s_p".to_owned(),
        primary_interval_rule: "observed_effect_plus_or_minus_common_critical_value".to_owned(),
        diagnostic_o_interval_rule:
            "type_7_marginal_q_0.025_and_q_0.975_of_bootstrap_o".to_owned(),
    }
}

fn criterion_protocol() -> SdJwtIssuanceCriterionProtocol {
    SdJwtIssuanceCriterionProtocol {
        logical_argv: [
            "--bench",
            "--exact",
            "{full_benchmark_id}",
            "--sample-size",
            "50",
            "--nresamples",
            "100000",
            "--warm-up-time",
            "15",
            "--measurement-time",
            "10",
            "--confidence-level",
            "0.95",
            "--save-baseline",
            "base",
            "--noplot",
        ]
        .map(str::to_owned)
        .to_vec(),
        sample_size: 50,
        nresamples: 100_000,
        warm_up_seconds: 15,
        measurement_seconds: 10,
        confidence_level: 0.95,
        sampling_mode: "auto".to_owned(),
        baseline_mode: "save".to_owned(),
        baseline_name: "base".to_owned(),
        no_plot: true,
        primary_statistic: "median.point_estimate".to_owned(),
    }
}

fn plan_for_manifest(
    manifest: &SdJwtIssuanceQualificationManifest,
    manifest_bytes: &[u8],
) -> Result<SdJwtIssuanceQualificationPlan> {
    validate_manifest(manifest)?;
    let mut canonical_manifest_bytes = serde_json::to_vec_pretty(manifest)
        .context("serialize canonical qualification manifest for plan binding")?;
    canonical_manifest_bytes.push(b'\n');
    anyhow::ensure!(
        manifest_bytes == canonical_manifest_bytes,
        "qualification manifest value and bound bytes differ"
    );
    let manifest_byte_length =
        u64::try_from(manifest_bytes.len()).context("manifest byte length overflow")?;
    let superblocks_per_cell =
        u32::try_from(SUPERBLOCK_ORDERS.len()).context("superblock count overflow")?;
    let processes_per_cell = superblocks_per_cell
        .checked_mul(PROCESSES_PER_SUPERBLOCK)
        .context("processes per cell overflow")?;
    let total_processes = processes_per_cell
        .checked_mul(u32::try_from(PAIRED_CELL_COUNT).context("paired cell count overflow")?)
        .context("total process count overflow")?;

    let plan = SdJwtIssuanceQualificationPlan {
        schema: PLAN_SCHEMA.to_owned(),
        manifest: ArtifactFingerprint {
            sha256: hex::encode_upper(Sha256::digest(manifest_bytes)),
            byte_length: manifest_byte_length,
        },
        manifest_schema: MANIFEST_SCHEMA.to_owned(),
        route_schema: manifest.route_schema.clone(),
        work_estimator_version: manifest.work_estimator_version.clone(),
        static_partition_rule_version: manifest.static_partition_rule_version.clone(),
        worker_cap: manifest.worker_cap,
        fixture_case_count: manifest.fixture_case_count,
        paired_cell_count: manifest.paired_cell_count,
        benchmark_id_count: manifest.benchmark_id_count,
        quiet_window_seconds: QUIET_WINDOW_SECONDS,
        quiet_windows: vec![
            "before_correctness_and_build".to_owned(),
            "after_fixed_binary_before_timing".to_owned(),
        ],
        fixed_binary_same_head: true,
        criterion: criterion_protocol(),
        superblock_orders: SUPERBLOCK_ORDERS.map(str::to_owned).to_vec(),
        abba_expansion: ABBA_EXPANSION.map(str::to_owned).to_vec(),
        baab_expansion: BAAB_EXPANSION.map(str::to_owned).to_vec(),
        superblocks_per_cell,
        processes_per_superblock: PROCESSES_PER_SUPERBLOCK,
        processes_per_cell,
        total_processes,
        global_rounds: global_round_protocol()?,
        bootstrap: bootstrap_protocol(superblocks_per_cell),
        effects: SdJwtIssuanceEffectProtocol {
            orientation: "ln(adaptive_median_ns)-ln(serial_median_ns)".to_owned(),
            abba_serial_first_pairs: vec![[1, 0], [7, 6]],
            abba_adaptive_first_pairs: vec![[2, 3], [4, 5]],
            baab_serial_first_pairs: vec![[3, 2], [5, 4]],
            baab_adaptive_first_pairs: vec![[0, 1], [6, 7]],
            s_definition: "mean(serial_first_pairs)".to_owned(),
            p_definition: "mean(adaptive_first_normalized_pairs)".to_owned(),
            d_definition: "(S+P)/2".to_owned(),
            o_definition: "S-P".to_owned(),
            primary_effects: vec!["D".to_owned(), "S".to_owned(), "P".to_owned()],
            disclosure_only_effects: vec!["O".to_owned()],
        },
        discovery: SdJwtIssuanceDiscoveryProtocol {
            required_ready_batch_count: 1,
            required_stages: vec!["executor_assembly".to_owned(), "full_issuance".to_owned()],
            percent_transform: "100.0 * (exp(effect) - 1.0)".to_owned(),
            d_upper_percent_less_than: -5.0,
            s_upper_percent_less_than: 0.0,
            p_upper_percent_less_than: 0.0,
            selection_rule: "unique_inclusion_maximal_else_none".to_owned(),
        },
        production_activation_separate: true,
    };
    validate_plan_schema(&plan)?;
    Ok(plan)
}

fn validate_plan_schema(plan: &SdJwtIssuanceQualificationPlan) -> Result<()> {
    anyhow::ensure!(
        plan.schema == PLAN_SCHEMA,
        "qualification plan schema must be the globally clustered v3 contract"
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct RouteBatchModel {
    ordinal: u64,
    selector: SelectorBatchModel,
    chunk_size: Option<u64>,
    chunks: Option<Vec<(u64, u64, u64)>>,
}

#[derive(Clone, Debug)]
struct RouteRecordModel {
    requested: &'static str,
    effective: &'static str,
    executor_batches: Option<u64>,
    serial_batches: Option<u64>,
    native_batches: Option<u64>,
    budget_fallback_batches: Option<u64>,
    max_native_worker_count: u64,
    worker_cap: u64,
    host_available_parallelism: u64,
    ready_batches: Option<Vec<RouteBatchModel>>,
}

#[derive(Clone, Debug)]
enum GateState {
    Skipped,
    Evaluated,
}

#[derive(Clone, Debug)]
struct SelectorBatchModel {
    jobs: u64,
    work: Option<u64>,
    work_status: &'static str,
    work_gate: GateState,
    available: Option<u64>,
    selected: Option<u64>,
    parallelism_gate: GateState,
    budget_gate: GateState,
    budget_result: &'static str,
    mode: &'static str,
    reason: &'static str,
    leased: Option<u64>,
    static_layout: Option<()>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RequiredNullable<T>(Option<T>);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteStaticChunkWire {
    ordinal: u64,
    job_count: u64,
    estimated_work_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteBatchWire {
    ordinal: u64,
    job_count: u64,
    estimated_work_bytes: RequiredNullable<u64>,
    work_estimate_status: String,
    work_gate_evaluated: bool,
    parallelism_gate_evaluated: bool,
    budget_gate_evaluated: bool,
    available_parallelism: RequiredNullable<u64>,
    selected_worker_count: RequiredNullable<u64>,
    leased_worker_count: RequiredNullable<u64>,
    budget_acquisition_result: String,
    selected_mode: String,
    selection_reason: String,
    static_chunk_size: RequiredNullable<u64>,
    static_chunks: RequiredNullable<Vec<RouteStaticChunkWire>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteRecordWire {
    schema: String,
    benchmark_id: String,
    fixture_id: String,
    stage: String,
    requested: String,
    effective: String,
    executor_batches: RequiredNullable<u64>,
    serial_batches: RequiredNullable<u64>,
    native_batches: RequiredNullable<u64>,
    budget_fallback_batches: RequiredNullable<u64>,
    max_native_worker_count: u64,
    worker_cap: u64,
    host_available_parallelism: u64,
    work_estimator_version: String,
    static_partition_rule_version: String,
    ready_batches: RequiredNullable<Vec<RouteBatchWire>>,
}

fn route_literal(value: &str) -> Option<&'static str> {
    match value {
        "serial_oracle" => Some("serial_oracle"),
        "adaptive_candidate" => Some("adaptive_candidate"),
        "bounded_native" => Some("bounded_native"),
        "mixed_native_and_serial" => Some("mixed_native_and_serial"),
        "ready_batch_serial_fallback" => Some("ready_batch_serial_fallback"),
        "budget_serial_fallback" => Some("budget_serial_fallback"),
        "target_serial_fallback" => Some("target_serial_fallback"),
        "not_evaluated" => Some("not_evaluated"),
        "available" => Some("available"),
        "overflow" => Some("overflow"),
        "acquired" => Some("acquired"),
        "unavailable" => Some("unavailable"),
        "serial" => Some("serial"),
        "native_parallel" => Some("native_parallel"),
        "below_min_jobs" => Some("below_min_jobs"),
        "work_estimate_overflow" => Some("work_estimate_overflow"),
        "below_min_estimated_work_bytes" => Some("below_min_estimated_work_bytes"),
        "insufficient_available_parallelism" => Some("insufficient_available_parallelism"),
        "worker_budget_unavailable" => Some("worker_budget_unavailable"),
        _ => None,
    }
}

fn route_batches_from_wire(values: Vec<RouteBatchWire>) -> Option<Vec<RouteBatchModel>> {
    let mut batches = Vec::with_capacity(values.len());
    for value in values {
        let work_status = route_literal(&value.work_estimate_status)?;
        let budget_result = route_literal(&value.budget_acquisition_result)?;
        let mode = route_literal(&value.selected_mode)?;
        let reason = route_literal(&value.selection_reason)?;
        let chunks = value.static_chunks.0.map(|chunks| {
            chunks
                .into_iter()
                .map(|chunk| (chunk.ordinal, chunk.job_count, chunk.estimated_work_bytes))
                .collect()
        });
        let static_layout = (value.static_chunk_size.0.is_some() && chunks.is_some()).then_some(());
        batches.push(RouteBatchModel {
            ordinal: value.ordinal,
            selector: SelectorBatchModel {
                jobs: value.job_count,
                work: value.estimated_work_bytes.0,
                work_status,
                work_gate: if value.work_gate_evaluated {
                    GateState::Evaluated
                } else {
                    GateState::Skipped
                },
                available: value.available_parallelism.0,
                selected: value.selected_worker_count.0,
                parallelism_gate: if value.parallelism_gate_evaluated {
                    GateState::Evaluated
                } else {
                    GateState::Skipped
                },
                budget_gate: if value.budget_gate_evaluated {
                    GateState::Evaluated
                } else {
                    GateState::Skipped
                },
                budget_result,
                mode,
                reason,
                leased: value.leased_worker_count.0,
                static_layout,
            },
            chunk_size: value.static_chunk_size.0,
            chunks,
        });
    }
    Some(batches)
}

fn valid_route_wire_bytes(
    bytes: &[u8],
    expected_benchmark_id: &str,
    expected_fixture_id: &str,
    expected_stage: &str,
    expected_requested: &str,
    expected_worker_cap: u64,
    expected_host_available_parallelism: u64,
) -> bool {
    if bytes.len() > 1024 * 1024 || !bytes.ends_with(b"\n") || bytes.ends_with(b"\n\n") {
        return false;
    }
    let body = &bytes[..bytes.len() - 1];
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let Ok(wire) = RouteRecordWire::deserialize(&mut deserializer) else {
        return false;
    };
    if deserializer.end().is_err() {
        return false;
    }
    let Ok(mut canonical) = serde_json::to_vec(&wire) else {
        return false;
    };
    canonical.push(b'\n');
    if canonical != bytes
        || wire.schema != ROUTE_SCHEMA
        || wire.benchmark_id != expected_benchmark_id
        || wire.fixture_id != expected_fixture_id
        || wire.stage != expected_stage
        || wire.requested != expected_requested
        || wire.work_estimator_version != WORK_ESTIMATOR_VERSION
        || wire.static_partition_rule_version != STATIC_PARTITION_RULE_VERSION
    {
        return false;
    }
    let Some(requested) = route_literal(&wire.requested) else {
        return false;
    };
    let Some(effective) = route_literal(&wire.effective) else {
        return false;
    };
    let batches = match wire.ready_batches.0 {
        None => None,
        Some(values) => Some(match route_batches_from_wire(values) {
            Some(batches) => batches,
            None => return false,
        }),
    };
    valid_route_record(
        &RouteRecordModel {
            requested,
            effective,
            executor_batches: wire.executor_batches.0,
            serial_batches: wire.serial_batches.0,
            native_batches: wire.native_batches.0,
            budget_fallback_batches: wire.budget_fallback_batches.0,
            max_native_worker_count: wire.max_native_worker_count,
            worker_cap: wire.worker_cap,
            host_available_parallelism: wire.host_available_parallelism,
            ready_batches: batches,
        },
        expected_worker_cap,
        expected_host_available_parallelism,
    )
}

fn valid_selector_batch(
    batch: &SelectorBatchModel,
    worker_cap: u64,
    host_available_parallelism: u64,
) -> bool {
    if batch.jobs == 0 || !(1..=64).contains(&worker_cap) || host_available_parallelism == 0 {
        return false;
    }
    let work_skipped = batch.work.is_none()
        && batch.work_status == "not_evaluated"
        && matches!(batch.work_gate, GateState::Skipped);
    let work_overflow = batch.work.is_none()
        && batch.work_status == "overflow"
        && matches!(batch.work_gate, GateState::Evaluated);
    let work_available = batch
        .work
        .filter(|_| batch.work_status == "available")
        .filter(|_| matches!(batch.work_gate, GateState::Evaluated));
    let parallel_skipped = batch.available.is_none()
        && batch.selected.is_none()
        && matches!(batch.parallelism_gate, GateState::Skipped);
    let expected_selected = host_available_parallelism.min(worker_cap).min(batch.jobs);
    let parallel_evaluated = batch.available == Some(host_available_parallelism)
        && batch.selected == Some(expected_selected)
        && matches!(batch.parallelism_gate, GateState::Evaluated);
    let budget_skipped =
        matches!(batch.budget_gate, GateState::Skipped) && batch.budget_result == "not_evaluated";
    let budget_unavailable =
        matches!(batch.budget_gate, GateState::Evaluated) && batch.budget_result == "unavailable";
    let budget_acquired =
        matches!(batch.budget_gate, GateState::Evaluated) && batch.budget_result == "acquired";
    let serial_static =
        batch.mode == "serial" && batch.leased.is_none() && batch.static_layout.is_none();
    match batch.reason {
        "below_min_jobs" => {
            batch.jobs < 2 && work_skipped && parallel_skipped && budget_skipped && serial_static
        }
        "work_estimate_overflow" => {
            batch.jobs >= 2 && work_overflow && parallel_skipped && budget_skipped && serial_static
        }
        "below_min_estimated_work_bytes" => {
            batch.jobs >= 2
                && work_available.is_some_and(|work| work < 1)
                && parallel_skipped
                && budget_skipped
                && serial_static
        }
        "insufficient_available_parallelism" => {
            batch.jobs >= 2
                && work_available.is_some_and(|work| work >= 1)
                && parallel_evaluated
                && expected_selected < 2
                && budget_skipped
                && serial_static
        }
        "worker_budget_unavailable" => {
            batch.jobs >= 2
                && work_available.is_some_and(|work| work >= 1)
                && parallel_evaluated
                && expected_selected >= 2
                && budget_unavailable
                && serial_static
        }
        "bounded_native" => {
            batch.jobs >= 2
                && work_available.is_some_and(|work| work >= 1)
                && parallel_evaluated
                && expected_selected >= 2
                && budget_acquired
                && batch.mode == "native_parallel"
                && batch.leased == batch.selected
                && batch.static_layout.is_some()
        }
        _ => false,
    }
}

fn valid_static_chunks(
    batch: &RouteBatchModel,
    worker_cap: u64,
    host_available_parallelism: u64,
) -> bool {
    if !valid_selector_batch(&batch.selector, worker_cap, host_available_parallelism) {
        return false;
    }
    if batch.selector.mode != "native_parallel" {
        return batch.chunk_size.is_none() && batch.chunks.is_none();
    }
    let (Some(workers), Some(leased), Some(work), Some(size), Some(chunks)) = (
        batch.selector.selected,
        batch.selector.leased,
        batch.selector.work,
        batch.chunk_size,
        batch.chunks.as_ref(),
    ) else {
        return false;
    };
    if workers == 0 || batch.selector.jobs == 0 {
        return false;
    }
    let Some(expected_size) = batch
        .selector
        .jobs
        .checked_add(workers - 1)
        .map(|value| value / workers)
    else {
        return false;
    };
    let Some(expected_count) = batch
        .selector
        .jobs
        .checked_add(expected_size - 1)
        .map(|value| value / expected_size)
    else {
        return false;
    };
    leased == workers
        && expected_count <= workers
        && size == expected_size
        && u64::try_from(chunks.len()) == Ok(expected_count)
        && chunks
            .iter()
            .enumerate()
            .all(|(index, (ordinal, jobs, _))| {
                *ordinal == index as u64
                    && *jobs > 0
                    && *jobs <= size
                    && (index + 1 == chunks.len() || *jobs == size)
            })
        && chunks
            .iter()
            .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.1))
            == Some(batch.selector.jobs)
        && chunks
            .iter()
            .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.2))
            == Some(work)
}

fn valid_route_record(
    record: &RouteRecordModel,
    expected_worker_cap: u64,
    expected_host_available_parallelism: u64,
) -> bool {
    if record.worker_cap != expected_worker_cap
        || record.host_available_parallelism != expected_host_available_parallelism
        || !(1..=64).contains(&record.worker_cap)
        || record.host_available_parallelism == 0
    {
        return false;
    }
    let Some(batches) = record.ready_batches.as_ref() else {
        let branch_valid = (record.requested == "serial_oracle"
            && record.effective == "serial_oracle")
            || (record.requested == "adaptive_candidate"
                && record.effective == "target_serial_fallback"
                && record.worker_cap == 1);
        return branch_valid
            && record.executor_batches.is_none()
            && record.serial_batches.is_none()
            && record.native_batches.is_none()
            && record.budget_fallback_batches.is_none()
            && record.max_native_worker_count == 0;
    };
    if record.worker_cap == 1 {
        return false;
    }
    let executor = batches.len() as u64;
    let native = batches
        .iter()
        .filter(|batch| batch.selector.mode == "native_parallel")
        .count() as u64;
    let serial = executor - native;
    let budget = batches
        .iter()
        .filter(|batch| batch.selector.reason == "worker_budget_unavailable")
        .count() as u64;
    let maximum = batches
        .iter()
        .filter_map(|batch| batch.selector.leased)
        .max()
        .unwrap_or(0);
    let effective = if native > 0 && serial > 0 {
        "mixed_native_and_serial"
    } else if native > 0 {
        "bounded_native"
    } else if budget > 0 {
        "budget_serial_fallback"
    } else {
        "ready_batch_serial_fallback"
    };
    record.requested == "adaptive_candidate"
        && record.effective == effective
        && record.executor_batches == Some(executor)
        && record.serial_batches == Some(serial)
        && record.native_batches == Some(native)
        && record.budget_fallback_batches == Some(budget)
        && record.max_native_worker_count == maximum
        && budget <= serial
        && maximum <= record.worker_cap
        && batches.iter().enumerate().all(|(ordinal, batch)| {
            batch.ordinal == ordinal as u64
                && valid_static_chunks(batch, record.worker_cap, record.host_available_parallelism)
        })
}

fn valid_uppercase_hex(value: &str, characters: usize) -> bool {
    value.len() == characters
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
}

fn valid_lowercase_hex(value: &str, characters: usize) -> bool {
    value.len() == characters
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceArchiveManifestWire {
    schema: String,
    git_object_format: String,
    source_commit: String,
    source_tree: String,
    entry_count: u32,
    entries: Vec<SourceArchiveEntryWire>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceArchiveEntryWire {
    repository_relative_path: String,
    git_mode: String,
    git_object_id: String,
    artifact_fingerprint: ArtifactFingerprint,
}

fn windows_reserved_device_stem(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn valid_source_archive_segment(segment: &str) -> bool {
    let portable = segment.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-')
    });
    portable
        && !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.eq_ignore_ascii_case(".git")
        && !segment.ends_with('.')
        && !windows_reserved_device_stem(segment)
        && usize::try_from(MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES)
            .is_ok_and(|maximum| segment.len() <= maximum)
}

fn valid_source_archive_path(path: &str) -> bool {
    usize::try_from(MAX_SOURCE_ARCHIVE_PATH_V1_BYTES)
        .is_ok_and(|maximum| (1..=maximum).contains(&path.len()))
        && !path.starts_with('/')
        && {
            let segments = path.split('/').collect::<Vec<_>>();
            u32::try_from(segments.len()).is_ok_and(|count| {
                count <= MAX_SOURCE_ARCHIVE_PATH_SEGMENTS
                    && segments.into_iter().all(valid_source_archive_segment)
            })
        }
}

enum SourcePathChild {
    Directory { name: String, node: usize },
    File { name: String, entry: usize },
}

#[derive(Default)]
struct SourcePathNode {
    children_by_folded_name: BTreeMap<String, SourcePathChild>,
}

fn add_derived_component_bytes(total: &mut u64, segment: &str, maximum: u64) -> Option<()> {
    *total = total.checked_add(u64::try_from(segment.len()).ok()?)?;
    (*total <= maximum).then_some(())
}

fn build_source_path_tree(
    entries: &[SourceArchiveEntryWire],
    maximum_nodes: usize,
    maximum_component_bytes: u64,
) -> Option<Vec<SourcePathNode>> {
    if maximum_nodes == 0 {
        return None;
    }
    let mut nodes = vec![SourcePathNode::default()];
    let mut component_bytes = 0_u64;
    for (entry_index, entry) in entries.iter().enumerate() {
        if !valid_source_archive_path(&entry.repository_relative_path) {
            return None;
        }
        let segments = entry
            .repository_relative_path
            .split('/')
            .collect::<Vec<_>>();
        let (file_name, directories) = segments.split_last()?;
        let mut parent = 0_usize;
        for segment in directories {
            let folded = segment.to_ascii_lowercase();
            let existing = nodes[parent].children_by_folded_name.get(&folded);
            if let Some(SourcePathChild::Directory { name, node }) = existing {
                if name != segment {
                    return None;
                }
                parent = *node;
                continue;
            }
            if existing.is_some() || nodes.len() >= maximum_nodes {
                return None;
            }
            add_derived_component_bytes(&mut component_bytes, segment, maximum_component_bytes)?;
            let child = nodes.len();
            nodes.push(SourcePathNode::default());
            nodes[parent].children_by_folded_name.insert(
                folded,
                SourcePathChild::Directory {
                    name: (*segment).to_owned(),
                    node: child,
                },
            );
            parent = child;
        }
        let folded = file_name.to_ascii_lowercase();
        if nodes[parent].children_by_folded_name.contains_key(&folded) {
            return None;
        }
        add_derived_component_bytes(&mut component_bytes, file_name, maximum_component_bytes)?;
        nodes[parent].children_by_folded_name.insert(
            folded,
            SourcePathChild::File {
                name: (*file_name).to_owned(),
                entry: entry_index,
            },
        );
    }
    Some(nodes)
}

fn source_archive_paths_are_materializable(entries: &[SourceArchiveEntryWire]) -> bool {
    usize::try_from(MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES).is_ok_and(|maximum_nodes| {
        build_source_path_tree(
            entries,
            maximum_nodes,
            MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
        )
        .is_some()
    })
}

fn git_object_id(kind: &str, body: &[u8]) -> [u8; 20] {
    let header = format!("{kind} {}\0", body.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn canonical_unsigned_decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value.starts_with(b"0"))
    {
        return None;
    }
    value.iter().try_fold(0_u64, |parsed, byte| {
        parsed.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn valid_git_timezone(value: &[u8]) -> bool {
    if value.len() != 5
        || !matches!(value[0], b'+' | b'-')
        || !value[1..].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let hours = (value[1] - b'0') * 10 + value[2] - b'0';
    let minutes = (value[3] - b'0') * 10 + value[4] - b'0';
    hours <= 23 && minutes <= 59 && !(hours == 0 && minutes == 0 && value[0] == b'-')
}

fn split_last_ascii_space(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let index = value.iter().rposition(|byte| *byte == b' ')?;
    Some((&value[..index], &value[index + 1..]))
}

fn git_commit_committer_timestamp(commit: &[u8], expected_tree: &str) -> Option<u64> {
    let header_end = commit.windows(2).position(|pair| pair == b"\n\n")?;
    let headers = &commit[..header_end];
    if headers.contains(&b'\r') || headers.contains(&0) {
        return None;
    }
    let mut lines = headers.split(|byte| *byte == b'\n');
    let expected_tree_header = format!("tree {expected_tree}");
    (lines.next()? == expected_tree_header.as_bytes()).then_some(())?;
    let mut tree_headers = 1_u32;
    let mut committer_timestamp = None;
    for line in lines {
        if line.starts_with(b"tree ") {
            tree_headers = tree_headers.checked_add(1)?;
        }
        let Some(committer) = line.strip_prefix(b"committer ") else {
            continue;
        };
        if committer_timestamp.is_some() {
            return None;
        }
        let (identity_and_timestamp, timezone) = split_last_ascii_space(committer)?;
        let (identity, timestamp) = split_last_ascii_space(identity_and_timestamp)?;
        if identity.is_empty()
            || !identity.contains(&b'<')
            || !identity.ends_with(b">")
            || !valid_git_timezone(timezone)
        {
            return None;
        }
        committer_timestamp = Some(canonical_unsigned_decimal(timestamp)?);
    }
    (tree_headers == 1).then_some(committer_timestamp?)
}

fn reconstructed_source_tree_with_limits(
    entries: &[SourceArchiveEntryWire],
    contents: &[&[u8]],
    maximum_nodes: usize,
    maximum_component_bytes: u64,
) -> Option<[u8; 20]> {
    if entries.len() != contents.len() {
        return None;
    }
    let nodes = build_source_path_tree(entries, maximum_nodes, maximum_component_bytes)?;
    let mut tree_ids = vec![[0_u8; 20]; nodes.len()];
    for node_index in (0..nodes.len()).rev() {
        let mut components = Vec::<(Vec<u8>, String, String, [u8; 20])>::new();
        for child in nodes[node_index].children_by_folded_name.values() {
            match child {
                SourcePathChild::File { name, entry } => {
                    let source_entry = entries.get(*entry)?;
                    let content = *contents.get(*entry)?;
                    let object_id = git_object_id("blob", content);
                    if hex::encode(object_id) != source_entry.git_object_id {
                        return None;
                    }
                    let mut sort_key = name.as_bytes().to_vec();
                    sort_key.push(0);
                    components.push((
                        sort_key,
                        name.clone(),
                        source_entry.git_mode.clone(),
                        object_id,
                    ));
                }
                SourcePathChild::Directory { name, node } => {
                    let object_id = *tree_ids.get(*node)?;
                    let mut sort_key = name.as_bytes().to_vec();
                    sort_key.push(b'/');
                    components.push((sort_key, name.clone(), "40000".to_owned(), object_id));
                }
            }
        }
        components.sort_by(|left, right| left.0.cmp(&right.0));
        let mut tree_body = Vec::new();
        for (_, name, mode, object_id) in components {
            tree_body.extend_from_slice(mode.as_bytes());
            tree_body.push(b' ');
            tree_body.extend_from_slice(name.as_bytes());
            tree_body.push(0);
            tree_body.extend_from_slice(&object_id);
        }
        tree_ids[node_index] = git_object_id("tree", &tree_body);
    }
    tree_ids.first().copied()
}

fn reconstructed_source_tree(
    entries: &[SourceArchiveEntryWire],
    contents: &[&[u8]],
) -> Option<[u8; 20]> {
    usize::try_from(MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES)
        .ok()
        .and_then(|maximum_nodes| {
            reconstructed_source_tree_with_limits(
                entries,
                contents,
                maximum_nodes,
                MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
            )
        })
}

fn take_u64_be(bytes: &[u8], cursor: &mut usize) -> Option<usize> {
    let end = cursor.checked_add(8)?;
    let encoded: [u8; 8] = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    usize::try_from(u64::from_be_bytes(encoded)).ok()
}

fn take_bounded<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    maximum: usize,
) -> Option<&'a [u8]> {
    if length > maximum {
        return None;
    }
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn parse_source_archive_manifest(bytes: &[u8]) -> Option<SourceArchiveManifestWire> {
    if !bytes.ends_with(b"\n") {
        return None;
    }
    let manifest = serde_json::from_slice::<SourceArchiveManifestWire>(bytes).ok()?;
    let mut canonical = serde_json::to_vec_pretty(&manifest).ok()?;
    canonical.push(b'\n');
    let valid = canonical == bytes
        && manifest.schema == "marty.performance/sd-jwt-issuance-source-archive-manifest/v1"
        && manifest.git_object_format == "sha1"
        && valid_lowercase_hex(&manifest.source_commit, 40)
        && valid_lowercase_hex(&manifest.source_tree, 40)
        && (1..=MAX_SOURCE_ARCHIVE_V1_ENTRIES).contains(&manifest.entry_count)
        && usize::try_from(manifest.entry_count) == Ok(manifest.entries.len())
        && source_archive_paths_are_materializable(&manifest.entries)
        && manifest.entries.iter().all(|entry| {
            valid_source_archive_path(&entry.repository_relative_path)
                && matches!(entry.git_mode.as_str(), "100644" | "100755")
                && valid_lowercase_hex(&entry.git_object_id, 40)
                && valid_artifact_fingerprint(&entry.artifact_fingerprint)
        })
        && manifest.entries.windows(2).all(|pair| {
            pair[0].repository_relative_path.as_bytes()
                < pair[1].repository_relative_path.as_bytes()
        });
    valid.then_some(manifest)
}

#[derive(Clone)]
struct ValidatedSourceArchive {
    manifest: SourceArchiveManifestWire,
    committer_timestamp: u64,
}

fn validate_source_archive_bytes(
    bytes: &[u8],
    expected_outer_fingerprint: &ArtifactFingerprint,
    expected_cargo_lock_fingerprint: &ArtifactFingerprint,
) -> Option<ValidatedSourceArchive> {
    let maximum_archive_bytes = usize::try_from(MAX_SOURCE_ARCHIVE_V1_BYTES).ok()?;
    let maximum_manifest_bytes = usize::try_from(MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES).ok()?;
    let maximum_commit_bytes = usize::try_from(MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES).ok()?;
    if bytes.len() > maximum_archive_bytes
        || fingerprint(bytes).ok().as_ref() != Some(expected_outer_fingerprint)
        || !bytes.starts_with(SOURCE_ARCHIVE_MAGIC)
    {
        return None;
    }
    let mut cursor = SOURCE_ARCHIVE_MAGIC.len();
    let manifest_length = take_u64_be(bytes, &mut cursor)?;
    let manifest_bytes = take_bounded(bytes, &mut cursor, manifest_length, maximum_manifest_bytes)?;
    let manifest = parse_source_archive_manifest(manifest_bytes)?;
    let commit_length = take_u64_be(bytes, &mut cursor)?;
    let commit = take_bounded(bytes, &mut cursor, commit_length, maximum_commit_bytes)?;
    let mut contents = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let content_length = take_u64_be(bytes, &mut cursor)?;
        let content = take_bounded(bytes, &mut cursor, content_length, maximum_archive_bytes)?;
        if fingerprint(content).ok().as_ref() != Some(&entry.artifact_fingerprint) {
            return None;
        }
        contents.push(content);
    }
    let source_tree = hex::encode(reconstructed_source_tree(&manifest.entries, &contents)?);
    let cargo_lock_matches = manifest
        .entries
        .iter()
        .zip(&contents)
        .find(|(entry, _)| entry.repository_relative_path == "Cargo.lock")
        .is_some_and(|(entry, content)| {
            entry.artifact_fingerprint == *expected_cargo_lock_fingerprint
                && fingerprint(content).ok().as_ref() == Some(expected_cargo_lock_fingerprint)
        });
    let committer_timestamp = git_commit_committer_timestamp(commit, &source_tree)?;
    (cursor == bytes.len()
        && source_tree == manifest.source_tree
        && hex::encode(git_object_id("commit", commit)) == manifest.source_commit
        && cargo_lock_matches)
        .then_some(ValidatedSourceArchive {
            manifest,
            committer_timestamp,
        })
}

fn fingerprint(bytes: &[u8]) -> Result<ArtifactFingerprint> {
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(Sha256::digest(bytes)),
        byte_length: u64::try_from(bytes.len()).context("artifact byte length overflow")?,
    })
}

fn valid_artifact_fingerprint(value: &ArtifactFingerprint) -> bool {
    valid_uppercase_hex(&value.sha256, 64)
}

fn valid_receipt_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn fixed_decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
    })
}

fn valid_utc_rfc3339_nanoseconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 30
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[29] != b'Z'
    {
        return false;
    }
    let Some(year) = fixed_decimal(&bytes[0..4]).and_then(|value| i32::try_from(value).ok()) else {
        return false;
    };
    let Some(month) = fixed_decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = fixed_decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = fixed_decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = fixed_decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = fixed_decimal(&bytes[17..19]) else {
        return false;
    };
    let Some(nanosecond) = fixed_decimal(&bytes[20..29]) else {
        return false;
    };
    year >= 1
        && NaiveDate::from_ymd_opt(year, month, day).is_some()
        && NaiveTime::from_hms_nano_opt(hour, minute, second, nanosecond).is_some()
}

#[derive(Serialize)]
struct TerminalObservationUnsigned<'a> {
    schema: &'a str,
    campaign_id: &'a str,
    channel_id: &'a str,
    log_id: &'a str,
    campaign_append_ordinal: u64,
    channel_clock_session_id: &'a str,
    channel_monotonic_nanoseconds: u64,
    observed_at_utc_rfc3339_nanoseconds: &'a str,
    channel_receipt_id: &'a str,
    challenge_uppercase_hex_256: &'a str,
    terminal_segment_fingerprint: ArtifactFingerprint,
    terminal_footer_monotonic_nanoseconds: u64,
    controller_request_monotonic_nanoseconds: u64,
    signing_key_id: &'a str,
}

#[derive(Serialize)]
struct CompletionAnchorUnsigned<'a> {
    schema: &'a str,
    campaign_id: &'a str,
    channel_id: &'a str,
    log_id: &'a str,
    campaign_append_ordinal: u64,
    channel_clock_session_id: &'a str,
    channel_monotonic_nanoseconds: u64,
    published_at_utc_rfc3339_nanoseconds: &'a str,
    channel_receipt_id: &'a str,
    challenge_uppercase_hex_256: &'a str,
    completion_fingerprint: ArtifactFingerprint,
    terminal_segment_fingerprint: ArtifactFingerprint,
    terminal_observation_evidence_fingerprint: ArtifactFingerprint,
    signing_key_id: &'a str,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalObservationReceiptWire {
    schema: String,
    campaign_id: String,
    channel_id: String,
    log_id: String,
    campaign_append_ordinal: u64,
    channel_clock_session_id: String,
    channel_monotonic_nanoseconds: u64,
    observed_at_utc_rfc3339_nanoseconds: String,
    channel_receipt_id: String,
    challenge_uppercase_hex_256: String,
    terminal_segment_fingerprint: ArtifactFingerprint,
    terminal_footer_monotonic_nanoseconds: u64,
    controller_request_monotonic_nanoseconds: u64,
    signing_key_id: String,
    signature_uppercase_hex_512: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionAnchorWire {
    schema: String,
    campaign_id: String,
    channel_id: String,
    log_id: String,
    campaign_append_ordinal: u64,
    channel_clock_session_id: String,
    channel_monotonic_nanoseconds: u64,
    published_at_utc_rfc3339_nanoseconds: String,
    channel_receipt_id: String,
    challenge_uppercase_hex_256: String,
    completion_fingerprint: ArtifactFingerprint,
    terminal_segment_fingerprint: ArtifactFingerprint,
    terminal_observation_evidence_fingerprint: ArtifactFingerprint,
    signing_key_id: String,
    signature_uppercase_hex_512: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalObservationEvidenceWire {
    schema: String,
    campaign_id: String,
    terminal_observation_receipt_fingerprint: ArtifactFingerprint,
    controller_receipt_observed_monotonic_nanoseconds: u64,
}

fn signed_json_preimage(domain_with_nul: &[u8], unsigned_json: &[u8]) -> Option<Vec<u8>> {
    let unsigned_length = u64::try_from(unsigned_json.len()).ok()?;
    let capacity = domain_with_nul
        .len()
        .checked_add(8)?
        .checked_add(unsigned_json.len())?;
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(domain_with_nul);
    preimage.extend_from_slice(&unsigned_length.to_be_bytes());
    preimage.extend_from_slice(unsigned_json);
    Some(preimage)
}

fn strict_signature_verifies(
    verifying_key: &VerifyingKey,
    preimage: &[u8],
    signature_uppercase_hex: &str,
) -> bool {
    if !valid_uppercase_hex(signature_uppercase_hex, 128) {
        return false;
    }
    let Ok(signature_bytes) = hex::decode(signature_uppercase_hex) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    verifying_key.verify_strict(preimage, &signature).is_ok()
}

fn canonical_pretty_bytes<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

fn terminal_receipt_preimage(receipt: &TerminalObservationReceiptWire) -> Option<Vec<u8>> {
    let unsigned = TerminalObservationUnsigned {
        schema: &receipt.schema,
        campaign_id: &receipt.campaign_id,
        channel_id: &receipt.channel_id,
        log_id: &receipt.log_id,
        campaign_append_ordinal: receipt.campaign_append_ordinal,
        channel_clock_session_id: &receipt.channel_clock_session_id,
        channel_monotonic_nanoseconds: receipt.channel_monotonic_nanoseconds,
        observed_at_utc_rfc3339_nanoseconds: &receipt.observed_at_utc_rfc3339_nanoseconds,
        channel_receipt_id: &receipt.channel_receipt_id,
        challenge_uppercase_hex_256: &receipt.challenge_uppercase_hex_256,
        terminal_segment_fingerprint: receipt.terminal_segment_fingerprint.clone(),
        terminal_footer_monotonic_nanoseconds: receipt.terminal_footer_monotonic_nanoseconds,
        controller_request_monotonic_nanoseconds: receipt.controller_request_monotonic_nanoseconds,
        signing_key_id: &receipt.signing_key_id,
    };
    let unsigned_json = serde_json::to_vec(&unsigned).ok()?;
    signed_json_preimage(b"MARTY-SD-JWT-TERMINAL-OBSERVATION-V1\0", &unsigned_json)
}

fn completion_anchor_preimage(receipt: &CompletionAnchorWire) -> Option<Vec<u8>> {
    let unsigned = CompletionAnchorUnsigned {
        schema: &receipt.schema,
        campaign_id: &receipt.campaign_id,
        channel_id: &receipt.channel_id,
        log_id: &receipt.log_id,
        campaign_append_ordinal: receipt.campaign_append_ordinal,
        channel_clock_session_id: &receipt.channel_clock_session_id,
        channel_monotonic_nanoseconds: receipt.channel_monotonic_nanoseconds,
        published_at_utc_rfc3339_nanoseconds: &receipt.published_at_utc_rfc3339_nanoseconds,
        channel_receipt_id: &receipt.channel_receipt_id,
        challenge_uppercase_hex_256: &receipt.challenge_uppercase_hex_256,
        completion_fingerprint: receipt.completion_fingerprint.clone(),
        terminal_segment_fingerprint: receipt.terminal_segment_fingerprint.clone(),
        terminal_observation_evidence_fingerprint: receipt
            .terminal_observation_evidence_fingerprint
            .clone(),
        signing_key_id: &receipt.signing_key_id,
    };
    let unsigned_json = serde_json::to_vec(&unsigned).ok()?;
    signed_json_preimage(b"MARTY-SD-JWT-COMPLETION-ANCHOR-V1\0", &unsigned_json)
}

fn valid_terminal_receipt_bytes(bytes: &[u8], verifying_key: &VerifyingKey) -> bool {
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_EXTERNAL_ANCHOR_V1_BYTES) {
        return false;
    }
    let Ok(receipt) = serde_json::from_slice::<TerminalObservationReceiptWire>(bytes) else {
        return false;
    };
    canonical_pretty_bytes(&receipt).as_deref() == Some(bytes)
        && receipt.schema == "marty.performance/sd-jwt-issuance-terminal-observation-receipt/v1"
        && receipt.channel_id == "marty-sd-jwt-issuance-anchor-v1"
        && receipt.log_id == "sd-jwt-issuance-qualification-v1"
        && receipt.campaign_append_ordinal == 0
        && receipt.signing_key_id == "marty-sd-jwt-issuance-anchor-ed25519-v1"
        && valid_uppercase_hex(&receipt.channel_clock_session_id, 64)
        && valid_uppercase_hex(&receipt.challenge_uppercase_hex_256, 64)
        && valid_receipt_id(&receipt.channel_receipt_id)
        && valid_utc_rfc3339_nanoseconds(&receipt.observed_at_utc_rfc3339_nanoseconds)
        && valid_artifact_fingerprint(&receipt.terminal_segment_fingerprint)
        && terminal_receipt_preimage(&receipt).is_some_and(|preimage| {
            strict_signature_verifies(
                verifying_key,
                &preimage,
                &receipt.signature_uppercase_hex_512,
            )
        })
}

#[cfg(test)]
fn terminal_receipt_set_has_no_conflict(receipts: &[&[u8]], verifying_key: &VerifyingKey) -> bool {
    let mut seen = BTreeMap::<(String, String, String, u64), Vec<u8>>::new();
    receipts.iter().all(|bytes| {
        if !valid_terminal_receipt_bytes(bytes, verifying_key) {
            return false;
        }
        let Ok(receipt) = serde_json::from_slice::<TerminalObservationReceiptWire>(bytes) else {
            return false;
        };
        let key = (
            receipt.channel_id,
            receipt.log_id,
            receipt.campaign_id,
            receipt.campaign_append_ordinal,
        );
        seen.insert(key, bytes.to_vec())
            .is_none_or(|previous| previous.as_slice() == *bytes)
    })
}

fn valid_completion_anchor_bytes(bytes: &[u8], verifying_key: &VerifyingKey) -> bool {
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_EXTERNAL_ANCHOR_V1_BYTES) {
        return false;
    }
    let Ok(receipt) = serde_json::from_slice::<CompletionAnchorWire>(bytes) else {
        return false;
    };
    canonical_pretty_bytes(&receipt).as_deref() == Some(bytes)
        && receipt.schema == "marty.performance/sd-jwt-issuance-completion-anchor/v1"
        && receipt.channel_id == "marty-sd-jwt-issuance-anchor-v1"
        && receipt.log_id == "sd-jwt-issuance-qualification-v1"
        && receipt.campaign_append_ordinal == 1
        && receipt.signing_key_id == "marty-sd-jwt-issuance-anchor-ed25519-v1"
        && valid_uppercase_hex(&receipt.channel_clock_session_id, 64)
        && valid_uppercase_hex(&receipt.challenge_uppercase_hex_256, 64)
        && valid_receipt_id(&receipt.channel_receipt_id)
        && valid_utc_rfc3339_nanoseconds(&receipt.published_at_utc_rfc3339_nanoseconds)
        && valid_artifact_fingerprint(&receipt.completion_fingerprint)
        && valid_artifact_fingerprint(&receipt.terminal_segment_fingerprint)
        && valid_artifact_fingerprint(&receipt.terminal_observation_evidence_fingerprint)
        && completion_anchor_preimage(&receipt).is_some_and(|preimage| {
            strict_signature_verifies(
                verifying_key,
                &preimage,
                &receipt.signature_uppercase_hex_512,
            )
        })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: FileIdentity,
    byte_length: u64,
    link_count: u64,
    change_token: [u64; 4],
    readonly: bool,
}

#[cfg(unix)]
fn handle_snapshot(
    file: &fs::File,
    require_directory: bool,
    role: &'static str,
) -> Result<FileSnapshot> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .with_context(|| format!("analysis rejected: {role}"))?;
    anyhow::ensure!(
        if require_directory {
            metadata.file_type().is_dir()
        } else {
            metadata.file_type().is_file()
        },
        "analysis rejected: {role}"
    );
    Ok(FileSnapshot {
        identity: FileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        },
        byte_length: metadata.len(),
        link_count: metadata.nlink(),
        change_token: [
            metadata.mtime().cast_unsigned(),
            metadata.mtime_nsec().cast_unsigned(),
            metadata.ctime().cast_unsigned(),
            metadata.ctime_nsec().cast_unsigned(),
        ],
        readonly: metadata.permissions().readonly(),
    })
}

#[cfg(windows)]
fn handle_snapshot(
    file: &fs::File,
    require_directory: bool,
    role: &'static str,
) -> Result<FileSnapshot> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0400;

    let metadata = file
        .metadata()
        .with_context(|| format!("analysis rejected: {role}"))?;
    let information = winapi_util::file::information(file)
        .with_context(|| format!("analysis rejected: {role}"))?;
    let file_type =
        winapi_util::file::typ(file).with_context(|| format!("analysis rejected: {role}"))?;
    anyhow::ensure!(
        file_type.is_disk()
            && information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && if require_directory {
                metadata.file_type().is_dir()
            } else {
                metadata.file_type().is_file()
            },
        "analysis rejected: {role}"
    );
    Ok(FileSnapshot {
        identity: FileIdentity {
            volume: information.volume_serial_number(),
            file: information.file_index(),
        },
        byte_length: information.file_size(),
        link_count: information.number_of_links(),
        change_token: [
            information.creation_time().unwrap_or_default(),
            information.last_write_time().unwrap_or_default(),
            information.file_attributes(),
            0,
        ],
        readonly: metadata.permissions().readonly(),
    })
}

#[cfg(not(any(unix, windows)))]
fn handle_snapshot(
    _file: &fs::File,
    _require_directory: bool,
    role: &'static str,
) -> Result<FileSnapshot> {
    Err(anyhow::anyhow!("analysis rejected: {role}"))
}

fn verified_directory_identity(file: &fs::File, role: &'static str) -> Result<FileIdentity> {
    Ok(handle_snapshot(file, true, role)?.identity)
}

fn verified_file_snapshot(
    file: &fs::File,
    maximum: u64,
    role: &'static str,
) -> Result<FileSnapshot> {
    let snapshot = handle_snapshot(file, false, role)?;
    anyhow::ensure!(
        snapshot.link_count == 1 && snapshot.byte_length <= maximum,
        "analysis rejected: {role}"
    );
    Ok(snapshot)
}

fn ensure_file_unchanged(file: &fs::File, before: FileSnapshot, role: &'static str) -> Result<()> {
    let after = handle_snapshot(file, false, role)?;
    anyhow::ensure!(
        after == before && after.link_count == 1,
        "analysis rejected: {role}"
    );
    Ok(())
}

fn ensure_exact_snapshot_byte_length(
    actual: u64,
    snapshot: FileSnapshot,
    role: &'static str,
) -> Result<()> {
    anyhow::ensure!(actual == snapshot.byte_length, "analysis rejected: {role}");
    Ok(())
}

fn rootless_components(path: &Path, role: &'static str) -> Result<Vec<OsString>> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(anyhow::anyhow!("analysis rejected: {role}")),
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!components.is_empty(), "analysis rejected: {role}");
    Ok(components)
}

#[cfg(unix)]
fn open_child_directory(
    parent: &fs::File,
    component: &OsString,
    role: &'static str,
) -> Result<fs::File> {
    use rustix::fs::{openat, Mode, OFlags};

    let descriptor = openat(
        parent,
        component.as_os_str(),
        OFlags::RDONLY
            | OFlags::DIRECTORY
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::NOCTTY
            | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("analysis rejected: {role}"))?;
    let directory = fs::File::from(descriptor);
    verified_directory_identity(&directory, role)?;
    Ok(directory)
}

#[cfg(windows)]
fn open_child_directory(
    parent: &fs::File,
    component: &OsString,
    role: &'static str,
) -> Result<fs::File> {
    let mut options = AtOpenOptions::default();
    options.read(true).follow(false);
    let directory = options
        .open_dir_at(parent, component)
        .with_context(|| format!("analysis rejected: {role}"))?;
    verified_directory_identity(&directory, role)?;
    Ok(directory)
}

#[cfg(not(any(unix, windows)))]
fn open_child_directory(
    _parent: &fs::File,
    _component: &OsString,
    role: &'static str,
) -> Result<fs::File> {
    Err(anyhow::anyhow!("analysis rejected: {role}"))
}

#[cfg(unix)]
fn open_child_file(
    parent: &fs::File,
    component: &std::ffi::OsStr,
    maximum: u64,
    role: &'static str,
) -> Result<OpenedInput> {
    use rustix::fs::{openat, Mode, OFlags};

    let descriptor = openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("analysis rejected: {role}"))?;
    let file = fs::File::from(descriptor);
    let snapshot = verified_file_snapshot(&file, maximum, role)?;
    Ok(OpenedInput { file, snapshot })
}

#[cfg(windows)]
fn open_child_file(
    parent: &fs::File,
    component: &std::ffi::OsStr,
    maximum: u64,
    role: &'static str,
) -> Result<OpenedInput> {
    let mut options = AtOpenOptions::default();
    options.read(true).follow(false);
    let file = options
        .open_at(parent, component)
        .with_context(|| format!("analysis rejected: {role}"))?;
    let snapshot = verified_file_snapshot(&file, maximum, role)?;
    Ok(OpenedInput { file, snapshot })
}

#[cfg(not(any(unix, windows)))]
fn open_child_file(
    _parent: &fs::File,
    _component: &std::ffi::OsStr,
    _maximum: u64,
    role: &'static str,
) -> Result<OpenedInput> {
    Err(anyhow::anyhow!("analysis rejected: {role}"))
}

#[cfg(unix)]
fn absolute_root_and_components(
    path: &Path,
    role: &'static str,
) -> Result<(fs::File, Vec<OsString>)> {
    anyhow::ensure!(path.is_absolute(), "analysis rejected: {role}");
    let mut components = path.components();
    anyhow::ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "analysis rejected: {role}"
    );
    let remaining = components
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(anyhow::anyhow!("analysis rejected: {role}")),
        })
        .collect::<Result<Vec<_>>>()?;
    let root = fs::File::open("/").with_context(|| format!("analysis rejected: {role}"))?;
    verified_directory_identity(&root, role)?;
    Ok((root, remaining))
}

#[cfg(windows)]
fn absolute_root_and_components(
    path: &Path,
    role: &'static str,
) -> Result<(fs::File, Vec<OsString>)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Prefix;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    anyhow::ensure!(path.is_absolute(), "analysis rejected: {role}");
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(anyhow::anyhow!("analysis rejected: {role}")),
        },
        _ => return Err(anyhow::anyhow!("analysis rejected: {role}")),
    };
    anyhow::ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "analysis rejected: {role}"
    );
    let remaining = components
        .map(|component| match component {
            Component::Normal(value)
                if !value.encode_wide().any(|unit| unit == u16::from(b':')) =>
            {
                Ok(value.to_os_string())
            }
            _ => Err(anyhow::anyhow!("analysis rejected: {role}")),
        })
        .collect::<Result<Vec<_>>>()?;
    let volume_root = format!("{}:\\", char::from(drive));
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(volume_root)
        .with_context(|| format!("analysis rejected: {role}"))?;
    verified_directory_identity(&root, role)?;
    Ok((root, remaining))
}

#[cfg(not(any(unix, windows)))]
fn absolute_root_and_components(
    _path: &Path,
    role: &'static str,
) -> Result<(fs::File, Vec<OsString>)> {
    Err(anyhow::anyhow!("analysis rejected: {role}"))
}

fn open_absolute_directory_excluding(
    path: &Path,
    forbidden_directory: Option<FileIdentity>,
    role: &'static str,
) -> Result<fs::File> {
    let (mut directory, components) = absolute_root_and_components(path, role)?;
    anyhow::ensure!(
        Some(verified_directory_identity(&directory, role)?) != forbidden_directory,
        "analysis rejected: {role}"
    );
    for component in components {
        directory = open_child_directory(&directory, &component, role)?;
        anyhow::ensure!(
            Some(verified_directory_identity(&directory, role)?) != forbidden_directory,
            "analysis rejected: {role}"
        );
    }
    Ok(directory)
}

fn open_absolute_directory(path: &Path, role: &'static str) -> Result<fs::File> {
    open_absolute_directory_excluding(path, None, role)
}

fn open_absolute_file(
    path: &Path,
    maximum: u64,
    forbidden_directory: Option<FileIdentity>,
    role: &'static str,
) -> Result<OpenedInput> {
    let (mut directory, mut components) = absolute_root_and_components(path, role)?;
    let file_name = components.pop().context("analysis rejected: input role")?;
    let mut directory_identity = verified_directory_identity(&directory, role)?;
    anyhow::ensure!(
        Some(directory_identity) != forbidden_directory,
        "analysis rejected: {role}"
    );
    for component in components {
        directory = open_child_directory(&directory, &component, role)?;
        directory_identity = verified_directory_identity(&directory, role)?;
        anyhow::ensure!(
            Some(directory_identity) != forbidden_directory,
            "analysis rejected: {role}"
        );
    }
    open_child_file(&directory, &file_name, maximum, role)
}

#[derive(Debug)]
struct OpenedInput {
    file: fs::File,
    snapshot: FileSnapshot,
}

#[derive(Debug)]
struct CampaignDirectory {
    root: fs::File,
    identity: FileIdentity,
}

impl CampaignDirectory {
    fn open(path: &Path) -> Result<Self> {
        let root = open_absolute_directory(path, "campaign root")?;
        let identity = verified_directory_identity(&root, "campaign root")?;
        Ok(Self { root, identity })
    }

    fn open_directory(&self, relative: &Path, role: &'static str) -> Result<fs::File> {
        let mut directory = self
            .root
            .try_clone()
            .with_context(|| format!("analysis rejected: {role}"))?;
        for component in rootless_components(relative, role)? {
            directory = open_child_directory(&directory, &component, role)?;
        }
        Ok(directory)
    }

    fn open_file(&self, relative: &Path, maximum: u64, role: &'static str) -> Result<OpenedInput> {
        let mut components = rootless_components(relative, role)?;
        let file_name = components.pop().context("analysis rejected: input role")?;
        let mut directory = self
            .root
            .try_clone()
            .with_context(|| format!("analysis rejected: {role}"))?;
        for component in components {
            directory = open_child_directory(&directory, &component, role)?;
        }
        open_child_file(&directory, &file_name, maximum, role)
    }

    fn validate_exact_directory_entries(
        &self,
        relative: &Path,
        expected: &BTreeSet<OsString>,
        role: &'static str,
    ) -> Result<()> {
        let directory = self.open_directory(relative, role)?;
        let before = handle_snapshot(&directory, true, role)?;
        let mut listing = directory
            .try_clone()
            .with_context(|| format!("analysis rejected: {role}"))?;
        let validation = (|| -> Result<BTreeSet<OsString>> {
            let mut entries = BTreeSet::new();
            let mut observed = 0_usize;
            for entry in fs_at::read_dir(&mut listing)
                .with_context(|| format!("analysis rejected: {role}"))?
            {
                observed = observed
                    .checked_add(1)
                    .context("analysis rejected: directory inventory")?;
                anyhow::ensure!(
                    observed <= expected.len().saturating_add(2),
                    "analysis rejected: {role}"
                );
                let entry = entry.with_context(|| format!("analysis rejected: {role}"))?;
                let name = entry.name();
                if name == "." || name == ".." {
                    continue;
                }
                anyhow::ensure!(
                    expected.contains(name) && entries.insert(name.to_os_string()),
                    "analysis rejected: {role}"
                );
            }
            Ok(entries)
        })();
        anyhow::ensure!(
            before == handle_snapshot(&directory, true, role)?
                && before == handle_snapshot(&listing, true, role)?,
            "analysis rejected: {role}"
        );
        anyhow::ensure!(validation? == *expected, "analysis rejected: {role}");
        Ok(())
    }
}

#[derive(Default)]
struct AnalysisReadBudget {
    charged_files: BTreeSet<FileIdentity>,
    total_bytes: u64,
}

impl AnalysisReadBudget {
    fn charge(&mut self, input: &OpenedInput) -> Result<()> {
        if self.charged_files.contains(&input.snapshot.identity) {
            return Ok(());
        }
        let total = self
            .total_bytes
            .checked_add(input.snapshot.byte_length)
            .context("analysis rejected: total evidence bytes")?;
        anyhow::ensure!(
            total <= MAX_TOTAL_EVIDENCE_BYTES,
            "analysis rejected: total evidence bytes"
        );
        self.total_bytes = total;
        self.charged_files.insert(input.snapshot.identity);
        Ok(())
    }
}

#[cfg(test)]
fn read_bounded(path: &Path, maximum: u64, role: &'static str) -> Result<Vec<u8>> {
    let input = open_absolute_file(path, maximum, None, role)?;
    read_opened_input(input, maximum, role)
}

fn read_opened_input(mut input: OpenedInput, maximum: u64, role: &'static str) -> Result<Vec<u8>> {
    let read_limit = maximum
        .checked_add(1)
        .context("analysis rejected: compiled input limit")?;
    let allocation =
        usize::try_from(read_limit).context("analysis rejected: compiled input limit")?;
    let mut bytes = Vec::with_capacity(allocation.min(64 * 1024));
    {
        let mut limited = (&mut input.file).take(read_limit);
        limited
            .read_to_end(&mut bytes)
            .with_context(|| format!("analysis rejected: {role}"))?;
    }
    let actual_length = u64::try_from(bytes.len()).context("analysis rejected: byte count")?;
    anyhow::ensure!(actual_length <= maximum, "analysis rejected: {role}");
    ensure_exact_snapshot_byte_length(actual_length, input.snapshot, role)?;
    ensure_file_unchanged(&input.file, input.snapshot, role)?;
    Ok(bytes)
}

fn read_campaign_input(
    budget: &mut AnalysisReadBudget,
    campaign: &CampaignDirectory,
    relative: &Path,
    maximum: u64,
    role: &'static str,
) -> Result<Vec<u8>> {
    let input = campaign.open_file(relative, maximum, role)?;
    budget.charge(&input)?;
    read_opened_input(input, maximum, role)
}

fn fingerprint_reader(
    file: &mut fs::File,
    maximum: u64,
    role: &'static str,
) -> Result<ArtifactFingerprint> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("analysis rejected: {role}"))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("analysis rejected: {role}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).context("analysis rejected: byte count")?)
            .context("analysis rejected: byte count")?;
        anyhow::ensure!(total <= maximum, "analysis rejected: {role}");
        hasher.update(&buffer[..read]);
    }
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(hasher.finalize()),
        byte_length: total,
    })
}

fn fingerprint_opened_input(
    mut input: OpenedInput,
    maximum: u64,
    role: &'static str,
) -> Result<ArtifactFingerprint> {
    let fingerprint = fingerprint_reader(&mut input.file, maximum, role)?;
    ensure_exact_snapshot_byte_length(fingerprint.byte_length, input.snapshot, role)?;
    ensure_file_unchanged(&input.file, input.snapshot, role)?;
    Ok(fingerprint)
}

fn fingerprint_campaign_file(
    budget: &mut AnalysisReadBudget,
    campaign: &CampaignDirectory,
    relative: &Path,
    maximum: u64,
    role: &'static str,
) -> Result<ArtifactFingerprint> {
    let input = campaign.open_file(relative, maximum, role)?;
    budget.charge(&input)?;
    fingerprint_opened_input(input, maximum, role)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use hmac::{Hmac, Mac};
    use marty_perf_schema::SdJwtIssuanceThresholds;
    use serde::{Deserialize, Serialize};
    use sha1::Sha1;

    use super::*;

    const REAL_EMITTED_MANIFEST: &[u8] =
        include_bytes!("../tests/fixtures/sd-jwt-issuance-qualification-manifest-v1.json");

    fn manifest() -> SdJwtIssuanceQualificationManifest {
        serde_json::from_slice(REAL_EMITTED_MANIFEST).expect("real emitted manifest JSON")
    }

    fn canonical_manifest_bytes(value: &SdJwtIssuanceQualificationManifest) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).expect("manifest JSON");
        bytes.push(b'\n');
        bytes
    }

    fn field_names(fields: &[SdJwtIssuanceEvidenceFieldProtocol]) -> Vec<&str> {
        fields.iter().map(|field| field.name.as_str()).collect()
    }

    #[derive(Clone, Debug)]
    struct RouteBatchModel {
        ordinal: u64,
        selector: SelectorBatchModel,
        chunk_size: Option<u64>,
        chunks: Option<Vec<(u64, u64, u64)>>,
    }

    #[derive(Clone, Debug)]
    struct RouteRecordModel {
        requested: &'static str,
        effective: &'static str,
        executor_batches: Option<u64>,
        serial_batches: Option<u64>,
        native_batches: Option<u64>,
        budget_fallback_batches: Option<u64>,
        max_native_worker_count: u64,
        worker_cap: u64,
        host_available_parallelism: u64,
        ready_batches: Option<Vec<RouteBatchModel>>,
    }

    #[derive(Clone, Debug)]
    enum GateState {
        Skipped,
        Evaluated,
    }

    #[derive(Clone, Debug)]
    struct SelectorBatchModel {
        jobs: u64,
        work: Option<u64>,
        work_status: &'static str,
        work_gate: GateState,
        available: Option<u64>,
        selected: Option<u64>,
        parallelism_gate: GateState,
        budget_gate: GateState,
        budget_result: &'static str,
        mode: &'static str,
        reason: &'static str,
        leased: Option<u64>,
        static_layout: Option<()>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct RequiredNullable<T>(Option<T>);

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RouteStaticChunkWire {
        ordinal: u64,
        job_count: u64,
        estimated_work_bytes: u64,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RouteBatchWire {
        ordinal: u64,
        job_count: u64,
        estimated_work_bytes: RequiredNullable<u64>,
        work_estimate_status: String,
        work_gate_evaluated: bool,
        parallelism_gate_evaluated: bool,
        budget_gate_evaluated: bool,
        available_parallelism: RequiredNullable<u64>,
        selected_worker_count: RequiredNullable<u64>,
        leased_worker_count: RequiredNullable<u64>,
        budget_acquisition_result: String,
        selected_mode: String,
        selection_reason: String,
        static_chunk_size: RequiredNullable<u64>,
        static_chunks: RequiredNullable<Vec<RouteStaticChunkWire>>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RouteRecordWire {
        schema: String,
        benchmark_id: String,
        fixture_id: String,
        stage: String,
        requested: String,
        effective: String,
        executor_batches: RequiredNullable<u64>,
        serial_batches: RequiredNullable<u64>,
        native_batches: RequiredNullable<u64>,
        budget_fallback_batches: RequiredNullable<u64>,
        max_native_worker_count: u64,
        worker_cap: u64,
        host_available_parallelism: u64,
        work_estimator_version: String,
        static_partition_rule_version: String,
        ready_batches: RequiredNullable<Vec<RouteBatchWire>>,
    }

    fn route_literal(value: &str) -> Option<&'static str> {
        match value {
            "serial_oracle" => Some("serial_oracle"),
            "adaptive_candidate" => Some("adaptive_candidate"),
            "bounded_native" => Some("bounded_native"),
            "mixed_native_and_serial" => Some("mixed_native_and_serial"),
            "ready_batch_serial_fallback" => Some("ready_batch_serial_fallback"),
            "budget_serial_fallback" => Some("budget_serial_fallback"),
            "target_serial_fallback" => Some("target_serial_fallback"),
            "not_evaluated" => Some("not_evaluated"),
            "available" => Some("available"),
            "overflow" => Some("overflow"),
            "acquired" => Some("acquired"),
            "unavailable" => Some("unavailable"),
            "serial" => Some("serial"),
            "native_parallel" => Some("native_parallel"),
            "below_min_jobs" => Some("below_min_jobs"),
            "work_estimate_overflow" => Some("work_estimate_overflow"),
            "below_min_estimated_work_bytes" => Some("below_min_estimated_work_bytes"),
            "insufficient_available_parallelism" => Some("insufficient_available_parallelism"),
            "worker_budget_unavailable" => Some("worker_budget_unavailable"),
            _ => None,
        }
    }

    fn route_batches_from_wire(values: Vec<RouteBatchWire>) -> Option<Vec<RouteBatchModel>> {
        let mut batches = Vec::with_capacity(values.len());
        for value in values {
            let work_status = route_literal(&value.work_estimate_status)?;
            let budget_result = route_literal(&value.budget_acquisition_result)?;
            let mode = route_literal(&value.selected_mode)?;
            let reason = route_literal(&value.selection_reason)?;
            let chunks = value.static_chunks.0.map(|chunks| {
                chunks
                    .into_iter()
                    .map(|chunk| (chunk.ordinal, chunk.job_count, chunk.estimated_work_bytes))
                    .collect()
            });
            let static_layout =
                (value.static_chunk_size.0.is_some() && chunks.is_some()).then_some(());
            batches.push(RouteBatchModel {
                ordinal: value.ordinal,
                selector: SelectorBatchModel {
                    jobs: value.job_count,
                    work: value.estimated_work_bytes.0,
                    work_status,
                    work_gate: if value.work_gate_evaluated {
                        GateState::Evaluated
                    } else {
                        GateState::Skipped
                    },
                    available: value.available_parallelism.0,
                    selected: value.selected_worker_count.0,
                    parallelism_gate: if value.parallelism_gate_evaluated {
                        GateState::Evaluated
                    } else {
                        GateState::Skipped
                    },
                    budget_gate: if value.budget_gate_evaluated {
                        GateState::Evaluated
                    } else {
                        GateState::Skipped
                    },
                    budget_result,
                    mode,
                    reason,
                    leased: value.leased_worker_count.0,
                    static_layout,
                },
                chunk_size: value.static_chunk_size.0,
                chunks,
            });
        }
        Some(batches)
    }

    fn valid_route_wire_bytes(
        bytes: &[u8],
        expected_benchmark_id: &str,
        expected_fixture_id: &str,
        expected_stage: &str,
        expected_requested: &str,
        expected_worker_cap: u64,
        expected_host_available_parallelism: u64,
    ) -> bool {
        if bytes.len() > 1024 * 1024 || !bytes.ends_with(b"\n") || bytes.ends_with(b"\n\n") {
            return false;
        }
        let body = &bytes[..bytes.len() - 1];
        let mut deserializer = serde_json::Deserializer::from_slice(body);
        let Ok(wire) = RouteRecordWire::deserialize(&mut deserializer) else {
            return false;
        };
        if deserializer.end().is_err() {
            return false;
        }
        let Ok(mut canonical) = serde_json::to_vec(&wire) else {
            return false;
        };
        canonical.push(b'\n');
        if canonical != bytes
            || wire.schema != ROUTE_SCHEMA
            || wire.benchmark_id != expected_benchmark_id
            || wire.fixture_id != expected_fixture_id
            || wire.stage != expected_stage
            || wire.requested != expected_requested
            || wire.work_estimator_version != WORK_ESTIMATOR_VERSION
            || wire.static_partition_rule_version != STATIC_PARTITION_RULE_VERSION
        {
            return false;
        }
        let Some(requested) = route_literal(&wire.requested) else {
            return false;
        };
        let Some(effective) = route_literal(&wire.effective) else {
            return false;
        };
        let batches = match wire.ready_batches.0 {
            None => None,
            Some(values) => Some(match route_batches_from_wire(values) {
                Some(batches) => batches,
                None => return false,
            }),
        };
        valid_route_record(
            &RouteRecordModel {
                requested,
                effective,
                executor_batches: wire.executor_batches.0,
                serial_batches: wire.serial_batches.0,
                native_batches: wire.native_batches.0,
                budget_fallback_batches: wire.budget_fallback_batches.0,
                max_native_worker_count: wire.max_native_worker_count,
                worker_cap: wire.worker_cap,
                host_available_parallelism: wire.host_available_parallelism,
                ready_batches: batches,
            },
            expected_worker_cap,
            expected_host_available_parallelism,
        )
    }

    fn valid_selector_batch(
        batch: &SelectorBatchModel,
        worker_cap: u64,
        host_available_parallelism: u64,
    ) -> bool {
        if batch.jobs == 0 || !(1..=64).contains(&worker_cap) || host_available_parallelism == 0 {
            return false;
        }
        let work_skipped = batch.work.is_none()
            && batch.work_status == "not_evaluated"
            && matches!(batch.work_gate, GateState::Skipped);
        let work_overflow = batch.work.is_none()
            && batch.work_status == "overflow"
            && matches!(batch.work_gate, GateState::Evaluated);
        let work_available = batch
            .work
            .filter(|_| batch.work_status == "available")
            .filter(|_| matches!(batch.work_gate, GateState::Evaluated));
        let parallel_skipped = batch.available.is_none()
            && batch.selected.is_none()
            && matches!(batch.parallelism_gate, GateState::Skipped);
        let expected_selected = host_available_parallelism.min(worker_cap).min(batch.jobs);
        let parallel_evaluated = batch.available == Some(host_available_parallelism)
            && batch.selected == Some(expected_selected)
            && matches!(batch.parallelism_gate, GateState::Evaluated);
        let budget_skipped = matches!(batch.budget_gate, GateState::Skipped)
            && batch.budget_result == "not_evaluated";
        let budget_unavailable = matches!(batch.budget_gate, GateState::Evaluated)
            && batch.budget_result == "unavailable";
        let budget_acquired =
            matches!(batch.budget_gate, GateState::Evaluated) && batch.budget_result == "acquired";
        let serial_static =
            batch.mode == "serial" && batch.leased.is_none() && batch.static_layout.is_none();
        match batch.reason {
            "below_min_jobs" => {
                batch.jobs < 2
                    && work_skipped
                    && parallel_skipped
                    && budget_skipped
                    && serial_static
            }
            "work_estimate_overflow" => {
                batch.jobs >= 2
                    && work_overflow
                    && parallel_skipped
                    && budget_skipped
                    && serial_static
            }
            "below_min_estimated_work_bytes" => {
                batch.jobs >= 2
                    && work_available.is_some_and(|work| work < 1)
                    && parallel_skipped
                    && budget_skipped
                    && serial_static
            }
            "insufficient_available_parallelism" => {
                batch.jobs >= 2
                    && work_available.is_some_and(|work| work >= 1)
                    && parallel_evaluated
                    && expected_selected < 2
                    && budget_skipped
                    && serial_static
            }
            "worker_budget_unavailable" => {
                batch.jobs >= 2
                    && work_available.is_some_and(|work| work >= 1)
                    && parallel_evaluated
                    && expected_selected >= 2
                    && budget_unavailable
                    && serial_static
            }
            "bounded_native" => {
                batch.jobs >= 2
                    && work_available.is_some_and(|work| work >= 1)
                    && parallel_evaluated
                    && expected_selected >= 2
                    && budget_acquired
                    && batch.mode == "native_parallel"
                    && batch.leased == batch.selected
                    && batch.static_layout.is_some()
            }
            _ => false,
        }
    }

    fn valid_static_chunks(
        batch: &RouteBatchModel,
        worker_cap: u64,
        host_available_parallelism: u64,
    ) -> bool {
        if !valid_selector_batch(&batch.selector, worker_cap, host_available_parallelism) {
            return false;
        }
        if batch.selector.mode != "native_parallel" {
            return batch.chunk_size.is_none() && batch.chunks.is_none();
        }
        let (Some(workers), Some(leased), Some(work), Some(size), Some(chunks)) = (
            batch.selector.selected,
            batch.selector.leased,
            batch.selector.work,
            batch.chunk_size,
            batch.chunks.as_ref(),
        ) else {
            return false;
        };
        if workers == 0 || batch.selector.jobs == 0 {
            return false;
        }
        let Some(expected_size) = batch
            .selector
            .jobs
            .checked_add(workers - 1)
            .map(|value| value / workers)
        else {
            return false;
        };
        let Some(expected_count) = batch
            .selector
            .jobs
            .checked_add(expected_size - 1)
            .map(|value| value / expected_size)
        else {
            return false;
        };
        leased == workers
            && expected_count <= workers
            && size == expected_size
            && u64::try_from(chunks.len()) == Ok(expected_count)
            && chunks
                .iter()
                .enumerate()
                .all(|(index, (ordinal, jobs, _))| {
                    *ordinal == index as u64
                        && *jobs > 0
                        && *jobs <= size
                        && (index + 1 == chunks.len() || *jobs == size)
                })
            && chunks
                .iter()
                .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.1))
                == Some(batch.selector.jobs)
            && chunks
                .iter()
                .try_fold(0_u64, |sum, chunk| sum.checked_add(chunk.2))
                == Some(work)
    }

    fn valid_route_record(
        record: &RouteRecordModel,
        expected_worker_cap: u64,
        expected_host_available_parallelism: u64,
    ) -> bool {
        if record.worker_cap != expected_worker_cap
            || record.host_available_parallelism != expected_host_available_parallelism
            || !(1..=64).contains(&record.worker_cap)
            || record.host_available_parallelism == 0
        {
            return false;
        }
        let Some(batches) = record.ready_batches.as_ref() else {
            let branch_valid = (record.requested == "serial_oracle"
                && record.effective == "serial_oracle")
                || (record.requested == "adaptive_candidate"
                    && record.effective == "target_serial_fallback"
                    && record.worker_cap == 1);
            return branch_valid
                && record.executor_batches.is_none()
                && record.serial_batches.is_none()
                && record.native_batches.is_none()
                && record.budget_fallback_batches.is_none()
                && record.max_native_worker_count == 0;
        };
        if record.worker_cap == 1 {
            return false;
        }
        let executor = batches.len() as u64;
        let native = batches
            .iter()
            .filter(|batch| batch.selector.mode == "native_parallel")
            .count() as u64;
        let serial = executor - native;
        let budget = batches
            .iter()
            .filter(|batch| batch.selector.reason == "worker_budget_unavailable")
            .count() as u64;
        let maximum = batches
            .iter()
            .filter_map(|batch| batch.selector.leased)
            .max()
            .unwrap_or(0);
        let effective = if native > 0 && serial > 0 {
            "mixed_native_and_serial"
        } else if native > 0 {
            "bounded_native"
        } else if budget > 0 {
            "budget_serial_fallback"
        } else {
            "ready_batch_serial_fallback"
        };
        record.requested == "adaptive_candidate"
            && record.effective == effective
            && record.executor_batches == Some(executor)
            && record.serial_batches == Some(serial)
            && record.native_batches == Some(native)
            && record.budget_fallback_batches == Some(budget)
            && record.max_native_worker_count == maximum
            && budget <= serial
            && maximum <= record.worker_cap
            && batches.iter().enumerate().all(|(ordinal, batch)| {
                batch.ordinal == ordinal as u64
                    && valid_static_chunks(
                        batch,
                        record.worker_cap,
                        record.host_available_parallelism,
                    )
            })
    }

    #[derive(Clone, Copy)]
    enum IndexArtifactKind {
        Criterion,
        Route,
    }

    impl IndexArtifactKind {
        fn schema(self) -> &'static str {
            match self {
                Self::Criterion => "marty.performance/sd-jwt-issuance-criterion-artifact-index/v1",
                Self::Route => "marty.performance/sd-jwt-issuance-route-artifact-index/v1",
            }
        }

        fn literal(self) -> &'static str {
            match self {
                Self::Criterion => "criterion_0_5_1_new_estimates_json",
                Self::Route => "sd_jwt_issuance_route_v2",
            }
        }

        fn fingerprint_domain(self) -> &'static [u8] {
            match self {
                Self::Criterion => b"criterion-index-fixture-v1\0",
                Self::Route => b"route-index-fixture-v1\0",
            }
        }
    }

    #[derive(Clone)]
    struct IndexEntryModel {
        global_round_ordinal: u32,
        cell_ordinal: u32,
        expansion_position: u32,
        timing_process_id: String,
        full_benchmark_id: String,
        relative_path: String,
        fingerprint: ArtifactFingerprint,
    }

    #[derive(Clone)]
    struct ArtifactIndexModel {
        schema: String,
        campaign_id: String,
        artifact_kind: String,
        entry_count: u32,
        entries: Vec<IndexEntryModel>,
    }

    fn coordinate_at(position: usize) -> Option<(u32, u32, u32)> {
        let position = u32::try_from(position).ok()?;
        (position < 10_560).then_some((position / 528, (position % 528) / 8, position % 8))
    }

    fn scheduled_benchmark_id(
        manifest: &SdJwtIssuanceQualificationManifest,
        round: u32,
        cell: u32,
        expansion: u32,
    ) -> Option<&str> {
        let order = *SUPERBLOCK_ORDERS.get(usize::try_from(round).ok()?)?;
        let route = match order {
            "ABBA_FIRST" => *ABBA_EXPANSION.get(usize::try_from(expansion).ok()?)?,
            "BAAB_FIRST" => *BAAB_EXPANSION.get(usize::try_from(expansion).ok()?)?,
            _ => return None,
        };
        let cell = manifest.paired_cells.get(usize::try_from(cell).ok()?)?;
        match route {
            "serial" => Some(cell.serial_id.as_str()),
            "adaptive" => Some(cell.adaptive_id.as_str()),
            _ => None,
        }
    }

    fn exact_index_path(
        kind: IndexArtifactKind,
        round: u32,
        cell: u32,
        expansion: u32,
        full_benchmark_id: &str,
    ) -> Option<String> {
        if round >= 20 || cell >= 66 || expansion >= 8 {
            return None;
        }
        match kind {
            IndexArtifactKind::Route => {
                Some(format!("routes/r{round:02}_c{cell:02}_e{expansion}.ndjson"))
            }
            IndexArtifactKind::Criterion => {
                let function_id = full_benchmark_id.strip_prefix("sd_jwt_issuance/")?;
                (!function_id.is_empty()).then(|| {
                    format!(
                        "criterion/r{round:02}_c{cell:02}_e{expansion}/sd_jwt_issuance/{function_id}/new/estimates.json"
                    )
                })
            }
        }
    }

    fn valid_index_entry(
        manifest: &SdJwtIssuanceQualificationManifest,
        position: usize,
        kind: IndexArtifactKind,
        entry: &IndexEntryModel,
        expected_fingerprint: &ArtifactFingerprint,
    ) -> bool {
        let Some((round, cell, expansion)) = coordinate_at(position) else {
            return false;
        };
        let Some(expected_id) = scheduled_benchmark_id(manifest, round, cell, expansion) else {
            return false;
        };
        let Some(expected_path) = exact_index_path(kind, round, cell, expansion, expected_id)
        else {
            return false;
        };
        entry.global_round_ordinal == round
            && entry.cell_ordinal == cell
            && entry.expansion_position == expansion
            && entry.timing_process_id == format!("r{round:02}-c{cell:02}-e{expansion}")
            && entry.full_benchmark_id == expected_id
            && entry.relative_path == expected_path
            && &entry.fingerprint == expected_fingerprint
    }

    fn valid_index_entries(
        manifest: &SdJwtIssuanceQualificationManifest,
        kind: IndexArtifactKind,
        entries: &[IndexEntryModel],
        expected_fingerprints: &[ArtifactFingerprint],
    ) -> bool {
        entries.len() == 10_560
            && expected_fingerprints.len() == entries.len()
            && entries.iter().enumerate().all(|(position, entry)| {
                valid_index_entry(
                    manifest,
                    position,
                    kind,
                    entry,
                    &expected_fingerprints[position],
                )
            })
    }

    fn valid_artifact_index(
        manifest: &SdJwtIssuanceQualificationManifest,
        expected_campaign_id: &str,
        kind: IndexArtifactKind,
        index: &ArtifactIndexModel,
        expected_fingerprints: &[ArtifactFingerprint],
    ) -> bool {
        index.schema == kind.schema()
            && index.campaign_id == expected_campaign_id
            && index.artifact_kind == kind.literal()
            && index.entry_count == 10_560
            && usize::try_from(index.entry_count) == Ok(index.entries.len())
            && valid_index_entries(manifest, kind, &index.entries, expected_fingerprints)
    }

    fn synthetic_index_fingerprint(
        position: usize,
        kind: IndexArtifactKind,
    ) -> ArtifactFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(kind.fingerprint_domain());
        hasher.update(u64::try_from(position).unwrap().to_be_bytes());
        ArtifactFingerprint {
            sha256: hex::encode_upper(hasher.finalize()),
            byte_length: u64::try_from(position).unwrap() + 1,
        }
    }

    fn canonical_index_entry(
        manifest: &SdJwtIssuanceQualificationManifest,
        position: usize,
        kind: IndexArtifactKind,
    ) -> IndexEntryModel {
        let (round, cell, expansion) = coordinate_at(position).unwrap();
        let full_benchmark_id = scheduled_benchmark_id(manifest, round, cell, expansion).unwrap();
        IndexEntryModel {
            global_round_ordinal: round,
            cell_ordinal: cell,
            expansion_position: expansion,
            timing_process_id: format!("r{round:02}-c{cell:02}-e{expansion}"),
            full_benchmark_id: full_benchmark_id.to_owned(),
            relative_path: exact_index_path(kind, round, cell, expansion, full_benchmark_id)
                .unwrap(),
            fingerprint: synthetic_index_fingerprint(position, kind),
        }
    }

    fn canonical_index_entries(
        manifest: &SdJwtIssuanceQualificationManifest,
        kind: IndexArtifactKind,
    ) -> Vec<IndexEntryModel> {
        (0..10_560)
            .map(|position| canonical_index_entry(manifest, position, kind))
            .collect()
    }

    fn canonical_artifact_index(
        manifest: &SdJwtIssuanceQualificationManifest,
        campaign_id: &str,
        kind: IndexArtifactKind,
    ) -> ArtifactIndexModel {
        ArtifactIndexModel {
            schema: kind.schema().to_owned(),
            campaign_id: campaign_id.to_owned(),
            artifact_kind: kind.literal().to_owned(),
            entry_count: 10_560,
            entries: canonical_index_entries(manifest, kind),
        }
    }

    fn valid_uppercase_hex(value: &str, characters: usize) -> bool {
        value.len() == characters
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    }

    fn valid_lowercase_hex(value: &str, characters: usize) -> bool {
        value.len() == characters
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SourceArchiveManifestWire {
        schema: String,
        git_object_format: String,
        source_commit: String,
        source_tree: String,
        entry_count: u32,
        entries: Vec<SourceArchiveEntryWire>,
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SourceArchiveEntryWire {
        repository_relative_path: String,
        git_mode: String,
        git_object_id: String,
        artifact_fingerprint: ArtifactFingerprint,
    }

    fn valid_source_archive_segment(segment: &str) -> bool {
        let portable = segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'@' | b'+' | b'-')
        });
        let stem = segment
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        portable
            && !segment.is_empty()
            && segment != "."
            && segment != ".."
            && !segment.eq_ignore_ascii_case(".git")
            && !segment.ends_with('.')
            && !reserved
            && segment.len() <= usize::try_from(MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES).unwrap()
    }

    fn valid_source_archive_path(path: &str) -> bool {
        (1..=usize::try_from(MAX_SOURCE_ARCHIVE_PATH_V1_BYTES).unwrap()).contains(&path.len())
            && !path.starts_with('/')
            && {
                let segments = path.split('/').collect::<Vec<_>>();
                u32::try_from(segments.len()).is_ok_and(|count| {
                    count <= MAX_SOURCE_ARCHIVE_PATH_SEGMENTS
                        && segments.into_iter().all(valid_source_archive_segment)
                })
            }
    }

    enum SourcePathChild {
        Directory { name: String, node: usize },
        File { name: String, entry: usize },
    }

    #[derive(Default)]
    struct SourcePathNode {
        children_by_folded_name: BTreeMap<String, SourcePathChild>,
    }

    fn add_derived_component_bytes(total: &mut u64, segment: &str, maximum: u64) -> Option<()> {
        *total = total.checked_add(u64::try_from(segment.len()).ok()?)?;
        (*total <= maximum).then_some(())
    }

    fn build_source_path_tree(
        entries: &[SourceArchiveEntryWire],
        maximum_nodes: usize,
        maximum_component_bytes: u64,
    ) -> Option<Vec<SourcePathNode>> {
        if maximum_nodes == 0 {
            return None;
        }
        let mut nodes = vec![SourcePathNode::default()];
        let mut component_bytes = 0_u64;
        for (entry_index, entry) in entries.iter().enumerate() {
            if !valid_source_archive_path(&entry.repository_relative_path) {
                return None;
            }
            let segments = entry
                .repository_relative_path
                .split('/')
                .collect::<Vec<_>>();
            let (file_name, directories) = segments.split_last()?;
            let mut parent = 0_usize;
            for segment in directories {
                let folded = segment.to_ascii_lowercase();
                let existing = nodes[parent].children_by_folded_name.get(&folded);
                if let Some(SourcePathChild::Directory { name, node }) = existing {
                    if name != segment {
                        return None;
                    }
                    parent = *node;
                    continue;
                }
                if existing.is_some() || nodes.len() >= maximum_nodes {
                    return None;
                }
                add_derived_component_bytes(
                    &mut component_bytes,
                    segment,
                    maximum_component_bytes,
                )?;
                let child = nodes.len();
                nodes.push(SourcePathNode::default());
                nodes[parent].children_by_folded_name.insert(
                    folded,
                    SourcePathChild::Directory {
                        name: (*segment).to_owned(),
                        node: child,
                    },
                );
                parent = child;
            }
            let folded = file_name.to_ascii_lowercase();
            if nodes[parent].children_by_folded_name.contains_key(&folded) {
                return None;
            }
            add_derived_component_bytes(&mut component_bytes, file_name, maximum_component_bytes)?;
            nodes[parent].children_by_folded_name.insert(
                folded,
                SourcePathChild::File {
                    name: (*file_name).to_owned(),
                    entry: entry_index,
                },
            );
        }
        Some(nodes)
    }

    fn source_archive_paths_are_materializable(entries: &[SourceArchiveEntryWire]) -> bool {
        build_source_path_tree(
            entries,
            usize::try_from(MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES).unwrap(),
            MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
        )
        .is_some()
    }

    fn git_object_id(kind: &str, body: &[u8]) -> [u8; 20] {
        let header = format!("{kind} {}\0", body.len());
        let mut hasher = Sha1::new();
        hasher.update(header.as_bytes());
        hasher.update(body);
        hasher.finalize().into()
    }

    fn canonical_unsigned_decimal(value: &[u8]) -> Option<u64> {
        if value.is_empty()
            || !value.iter().all(u8::is_ascii_digit)
            || (value.len() > 1 && value.starts_with(b"0"))
        {
            return None;
        }
        value.iter().try_fold(0_u64, |parsed, byte| {
            parsed.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
        })
    }

    fn valid_git_timezone(value: &[u8]) -> bool {
        if value.len() != 5
            || !matches!(value[0], b'+' | b'-')
            || !value[1..].iter().all(u8::is_ascii_digit)
        {
            return false;
        }
        let hours = (value[1] - b'0') * 10 + value[2] - b'0';
        let minutes = (value[3] - b'0') * 10 + value[4] - b'0';
        hours <= 23 && minutes <= 59 && !(hours == 0 && minutes == 0 && value[0] == b'-')
    }

    fn split_last_ascii_space(value: &[u8]) -> Option<(&[u8], &[u8])> {
        let index = value.iter().rposition(|byte| *byte == b' ')?;
        Some((&value[..index], &value[index + 1..]))
    }

    fn git_commit_committer_timestamp(commit: &[u8], expected_tree: &str) -> Option<u64> {
        let header_end = commit.windows(2).position(|pair| pair == b"\n\n")?;
        let headers = &commit[..header_end];
        if headers.contains(&b'\r') || headers.contains(&0) {
            return None;
        }
        let mut lines = headers.split(|byte| *byte == b'\n');
        let expected_tree_header = format!("tree {expected_tree}");
        (lines.next()? == expected_tree_header.as_bytes()).then_some(())?;
        let mut tree_headers = 1_u32;
        let mut committer_timestamp = None;
        for line in lines {
            if line.starts_with(b"tree ") {
                tree_headers = tree_headers.checked_add(1)?;
            }
            let Some(committer) = line.strip_prefix(b"committer ") else {
                continue;
            };
            if committer_timestamp.is_some() {
                return None;
            }
            let (identity_and_timestamp, timezone) = split_last_ascii_space(committer)?;
            let (identity, timestamp) = split_last_ascii_space(identity_and_timestamp)?;
            if identity.is_empty()
                || !identity.contains(&b'<')
                || !identity.ends_with(b">")
                || !valid_git_timezone(timezone)
            {
                return None;
            }
            committer_timestamp = Some(canonical_unsigned_decimal(timestamp)?);
        }
        (tree_headers == 1).then_some(committer_timestamp?)
    }

    fn reconstructed_source_tree_with_limits(
        entries: &[SourceArchiveEntryWire],
        contents: &[&[u8]],
        maximum_nodes: usize,
        maximum_component_bytes: u64,
    ) -> Option<[u8; 20]> {
        if entries.len() != contents.len() {
            return None;
        }
        let nodes = build_source_path_tree(entries, maximum_nodes, maximum_component_bytes)?;
        let mut tree_ids = vec![[0_u8; 20]; nodes.len()];
        for node_index in (0..nodes.len()).rev() {
            let mut components = Vec::<(Vec<u8>, String, String, [u8; 20])>::new();
            for child in nodes[node_index].children_by_folded_name.values() {
                match child {
                    SourcePathChild::File { name, entry } => {
                        let source_entry = entries.get(*entry)?;
                        let content = *contents.get(*entry)?;
                        let object_id = git_object_id("blob", content);
                        if hex::encode(object_id) != source_entry.git_object_id {
                            return None;
                        }
                        let mut sort_key = name.as_bytes().to_vec();
                        sort_key.push(0);
                        components.push((
                            sort_key,
                            name.clone(),
                            source_entry.git_mode.clone(),
                            object_id,
                        ));
                    }
                    SourcePathChild::Directory { name, node } => {
                        let object_id = *tree_ids.get(*node)?;
                        let mut sort_key = name.as_bytes().to_vec();
                        sort_key.push(b'/');
                        components.push((sort_key, name.clone(), "40000".to_owned(), object_id));
                    }
                }
            }
            components.sort_by(|left, right| left.0.cmp(&right.0));
            let mut tree_body = Vec::new();
            for (_, name, mode, object_id) in components {
                tree_body.extend_from_slice(mode.as_bytes());
                tree_body.push(b' ');
                tree_body.extend_from_slice(name.as_bytes());
                tree_body.push(0);
                tree_body.extend_from_slice(&object_id);
            }
            tree_ids[node_index] = git_object_id("tree", &tree_body);
        }
        tree_ids.first().copied()
    }

    fn reconstructed_source_tree(
        entries: &[SourceArchiveEntryWire],
        contents: &[&[u8]],
    ) -> Option<[u8; 20]> {
        reconstructed_source_tree_with_limits(
            entries,
            contents,
            usize::try_from(MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES).unwrap(),
            MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
        )
    }

    fn take_u64_be(bytes: &[u8], cursor: &mut usize) -> Option<usize> {
        let end = cursor.checked_add(8)?;
        let encoded: [u8; 8] = bytes.get(*cursor..end)?.try_into().ok()?;
        *cursor = end;
        usize::try_from(u64::from_be_bytes(encoded)).ok()
    }

    fn take_bounded<'a>(
        bytes: &'a [u8],
        cursor: &mut usize,
        length: usize,
        maximum: usize,
    ) -> Option<&'a [u8]> {
        if length > maximum {
            return None;
        }
        let end = cursor.checked_add(length)?;
        let value = bytes.get(*cursor..end)?;
        *cursor = end;
        Some(value)
    }

    fn parse_source_archive_manifest(bytes: &[u8]) -> Option<SourceArchiveManifestWire> {
        if !bytes.ends_with(b"\n") {
            return None;
        }
        let manifest = serde_json::from_slice::<SourceArchiveManifestWire>(bytes).ok()?;
        let mut canonical = serde_json::to_vec_pretty(&manifest).ok()?;
        canonical.push(b'\n');
        let valid = canonical == bytes
            && manifest.schema == "marty.performance/sd-jwt-issuance-source-archive-manifest/v1"
            && manifest.git_object_format == "sha1"
            && valid_lowercase_hex(&manifest.source_commit, 40)
            && valid_lowercase_hex(&manifest.source_tree, 40)
            && (1..=MAX_SOURCE_ARCHIVE_V1_ENTRIES).contains(&manifest.entry_count)
            && usize::try_from(manifest.entry_count) == Ok(manifest.entries.len())
            && source_archive_paths_are_materializable(&manifest.entries)
            && manifest.entries.iter().all(|entry| {
                valid_source_archive_path(&entry.repository_relative_path)
                    && matches!(entry.git_mode.as_str(), "100644" | "100755")
                    && valid_lowercase_hex(&entry.git_object_id, 40)
            })
            && manifest.entries.windows(2).all(|pair| {
                pair[0].repository_relative_path.as_bytes()
                    < pair[1].repository_relative_path.as_bytes()
            });
        valid.then_some(manifest)
    }

    fn valid_source_archive_bytes(
        bytes: &[u8],
        expected_outer_fingerprint: &ArtifactFingerprint,
        expected_cargo_lock_fingerprint: &ArtifactFingerprint,
    ) -> bool {
        let Ok(maximum_archive_bytes) = usize::try_from(MAX_SOURCE_ARCHIVE_V1_BYTES) else {
            return false;
        };
        let Ok(maximum_manifest_bytes) = usize::try_from(MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES)
        else {
            return false;
        };
        let Ok(maximum_commit_bytes) = usize::try_from(MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES) else {
            return false;
        };
        if bytes.len() > maximum_archive_bytes
            || expected_outer_fingerprint.byte_length != bytes.len() as u64
            || expected_outer_fingerprint.sha256 != hex::encode_upper(Sha256::digest(bytes))
        {
            return false;
        }
        let magic = b"MARTY-SD-JWT-SOURCE-ARCHIVE-V1\n";
        if !bytes.starts_with(magic) {
            return false;
        }
        let mut cursor = magic.len();
        let Some(manifest_length) = take_u64_be(bytes, &mut cursor) else {
            return false;
        };
        let Some(manifest_bytes) =
            take_bounded(bytes, &mut cursor, manifest_length, maximum_manifest_bytes)
        else {
            return false;
        };
        let Some(manifest) = parse_source_archive_manifest(manifest_bytes) else {
            return false;
        };
        let Some(commit_length) = take_u64_be(bytes, &mut cursor) else {
            return false;
        };
        let Some(commit) = take_bounded(bytes, &mut cursor, commit_length, maximum_commit_bytes)
        else {
            return false;
        };
        let mut contents = Vec::with_capacity(manifest.entries.len());
        for entry in &manifest.entries {
            let Some(content_length) = take_u64_be(bytes, &mut cursor) else {
                return false;
            };
            let Some(content) =
                take_bounded(bytes, &mut cursor, content_length, maximum_archive_bytes)
            else {
                return false;
            };
            if entry.artifact_fingerprint.byte_length != content.len() as u64
                || entry.artifact_fingerprint.sha256 != hex::encode_upper(Sha256::digest(content))
            {
                return false;
            }
            contents.push(content);
        }
        let Some(source_tree) = reconstructed_source_tree(&manifest.entries, &contents) else {
            return false;
        };
        let source_tree = hex::encode(source_tree);
        let cargo_lock_matches = manifest
            .entries
            .iter()
            .zip(&contents)
            .find(|(entry, _)| entry.repository_relative_path == "Cargo.lock")
            .is_some_and(|(entry, content)| {
                entry.artifact_fingerprint == *expected_cargo_lock_fingerprint
                    && source_archive_fingerprint(content) == *expected_cargo_lock_fingerprint
            });
        cursor == bytes.len()
            && source_tree == manifest.source_tree
            && git_commit_committer_timestamp(commit, &source_tree).is_some()
            && hex::encode(git_object_id("commit", commit)) == manifest.source_commit
            && cargo_lock_matches
    }

    fn encode_source_archive(
        manifest: &SourceArchiveManifestWire,
        commit: &[u8],
        contents: &[&[u8]],
    ) -> Vec<u8> {
        let mut manifest_bytes = serde_json::to_vec_pretty(manifest).unwrap();
        manifest_bytes.push(b'\n');
        let mut archive = b"MARTY-SD-JWT-SOURCE-ARCHIVE-V1\n".to_vec();
        archive.extend_from_slice(&u64::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
        archive.extend_from_slice(&manifest_bytes);
        archive.extend_from_slice(&u64::try_from(commit.len()).unwrap().to_be_bytes());
        archive.extend_from_slice(commit);
        for content in contents {
            archive.extend_from_slice(&u64::try_from(content.len()).unwrap().to_be_bytes());
            archive.extend_from_slice(content);
        }
        archive
    }

    fn source_archive_fingerprint(bytes: &[u8]) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: hex::encode_upper(Sha256::digest(bytes)),
            byte_length: u64::try_from(bytes.len()).unwrap(),
        }
    }

    fn source_archive_with_rebound_commit(
        fixture: &GoldenSourceArchiveFixture,
        commit: &[u8],
    ) -> Vec<u8> {
        let mut manifest = fixture.manifest.clone();
        manifest.source_commit = hex::encode(git_object_id("commit", commit));
        encode_source_archive(&manifest, commit, &fixture.contents)
    }

    struct GoldenSourceArchiveFixture {
        manifest: SourceArchiveManifestWire,
        contents: [&'static [u8]; 2],
        commit: Vec<u8>,
        archive: Vec<u8>,
        cargo_lock_fingerprint: ArtifactFingerprint,
    }

    fn golden_source_archive_fixture() -> GoldenSourceArchiveFixture {
        let contents = [b"lock\n".as_slice(), b"pub fn fixture() {}\n".as_slice()];
        let mut manifest = SourceArchiveManifestWire {
            schema: "marty.performance/sd-jwt-issuance-source-archive-manifest/v1".to_owned(),
            git_object_format: "sha1".to_owned(),
            source_commit: String::new(),
            source_tree: String::new(),
            entry_count: 2,
            entries: vec![
                SourceArchiveEntryWire {
                    repository_relative_path: "Cargo.lock".to_owned(),
                    git_mode: "100644".to_owned(),
                    git_object_id: hex::encode(git_object_id("blob", contents[0])),
                    artifact_fingerprint: ArtifactFingerprint {
                        sha256: hex::encode_upper(Sha256::digest(contents[0])),
                        byte_length: u64::try_from(contents[0].len()).unwrap(),
                    },
                },
                SourceArchiveEntryWire {
                    repository_relative_path: "src/lib.rs".to_owned(),
                    git_mode: "100644".to_owned(),
                    git_object_id: hex::encode(git_object_id("blob", contents[1])),
                    artifact_fingerprint: ArtifactFingerprint {
                        sha256: hex::encode_upper(Sha256::digest(contents[1])),
                        byte_length: u64::try_from(contents[1].len()).unwrap(),
                    },
                },
            ],
        };
        manifest.source_tree =
            hex::encode(reconstructed_source_tree(&manifest.entries, &contents).unwrap());
        let commit = format!(
            "tree {}\nauthor Marty Fixture <fixture@example.invalid> 1700000000 -0700\ncommitter Marty Fixture <fixture@example.invalid> 1700000123 +0530\n\nfixture\n",
            manifest.source_tree
        )
        .into_bytes();
        manifest.source_commit = hex::encode(git_object_id("commit", &commit));
        let archive = encode_source_archive(&manifest, &commit, &contents);
        let cargo_lock_fingerprint = source_archive_fingerprint(contents[0]);
        GoldenSourceArchiveFixture {
            manifest,
            contents,
            commit,
            archive,
            cargo_lock_fingerprint,
        }
    }

    fn valid_receipt_id(value: &str) -> bool {
        (1..=128).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    }

    #[derive(Serialize)]
    struct GoldenSample {
        schema: &'static str,
        campaign_id: &'static str,
        segment_ordinal: u32,
        record_ordinal: u32,
        sample_ordinal: u64,
        utc_rfc3339_nanoseconds: &'static str,
        monotonic_nanoseconds: u64,
        boot_identity_pseudonym: &'static str,
        timing_state: &'static str,
        global_round_ordinal: Option<u32>,
        cell_ordinal: Option<u32>,
        expansion_position: Option<u32>,
        timing_process_id: Option<&'static str>,
        total_cpu_percent: f64,
        monitor_cpu_percent: f64,
        benchmark_cpu_percent: f64,
        unrelated_cpu_percent: f64,
        available_memory_bytes: u64,
        cpu_frequency_hz: u64,
        maximum_temperature_millidegrees_celsius: i64,
        throttle_flags: Vec<&'static str>,
        unrelated_process_set_fingerprint: ArtifactFingerprint,
        active_test_window_attestation_fingerprint: ArtifactFingerprint,
    }

    #[derive(Serialize)]
    struct GoldenProcessCompletion {
        global_round_ordinal: u32,
        cell_ordinal: u32,
        expansion_position: u32,
        timing_process_id: &'static str,
        full_benchmark_id: &'static str,
        process_intent_record_fingerprint: ArtifactFingerprint,
        process_start_record_fingerprint: ArtifactFingerprint,
        process_finish_record_fingerprint: ArtifactFingerprint,
        invocation_descriptor_fingerprint: ArtifactFingerprint,
        launch_barrier_receipt_fingerprint: ArtifactFingerprint,
        criterion_home_initial_inventory_fingerprint: ArtifactFingerprint,
        criterion_home_final_inventory_fingerprint: ArtifactFingerprint,
        criterion_artifact_fingerprint: ArtifactFingerprint,
        route_artifact_fingerprint: ArtifactFingerprint,
    }

    #[derive(Clone, Serialize)]
    struct GoldenTerminalObservationUnsigned<'a> {
        schema: &'a str,
        campaign_id: &'a str,
        channel_id: &'a str,
        log_id: &'a str,
        campaign_append_ordinal: u64,
        channel_clock_session_id: &'a str,
        channel_monotonic_nanoseconds: u64,
        observed_at_utc_rfc3339_nanoseconds: &'a str,
        channel_receipt_id: &'a str,
        challenge_uppercase_hex_256: &'a str,
        terminal_segment_fingerprint: ArtifactFingerprint,
        terminal_footer_monotonic_nanoseconds: u64,
        controller_request_monotonic_nanoseconds: u64,
        signing_key_id: &'a str,
    }

    #[derive(Clone, Serialize)]
    struct GoldenCompletionAnchorUnsigned<'a> {
        schema: &'a str,
        campaign_id: &'a str,
        channel_id: &'a str,
        log_id: &'a str,
        campaign_append_ordinal: u64,
        channel_clock_session_id: &'a str,
        channel_monotonic_nanoseconds: u64,
        published_at_utc_rfc3339_nanoseconds: &'a str,
        channel_receipt_id: &'a str,
        challenge_uppercase_hex_256: &'a str,
        completion_fingerprint: ArtifactFingerprint,
        terminal_segment_fingerprint: ArtifactFingerprint,
        terminal_observation_evidence_fingerprint: ArtifactFingerprint,
        signing_key_id: &'a str,
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TerminalObservationReceiptWire {
        schema: String,
        campaign_id: String,
        channel_id: String,
        log_id: String,
        campaign_append_ordinal: u64,
        channel_clock_session_id: String,
        channel_monotonic_nanoseconds: u64,
        observed_at_utc_rfc3339_nanoseconds: String,
        channel_receipt_id: String,
        challenge_uppercase_hex_256: String,
        terminal_segment_fingerprint: ArtifactFingerprint,
        terminal_footer_monotonic_nanoseconds: u64,
        controller_request_monotonic_nanoseconds: u64,
        signing_key_id: String,
        signature_uppercase_hex_512: String,
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct CompletionAnchorWire {
        schema: String,
        campaign_id: String,
        channel_id: String,
        log_id: String,
        campaign_append_ordinal: u64,
        channel_clock_session_id: String,
        channel_monotonic_nanoseconds: u64,
        published_at_utc_rfc3339_nanoseconds: String,
        channel_receipt_id: String,
        challenge_uppercase_hex_256: String,
        completion_fingerprint: ArtifactFingerprint,
        terminal_segment_fingerprint: ArtifactFingerprint,
        terminal_observation_evidence_fingerprint: ArtifactFingerprint,
        signing_key_id: String,
        signature_uppercase_hex_512: String,
    }

    fn signed_json_preimage(domain_with_nul: &[u8], unsigned_json: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(domain_with_nul.len() + 8 + unsigned_json.len());
        preimage.extend_from_slice(domain_with_nul);
        preimage.extend_from_slice(&(unsigned_json.len() as u64).to_be_bytes());
        preimage.extend_from_slice(unsigned_json);
        preimage
    }

    fn golden_terminal_unsigned() -> GoldenTerminalObservationUnsigned<'static> {
        GoldenTerminalObservationUnsigned {
            schema: "marty.performance/sd-jwt-issuance-terminal-observation-receipt/v1",
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001",
            channel_id: "marty-sd-jwt-issuance-anchor-v1",
            log_id: "sd-jwt-issuance-qualification-v1",
            campaign_append_ordinal: 0,
            channel_clock_session_id:
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            channel_monotonic_nanoseconds: 10_000_000_000,
            observed_at_utc_rfc3339_nanoseconds: "2026-08-29T12:35:00.000000000Z",
            channel_receipt_id: "receipt:0",
            challenge_uppercase_hex_256:
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            terminal_segment_fingerprint: golden_fingerprint(4),
            terminal_footer_monotonic_nanoseconds: 1_900_000_000,
            controller_request_monotonic_nanoseconds: 1_950_000_000,
            signing_key_id: "marty-sd-jwt-issuance-anchor-ed25519-v1",
        }
    }

    fn golden_completion_anchor_unsigned() -> GoldenCompletionAnchorUnsigned<'static> {
        GoldenCompletionAnchorUnsigned {
            schema: "marty.performance/sd-jwt-issuance-completion-anchor/v1",
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001",
            channel_id: "marty-sd-jwt-issuance-anchor-v1",
            log_id: "sd-jwt-issuance-qualification-v1",
            campaign_append_ordinal: 1,
            channel_clock_session_id:
                "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            channel_monotonic_nanoseconds: 110_000_000_000,
            published_at_utc_rfc3339_nanoseconds: "2026-08-29T12:36:40.000000000Z",
            channel_receipt_id: "receipt:1",
            challenge_uppercase_hex_256:
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            completion_fingerprint: golden_fingerprint(7),
            terminal_segment_fingerprint: golden_fingerprint(4),
            terminal_observation_evidence_fingerprint: golden_fingerprint(6),
            signing_key_id: "marty-sd-jwt-issuance-anchor-ed25519-v1",
        }
    }

    fn signed_terminal_receipt(
        signing_key: &SigningKey,
    ) -> (TerminalObservationReceiptWire, Vec<u8>) {
        let unsigned = golden_terminal_unsigned();
        let unsigned_json = serde_json::to_vec(&unsigned).unwrap();
        let preimage =
            signed_json_preimage(b"MARTY-SD-JWT-TERMINAL-OBSERVATION-V1\0", &unsigned_json);
        let signature = signing_key.sign(&preimage);
        (
            TerminalObservationReceiptWire {
                schema: unsigned.schema.to_owned(),
                campaign_id: unsigned.campaign_id.to_owned(),
                channel_id: unsigned.channel_id.to_owned(),
                log_id: unsigned.log_id.to_owned(),
                campaign_append_ordinal: unsigned.campaign_append_ordinal,
                channel_clock_session_id: unsigned.channel_clock_session_id.to_owned(),
                channel_monotonic_nanoseconds: unsigned.channel_monotonic_nanoseconds,
                observed_at_utc_rfc3339_nanoseconds: unsigned
                    .observed_at_utc_rfc3339_nanoseconds
                    .to_owned(),
                channel_receipt_id: unsigned.channel_receipt_id.to_owned(),
                challenge_uppercase_hex_256: unsigned.challenge_uppercase_hex_256.to_owned(),
                terminal_segment_fingerprint: unsigned.terminal_segment_fingerprint,
                terminal_footer_monotonic_nanoseconds: unsigned
                    .terminal_footer_monotonic_nanoseconds,
                controller_request_monotonic_nanoseconds: unsigned
                    .controller_request_monotonic_nanoseconds,
                signing_key_id: unsigned.signing_key_id.to_owned(),
                signature_uppercase_hex_512: hex::encode_upper(signature.to_bytes()),
            },
            preimage,
        )
    }

    fn signed_completion_anchor(signing_key: &SigningKey) -> (CompletionAnchorWire, Vec<u8>) {
        let unsigned = golden_completion_anchor_unsigned();
        let unsigned_json = serde_json::to_vec(&unsigned).unwrap();
        let preimage = signed_json_preimage(b"MARTY-SD-JWT-COMPLETION-ANCHOR-V1\0", &unsigned_json);
        let signature = signing_key.sign(&preimage);
        (
            CompletionAnchorWire {
                schema: unsigned.schema.to_owned(),
                campaign_id: unsigned.campaign_id.to_owned(),
                channel_id: unsigned.channel_id.to_owned(),
                log_id: unsigned.log_id.to_owned(),
                campaign_append_ordinal: unsigned.campaign_append_ordinal,
                channel_clock_session_id: unsigned.channel_clock_session_id.to_owned(),
                channel_monotonic_nanoseconds: unsigned.channel_monotonic_nanoseconds,
                published_at_utc_rfc3339_nanoseconds: unsigned
                    .published_at_utc_rfc3339_nanoseconds
                    .to_owned(),
                channel_receipt_id: unsigned.channel_receipt_id.to_owned(),
                challenge_uppercase_hex_256: unsigned.challenge_uppercase_hex_256.to_owned(),
                completion_fingerprint: unsigned.completion_fingerprint,
                terminal_segment_fingerprint: unsigned.terminal_segment_fingerprint,
                terminal_observation_evidence_fingerprint: unsigned
                    .terminal_observation_evidence_fingerprint,
                signing_key_id: unsigned.signing_key_id.to_owned(),
                signature_uppercase_hex_512: hex::encode_upper(signature.to_bytes()),
            },
            preimage,
        )
    }

    fn strict_signature_verifies(
        verifying_key: &VerifyingKey,
        preimage: &[u8],
        signature_uppercase_hex: &str,
    ) -> bool {
        if !valid_uppercase_hex(signature_uppercase_hex, 128) {
            return false;
        }
        let Ok(signature_bytes) = hex::decode(signature_uppercase_hex) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };
        verifying_key.verify_strict(preimage, &signature).is_ok()
    }

    fn canonical_pretty_bytes<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn terminal_receipt_preimage(receipt: &TerminalObservationReceiptWire) -> Vec<u8> {
        let unsigned = GoldenTerminalObservationUnsigned {
            schema: &receipt.schema,
            campaign_id: &receipt.campaign_id,
            channel_id: &receipt.channel_id,
            log_id: &receipt.log_id,
            campaign_append_ordinal: receipt.campaign_append_ordinal,
            channel_clock_session_id: &receipt.channel_clock_session_id,
            channel_monotonic_nanoseconds: receipt.channel_monotonic_nanoseconds,
            observed_at_utc_rfc3339_nanoseconds: &receipt.observed_at_utc_rfc3339_nanoseconds,
            channel_receipt_id: &receipt.channel_receipt_id,
            challenge_uppercase_hex_256: &receipt.challenge_uppercase_hex_256,
            terminal_segment_fingerprint: receipt.terminal_segment_fingerprint.clone(),
            terminal_footer_monotonic_nanoseconds: receipt.terminal_footer_monotonic_nanoseconds,
            controller_request_monotonic_nanoseconds: receipt
                .controller_request_monotonic_nanoseconds,
            signing_key_id: &receipt.signing_key_id,
        };
        let unsigned_json = serde_json::to_vec(&unsigned).unwrap();
        signed_json_preimage(b"MARTY-SD-JWT-TERMINAL-OBSERVATION-V1\0", &unsigned_json)
    }

    fn resign_terminal_receipt(
        receipt: &mut TerminalObservationReceiptWire,
        signing_key: &SigningKey,
    ) {
        receipt.signature_uppercase_hex_512 = hex::encode_upper(
            signing_key
                .sign(&terminal_receipt_preimage(receipt))
                .to_bytes(),
        );
    }

    fn valid_terminal_receipt_bytes(bytes: &[u8], verifying_key: &VerifyingKey) -> bool {
        if bytes.len() > usize::try_from(MAX_EXTERNAL_ANCHOR_V1_BYTES).unwrap() {
            return false;
        }
        let Ok(receipt) = serde_json::from_slice::<TerminalObservationReceiptWire>(bytes) else {
            return false;
        };
        if canonical_pretty_bytes(&receipt) != bytes
            || receipt.schema != "marty.performance/sd-jwt-issuance-terminal-observation-receipt/v1"
            || receipt.channel_id != "marty-sd-jwt-issuance-anchor-v1"
            || receipt.log_id != "sd-jwt-issuance-qualification-v1"
            || receipt.campaign_append_ordinal != 0
            || receipt.signing_key_id != "marty-sd-jwt-issuance-anchor-ed25519-v1"
            || !valid_uppercase_hex(&receipt.channel_clock_session_id, 64)
            || !valid_uppercase_hex(&receipt.challenge_uppercase_hex_256, 64)
            || !valid_receipt_id(&receipt.channel_receipt_id)
        {
            return false;
        }
        strict_signature_verifies(
            verifying_key,
            &terminal_receipt_preimage(&receipt),
            &receipt.signature_uppercase_hex_512,
        )
    }

    fn terminal_receipt_set_has_no_conflict(
        receipts: &[&[u8]],
        verifying_key: &VerifyingKey,
    ) -> bool {
        let mut seen = BTreeMap::<(String, String, String, u64), Vec<u8>>::new();
        receipts.iter().all(|bytes| {
            if !valid_terminal_receipt_bytes(bytes, verifying_key) {
                return false;
            }
            let Ok(receipt) = serde_json::from_slice::<TerminalObservationReceiptWire>(bytes)
            else {
                return false;
            };
            let key = (
                receipt.channel_id,
                receipt.log_id,
                receipt.campaign_id,
                receipt.campaign_append_ordinal,
            );
            seen.insert(key, bytes.to_vec())
                .is_none_or(|previous| previous.as_slice() == *bytes)
        })
    }

    fn valid_completion_anchor_bytes(bytes: &[u8], verifying_key: &VerifyingKey) -> bool {
        if bytes.len() > usize::try_from(MAX_EXTERNAL_ANCHOR_V1_BYTES).unwrap() {
            return false;
        }
        let Ok(receipt) = serde_json::from_slice::<CompletionAnchorWire>(bytes) else {
            return false;
        };
        if canonical_pretty_bytes(&receipt) != bytes
            || receipt.schema != "marty.performance/sd-jwt-issuance-completion-anchor/v1"
            || receipt.channel_id != "marty-sd-jwt-issuance-anchor-v1"
            || receipt.log_id != "sd-jwt-issuance-qualification-v1"
            || receipt.campaign_append_ordinal != 1
            || receipt.signing_key_id != "marty-sd-jwt-issuance-anchor-ed25519-v1"
            || !valid_uppercase_hex(&receipt.channel_clock_session_id, 64)
            || !valid_uppercase_hex(&receipt.challenge_uppercase_hex_256, 64)
            || !valid_receipt_id(&receipt.channel_receipt_id)
        {
            return false;
        }
        let unsigned = GoldenCompletionAnchorUnsigned {
            schema: &receipt.schema,
            campaign_id: &receipt.campaign_id,
            channel_id: &receipt.channel_id,
            log_id: &receipt.log_id,
            campaign_append_ordinal: receipt.campaign_append_ordinal,
            channel_clock_session_id: &receipt.channel_clock_session_id,
            channel_monotonic_nanoseconds: receipt.channel_monotonic_nanoseconds,
            published_at_utc_rfc3339_nanoseconds: &receipt.published_at_utc_rfc3339_nanoseconds,
            channel_receipt_id: &receipt.channel_receipt_id,
            challenge_uppercase_hex_256: &receipt.challenge_uppercase_hex_256,
            completion_fingerprint: receipt.completion_fingerprint.clone(),
            terminal_segment_fingerprint: receipt.terminal_segment_fingerprint.clone(),
            terminal_observation_evidence_fingerprint: receipt
                .terminal_observation_evidence_fingerprint
                .clone(),
            signing_key_id: &receipt.signing_key_id,
        };
        let unsigned_json = serde_json::to_vec(&unsigned).unwrap();
        let preimage = signed_json_preimage(b"MARTY-SD-JWT-COMPLETION-ANCHOR-V1\0", &unsigned_json);
        strict_signature_verifies(
            verifying_key,
            &preimage,
            &receipt.signature_uppercase_hex_512,
        )
    }

    fn domain_length_hmac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(domain);
        mac.update(&[0]);
        mac.update(&u64::try_from(payload.len()).unwrap().to_be_bytes());
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    fn process_identity_tuple(
        operating_system_family: &str,
        pid: u64,
        process_start_unix_nanoseconds: u64,
        executable_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let mut tuple = Vec::new();
        tuple.extend_from_slice(
            &u64::try_from(operating_system_family.len())
                .unwrap()
                .to_be_bytes(),
        );
        tuple.extend_from_slice(operating_system_family.as_bytes());
        tuple.extend_from_slice(&pid.to_be_bytes());
        tuple.extend_from_slice(&process_start_unix_nanoseconds.to_be_bytes());
        tuple.extend_from_slice(executable_sha256);
        tuple
    }

    #[derive(Serialize)]
    struct GoldenCompletion {
        schema: &'static str,
        campaign_id: &'static str,
        created_at_utc_rfc3339_nanoseconds: &'static str,
        created_at_monotonic_nanoseconds: u64,
        plan_fingerprint: ArtifactFingerprint,
        manifest_fingerprint: ArtifactFingerprint,
        external_anchor_channel_configuration_fingerprint: ArtifactFingerprint,
        genesis_header_fingerprint: ArtifactFingerprint,
        ordered_segment_fingerprints: Vec<ArtifactFingerprint>,
        terminal_segment_fingerprint: ArtifactFingerprint,
        terminal_observation_evidence_fingerprint: ArtifactFingerprint,
        ordered_test_window_attestation_fingerprints: Vec<ArtifactFingerprint>,
        first_monotonic_nanoseconds: u64,
        last_monotonic_nanoseconds: u64,
        segment_count: u32,
        sample_count: u64,
        process_intent_count: u32,
        process_start_count: u32,
        process_finish_count: u32,
        attestation_transition_count: u32,
        process_completions: Vec<GoldenProcessCompletion>,
        criterion_artifact_set_fingerprint: ArtifactFingerprint,
        route_artifact_set_fingerprint: ArtifactFingerprint,
        first_quiet_window_evidence_fingerprint: ArtifactFingerprint,
        invalidating_event_count: u32,
        validity_status: &'static str,
    }

    fn golden_fingerprint(discriminator: u8) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: format!("{discriminator:064X}"),
            byte_length: u64::from(discriminator),
        }
    }

    fn assert_genesis_fields(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(
            field_names(&validity.records.genesis_header.fields),
            [
                "schema",
                "campaign_id",
                "segment_ordinal",
                "record_ordinal",
                "utc_rfc3339_nanoseconds",
                "monotonic_nanoseconds",
                "plan_fingerprint",
                "manifest_fingerprint",
                "fixed_binary_fingerprint",
                "fixed_binary_build_receipt_fingerprint",
                "monitor_binary_fingerprint",
                "controller_binary_fingerprint",
                "controller_configuration_fingerprint",
                "monitor_configuration_fingerprint",
                "external_anchor_channel_configuration_fingerprint",
                "source_commit",
                "source_tree",
                "source_archive_fingerprint",
                "cargo_lock_fingerprint",
                "rustc_verbose_version",
                "target_triple",
                "build_profile",
                "host_identity_fingerprint",
                "boot_identity_pseudonym",
                "hardware_profile_fingerprint",
                "validity_thresholds_fingerprint",
                "first_quiet_window_evidence_fingerprint",
                "initial_test_window_attestation_fingerprint",
                "baseline_unrelated_process_set_fingerprint",
            ]
        );
        assert!(!field_names(&validity.records.genesis_header.fields)
            .contains(&"test_window_attestation_chain_fingerprint"));
    }

    fn assert_process_fields(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(
            field_names(&validity.records.process_intent.fields),
            [
                "schema",
                "campaign_id",
                "segment_ordinal",
                "record_ordinal",
                "event_ordinal",
                "utc_rfc3339_nanoseconds",
                "monotonic_nanoseconds",
                "global_round_ordinal",
                "cell_ordinal",
                "expansion_position",
                "timing_process_id",
                "full_benchmark_id",
                "invocation_descriptor_fingerprint",
                "criterion_home_initial_inventory_fingerprint",
                "launch_barrier_token_fingerprint",
            ]
        );
        assert_eq!(
            field_names(&validity.records.process_start.fields),
            [
                "schema",
                "campaign_id",
                "segment_ordinal",
                "record_ordinal",
                "event_ordinal",
                "utc_rfc3339_nanoseconds",
                "monotonic_nanoseconds",
                "global_round_ordinal",
                "cell_ordinal",
                "expansion_position",
                "timing_process_id",
                "process_identity_pseudonym",
                "full_benchmark_id",
                "process_intent_record_fingerprint",
                "invocation_descriptor_fingerprint",
                "launch_barrier_token_fingerprint",
                "launch_barrier_ready_frame_fingerprint",
                "active_test_window_attestation_fingerprint",
            ]
        );
        assert!(!field_names(&validity.records.process_start.fields).contains(&"exit_code"));
        assert!(field_names(&validity.records.process_finish.fields).contains(&"exit_code"));
        assert!(field_names(&validity.records.process_finish.fields)
            .contains(&"stdout_after_ready_bytes"));
        assert!(field_names(&validity.records.process_finish.fields).contains(&"stderr_bytes"));
    }

    fn assert_completion_fields(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(
            field_names(&validity.completion.process_completion_fields),
            [
                "global_round_ordinal",
                "cell_ordinal",
                "expansion_position",
                "timing_process_id",
                "full_benchmark_id",
                "process_intent_record_fingerprint",
                "process_start_record_fingerprint",
                "process_finish_record_fingerprint",
                "invocation_descriptor_fingerprint",
                "launch_barrier_receipt_fingerprint",
                "criterion_home_initial_inventory_fingerprint",
                "criterion_home_final_inventory_fingerprint",
                "criterion_artifact_fingerprint",
                "route_artifact_fingerprint",
            ]
        );
        assert!(field_names(&validity.completion.fields)
            .contains(&"ordered_test_window_attestation_fingerprints"));
        assert!(field_names(&validity.completion.fields)
            .contains(&"external_anchor_channel_configuration_fingerprint"));
        assert!(field_names(&validity.completion.fields)
            .contains(&"terminal_observation_evidence_fingerprint"));
        assert!(validity
            .completion
            .validity_rule
            .contains("build/input-files.bia"));
    }

    #[test]
    fn exact_protocol_schedule_and_effect_definitions_are_frozen() {
        let value = manifest();
        let bytes = canonical_manifest_bytes(&value);
        let plan = plan_for_manifest(&value, &bytes).expect("valid qualification plan");

        assert_eq!(plan.superblock_orders, SUPERBLOCK_ORDERS);
        assert_eq!(plan.abba_expansion, ABBA_EXPANSION);
        assert_eq!(plan.baab_expansion, BAAB_EXPANSION);
        assert_eq!(plan.processes_per_cell, 160);
        assert_eq!(plan.total_processes, 10_560);
        assert_eq!(plan.global_rounds.cells_per_round, 66);
        assert_eq!(plan.global_rounds.processes_per_round, 528);
        assert_eq!(plan.global_rounds.concurrent_timing_processes, 1);
        assert_eq!(
            plan.global_rounds.run_validity.schema,
            "marty.performance/sd-jwt-issuance-run-validity/v1"
        );
        assert_eq!(
            plan.global_rounds.execution_nesting,
            "global_round_then_manifest_cell_then_expansion_position"
        );
        assert_eq!(
            plan.global_rounds.ordinal_alignment,
            "shared_campaign_cluster_across_all_cells"
        );
        assert_eq!(
            plan.global_rounds.processes_per_round * plan.superblocks_per_cell,
            plan.total_processes
        );
        assert_eq!(plan.quiet_window_seconds, 2_700);
        assert_eq!(plan.bootstrap.replicates, 100_000);
        assert!((plan.bootstrap.confidence_level - 0.95).abs() < f64::EPSILON);
        assert_eq!(plan.bootstrap.seed, 2_453_812_215);
        assert!(plan.bootstrap.seed_is_initial_state);
        assert_eq!(plan.bootstrap.draws_per_replicate, 20);
        assert_eq!(plan.bootstrap.sampling_method, "with_replacement");
        assert_eq!(
            plan.bootstrap.stream_scope,
            "single_continuous_stream_across_all_replicates"
        );
        assert_eq!(
            plan.bootstrap.consumption_order,
            "replicate_major_then_accepted_draw_major"
        );
        assert_eq!(
            plan.bootstrap.rejected_output_rule,
            "rejected_output_consumes_state_and_retries_current_draw"
        );
        assert_eq!(
            plan.bootstrap.uniform_index_rule,
            "accept_x_below_18446744073709551600_then_x_mod_20"
        );
        assert_eq!(
            plan.bootstrap.rng_state_transition,
            "state=wrapping_add(state,0x9E3779B97F4A7C15);z=wrapping_mul(state^(state>>30),0xBF58476D1CE4E5B9);z=wrapping_mul(z^(z>>27),0x94D049BB133111EB);output=z^(z>>31)"
        );
        assert_eq!(plan.bootstrap.resampling_unit, "whole_global_round");
        assert_eq!(
            plan.bootstrap.common_index_scope,
            "all_paired_cells_and_effects_d_s_p_o"
        );
        assert_eq!(
            plan.bootstrap.simultaneous_band,
            "type_7_q_0.95_of_replicate_max_abs_bootstrap_minus_observed_over_66_cells_d_s_p"
        );
        assert_eq!(
            plan.bootstrap.primary_interval_rule,
            "observed_effect_plus_or_minus_common_critical_value"
        );
        assert_eq!(
            plan.bootstrap.diagnostic_o_interval_rule,
            "type_7_marginal_q_0.025_and_q_0.975_of_bootstrap_o"
        );
        assert_eq!(plan.effects.abba_serial_first_pairs, [[1, 0], [7, 6]]);
        assert_eq!(plan.effects.baab_adaptive_first_pairs, [[0, 1], [6, 7]]);
        assert_eq!(
            plan.discovery.percent_transform,
            "100.0 * (exp(effect) - 1.0)"
        );
        assert_eq!(
            plan.discovery.d_upper_percent_less_than.to_bits(),
            (-5.0_f64).to_bits()
        );
        assert_eq!(
            plan.discovery.s_upper_percent_less_than.to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(
            plan.discovery.p_upper_percent_less_than.to_bits(),
            0.0_f64.to_bits()
        );
        assert!(plan.production_activation_separate);
        assert_eq!(plan.manifest.byte_length, bytes.len() as u64);
        assert_eq!(plan.manifest.sha256.len(), 64);
        assert!(plan
            .manifest
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)));
    }

    #[test]
    fn criterion_invocation_is_frozen_in_benchmark_exact_mode() {
        let criterion = criterion_protocol();
        assert_eq!(
            criterion.logical_argv,
            [
                "--bench",
                "--exact",
                "{full_benchmark_id}",
                "--sample-size",
                "50",
                "--nresamples",
                "100000",
                "--warm-up-time",
                "15",
                "--measurement-time",
                "10",
                "--confidence-level",
                "0.95",
                "--save-baseline",
                "base",
                "--noplot",
            ]
        );
        assert_eq!((criterion.sample_size, criterion.nresamples), (50, 100_000));
        assert_eq!(criterion.sampling_mode, "auto");
        assert_eq!(criterion.baseline_mode, "save");
        assert_eq!(criterion.baseline_name, "base");
    }

    #[test]
    fn canonical_v3_plan_bytes_are_frozen() {
        let value = manifest();
        let manifest_bytes = canonical_manifest_bytes(&value);
        let plan = plan_for_manifest(&value, &manifest_bytes).expect("valid qualification plan");
        let mut plan_bytes = serde_json::to_vec_pretty(&plan).expect("canonical plan JSON");
        plan_bytes.push(b'\n');
        assert_eq!(plan_bytes.len(), 152_138);
        assert_eq!(
            hex::encode_upper(Sha256::digest(&plan_bytes)),
            "4BE955DF8371FF4790C8876397162D1ACEC1DC6EF190E65F7281831FF22C2C91"
        );
    }

    #[test]
    fn canonical_validity_sample_golden_bytes_are_frozen() {
        let sample = GoldenSample {
            schema: "marty.performance/sd-jwt-issuance-validity-sample/v1",
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001",
            segment_ordinal: 0,
            record_ordinal: 1,
            sample_ordinal: 0,
            utc_rfc3339_nanoseconds: "2026-08-29T12:34:56.123456789Z",
            monotonic_nanoseconds: 1_000_000_000,
            boot_identity_pseudonym:
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            timing_state: "idle",
            global_round_ordinal: None,
            cell_ordinal: None,
            expansion_position: None,
            timing_process_id: None,
            total_cpu_percent: 1.0,
            monitor_cpu_percent: 0.05,
            benchmark_cpu_percent: 0.0,
            unrelated_cpu_percent: 0.25,
            available_memory_bytes: 8_589_934_592,
            cpu_frequency_hz: 3_200_000_000,
            maximum_temperature_millidegrees_celsius: 42_125,
            throttle_flags: vec!["none"],
            unrelated_process_set_fingerprint: golden_fingerprint(1),
            active_test_window_attestation_fingerprint: golden_fingerprint(2),
        };
        let mut bytes = serde_json::to_vec(&sample).expect("serialize golden sample");
        bytes.push(b'\n');
        let encoded = String::from_utf8(bytes.clone()).expect("sample UTF-8");
        let expected = concat!(
            r#"{"schema":"marty.performance/sd-jwt-issuance-validity-sample/v1","campaign_id":"018f4f9a-3f5b-4ae8-8a37-11c9fc12d001","segment_ordinal":0,"record_ordinal":1,"sample_ordinal":0,"utc_rfc3339_nanoseconds":"2026-08-29T12:34:56.123456789Z","monotonic_nanoseconds":1000000000,"boot_identity_pseudonym":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","timing_state":"idle","global_round_ordinal":null,"cell_ordinal":null,"expansion_position":null,"timing_process_id":null,"total_cpu_percent":1.0,"monitor_cpu_percent":0.05,"benchmark_cpu_percent":0.0,"unrelated_cpu_percent":0.25,"available_memory_bytes":8589934592,"cpu_frequency_hz":3200000000,"maximum_temperature_millidegrees_celsius":42125,"throttle_flags":["none"],"unrelated_process_set_fingerprint":{"sha256":"0000000000000000000000000000000000000000000000000000000000000001","byte_length":1},"active_test_window_attestation_fingerprint":{"sha256":"0000000000000000000000000000000000000000000000000000000000000002","byte_length":2}}"#,
            "\n"
        );
        assert_eq!(encoded, expected);
        assert_eq!(
            hex::encode_upper(Sha256::digest(&bytes)),
            "E520F65374515ADF2F8D59345551D103F7CE61B30A3AB635F34D4E7EED0007B3"
        );
    }

    #[test]
    fn canonical_completion_golden_hash_is_frozen() {
        let completion = GoldenCompletion {
            schema: "marty.performance/sd-jwt-issuance-validity-completion/v1",
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001",
            created_at_utc_rfc3339_nanoseconds: "2026-08-29T12:35:00.000000000Z",
            created_at_monotonic_nanoseconds: 2_000_000_000,
            plan_fingerprint: golden_fingerprint(1),
            manifest_fingerprint: golden_fingerprint(2),
            external_anchor_channel_configuration_fingerprint: golden_fingerprint(18),
            genesis_header_fingerprint: golden_fingerprint(3),
            ordered_segment_fingerprints: vec![golden_fingerprint(4)],
            terminal_segment_fingerprint: golden_fingerprint(4),
            terminal_observation_evidence_fingerprint: golden_fingerprint(14),
            ordered_test_window_attestation_fingerprints: vec![golden_fingerprint(5)],
            first_monotonic_nanoseconds: 1_000_000_000,
            last_monotonic_nanoseconds: 1_900_000_000,
            segment_count: 1,
            sample_count: 1,
            process_intent_count: 1,
            process_start_count: 1,
            process_finish_count: 1,
            attestation_transition_count: 0,
            process_completions: vec![GoldenProcessCompletion {
                global_round_ordinal: 0,
                cell_ordinal: 0,
                expansion_position: 0,
                timing_process_id: "r00-c00-e0",
                full_benchmark_id: "group/fixture/serial",
                process_intent_record_fingerprint: golden_fingerprint(6),
                process_start_record_fingerprint: golden_fingerprint(7),
                process_finish_record_fingerprint: golden_fingerprint(8),
                invocation_descriptor_fingerprint: golden_fingerprint(9),
                launch_barrier_receipt_fingerprint: golden_fingerprint(10),
                criterion_home_initial_inventory_fingerprint: golden_fingerprint(11),
                criterion_home_final_inventory_fingerprint: golden_fingerprint(12),
                criterion_artifact_fingerprint: golden_fingerprint(13),
                route_artifact_fingerprint: golden_fingerprint(14),
            }],
            criterion_artifact_set_fingerprint: golden_fingerprint(15),
            route_artifact_set_fingerprint: golden_fingerprint(16),
            first_quiet_window_evidence_fingerprint: golden_fingerprint(17),
            invalidating_event_count: 0,
            validity_status: "valid",
        };
        let mut bytes = serde_json::to_vec_pretty(&completion).expect("serialize completion");
        bytes.push(b'\n');
        assert_eq!(
            (bytes.len(), hex::encode_upper(Sha256::digest(&bytes))),
            (
                3_966,
                "B3983786847EF1972340AA27358541944F8CEF078F948B3E58C874FA55E2952C".to_owned()
            )
        );
    }

    fn named_dedicated_cap_floor(
        limits: &SdJwtIssuanceRunValidityLimits,
        build_input_archive_bytes: u64,
    ) -> Option<u64> {
        limits
            .maximum_segment_bytes
            .checked_mul(u64::from(limits.maximum_segment_count))
            .and_then(|total| total.checked_add(limits.maximum_completion_manifest_bytes))
            .and_then(|total| total.checked_add(MAX_SOURCE_ARCHIVE_V1_BYTES))
            .and_then(|total| total.checked_add(build_input_archive_bytes))
            .and_then(|total| total.checked_add(limits.maximum_total_route_artifact_bytes))
            .and_then(|total| total.checked_add(limits.maximum_total_criterion_home_bytes))
            .and_then(|total| {
                limits
                    .maximum_external_anchor_bytes
                    .checked_mul(2)
                    .and_then(|anchors| total.checked_add(anchors))
            })
            .and_then(|total| total.checked_add(limits.maximum_plan_bytes))
            .and_then(|total| total.checked_add(MAX_MANIFEST_BYTES))
            .and_then(|total| total.checked_add(limits.maximum_auxiliary_preimage_bytes))
    }

    fn assert_validity_limits(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(validity.limits.maximum_plan_bytes, 1_048_576);
        assert_eq!(validity.limits.maximum_segment_seconds, 43_200);
        assert_eq!(validity.limits.maximum_segment_bytes, 67_108_864);
        assert_eq!(validity.limits.maximum_segment_count, 16);
        assert_eq!(validity.limits.maximum_campaign_seconds, 604_800);
        assert_eq!(validity.limits.maximum_timing_process_seconds, 300);
        assert_eq!(
            validity.limits.maximum_anchor_publication_delay_seconds,
            300
        );
        assert_eq!(validity.limits.maximum_external_anchor_bytes, 16_384);
        assert_eq!(validity.limits.maximum_auxiliary_preimage_bytes, 16_777_216);
        assert_eq!(validity.limits.maximum_route_artifact_bytes, 1_048_576);
        assert_eq!(
            validity.limits.maximum_total_route_artifact_bytes,
            134_217_728
        );
        assert_eq!(validity.limits.maximum_criterion_home_bytes, 1_048_576);
        assert_eq!(
            validity.limits.maximum_total_criterion_home_bytes,
            536_870_912
        );
        assert_eq!(validity.limits.maximum_build_input_bytes, 2_147_483_648);
        assert_eq!(validity.limits.maximum_total_evidence_bytes, 4_294_967_296);
        let named_cap_floor =
            named_dedicated_cap_floor(&validity.limits, validity.limits.maximum_build_input_bytes)
                .expect("named evidence cap floor fits u64");
        assert_eq!(named_cap_floor, 3_964_698_624);
        assert!(named_cap_floor <= validity.limits.maximum_total_evidence_bytes);
        let remaining = validity.limits.maximum_total_evidence_bytes - named_cap_floor;
        assert!(named_dedicated_cap_floor(
            &validity.limits,
            validity.limits.maximum_build_input_bytes + remaining + 1,
        )
        .is_some_and(|total| total > validity.limits.maximum_total_evidence_bytes));
        assert!(named_dedicated_cap_floor(&validity.limits, u64::MAX).is_none());
        assert_eq!(validity.limits.maximum_launch_frame_bytes, 65_536);
        assert_eq!(validity.limits.maximum_spawn_to_ready_seconds, 30);
        assert_eq!(validity.limits.maximum_test_window_attestations, 16);
        assert_eq!(validity.limits.exact_timing_processes, 10_560);
    }

    fn assert_source_archive_contract(preimages: &SdJwtIssuanceGlobalPreimageProtocol) {
        assert_eq!(
            preimages.source_archive_manifest_schema,
            "marty.performance/sd-jwt-issuance-source-archive-manifest/v1"
        );
        assert_eq!(
            preimages.maximum_source_archive_derived_directory_nodes,
            131_072
        );
        assert_eq!(
            preimages.maximum_source_archive_derived_component_bytes,
            4_194_304
        );
        assert_eq!(
            preimages.fixed_binary_build_root_windows,
            "M:/marty-cdla-build-v1"
        );
        assert!(preimages
            .resolution_rule
            .contains("attestations/first-quiet-window.json"));
        assert!(preimages
            .resolution_rule
            .contains("timing-window-0000.json_through_timing-window-0015.json"));
        assert!(preimages.resolution_rule.contains("source/exact-tree.sar"));
        assert!(!preimages.privacy_rule.contains("repository.bundle"));
        assert!(preimages
            .source_archive_format
            .contains("MARTY-SD-JWT-SOURCE-ARCHIVE-V1"));
        assert!(!preimages.source_archive_format.contains("ustar"));
        assert_eq!(
            field_names(&preimages.source_archive_manifest_fields),
            [
                "schema",
                "git_object_format",
                "source_commit",
                "source_tree",
                "entry_count",
                "entries",
            ]
        );
        assert_eq!(preimages.maximum_source_archive_bytes, 16_777_216);
        assert_eq!(preimages.maximum_source_archive_manifest_bytes, 4_194_304);
        assert_eq!(preimages.maximum_source_archive_commit_bytes, 1_048_576);
        assert_eq!(preimages.maximum_source_archive_entries, 65_536);
        assert_eq!(preimages.maximum_source_archive_path_bytes, 1_024);
        assert_eq!(preimages.maximum_source_archive_path_segment_bytes, 255);
        assert_eq!(preimages.maximum_source_archive_path_segments, 256);
    }

    fn assert_global_preimage_contract(validity: &SdJwtIssuanceRunValidityProtocol) {
        let preimages = &validity.global_preimages;
        assert_eq!(
            preimages.controller_configuration.schema,
            "marty.performance/sd-jwt-issuance-controller-config/v1"
        );
        assert_eq!(
            preimages.host_identity.schema,
            "marty.performance/sd-jwt-issuance-host-identity/v1"
        );
        assert_source_archive_contract(preimages);
        assert_eq!(
            preimages.operating_system_family_literals,
            ["windows", "linux", "macos"]
        );
        assert_eq!(preimages.architecture_literals, ["x86_64", "aarch64"]);
        assert_eq!(
            preimages.test_window_target_role_literals,
            [
                "isolated_production_gateway",
                "dedicated_performance_gateway"
            ]
        );
        assert!(preimages
            .unrelated_process_set
            .semantic_rule
            .contains("marty.unrelated-process-instance.v1"));
        assert!(preimages
            .test_window_attestation
            .semantic_rule
            .contains("marty.test-window-target.v1"));
        assert!(preimages
            .unrelated_process_set
            .semantic_rule
            .contains("u64_big_endian_total_tuple_byte_length"));
        assert!(preimages
            .test_window_attestation
            .semantic_rule
            .contains("u64_big_endian_length"));
        assert_eq!(
            preimages.fixed_binary_build_receipt.schema,
            "marty.performance/sd-jwt-issuance-fixed-binary-build/v2"
        );
        assert_eq!(
            preimages.fixed_binary_build_input_inventory.schema,
            "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2"
        );
        assert_eq!(
            preimages.fixed_binary_build_input_mode_literals,
            ["100644", "100755"]
        );
        assert_eq!(preimages.maximum_fixed_binary_build_input_entries, 65_536);
        assert_eq!(
            validity.first_quiet_window.schema,
            "marty.performance/sd-jwt-issuance-first-quiet-window/v1"
        );
        assert!(field_names(&validity.first_quiet_window.fields)
            .contains(&"first_quiet_window_attestation_fingerprint"));
        assert!(!field_names(&validity.first_quiet_window.fields)
            .contains(&"initial_test_window_attestation_fingerprint"));
    }

    fn assert_invocation_and_launch_contract(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(
            validity.invocation_descriptor.environment_allowlist,
            [
                "CRITERION_HOME",
                "MARTY_PERF_START_BARRIER",
                "NO_COLOR",
                "RUST_BACKTRACE",
                "SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID",
                "SD_JWT_ISSUANCE_ROUTE_NDJSON",
                "SystemRoot",
                "TEMP",
                "TMP",
                "WINDIR",
            ]
        );
        assert_eq!(
            validity.launch_barrier.receipt_schema,
            "marty.performance/sd-jwt-issuance-launch-receipt/v1"
        );
        assert_eq!(
            validity.launch_barrier.ready_frame_schema,
            "marty.performance/sd-jwt-issuance-launch-ready/v1"
        );
        assert_eq!(
            validity.launch_barrier.release_frame_schema,
            "marty.performance/sd-jwt-issuance-launch-release/v1"
        );
        assert!(!field_names(&validity.launch_barrier.ready_frame_fields)
            .contains(&"ready_at_monotonic_nanoseconds"));
        assert_eq!(
            validity.criterion_home.inventory_schema,
            "marty.performance/sd-jwt-issuance-criterion-home-inventory/v1"
        );
    }

    fn assert_route_and_index_contract(validity: &SdJwtIssuanceRunValidityProtocol) {
        assert_eq!(
            validity.route_artifact.record_schema,
            "sd_jwt_issuance_route_v2"
        );
        assert_eq!(
            validity.route_artifact.effective_literals,
            [
                "serial_oracle",
                "bounded_native",
                "mixed_native_and_serial",
                "ready_batch_serial_fallback",
                "budget_serial_fallback",
                "target_serial_fallback",
            ]
        );
        assert_eq!(
            validity.route_artifact.selection_reason_literals,
            [
                "below_min_jobs",
                "work_estimate_overflow",
                "below_min_estimated_work_bytes",
                "insufficient_available_parallelism",
                "worker_budget_unavailable",
                "bounded_native",
            ]
        );
        assert_eq!(
            validity.artifact_indexes.criterion_schema,
            "marty.performance/sd-jwt-issuance-criterion-artifact-index/v1"
        );
        assert_eq!(
            validity.artifact_indexes.route_schema,
            "marty.performance/sd-jwt-issuance-route-artifact-index/v1"
        );
        assert_eq!(
            field_names(&validity.artifact_indexes.fields),
            [
                "schema",
                "campaign_id",
                "artifact_kind",
                "entry_count",
                "entries"
            ]
        );
        assert_eq!(
            field_names(&validity.artifact_indexes.entry_fields),
            [
                "global_round_ordinal",
                "cell_ordinal",
                "expansion_position",
                "timing_process_id",
                "full_benchmark_id",
                "relative_path",
                "fingerprint",
            ]
        );
        assert_eq!(
            validity.artifact_indexes.criterion_artifact_kind,
            "criterion_0_5_1_new_estimates_json"
        );
        assert_eq!(
            validity.artifact_indexes.route_artifact_kind,
            "sd_jwt_issuance_route_v2"
        );
    }

    fn assert_anchor_contract(validity: &SdJwtIssuanceRunValidityProtocol) {
        let completion = &validity.completion;
        assert_eq!(
            completion.external_anchor_schema,
            "marty.performance/sd-jwt-issuance-completion-anchor/v1"
        );
        assert_eq!(
            completion.external_anchor_channel.schema,
            "marty.performance/sd-jwt-issuance-external-anchor-channel/v1"
        );
        assert_eq!(
            field_names(&completion.terminal_observation_receipt_fields),
            [
                "schema",
                "campaign_id",
                "channel_id",
                "log_id",
                "campaign_append_ordinal",
                "channel_clock_session_id",
                "channel_monotonic_nanoseconds",
                "observed_at_utc_rfc3339_nanoseconds",
                "channel_receipt_id",
                "challenge_uppercase_hex_256",
                "terminal_segment_fingerprint",
                "terminal_footer_monotonic_nanoseconds",
                "controller_request_monotonic_nanoseconds",
                "signing_key_id",
                "signature_uppercase_hex_512",
            ]
        );
        assert_eq!(
            field_names(&completion.external_anchor_fields),
            [
                "schema",
                "campaign_id",
                "channel_id",
                "log_id",
                "campaign_append_ordinal",
                "channel_clock_session_id",
                "channel_monotonic_nanoseconds",
                "published_at_utc_rfc3339_nanoseconds",
                "channel_receipt_id",
                "challenge_uppercase_hex_256",
                "completion_fingerprint",
                "terminal_segment_fingerprint",
                "terminal_observation_evidence_fingerprint",
                "signing_key_id",
                "signature_uppercase_hex_512",
            ]
        );
        assert_eq!(
            field_names(&completion.terminal_observation_evidence_fields),
            [
                "schema",
                "campaign_id",
                "terminal_observation_receipt_fingerprint",
                "controller_receipt_observed_monotonic_nanoseconds",
            ]
        );
        assert_eq!(
            field_names(&completion.external_anchor_channel.fields),
            [
                "schema",
                "campaign_id",
                "channel_id",
                "channel_kind",
                "endpoint_role",
                "log_id",
                "connector_authentication_policy",
                "receipt_verification_scheme",
                "signing_key_id",
                "trust_root_fingerprint",
                "clock_policy",
                "maximum_receipt_bytes",
            ]
        );
    }

    #[test]
    fn continuous_run_validity_contract_is_segmented_and_fail_closed() {
        let validity = run_validity_protocol();
        assert_eq!(
            validity.artifact_format,
            "create_new_utf8_ndjson_segments_one_compact_json_record_per_lf_line_keys_in_protocol_order_no_bom_no_cr_record_fingerprints_cover_exact_line_including_lf_each_segment_flushed_and_durably_synced_before_successor"
        );
        assert_eq!(validity.pre_timing_quiet_seconds, 2_700);
        assert_eq!(validity.sample_interval_seconds, 5);
        assert_eq!(validity.maximum_sample_gap_seconds, 10);
        assert_validity_limits(&validity);
        assert_global_preimage_contract(&validity);
        assert_invocation_and_launch_contract(&validity);
        assert_route_and_index_contract(&validity);
        assert_anchor_contract(&validity);
        assert_genesis_fields(&validity);
        assert_process_fields(&validity);
        let sample_fields = &validity.records.sample.fields;
        for name in [
            "global_round_ordinal",
            "cell_ordinal",
            "expansion_position",
            "timing_process_id",
        ] {
            assert!(sample_fields
                .iter()
                .any(|field| field.name == name && field.nullable));
        }
        assert_completion_fields(&validity);
        assert_eq!(validity.invalidating_events.len(), 24);
        assert_eq!(
            validity.invalidation_rule,
            "any_event_gap_write_failure_or_missing_terminal_commitment_invalidates_entire_campaign_no_round_deletion_resume_or_partial_analysis"
        );
    }

    #[test]
    fn conservative_spawn_to_ready_bound_is_checked_and_closed() {
        let within_bound = |intent: u64, start: u64| {
            start
                .checked_sub(intent)
                .is_some_and(|elapsed| elapsed <= 30_000_000_000)
        };

        assert!(within_bound(5, 30_000_000_005));
        assert!(!within_bound(5, 30_000_000_006));
        assert!(!within_bound(u64::MAX, 0));
        assert!(run_validity_protocol()
            .records
            .process_start
            .semantic_rule
            .contains("checked_subtraction"));
    }

    fn assert_observation_bounds(bounds: &SdJwtIssuanceObservationBounds) {
        assert!(bounds.minimum_cpu_percent.abs() < f64::EPSILON);
        assert!((bounds.maximum_cpu_percent - 100.0).abs() < f64::EPSILON);
        assert_eq!(bounds.maximum_cpu_frequency_hz, 10_000_000_000);
        assert_eq!(bounds.minimum_temperature_millidegrees_celsius, -100_000);
        assert_eq!(bounds.maximum_temperature_millidegrees_celsius, 200_000);
        assert_eq!(bounds.maximum_unrelated_process_count, 4_096);
        for value in [0.0_f64, 100.0] {
            assert!(
                value.is_finite()
                    && value >= bounds.minimum_cpu_percent
                    && value <= bounds.maximum_cpu_percent
            );
        }
        for value in [
            -f64::EPSILON,
            f64::from_bits(100.0_f64.to_bits() + 1),
            f64::NAN,
            f64::INFINITY,
        ] {
            assert!(
                !(value.is_finite()
                    && value >= bounds.minimum_cpu_percent
                    && value <= bounds.maximum_cpu_percent)
            );
        }
    }

    #[derive(Clone)]
    struct ThresholdObservation<'a> {
        total_cpu_percent: f64,
        monitor_cpu_percent: f64,
        unrelated_cpu_percent: f64,
        available_memory_bytes: u64,
        cpu_frequency_hz: u64,
        maximum_temperature_millidegrees_celsius: i64,
        throttle_flags: &'a [&'a str],
        unrelated_process_count: u32,
    }

    struct ThresholdLimits<'a> {
        maximum_total_cpu_percent: f64,
        maximum_monitor_cpu_percent: f64,
        maximum_unrelated_cpu_percent: f64,
        minimum_available_memory_bytes: u64,
        minimum_cpu_frequency_hz: u64,
        maximum_temperature_millidegrees_celsius: i64,
        forbidden_throttle_flags: &'a [&'a str],
        maximum_unrelated_process_count: u32,
    }

    fn observation_satisfies_thresholds(
        observation: &ThresholdObservation<'_>,
        thresholds: &ThresholdLimits<'_>,
    ) -> bool {
        observation.total_cpu_percent <= thresholds.maximum_total_cpu_percent
            && observation.monitor_cpu_percent <= thresholds.maximum_monitor_cpu_percent
            && observation.unrelated_cpu_percent <= thresholds.maximum_unrelated_cpu_percent
            && (thresholds.minimum_available_memory_bytes == 0
                || observation.available_memory_bytes >= thresholds.minimum_available_memory_bytes)
            && (thresholds.minimum_cpu_frequency_hz == 0
                || observation.cpu_frequency_hz >= thresholds.minimum_cpu_frequency_hz)
            && observation.maximum_temperature_millidegrees_celsius
                <= thresholds.maximum_temperature_millidegrees_celsius
            && observation.unrelated_process_count <= thresholds.maximum_unrelated_process_count
            && !observation.throttle_flags.iter().any(|flag| {
                thresholds
                    .forbidden_throttle_flags
                    .iter()
                    .any(|forbidden| forbidden == flag)
            })
    }

    fn attestation_chain_covers(
        intervals: &[(u64, u64)],
        referenced_events: &[(usize, u64)],
    ) -> bool {
        !intervals.is_empty()
            && intervals.iter().all(|(start, expiry)| start < expiry)
            && intervals.windows(2).all(|pair| pair[1].0 <= pair[0].1)
            && referenced_events.iter().all(|(index, event)| {
                intervals
                    .get(*index)
                    .is_some_and(|(start, expiry)| start <= event && event < expiry)
            })
    }

    #[test]
    fn thresholds_and_attestation_coverage_fail_closed_at_boundaries() {
        let thresholds = ThresholdLimits {
            maximum_total_cpu_percent: 80.0,
            maximum_monitor_cpu_percent: 5.0,
            maximum_unrelated_cpu_percent: 10.0,
            minimum_available_memory_bytes: 1_000,
            minimum_cpu_frequency_hz: 2_000,
            maximum_temperature_millidegrees_celsius: 80_000,
            forbidden_throttle_flags: &["thermal", "power_limit"],
            maximum_unrelated_process_count: 4,
        };
        let observation = ThresholdObservation {
            total_cpu_percent: 80.0,
            monitor_cpu_percent: 5.0,
            unrelated_cpu_percent: 10.0,
            available_memory_bytes: 1_000,
            cpu_frequency_hz: 2_000,
            maximum_temperature_millidegrees_celsius: 80_000,
            throttle_flags: &["none"],
            unrelated_process_count: 4,
        };
        assert!(observation_satisfies_thresholds(&observation, &thresholds));
        let mut changed = observation.clone();
        changed.total_cpu_percent = f64::from_bits(80.0_f64.to_bits() + 1);
        assert!(!observation_satisfies_thresholds(&changed, &thresholds));
        for mutation in [
            |value: &mut ThresholdObservation<'_>| value.monitor_cpu_percent = 5.000_000_1,
            |value: &mut ThresholdObservation<'_>| value.unrelated_cpu_percent = 10.000_000_1,
            |value: &mut ThresholdObservation<'_>| value.available_memory_bytes = 999,
            |value: &mut ThresholdObservation<'_>| value.cpu_frequency_hz = 1_999,
            |value: &mut ThresholdObservation<'_>| {
                value.maximum_temperature_millidegrees_celsius = 80_001;
            },
            |value: &mut ThresholdObservation<'_>| value.unrelated_process_count = 5,
        ] {
            let mut changed = observation.clone();
            mutation(&mut changed);
            assert!(!observation_satisfies_thresholds(&changed, &thresholds));
        }
        let mut throttled = observation.clone();
        throttled.throttle_flags = &["thermal"];
        assert!(!observation_satisfies_thresholds(&throttled, &thresholds));
        let disabled = ThresholdLimits {
            minimum_available_memory_bytes: 0,
            minimum_cpu_frequency_hz: 0,
            ..thresholds
        };
        let mut zero_minimum_observation = observation;
        zero_minimum_observation.available_memory_bytes = 0;
        zero_minimum_observation.cpu_frequency_hz = 1;
        assert!(observation_satisfies_thresholds(
            &zero_minimum_observation,
            &disabled
        ));

        assert!(attestation_chain_covers(
            &[(10, 20), (20, 31)],
            &[(0, 10), (0, 19), (1, 20), (1, 30)]
        ));
        assert!(!attestation_chain_covers(&[(10, 20)], &[(0, 20)]));
        assert!(!attestation_chain_covers(
            &[(10, 20), (21, 31)],
            &[(0, 19), (1, 21)]
        ));
        assert!(!attestation_chain_covers(&[(10, 20)], &[(0, 9)]));

        let validity = run_validity_protocol();
        assert!(validity
            .records
            .sample
            .semantic_rule
            .contains("applies_the_bound_validity_thresholds_exactly"));
        assert!(validity
            .first_quiet_window
            .validity_rule
            .contains("bound_validity_threshold_predicate"));
        assert!(validity.attestation_chain_rule.contains("expiry_exclusive"));
    }

    #[test]
    fn lifecycle_alias_threshold_and_root_bounds_are_exact() {
        let elapsed_valid = |start: u64, finish: u64, retained: u64| {
            finish
                .checked_sub(start)
                .is_some_and(|actual| actual == retained && (1..=300_000_000_000).contains(&actual))
        };
        assert!(elapsed_valid(7, 300_000_000_007, 300_000_000_000));
        assert!(!elapsed_valid(7, 300_000_000_008, 300_000_000_001));
        assert!(!elapsed_valid(7, 7, 0));
        assert!(!elapsed_valid(8, 7, u64::MAX));

        let validity = run_validity_protocol();
        assert_eq!(
            validity.segment_close_reason_literals,
            [
                "next_event_would_exceed_duration_limit",
                "next_record_would_exceed_byte_limit",
                "next_record_would_exceed_record_limit",
                "campaign_complete",
            ]
        );
        assert!(validity
            .records
            .process_finish
            .semantic_rule
            .contains("equals_checked_finish_monotonic_nanoseconds_minus_matching_start"));
        assert!(validity
            .launch_barrier
            .nonce_rule
            .contains("64_ASCII_uppercase_hex"));
        assert!(validity
            .launch_barrier
            .process_identity_pseudonym_rule
            .contains("distinct_from_every_launch_nonce"));
        assert!(valid_uppercase_hex(&"0123456789ABCDEF".repeat(4), 64));
        assert!(!valid_uppercase_hex(&"0123456789abcdef".repeat(4), 64));
        assert!(
            field_names(&validity.global_preimages.test_window_attestation.fields)
                .contains(&"change_reference_pseudonym")
        );
        assert!(
            !field_names(&validity.global_preimages.test_window_attestation.fields)
                .contains(&"change_reference_alias")
        );

        assert_observation_bounds(&validity.global_preimages.observation_bounds);
        assert!(field_names(&validity.records.sample.fields).contains(&"monitor_cpu_percent"));

        assert_eq!(
            validity.limits.maximum_plan_bytes,
            MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES
        );
        let parser_called = std::cell::Cell::new(false);
        let guarded_parse = |bytes: &[u8]| {
            if bytes.len() as u64 > MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES {
                return false;
            }
            parser_called.set(true);
            serde_json::from_slice::<serde_json::Value>(bytes).is_ok()
        };
        assert!(!guarded_parse(&vec![b' '; 1_048_577]));
        assert!(!parser_called.get());
        assert!(!guarded_parse(&vec![b' '; 1_048_576]));
        assert!(parser_called.get());

        let build = &validity.global_preimages.fixed_binary_build_receipt;
        assert_eq!(
            build.schema,
            "marty.performance/sd-jwt-issuance-fixed-binary-build/v2"
        );
        for field in [
            "source_archive_fingerprint",
            "cargo_lock_fingerprint",
            "cargo_binary_fingerprint",
            "rustc_binary_fingerprint",
            "rustc_reported_sysroot",
            "build_input_inventory_fingerprint",
            "build_input_archive_fingerprint",
            "materialized_build_root",
            "logical_argv",
            "enabled_features",
            "offline_dependency_resolution_argv",
            "offline_dependency_resolution_succeeded",
            "produced_binary_fingerprint",
            "installed_fixed_binary_fingerprint",
        ] {
            assert!(field_names(&build.fields).contains(&field));
        }
        assert!(build
            .semantic_rule
            .contains("exactly_one_Cargo_compiler-artifact"));
    }

    #[test]
    fn privacy_hmac_encodings_have_independent_golden_vectors() {
        let process_key = [0x11; 32];
        let target_key = [0x22; 32];
        let executable = [0x33; 32];
        let tuple = process_identity_tuple("windows", 42, 1_234_567_890, &executable);
        let process =
            domain_length_hmac(&process_key, b"marty.unrelated-process-instance.v1", &tuple);
        let normalized_origin = b"https://example.com";
        let target = domain_length_hmac(
            &target_key,
            b"marty.test-window-target.v1",
            normalized_origin,
        );
        assert_eq!(
            hex::encode_upper(process),
            "6D98E72A1ADA1919BC2D06CD8141414DFAE0053BFBF6DD478DCC6469E171F6BB"
        );
        assert_eq!(
            hex::encode_upper(target),
            "0368A0CEFF8D5CEC1CBD8070384E088ED2F3726F63E6C4CEFFE256A0826BC633"
        );
        assert_ne!(
            process,
            domain_length_hmac(&target_key, b"marty.unrelated-process-instance.v1", &tuple)
        );
        assert_ne!(
            target,
            domain_length_hmac(
                &target_key,
                b"marty.unrelated-process-instance.v1",
                normalized_origin
            )
        );
        assert_ne!(
            target,
            domain_length_hmac(
                &target_key,
                b"marty.test-window-target.v1",
                b"https://example.com:443"
            )
        );
        assert_eq!(u64::from_be_bytes(tuple[..8].try_into().unwrap()), 7);
    }

    #[test]
    fn selector_branch_and_coupling_mutations_fail_closed() {
        let below_jobs = SelectorBatchModel {
            jobs: 1,
            work: None,
            work_status: "not_evaluated",
            work_gate: GateState::Skipped,
            available: None,
            selected: None,
            parallelism_gate: GateState::Skipped,
            budget_gate: GateState::Skipped,
            budget_result: "not_evaluated",
            mode: "serial",
            reason: "below_min_jobs",
            leased: None,
            static_layout: None,
        };
        let mut overflow = below_jobs.clone();
        overflow.jobs = 2;
        overflow.work_status = "overflow";
        overflow.work_gate = GateState::Evaluated;
        overflow.reason = "work_estimate_overflow";
        let mut below_work = overflow.clone();
        below_work.work = Some(0);
        below_work.work_status = "available";
        below_work.reason = "below_min_estimated_work_bytes";
        let mut insufficient = below_work.clone();
        insufficient.work = Some(1);
        insufficient.available = Some(1);
        insufficient.selected = Some(1);
        insufficient.parallelism_gate = GateState::Evaluated;
        insufficient.reason = "insufficient_available_parallelism";
        let mut budget = insufficient.clone();
        budget.available = Some(4);
        budget.selected = Some(2);
        budget.budget_gate = GateState::Evaluated;
        budget.budget_result = "unavailable";
        budget.reason = "worker_budget_unavailable";
        let mut native = budget.clone();
        native.jobs = 5;
        native.work = Some(59);
        native.available = Some(12);
        native.selected = Some(4);
        native.budget_result = "acquired";
        native.mode = "native_parallel";
        native.reason = "bounded_native";
        native.leased = Some(4);
        native.static_layout = Some(());

        for (fixture, worker_cap, host_parallelism) in [
            (below_jobs.clone(), 4, 12),
            (overflow, 4, 12),
            (below_work, 4, 12),
            (insufficient.clone(), 4, 1),
            (budget.clone(), 4, 4),
            (native.clone(), 4, 12),
        ] {
            assert!(valid_selector_batch(&fixture, worker_cap, host_parallelism));
            let mut unknown = fixture;
            unknown.reason = "unknown";
            assert!(!valid_selector_batch(
                &unknown,
                worker_cap,
                host_parallelism
            ));
        }
        let mut zero_jobs = below_jobs;
        zero_jobs.jobs = 0;
        assert!(!valid_selector_batch(&zero_jobs, 4, 12));
        let mut bypass_jobs = insufficient;
        bypass_jobs.jobs = 1;
        assert!(!valid_selector_batch(&bypass_jobs, 4, 1));
        let mut bypass_work = budget;
        bypass_work.work = None;
        bypass_work.work_status = "not_evaluated";
        bypass_work.work_gate = GateState::Skipped;
        assert!(!valid_selector_batch(&bypass_work, 4, 4));
        let mut zero_work = native.clone();
        zero_work.work = Some(0);
        assert!(!valid_selector_batch(&zero_work, 4, 12));
        let mut wrong_workers = native.clone();
        wrong_workers.selected = Some(3);
        wrong_workers.leased = Some(3);
        assert!(!valid_selector_batch(&wrong_workers, 4, 12));
        let mut wrong_available = native.clone();
        wrong_available.available = Some(11);
        assert!(!valid_selector_batch(&wrong_available, 4, 12));
        let mut wrong_lease = native.clone();
        wrong_lease.leased = Some(3);
        assert!(!valid_selector_batch(&wrong_lease, 4, 12));
        let mut wrong_gate = native.clone();
        wrong_gate.work_gate = GateState::Skipped;
        assert!(!valid_selector_batch(&wrong_gate, 4, 12));
        let mut unknown_status = native;
        unknown_status.work_status = "unknown";
        assert!(!valid_selector_batch(&unknown_status, 4, 12));
    }

    fn canonical_native_route_batch() -> RouteBatchModel {
        RouteBatchModel {
            ordinal: 0,
            selector: SelectorBatchModel {
                jobs: 5,
                work: Some(59),
                work_status: "available",
                work_gate: GateState::Evaluated,
                available: Some(12),
                selected: Some(4),
                parallelism_gate: GateState::Evaluated,
                budget_gate: GateState::Evaluated,
                budget_result: "acquired",
                mode: "native_parallel",
                reason: "bounded_native",
                leased: Some(4),
                static_layout: Some(()),
            },
            chunk_size: Some(2),
            chunks: Some(vec![(0, 2, 28), (1, 2, 19), (2, 1, 12)]),
        }
    }

    #[test]
    fn route_aggregate_and_static_chunk_mutations_fail_closed() {
        let native = canonical_native_route_batch();
        let record = RouteRecordModel {
            requested: "adaptive_candidate",
            effective: "bounded_native",
            executor_batches: Some(1),
            serial_batches: Some(0),
            native_batches: Some(1),
            budget_fallback_batches: Some(0),
            max_native_worker_count: 4,
            worker_cap: 4,
            host_available_parallelism: 12,
            ready_batches: Some(vec![native.clone()]),
        };
        assert!(valid_route_record(&record, 4, 12));

        let mut wrong_effective = record.clone();
        wrong_effective.effective = "budget_serial_fallback";
        assert!(!valid_route_record(&wrong_effective, 4, 12));
        let mut wrong_count = record.clone();
        wrong_count.executor_batches = Some(2);
        assert!(!valid_route_record(&wrong_count, 4, 12));
        let mut wrong_serial_count = record.clone();
        wrong_serial_count.serial_batches = Some(1);
        assert!(!valid_route_record(&wrong_serial_count, 4, 12));
        let mut wrong_native_count = record.clone();
        wrong_native_count.native_batches = Some(0);
        assert!(!valid_route_record(&wrong_native_count, 4, 12));
        let mut wrong_budget_count = record.clone();
        wrong_budget_count.budget_fallback_batches = Some(1);
        assert!(!valid_route_record(&wrong_budget_count, 4, 12));
        let mut wrong_maximum = record.clone();
        wrong_maximum.max_native_worker_count = 3;
        assert!(!valid_route_record(&wrong_maximum, 4, 12));
        let mut wrong_chunk = record.clone();
        wrong_chunk.ready_batches.as_mut().unwrap()[0]
            .chunks
            .as_mut()
            .unwrap()[1]
            .2 += 1;
        assert!(!valid_route_record(&wrong_chunk, 4, 12));
        let mut wrong_partition = record.clone();
        let chunks = wrong_partition.ready_batches.as_mut().unwrap()[0]
            .chunks
            .as_mut()
            .unwrap();
        chunks[0].1 = 1;
        chunks[2].1 = 2;
        assert!(!valid_route_record(&wrong_partition, 4, 12));
        let mut wrong_ordinal = record.clone();
        wrong_ordinal.ready_batches.as_mut().unwrap()[0]
            .chunks
            .as_mut()
            .unwrap()[1]
            .0 = 0;
        assert!(!valid_route_record(&wrong_ordinal, 4, 12));

        let mut wrong_batch_ordinal = record.clone();
        wrong_batch_ordinal.ready_batches.as_mut().unwrap()[0].ordinal = 1;
        assert!(!valid_route_record(&wrong_batch_ordinal, 4, 12));
        let mut unknown_mode = record.clone();
        unknown_mode.ready_batches.as_mut().unwrap()[0]
            .selector
            .mode = "unknown";
        assert!(!valid_route_record(&unknown_mode, 4, 12));
        let mut mismatched_reason = record.clone();
        mismatched_reason.ready_batches.as_mut().unwrap()[0]
            .selector
            .reason = "below_min_jobs";
        assert!(!valid_route_record(&mismatched_reason, 4, 12));
        let mut wrong_context = record.clone();
        wrong_context.host_available_parallelism = 11;
        wrong_context.ready_batches.as_mut().unwrap()[0]
            .selector
            .available = Some(11);
        assert!(!valid_route_record(&wrong_context, 4, 12));

        let mut overflow = native.clone();
        overflow.selector.jobs = u64::MAX;
        assert!(!valid_static_chunks(&overflow, 4, 12));

        let mut budget = native.clone();
        budget.ordinal = 1;
        budget.selector.budget_result = "unavailable";
        budget.selector.mode = "serial";
        budget.selector.reason = "worker_budget_unavailable";
        budget.selector.leased = None;
        budget.selector.static_layout = None;
        budget.chunk_size = None;
        budget.chunks = None;
        let mixed = RouteRecordModel {
            requested: "adaptive_candidate",
            effective: "mixed_native_and_serial",
            executor_batches: Some(2),
            serial_batches: Some(1),
            native_batches: Some(1),
            budget_fallback_batches: Some(1),
            max_native_worker_count: 4,
            worker_cap: 4,
            host_available_parallelism: 12,
            ready_batches: Some(vec![native, budget]),
        };
        assert!(valid_route_record(&mixed, 4, 12));
    }

    #[test]
    fn target_fallback_requires_the_exact_single_worker_cap() {
        let target_fallback = RouteRecordModel {
            requested: "adaptive_candidate",
            effective: "target_serial_fallback",
            executor_batches: None,
            serial_batches: None,
            native_batches: None,
            budget_fallback_batches: None,
            max_native_worker_count: 0,
            worker_cap: 1,
            host_available_parallelism: 12,
            ready_batches: None,
        };
        assert!(valid_route_record(&target_fallback, 1, 12));
        let mut wrong_target_cap = target_fallback;
        wrong_target_cap.worker_cap = 2;
        assert!(!valid_route_record(&wrong_target_cap, 2, 12));

        let cap_one_ready_bypass = RouteRecordModel {
            requested: "adaptive_candidate",
            effective: "ready_batch_serial_fallback",
            executor_batches: Some(0),
            serial_batches: Some(0),
            native_batches: Some(0),
            budget_fallback_batches: Some(0),
            max_native_worker_count: 0,
            worker_cap: 1,
            host_available_parallelism: 12,
            ready_batches: Some(Vec::new()),
        };
        assert!(!valid_route_record(&cap_one_ready_bypass, 1, 12));
    }

    fn canonical_route_wire(benchmark_id: &str, fixture_id: &str, stage: &str) -> RouteRecordWire {
        RouteRecordWire {
            schema: ROUTE_SCHEMA.to_owned(),
            benchmark_id: benchmark_id.to_owned(),
            fixture_id: fixture_id.to_owned(),
            stage: stage.to_owned(),
            requested: "adaptive_candidate".to_owned(),
            effective: "bounded_native".to_owned(),
            executor_batches: RequiredNullable(Some(1)),
            serial_batches: RequiredNullable(Some(0)),
            native_batches: RequiredNullable(Some(1)),
            budget_fallback_batches: RequiredNullable(Some(0)),
            max_native_worker_count: 4,
            worker_cap: 4,
            host_available_parallelism: 12,
            work_estimator_version: WORK_ESTIMATOR_VERSION.to_owned(),
            static_partition_rule_version: STATIC_PARTITION_RULE_VERSION.to_owned(),
            ready_batches: RequiredNullable(Some(vec![RouteBatchWire {
                ordinal: 0,
                job_count: 5,
                estimated_work_bytes: RequiredNullable(Some(59)),
                work_estimate_status: "available".to_owned(),
                work_gate_evaluated: true,
                parallelism_gate_evaluated: true,
                budget_gate_evaluated: true,
                available_parallelism: RequiredNullable(Some(12)),
                selected_worker_count: RequiredNullable(Some(4)),
                leased_worker_count: RequiredNullable(Some(4)),
                budget_acquisition_result: "acquired".to_owned(),
                selected_mode: "native_parallel".to_owned(),
                selection_reason: "bounded_native".to_owned(),
                static_chunk_size: RequiredNullable(Some(2)),
                static_chunks: RequiredNullable(Some(vec![
                    RouteStaticChunkWire {
                        ordinal: 0,
                        job_count: 2,
                        estimated_work_bytes: 28,
                    },
                    RouteStaticChunkWire {
                        ordinal: 1,
                        job_count: 2,
                        estimated_work_bytes: 19,
                    },
                    RouteStaticChunkWire {
                        ordinal: 2,
                        job_count: 1,
                        estimated_work_bytes: 12,
                    },
                ])),
            }])),
        }
    }

    fn encoded_route_wire(value: &RouteRecordWire) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn serialized_route_fixture_rejects_lexical_and_semantic_mutations() {
        let manifest = manifest();
        let cell = &manifest.paired_cells[0];
        let wire = canonical_route_wire(&cell.adaptive_id, &cell.fixture_id, &cell.stage);
        let accepted = |bytes: &[u8]| {
            valid_route_wire_bytes(
                bytes,
                &cell.adaptive_id,
                &cell.fixture_id,
                &cell.stage,
                "adaptive_candidate",
                4,
                12,
            )
        };
        let bytes = encoded_route_wire(&wire);
        assert!(accepted(&bytes));

        let mut zero_work = wire.clone();
        zero_work.ready_batches.0.as_mut().unwrap()[0].estimated_work_bytes =
            RequiredNullable(Some(0));
        assert!(!accepted(&encoded_route_wire(&zero_work)));
        let mut skipped_work = wire.clone();
        let batch = &mut skipped_work.ready_batches.0.as_mut().unwrap()[0];
        batch.estimated_work_bytes = RequiredNullable(None);
        batch.work_estimate_status = "not_evaluated".to_owned();
        batch.work_gate_evaluated = false;
        assert!(!accepted(&encoded_route_wire(&skipped_work)));
        let mut unknown_mode = wire.clone();
        unknown_mode.ready_batches.0.as_mut().unwrap()[0].selected_mode = "unknown".to_owned();
        assert!(!accepted(&encoded_route_wire(&unknown_mode)));
        let mut wrong_cap = wire.clone();
        wrong_cap.worker_cap = 3;
        wrong_cap.max_native_worker_count = 3;
        let batch = &mut wrong_cap.ready_batches.0.as_mut().unwrap()[0];
        batch.selected_worker_count = RequiredNullable(Some(3));
        batch.leased_worker_count = RequiredNullable(Some(3));
        assert!(!accepted(&encoded_route_wire(&wrong_cap)));

        let mut route_swap = wire;
        route_swap.requested = "serial_oracle".to_owned();
        route_swap.effective = "serial_oracle".to_owned();
        route_swap.executor_batches = RequiredNullable(None);
        route_swap.serial_batches = RequiredNullable(None);
        route_swap.native_batches = RequiredNullable(None);
        route_swap.budget_fallback_batches = RequiredNullable(None);
        route_swap.max_native_worker_count = 0;
        route_swap.ready_batches = RequiredNullable(None);
        assert!(!accepted(&encoded_route_wire(&route_swap)));
    }

    #[test]
    fn serialized_route_fixture_has_fixed_bytes_and_rejects_raw_mutations() {
        let manifest = manifest();
        let cell = &manifest.paired_cells[0];
        let wire = canonical_route_wire(&cell.adaptive_id, &cell.fixture_id, &cell.stage);
        let accepted = |bytes: &[u8]| {
            valid_route_wire_bytes(
                bytes,
                &cell.adaptive_id,
                &cell.fixture_id,
                &cell.stage,
                "adaptive_candidate",
                4,
                12,
            )
        };
        let bytes = encoded_route_wire(&wire);
        assert_eq!(
            hex::encode_upper(Sha256::digest(&bytes)),
            "E8E56807D772550FFE8A316AA1D7B01A386E99C150405D59A992EA506B3D65BF"
        );
        let text = String::from_utf8(bytes.clone()).unwrap();
        for changed in [
            text.replacen(":\"", ": \"", 1).into_bytes(),
            text.replacen("\"executor_batches\":1,", "", 1).into_bytes(),
            text.replacen("\"worker_cap\":4", "\"worker_cap\":4,\"worker_cap\":4", 1)
                .into_bytes(),
            text.replacen("\"worker_cap\":4", "\"worker_cap\":\"4\"", 1)
                .into_bytes(),
            text.replacen(
                "\"ready_batches\":",
                "\"unknown\":true,\"ready_batches\":",
                1,
            )
            .into_bytes(),
        ] {
            assert!(!accepted(&changed));
        }
        let mut reordered = serde_json::to_vec(&serde_json::to_value(&wire).unwrap()).unwrap();
        reordered.push(b'\n');
        assert!(!accepted(&reordered));
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&bytes);
        assert!(!accepted(&bom));
        let mut crlf = bytes.clone();
        crlf.splice(crlf.len() - 1.., [b'\r', b'\n']);
        assert!(!accepted(&crlf));
        let mut trailing_json = bytes;
        trailing_json.splice(trailing_json.len() - 1.., *b"{}\n");
        assert!(!accepted(&trailing_json));
    }

    #[derive(Clone, PartialEq, Eq)]
    struct BuildEnvironmentEntry {
        name: String,
        value_kind: String,
        resolved_value: String,
    }

    fn concrete_target_linker_environment_name(target_triple: &str) -> Option<String> {
        if target_triple.is_empty()
            || target_triple.len() > 128
            || !target_triple
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return None;
        }
        let mapped = target_triple
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() {
                    byte.to_ascii_uppercase() as char
                } else {
                    '_'
                }
            })
            .collect::<String>();
        Some(format!("CARGO_TARGET_{mapped}_LINKER"))
    }

    fn fixture_target_linker_relative_path(windows: bool) -> &'static str {
        if windows {
            "tools/linker/link.exe"
        } else {
            "tools/linker/cc"
        }
    }

    fn canonical_build_environment(
        windows: bool,
        target_triple: &str,
        committer_timestamp: u64,
        target_linker_relative_path: &str,
    ) -> Option<Vec<BuildEnvironmentEntry>> {
        let root = if windows {
            FIXED_BUILD_ROOT_WINDOWS
        } else {
            FIXED_BUILD_ROOT_NON_WINDOWS
        };
        let separator = if windows { ";" } else { ":" };
        let executable_directories = [
            "toolchain/bin",
            "tools/linker",
            "tools/archiver",
            "tools/runtime",
        ];
        let path = executable_directories
            .map(|directory| format!("{root}/inputs/{directory}"))
            .join(separator);
        let rustc = format!(
            "{root}/inputs/toolchain/bin/{}",
            if windows { "rustc.exe" } else { "rustc" }
        );
        let linker = format!("{root}/inputs/{target_linker_relative_path}");
        let linker_name = concrete_target_linker_environment_name(target_triple)?;
        let mut entries = vec![
            BuildEnvironmentEntry {
                name: "CARGO_HOME".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/inputs/cargo-home"),
            },
            BuildEnvironmentEntry {
                name: "CARGO_INCREMENTAL".to_owned(),
                value_kind: "literal".to_owned(),
                resolved_value: "0".to_owned(),
            },
            BuildEnvironmentEntry {
                name: "CARGO_NET_OFFLINE".to_owned(),
                value_kind: "literal".to_owned(),
                resolved_value: "true".to_owned(),
            },
            BuildEnvironmentEntry {
                name: "CARGO_TARGET_DIR".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/target"),
            },
            BuildEnvironmentEntry {
                name: linker_name,
                value_kind: "inventoried_absolute_path".to_owned(),
                resolved_value: linker,
            },
            BuildEnvironmentEntry {
                name: "PATH".to_owned(),
                value_kind: "ordered_absolute_path_list".to_owned(),
                resolved_value: path,
            },
            BuildEnvironmentEntry {
                name: "RUSTC".to_owned(),
                value_kind: "inventoried_absolute_path".to_owned(),
                resolved_value: rustc,
            },
            BuildEnvironmentEntry {
                name: "SOURCE_DATE_EPOCH".to_owned(),
                value_kind: "commit_timestamp_decimal".to_owned(),
                resolved_value: committer_timestamp.to_string(),
            },
        ];
        if windows {
            entries.push(BuildEnvironmentEntry {
                name: "SystemRoot".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/inputs/windows-runtime/SystemRoot"),
            });
        }
        entries.extend([
            BuildEnvironmentEntry {
                name: "TEMP".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/tmp"),
            },
            BuildEnvironmentEntry {
                name: "TMP".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/tmp"),
            },
        ]);
        if windows {
            entries.push(BuildEnvironmentEntry {
                name: "WINDIR".to_owned(),
                value_kind: "canonical_absolute_path".to_owned(),
                resolved_value: format!("{root}/inputs/windows-runtime/SystemRoot"),
            });
        }
        Some(entries)
    }

    fn valid_build_environment(
        entries: &[BuildEnvironmentEntry],
        windows: bool,
        target_triple: &str,
        committer_timestamp: u64,
        target_linker_relative_path: &str,
    ) -> bool {
        canonical_build_environment(
            windows,
            target_triple,
            committer_timestamp,
            target_linker_relative_path,
        )
        .is_some_and(|expected| entries == expected)
    }

    #[derive(Clone)]
    struct OfflineDependencyProbeObservation {
        argv: Vec<String>,
        succeeded: bool,
        materialized_build_root: String,
        working_directory: String,
        build_environment: Vec<BuildEnvironmentEntry>,
    }

    struct OfflineDependencyProbeReceiptContext<'a> {
        materialized_build_root: &'a str,
        working_directory: &'a str,
        build_environment: &'a [BuildEnvironmentEntry],
        windows: bool,
        target_triple: &'a str,
        committer_timestamp: u64,
        target_linker_relative_path: &'a str,
    }

    fn valid_offline_dependency_probe_observation(
        observation: &OfflineDependencyProbeObservation,
        receipt: &OfflineDependencyProbeReceiptContext<'_>,
    ) -> bool {
        const EXACT_ARGV: [&str; 7] = [
            "cargo",
            "metadata",
            "--frozen",
            "--offline",
            "--locked",
            "--format-version",
            "1",
        ];
        observation.argv.iter().map(String::as_str).eq(EXACT_ARGV)
            && observation.succeeded
            && valid_fixed_build_root(receipt.materialized_build_root, receipt.windows)
            && receipt.working_directory == format!("{}/worktree", receipt.materialized_build_root)
            && valid_build_environment(
                receipt.build_environment,
                receipt.windows,
                receipt.target_triple,
                receipt.committer_timestamp,
                receipt.target_linker_relative_path,
            )
            && observation.materialized_build_root == receipt.materialized_build_root
            && observation.working_directory == receipt.working_directory
            && observation.build_environment == receipt.build_environment
    }

    fn valid_fixed_build_root(root: &str, windows: bool) -> bool {
        root == if windows {
            FIXED_BUILD_ROOT_WINDOWS
        } else {
            FIXED_BUILD_ROOT_NON_WINDOWS
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct BuildInputEntry {
        role: String,
        relative_path: String,
        file_mode: String,
        fingerprint: ArtifactFingerprint,
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct BuildInputInventory {
        schema: String,
        campaign_id: String,
        target_triple: String,
        entry_count: u32,
        total_byte_length: u64,
        archive_fingerprint: ArtifactFingerprint,
        executable_path_directories: Vec<String>,
        entries: Vec<BuildInputEntry>,
    }

    fn build_input_parent_directory(path: &str) -> Option<&str> {
        path.rsplit_once('/').map(|(parent, _)| parent)
    }

    fn build_input_is_below_executable_path_directory(path: &str) -> bool {
        [
            "toolchain/bin/",
            "tools/linker/",
            "tools/archiver/",
            "tools/runtime/",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    }

    fn build_input_path_matches_role(entry: &BuildInputEntry, windows: bool) -> bool {
        let path = entry.relative_path.as_str();
        match entry.role.as_str() {
            "cargo_configuration" => path == "cargo-home/config.toml",
            "cargo_dependency_source" => {
                path.starts_with("cargo-home/registry/src/")
                    || path.starts_with("cargo-home/git/checkouts/")
            }
            "cargo_executable" => {
                path == if windows {
                    "toolchain/bin/cargo.exe"
                } else {
                    "toolchain/bin/cargo"
                }
            }
            "executable_path_input" | "tool_dynamic_dependency" => {
                build_input_is_below_executable_path_directory(path)
            }
            "rustc_executable" => {
                path == if windows {
                    "toolchain/bin/rustc.exe"
                } else {
                    "toolchain/bin/rustc"
                }
            }
            "rustc_sysroot_file" => path.starts_with("toolchain/"),
            "target_archiver_executable" => path.starts_with("tools/archiver/"),
            "target_linker_executable" => path.starts_with("tools/linker/"),
            "windows_runtime_input" => windows && path.starts_with("windows-runtime/SystemRoot/"),
            _ => false,
        }
    }

    fn build_input_mode_matches_role(entry: &BuildInputEntry) -> bool {
        match entry.role.as_str() {
            "cargo_executable"
            | "executable_path_input"
            | "rustc_executable"
            | "target_archiver_executable"
            | "target_linker_executable" => entry.file_mode == "100755",
            "cargo_configuration" | "tool_dynamic_dependency" | "windows_runtime_input" => {
                entry.file_mode == "100644"
            }
            "cargo_dependency_source" | "rustc_sysroot_file" => {
                matches!(entry.file_mode.as_str(), "100644" | "100755")
            }
            _ => false,
        }
    }

    fn build_input_paths_are_materializable(entries: &[BuildInputEntry]) -> bool {
        let projected = entries
            .iter()
            .map(|entry| SourceArchiveEntryWire {
                repository_relative_path: entry.relative_path.clone(),
                git_mode: "100644".to_owned(),
                git_object_id: "0".repeat(40),
                artifact_fingerprint: golden_fingerprint(0),
            })
            .collect::<Vec<_>>();
        source_archive_paths_are_materializable(&projected)
    }

    fn build_input_dynamic_dependencies_resolve(entries: &[BuildInputEntry]) -> bool {
        entries
            .iter()
            .filter(|entry| entry.role == "tool_dynamic_dependency")
            .all(|dependency| {
                let Some(parent) = build_input_parent_directory(&dependency.relative_path) else {
                    return false;
                };
                (parent == "tools/runtime" || parent.starts_with("tools/runtime/"))
                    || entries.iter().any(|candidate| {
                        candidate.role != "tool_dynamic_dependency"
                            && candidate.file_mode == "100755"
                            && build_input_parent_directory(&candidate.relative_path)
                                == Some(parent)
                    })
            })
    }

    fn valid_build_input_inventory(
        inventory: &BuildInputInventory,
        windows: bool,
        expected_target_triple: &str,
    ) -> bool {
        const EXACTLY_ONE: [&str; 5] = [
            "cargo_configuration",
            "cargo_executable",
            "rustc_executable",
            "target_archiver_executable",
            "target_linker_executable",
        ];
        let expected_directories = [
            "toolchain/bin",
            "tools/linker",
            "tools/archiver",
            "tools/runtime",
        ];
        let sorted = inventory.entries.windows(2).all(|pair| {
            (pair[0].role.as_bytes(), pair[0].relative_path.as_bytes())
                < (pair[1].role.as_bytes(), pair[1].relative_path.as_bytes())
        });
        let total = inventory.entries.iter().try_fold(0_u64, |sum, entry| {
            sum.checked_add(entry.fingerprint.byte_length)
        });
        let archive_byte_length = u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len())
            .ok()
            .and_then(|magic| {
                u64::from(inventory.entry_count)
                    .checked_mul(8)
                    .and_then(|framing| magic.checked_add(framing))
            })
            .and_then(|framing| framing.checked_add(inventory.total_byte_length));
        let count_role = |role: &str| {
            inventory
                .entries
                .iter()
                .filter(|entry| entry.role == role)
                .count()
        };
        inventory.schema == "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2"
            && inventory.campaign_id == "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001"
            && inventory.target_triple == expected_target_triple
            && (1..=MAX_FIXED_BUILD_INPUT_ENTRIES).contains(&inventory.entry_count)
            && inventory.entry_count == u32::try_from(inventory.entries.len()).unwrap_or(u32::MAX)
            && total == Some(inventory.total_byte_length)
            && archive_byte_length == Some(inventory.archive_fingerprint.byte_length)
            && inventory.archive_fingerprint.byte_length <= MAX_FIXED_BUILD_INPUT_BYTES
            && valid_uppercase_hex(&inventory.archive_fingerprint.sha256, 64)
            && inventory.executable_path_directories == expected_directories.map(str::to_owned)
            && inventory
                .executable_path_directories
                .iter()
                .all(|directory| {
                    inventory.entries.iter().any(|entry| {
                        entry.relative_path.starts_with(&format!("{directory}/"))
                            && entry.file_mode == "100755"
                    })
                })
            && sorted
            && build_input_paths_are_materializable(&inventory.entries)
            && build_input_dynamic_dependencies_resolve(&inventory.entries)
            && inventory.entries.iter().all(|entry| {
                build_input_path_matches_role(entry, windows)
                    && build_input_mode_matches_role(entry)
                    && valid_uppercase_hex(&entry.fingerprint.sha256, 64)
            })
            && EXACTLY_ONE.iter().all(|role| count_role(role) == 1)
            && count_role("rustc_sysroot_file") >= 1
            && count_role("cargo_dependency_source") >= 1
            && (count_role("windows_runtime_input") >= 1) == windows
    }

    fn build_environment_value<'a>(
        entries: &'a [BuildEnvironmentEntry],
        name: &str,
    ) -> Option<&'a str> {
        let mut matches = entries.iter().filter(|entry| entry.name == name);
        let value = matches.next()?.resolved_value.as_str();
        matches.next().is_none().then_some(value)
    }

    fn valid_build_layout(
        environment: &[BuildEnvironmentEntry],
        inventory: &BuildInputInventory,
        windows: bool,
        target_triple: &str,
        committer_timestamp: u64,
        rustc_reported_sysroot: &str,
    ) -> bool {
        if !valid_build_input_inventory(inventory, windows, target_triple) {
            return false;
        }
        let Some(target_linker_relative_path) = inventory
            .entries
            .iter()
            .find(|entry| entry.role == "target_linker_executable")
            .map(|entry| entry.relative_path.as_str())
        else {
            return false;
        };
        if !valid_build_environment(
            environment,
            windows,
            target_triple,
            committer_timestamp,
            target_linker_relative_path,
        ) {
            return false;
        }
        let root = if windows {
            FIXED_BUILD_ROOT_WINDOWS
        } else {
            FIXED_BUILD_ROOT_NON_WINDOWS
        };
        let absolute_entry =
            |entry: &BuildInputEntry| format!("{root}/inputs/{}", entry.relative_path);
        let unique_role_path = |role: &str| {
            let mut matches = inventory.entries.iter().filter(|entry| entry.role == role);
            let path = absolute_entry(matches.next()?);
            matches.next().is_none().then_some(path)
        };
        let Some(linker_name) = concrete_target_linker_environment_name(target_triple) else {
            return false;
        };
        let cargo_home = format!("{root}/inputs/cargo-home");
        let expected_path = inventory
            .executable_path_directories
            .iter()
            .map(|directory| format!("{root}/inputs/{directory}"))
            .collect::<Vec<_>>()
            .join(if windows { ";" } else { ":" });
        let cargo_inputs_resolve = inventory.entries.iter().all(|entry| {
            if !matches!(
                entry.role.as_str(),
                "cargo_configuration" | "cargo_dependency_source"
            ) {
                return true;
            }
            entry
                .relative_path
                .strip_prefix("cargo-home/")
                .is_some_and(|suffix| format!("{cargo_home}/{suffix}") == absolute_entry(entry))
        });
        let windows_runtime_resolves = inventory.entries.iter().all(|entry| {
            if entry.role != "windows_runtime_input" {
                return true;
            }
            build_environment_value(environment, "SystemRoot").is_some_and(|system_root| {
                entry
                    .relative_path
                    .strip_prefix("windows-runtime/SystemRoot/")
                    .is_some_and(|suffix| {
                        format!("{system_root}/{suffix}") == absolute_entry(entry)
                    })
            })
        });
        build_environment_value(environment, "CARGO_HOME") == Some(cargo_home.as_str())
            && cargo_inputs_resolve
            && build_environment_value(environment, "RUSTC")
                == unique_role_path("rustc_executable").as_deref()
            && build_environment_value(environment, &linker_name)
                == unique_role_path("target_linker_executable").as_deref()
            && build_environment_value(environment, "PATH") == Some(expected_path.as_str())
            && rustc_reported_sysroot == format!("{root}/inputs/toolchain")
            && windows_runtime_resolves
            && (!windows
                || build_environment_value(environment, "SystemRoot")
                    == build_environment_value(environment, "WINDIR"))
    }

    const MEASURED_PINNED_WINDOWS_SYSROOT_BYTES: u64 = 733_006_527;
    const MEASURED_PINNED_WINDOWS_SYSROOT_FILES: u64 = 224;

    fn build_input_entry(
        role: &str,
        path: &str,
        file_mode: &str,
        byte_length: u64,
    ) -> BuildInputEntry {
        let mut hasher = Sha256::new();
        hasher.update(b"marty.synthetic-build-input-projection.v1\0");
        hasher.update(role.as_bytes());
        hasher.update([0]);
        hasher.update(path.as_bytes());
        hasher.update(byte_length.to_be_bytes());
        BuildInputEntry {
            role: role.to_owned(),
            relative_path: path.to_owned(),
            file_mode: file_mode.to_owned(),
            fingerprint: ArtifactFingerprint {
                sha256: hex::encode_upper(hasher.finalize()),
                byte_length,
            },
        }
    }

    fn initial_build_input_entries(windows: bool) -> Vec<BuildInputEntry> {
        vec![
            build_input_entry(
                "cargo_configuration",
                "cargo-home/config.toml",
                "100644",
                4_096,
            ),
            build_input_entry(
                "cargo_dependency_source",
                "cargo-home/registry/src/index/dependencies.sar",
                "100644",
                256 * 1024 * 1024,
            ),
            build_input_entry(
                "cargo_executable",
                if windows {
                    "toolchain/bin/cargo.exe"
                } else {
                    "toolchain/bin/cargo"
                },
                "100755",
                20 * 1024 * 1024,
            ),
            build_input_entry(
                "executable_path_input",
                if windows {
                    "tools/runtime/path-helper.exe"
                } else {
                    "tools/runtime/path-helper"
                },
                "100755",
                1024 * 1024,
            ),
            build_input_entry(
                "rustc_executable",
                if windows {
                    "toolchain/bin/rustc.exe"
                } else {
                    "toolchain/bin/rustc"
                },
                "100755",
                100 * 1024 * 1024,
            ),
        ]
    }

    fn append_measured_sysroot_entries(entries: &mut Vec<BuildInputEntry>) {
        let base = MEASURED_PINNED_WINDOWS_SYSROOT_BYTES / MEASURED_PINNED_WINDOWS_SYSROOT_FILES;
        let remainder =
            MEASURED_PINNED_WINDOWS_SYSROOT_BYTES % MEASURED_PINNED_WINDOWS_SYSROOT_FILES;
        for ordinal in 0..MEASURED_PINNED_WINDOWS_SYSROOT_FILES {
            entries.push(build_input_entry(
                "rustc_sysroot_file",
                &format!("toolchain/lib/rustlib/file-{ordinal:03}.bin"),
                "100644",
                base + u64::from(ordinal < remainder),
            ));
        }
    }

    fn append_platform_build_input_entries(entries: &mut Vec<BuildInputEntry>, windows: bool) {
        entries.extend([
            build_input_entry(
                "target_archiver_executable",
                if windows {
                    "tools/archiver/lib.exe"
                } else {
                    "tools/archiver/ar"
                },
                "100755",
                20 * 1024 * 1024,
            ),
            build_input_entry(
                "target_linker_executable",
                if windows {
                    "tools/linker/link.exe"
                } else {
                    "tools/linker/cc"
                },
                "100755",
                200 * 1024 * 1024,
            ),
            build_input_entry(
                "tool_dynamic_dependency",
                if windows {
                    "tools/runtime/tool-runtime.dll"
                } else {
                    "tools/runtime/tool-runtime.so"
                },
                "100644",
                100 * 1024 * 1024,
            ),
        ]);
        if windows {
            entries.push(build_input_entry(
                "windows_runtime_input",
                "windows-runtime/SystemRoot/System32/system-runtime.sar",
                "100644",
                200 * 1024 * 1024,
            ));
        }
    }

    fn canonical_build_input_inventory(windows: bool, target_triple: &str) -> BuildInputInventory {
        let mut entries = initial_build_input_entries(windows);
        append_measured_sysroot_entries(&mut entries);
        append_platform_build_input_entries(&mut entries, windows);
        entries.sort_by(|left, right| {
            (left.role.as_bytes(), left.relative_path.as_bytes())
                .cmp(&(right.role.as_bytes(), right.relative_path.as_bytes()))
        });
        let total_byte_length = entries
            .iter()
            .try_fold(0_u64, |sum, entry| {
                sum.checked_add(entry.fingerprint.byte_length)
            })
            .unwrap();
        let entry_count = u32::try_from(entries.len()).unwrap();
        let archive_byte_length = u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len())
            .unwrap()
            .checked_add(u64::from(entry_count).checked_mul(8).unwrap())
            .and_then(|framing| framing.checked_add(total_byte_length))
            .unwrap();
        BuildInputInventory {
            schema: "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2".to_owned(),
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001".to_owned(),
            target_triple: target_triple.to_owned(),
            entry_count,
            total_byte_length,
            archive_fingerprint: ArtifactFingerprint {
                sha256: hex::encode_upper(Sha256::digest(if windows {
                    b"synthetic measured Windows build-input archive".as_slice()
                } else {
                    b"synthetic measured non-Windows build-input archive".as_slice()
                })),
                byte_length: archive_byte_length,
            },
            executable_path_directories: [
                "toolchain/bin",
                "tools/linker",
                "tools/archiver",
                "tools/runtime",
            ]
            .map(str::to_owned)
            .to_vec(),
            entries,
        }
    }

    fn refresh_build_input_inventory_projection(inventory: &mut BuildInputInventory) {
        inventory.entry_count = u32::try_from(inventory.entries.len()).unwrap();
        inventory.total_byte_length = inventory
            .entries
            .iter()
            .map(|entry| entry.fingerprint.byte_length)
            .sum();
        inventory.archive_fingerprint.byte_length =
            u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len())
                .unwrap()
                .checked_add(u64::from(inventory.entry_count).checked_mul(8).unwrap())
                .and_then(|framing| framing.checked_add(inventory.total_byte_length))
                .unwrap();
    }

    fn canonical_build_input_inventory_bytes(inventory: &BuildInputInventory) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(inventory).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn encode_build_input_archive(contents: &[Vec<u8>]) -> Vec<u8> {
        let mut archive = FIXED_BUILD_INPUT_ARCHIVE_MAGIC.to_vec();
        for content in contents {
            archive.extend_from_slice(&u64::try_from(content.len()).unwrap().to_be_bytes());
            archive.extend_from_slice(content);
        }
        archive
    }

    fn build_input_archive_length_is_valid(byte_length: u64) -> bool {
        byte_length <= MAX_FIXED_BUILD_INPUT_BYTES
    }

    fn valid_build_input_archive_bytes(
        bytes: &[u8],
        inventory: &BuildInputInventory,
        expected_inventory_fingerprint: &ArtifactFingerprint,
        expected_archive_fingerprint: &ArtifactFingerprint,
        windows: bool,
        expected_target_triple: &str,
    ) -> bool {
        if !u64::try_from(bytes.len()).is_ok_and(build_input_archive_length_is_valid)
            || source_archive_fingerprint(bytes) != *expected_archive_fingerprint
            || inventory.archive_fingerprint != *expected_archive_fingerprint
            || source_archive_fingerprint(&canonical_build_input_inventory_bytes(inventory))
                != *expected_inventory_fingerprint
            || !valid_build_input_inventory(inventory, windows, expected_target_triple)
            || !bytes.starts_with(FIXED_BUILD_INPUT_ARCHIVE_MAGIC)
        {
            return false;
        }
        let mut cursor = FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len();
        let mut member_total = 0_u64;
        for entry in &inventory.entries {
            let Some(length) = take_u64_be(bytes, &mut cursor) else {
                return false;
            };
            if u64::try_from(length) != Ok(entry.fingerprint.byte_length) {
                return false;
            }
            let Some(content) = take_bounded(bytes, &mut cursor, length, bytes.len()) else {
                return false;
            };
            if source_archive_fingerprint(content) != entry.fingerprint {
                return false;
            }
            let Some(next_total) = member_total.checked_add(entry.fingerprint.byte_length) else {
                return false;
            };
            member_total = next_total;
        }
        cursor == bytes.len() && member_total == inventory.total_byte_length
    }

    struct GoldenBuildInputArchiveFixture {
        inventory: BuildInputInventory,
        inventory_fingerprint: ArtifactFingerprint,
        contents: Vec<Vec<u8>>,
        archive: Vec<u8>,
    }

    const GOLDEN_RETAINED_CARGO_CONFIG: &[u8] = b"[build]\ntarget-dir = \"retained-target\"\n";

    fn golden_build_input_archive_fixture() -> GoldenBuildInputArchiveFixture {
        let mut members = [
            (
                "cargo_executable",
                "toolchain/bin/cargo",
                "100755",
                b"cargo-v1\n".to_vec(),
            ),
            (
                "rustc_executable",
                "toolchain/bin/rustc",
                "100755",
                b"rustc-v1\n".to_vec(),
            ),
            (
                "target_linker_executable",
                "tools/linker/cc",
                "100755",
                b"link-v1\n".to_vec(),
            ),
            (
                "target_archiver_executable",
                "tools/archiver/ar",
                "100755",
                b"ar-v1\n".to_vec(),
            ),
            (
                "rustc_sysroot_file",
                "toolchain/lib/rustlib/libfixture.rlib",
                "100644",
                b"sysroot-v1\n".to_vec(),
            ),
            (
                "cargo_configuration",
                "cargo-home/config.toml",
                "100644",
                GOLDEN_RETAINED_CARGO_CONFIG.to_vec(),
            ),
            (
                "cargo_dependency_source",
                "cargo-home/registry/src/index/dep.rs",
                "100644",
                b"dep-v1\n".to_vec(),
            ),
            (
                "executable_path_input",
                "tools/runtime/path-helper",
                "100755",
                b"runtime-v1\n".to_vec(),
            ),
        ];
        members.sort_by(|left, right| {
            (left.0.as_bytes(), left.1.as_bytes()).cmp(&(right.0.as_bytes(), right.1.as_bytes()))
        });
        let contents = members
            .iter()
            .map(|member| member.3.clone())
            .collect::<Vec<_>>();
        let entries = members
            .iter()
            .map(|(role, path, mode, content)| BuildInputEntry {
                role: (*role).to_owned(),
                relative_path: (*path).to_owned(),
                file_mode: (*mode).to_owned(),
                fingerprint: source_archive_fingerprint(content),
            })
            .collect::<Vec<_>>();
        let archive = encode_build_input_archive(&contents);
        let archive_fingerprint = source_archive_fingerprint(&archive);
        let total_byte_length = entries
            .iter()
            .map(|entry| entry.fingerprint.byte_length)
            .sum();
        let inventory = BuildInputInventory {
            schema: "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2".to_owned(),
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001".to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            entry_count: u32::try_from(entries.len()).unwrap(),
            total_byte_length,
            archive_fingerprint,
            executable_path_directories: [
                "toolchain/bin",
                "tools/linker",
                "tools/archiver",
                "tools/runtime",
            ]
            .map(str::to_owned)
            .to_vec(),
            entries,
        };
        let inventory_fingerprint =
            source_archive_fingerprint(&canonical_build_input_inventory_bytes(&inventory));
        GoldenBuildInputArchiveFixture {
            inventory,
            inventory_fingerprint,
            contents,
            archive,
        }
    }

    #[test]
    fn invocation_environment_acceptance_is_exact() {
        let validity = run_validity_protocol();
        assert_eq!(
            validity
                .invocation_descriptor
                .environment_value_kind_literals,
            [
                "literal",
                "campaign_relative_path",
                "windows_host_runtime_path"
            ]
        );
        assert!(!validity
            .invocation_descriptor
            .environment_value_kind_literals
            .contains(&"inherited".to_owned()));
        for required in [
            "NO_COLOR_literal_1",
            "RUST_BACKTRACE_literal_0",
            "TEMP_campaign_relative_path_tmp/rNN_cNN_eN",
            "non_windows_has_exactly_8_entries",
            "windows_has_exactly_10",
        ] {
            assert!(validity
                .invocation_descriptor
                .environment_mapping_rule
                .contains(required));
        }
    }

    fn assert_build_environment_mutations_reject(
        environment: &[BuildEnvironmentEntry],
        windows: bool,
        target_triple: &str,
        committer_timestamp: u64,
        target_linker_relative_path: &str,
    ) {
        let rejected = |changed: &[BuildEnvironmentEntry]| {
            !valid_build_environment(
                changed,
                windows,
                target_triple,
                committer_timestamp,
                target_linker_relative_path,
            )
        };
        for index in 0..environment.len() {
            let mut changed = environment.to_vec();
            changed[index].resolved_value = "substituted".to_owned();
            assert!(rejected(&changed));
        }
        let mut wrong_name = environment.to_vec();
        wrong_name[4].name = "CARGO_TARGET_{TARGET_TRIPLE_ENV}_LINKER".to_owned();
        assert!(rejected(&wrong_name));
        let mut wrong_kind = environment.to_vec();
        wrong_kind[0].value_kind = "literal".to_owned();
        assert!(rejected(&wrong_kind));
        let mut reordered = environment.to_vec();
        reordered.swap(0, 1);
        assert!(rejected(&reordered));
        let mut missing = environment.to_vec();
        missing.pop();
        assert!(rejected(&missing));
        let mut extra = environment.to_vec();
        extra.push(BuildEnvironmentEntry {
            name: "RUSTC_WRAPPER".to_owned(),
            value_kind: "literal".to_owned(),
            resolved_value: "wrapper".to_owned(),
        });
        assert!(rejected(&extra));
        let zero_epoch =
            canonical_build_environment(windows, target_triple, 0, target_linker_relative_path)
                .unwrap();
        assert!(rejected(&zero_epoch));
    }

    fn assert_build_environment_vector(
        windows: bool,
        target_triple: &str,
        exact_linker_name: &str,
    ) {
        const COMMITTER_TIMESTAMP: u64 = 1_700_000_123;
        let target_linker_relative_path = fixture_target_linker_relative_path(windows);
        let environment = canonical_build_environment(
            windows,
            target_triple,
            COMMITTER_TIMESTAMP,
            target_linker_relative_path,
        )
        .unwrap();
        assert!(valid_build_environment(
            &environment,
            windows,
            target_triple,
            COMMITTER_TIMESTAMP,
            target_linker_relative_path,
        ));
        assert_eq!(environment[4].name, exact_linker_name);
        assert!(!environment[4].name.contains(['{', '}', '<', '>']));
        let root = if windows {
            FIXED_BUILD_ROOT_WINDOWS
        } else {
            FIXED_BUILD_ROOT_NON_WINDOWS
        };
        assert_eq!(
            environment[0].resolved_value,
            format!("{root}/inputs/cargo-home")
        );
        assert_eq!(
            environment[6].resolved_value,
            format!(
                "{root}/inputs/toolchain/bin/{}",
                if windows { "rustc.exe" } else { "rustc" }
            )
        );
        assert_build_environment_mutations_reject(
            &environment,
            windows,
            target_triple,
            COMMITTER_TIMESTAMP,
            target_linker_relative_path,
        );
    }

    #[test]
    fn fixed_build_environment_and_input_inventory_are_exact() {
        const COMMITTER_TIMESTAMP: u64 = 1_700_000_123;
        assert_build_environment_vector(
            false,
            "x86_64-unknown-linux-gnu",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        );
        assert_build_environment_vector(
            true,
            "x86_64-pc-windows-msvc",
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
        );
        assert_eq!(
            concrete_target_linker_environment_name("a.b_c-d9").as_deref(),
            Some("CARGO_TARGET_A_B_C_D9_LINKER")
        );
        for invalid in ["", "a/b", "a+b", "a b", "a{b"] {
            assert!(concrete_target_linker_environment_name(invalid).is_none());
        }
        assert!(concrete_target_linker_environment_name(&"a".repeat(129)).is_none());
        let global = run_validity_protocol().global_preimages;
        assert_eq!(
            field_names(&global.fixed_binary_build_input_inventory.fields),
            [
                "schema",
                "campaign_id",
                "target_triple",
                "entry_count",
                "total_byte_length",
                "archive_fingerprint",
                "executable_path_directories",
                "entries"
            ]
        );
        for required in [
            "--frozen_--offline",
            "forces_the_fingerprinted_rustc",
            "rejects_RUSTC_WRAPPER",
            "sandboxes_reads_to_worktree",
            "real_prebuild_probe",
        ] {
            assert!(global
                .fixed_binary_build_receipt
                .semantic_rule
                .contains(required));
        }
        for required in [
            "analyzer_reconstructs_the_exact_retained_tree",
            "repeats_rustc_--print_sysroot",
            "exact_cargo_metadata_--frozen_--offline_--locked_--format-version_1",
            "same_resolved_dependency_graph",
        ] {
            assert!(global.fixed_binary_build_rule.contains(required));
        }
        let fixture = golden_source_archive_fixture();
        let committer_timestamp =
            git_commit_committer_timestamp(&fixture.commit, &fixture.manifest.source_tree).unwrap();
        assert_eq!(committer_timestamp, COMMITTER_TIMESTAMP);
        let source_date_epoch = canonical_build_environment(
            true,
            "x86_64-pc-windows-msvc",
            committer_timestamp,
            fixture_target_linker_relative_path(true),
        )
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == "SOURCE_DATE_EPOCH")
        .unwrap();
        assert_eq!(source_date_epoch.resolved_value, "1700000123");
    }

    #[test]
    fn offline_dependency_resolution_probe_is_exact_and_coupled() {
        const COMMITTER_TIMESTAMP: u64 = 1_700_000_123;
        let windows = false;
        let target_triple = "x86_64-unknown-linux-gnu";
        let target_linker_relative_path = fixture_target_linker_relative_path(windows);
        let receipt_build_environment = canonical_build_environment(
            windows,
            target_triple,
            COMMITTER_TIMESTAMP,
            target_linker_relative_path,
        )
        .unwrap();
        let receipt_materialized_build_root = FIXED_BUILD_ROOT_NON_WINDOWS;
        let receipt_working_directory = format!("{receipt_materialized_build_root}/worktree");
        let observation = OfflineDependencyProbeObservation {
            argv: [
                "cargo",
                "metadata",
                "--frozen",
                "--offline",
                "--locked",
                "--format-version",
                "1",
            ]
            .map(str::to_owned)
            .to_vec(),
            succeeded: true,
            materialized_build_root: receipt_materialized_build_root.to_owned(),
            working_directory: receipt_working_directory.clone(),
            build_environment: receipt_build_environment.clone(),
        };
        let receipt = OfflineDependencyProbeReceiptContext {
            materialized_build_root: receipt_materialized_build_root,
            working_directory: &receipt_working_directory,
            build_environment: &receipt_build_environment,
            windows,
            target_triple,
            committer_timestamp: COMMITTER_TIMESTAMP,
            target_linker_relative_path,
        };
        let accepted = |candidate: &OfflineDependencyProbeObservation| {
            valid_offline_dependency_probe_observation(candidate, &receipt)
        };
        assert!(accepted(&observation));

        let mut missing = observation.clone();
        missing.argv.pop();
        assert!(!accepted(&missing));
        let mut extra = observation.clone();
        extra.argv.push("--extra".to_owned());
        assert!(!accepted(&extra));
        let mut reordered = observation.clone();
        reordered.argv.swap(2, 3);
        assert!(!accepted(&reordered));
        let mut mutated = observation.clone();
        mutated.argv[3] = "--online".to_owned();
        assert!(!accepted(&mutated));
        let mut failed = observation.clone();
        failed.succeeded = false;
        assert!(!accepted(&failed));
        let mut wrong_root = observation.clone();
        wrong_root.materialized_build_root = "/different-root".to_owned();
        assert!(!accepted(&wrong_root));
        let mut wrong_working_directory = observation.clone();
        wrong_working_directory.working_directory =
            format!("{receipt_materialized_build_root}/other-tree");
        assert!(!accepted(&wrong_working_directory));
        let mut wrong_environment = observation;
        wrong_environment.build_environment[0].resolved_value =
            "/different-root/inputs/cargo-home".to_owned();
        assert!(!accepted(&wrong_environment));
    }

    fn synthetic_cargo_metadata_output(project: &Path, cargo_home: &Path) -> std::process::Output {
        std::process::Command::new(env!("CARGO"))
            .args([
                "metadata",
                "--frozen",
                "--offline",
                "--locked",
                "--format-version",
                "1",
            ])
            .current_dir(project)
            .env("CARGO_HOME", cargo_home)
            .env_remove("CARGO_BUILD_TARGET")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTFLAGS")
            .output()
            .expect("run synthetic offline Cargo metadata fixture")
    }

    fn run_synthetic_cargo_metadata(project: &Path, cargo_home: &Path) -> std::path::PathBuf {
        let output = synthetic_cargo_metadata_output(project, cargo_home);
        assert!(
            output.status.success(),
            "synthetic Cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON");
        std::path::PathBuf::from(
            metadata["target_directory"]
                .as_str()
                .expect("Cargo metadata target_directory"),
        )
    }

    #[test]
    fn cargo_metadata_consumes_only_the_home_level_retained_config() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let cargo_home = temp.path().join("cargo-home");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::create_dir_all(&cargo_home).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"retained-config-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
        )
        .unwrap();
        fs::write(project.join("src/lib.rs"), "").unwrap();
        fs::write(
            project.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"retained-config-fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let fixture = golden_build_input_archive_fixture();
        let config_position = fixture
            .inventory
            .entries
            .iter()
            .position(|entry| entry.role == "cargo_configuration")
            .unwrap();
        let config_entry = &fixture.inventory.entries[config_position];
        let retained_config = &fixture.contents[config_position];
        assert_eq!(config_entry.relative_path, "cargo-home/config.toml");
        assert_eq!(
            source_archive_fingerprint(retained_config),
            config_entry.fingerprint
        );
        fs::write(cargo_home.join("config.toml"), retained_config).unwrap();
        assert_eq!(
            run_synthetic_cargo_metadata(&project, &cargo_home),
            temp.path().join("retained-target")
        );

        fs::remove_file(cargo_home.join("config.toml")).unwrap();
        fs::create_dir_all(cargo_home.join("config")).unwrap();
        fs::write(cargo_home.join("config/config.toml"), retained_config).unwrap();
        let nested_config_output = synthetic_cargo_metadata_output(&project, &cargo_home);
        assert!(!nested_config_output.status.success());
    }

    #[test]
    fn fixed_build_layout_couples_environment_to_retained_member_paths() {
        const COMMITTER_TIMESTAMP: u64 = 1_700_000_123;
        for (windows, target_triple) in [
            (false, "x86_64-unknown-linux-gnu"),
            (true, "x86_64-pc-windows-msvc"),
        ] {
            let inventory = canonical_build_input_inventory(windows, target_triple);
            let environment = canonical_build_environment(
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                fixture_target_linker_relative_path(windows),
            )
            .unwrap();
            let root = if windows {
                FIXED_BUILD_ROOT_WINDOWS
            } else {
                FIXED_BUILD_ROOT_NON_WINDOWS
            };
            let reported_sysroot = format!("{root}/inputs/toolchain");
            assert!(valid_build_layout(
                &environment,
                &inventory,
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                &reported_sysroot,
            ));

            let mut alternate_linker_inventory = inventory.clone();
            let alternate_linker_relative_path = if windows {
                "tools/linker/retained-link.exe"
            } else {
                "tools/linker/retained-cc"
            };
            alternate_linker_inventory
                .entries
                .iter_mut()
                .find(|entry| entry.role == "target_linker_executable")
                .unwrap()
                .relative_path = alternate_linker_relative_path.to_owned();
            let alternate_linker_environment = canonical_build_environment(
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                alternate_linker_relative_path,
            )
            .unwrap();
            assert!(valid_build_layout(
                &alternate_linker_environment,
                &alternate_linker_inventory,
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                &reported_sysroot,
            ));
            assert!(!valid_build_layout(
                &environment,
                &alternate_linker_inventory,
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                &reported_sysroot,
            ));

            let mut disconnected_cargo_home = environment.clone();
            disconnected_cargo_home[0].resolved_value = format!("{root}/cargo-home");
            assert!(!valid_build_layout(
                &disconnected_cargo_home,
                &inventory,
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                &reported_sysroot,
            ));
            assert!(!valid_build_layout(
                &environment,
                &inventory,
                windows,
                target_triple,
                COMMITTER_TIMESTAMP,
                &format!("{root}/inputs/sysroot"),
            ));
            if windows {
                let mut live_system_root = environment.clone();
                let system_root = live_system_root
                    .iter_mut()
                    .find(|entry| entry.name == "SystemRoot")
                    .unwrap();
                system_root.resolved_value = "C:/Windows".to_owned();
                assert!(!valid_build_layout(
                    &live_system_root,
                    &inventory,
                    windows,
                    target_triple,
                    COMMITTER_TIMESTAMP,
                    &reported_sysroot,
                ));
            }
        }
    }

    fn assert_flexible_build_input_role_paths(
        inventory: &BuildInputInventory,
        windows: bool,
        target_triple: &str,
    ) {
        let mut linker_side_helper = inventory.clone();
        linker_side_helper.entries.push(build_input_entry(
            "executable_path_input",
            if windows {
                "tools/linker/side-helper.exe"
            } else {
                "tools/linker/side-helper"
            },
            "100755",
            4_096,
        ));
        linker_side_helper.entries.sort_by(|left, right| {
            (left.role.as_bytes(), left.relative_path.as_bytes())
                .cmp(&(right.role.as_bytes(), right.relative_path.as_bytes()))
        });
        refresh_build_input_inventory_projection(&mut linker_side_helper);
        assert!(valid_build_input_inventory(
            &linker_side_helper,
            windows,
            target_triple,
        ));

        let dynamic_dependency = inventory
            .entries
            .iter()
            .position(|entry| entry.role == "tool_dynamic_dependency")
            .unwrap();
        let dynamic_file = if windows {
            "side-runtime.dll"
        } else {
            "side-runtime.so"
        };
        let mut linker_side_dynamic = inventory.clone();
        linker_side_dynamic.entries[dynamic_dependency].relative_path =
            format!("tools/linker/{dynamic_file}");
        assert!(valid_build_input_inventory(
            &linker_side_dynamic,
            windows,
            target_triple,
        ));
        let mut nested_runtime_dynamic = inventory.clone();
        nested_runtime_dynamic.entries[dynamic_dependency].relative_path =
            format!("tools/runtime/nested/{dynamic_file}");
        assert!(valid_build_input_inventory(
            &nested_runtime_dynamic,
            windows,
            target_triple,
        ));
        let mut unpaired_nested_dynamic = linker_side_dynamic;
        unpaired_nested_dynamic.entries[dynamic_dependency].relative_path =
            format!("tools/linker/nested/{dynamic_file}");
        assert!(!valid_build_input_inventory(
            &unpaired_nested_dynamic,
            windows,
            target_triple,
        ));

        let mut undeclared_path_helper = inventory.clone();
        undeclared_path_helper
            .entries
            .iter_mut()
            .find(|entry| entry.role == "executable_path_input")
            .unwrap()
            .relative_path = "tools/other/path-helper".to_owned();
        assert!(!valid_build_input_inventory(
            &undeclared_path_helper,
            windows,
            target_triple,
        ));
    }

    fn assert_build_input_inventory_projection(windows: bool, target_triple: &str) {
        let inventory = canonical_build_input_inventory(windows, target_triple);
        assert!(valid_build_input_inventory(
            &inventory,
            windows,
            target_triple
        ));
        assert_eq!(
            inventory.total_byte_length,
            if windows {
                1_673_583_295
            } else {
                1_463_868_095
            }
        );
        assert!(inventory.total_byte_length <= MAX_FIXED_BUILD_INPUT_BYTES);
        assert_eq!(
            inventory
                .entries
                .iter()
                .filter(|entry| entry.role == "rustc_sysroot_file")
                .map(|entry| entry.fingerprint.byte_length)
                .sum::<u64>(),
            MEASURED_PINNED_WINDOWS_SYSROOT_BYTES
        );
        assert_eq!(
            inventory.archive_fingerprint.byte_length,
            u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len()).unwrap()
                + u64::from(inventory.entry_count) * 8
                + inventory.total_byte_length
        );
        assert_flexible_build_input_role_paths(&inventory, windows, target_triple);

        let mut missing_tool = inventory.clone();
        let position = missing_tool
            .entries
            .iter()
            .position(|entry| entry.role == "cargo_executable")
            .unwrap();
        missing_tool.entries.remove(position);
        refresh_build_input_inventory_projection(&mut missing_tool);
        assert!(!valid_build_input_inventory(
            &missing_tool,
            windows,
            target_triple
        ));

        let mut unknown_role = inventory.clone();
        unknown_role.entries[0].role = "unknown".to_owned();
        unknown_role.entries.sort_by(|left, right| {
            (left.role.as_bytes(), left.relative_path.as_bytes())
                .cmp(&(right.role.as_bytes(), right.relative_path.as_bytes()))
        });
        assert!(!valid_build_input_inventory(
            &unknown_role,
            windows,
            target_triple
        ));

        let mut missing_runtime_executable = inventory.clone();
        missing_runtime_executable
            .entries
            .retain(|entry| entry.role != "executable_path_input");
        refresh_build_input_inventory_projection(&mut missing_runtime_executable);
        assert!(missing_runtime_executable
            .entries
            .iter()
            .any(|entry| entry.relative_path.starts_with("tools/runtime/")));
        assert!(!valid_build_input_inventory(
            &missing_runtime_executable,
            windows,
            target_triple,
        ));

        let mut alias = inventory.clone();
        let sysroot = alias
            .entries
            .iter()
            .position(|entry| entry.role == "rustc_sysroot_file")
            .unwrap();
        alias.entries[sysroot + 1].relative_path =
            alias.entries[sysroot].relative_path.to_ascii_uppercase();
        alias.entries.sort_by(|left, right| {
            (left.role.as_bytes(), left.relative_path.as_bytes())
                .cmp(&(right.role.as_bytes(), right.relative_path.as_bytes()))
        });
        assert!(!valid_build_input_inventory(&alias, windows, target_triple));

        let mut reordered_path = inventory;
        reordered_path.executable_path_directories.swap(0, 1);
        assert!(!valid_build_input_inventory(
            &reordered_path,
            windows,
            target_triple
        ));
    }

    #[test]
    fn fixed_build_input_inventory_roles_paths_and_feasibility_are_exact() {
        assert_build_input_inventory_projection(false, "x86_64-unknown-linux-gnu");
        assert_build_input_inventory_projection(true, "x86_64-pc-windows-msvc");
        assert!(valid_fixed_build_root(FIXED_BUILD_ROOT_WINDOWS, true));
        assert!(valid_fixed_build_root(FIXED_BUILD_ROOT_NON_WINDOWS, false));
        assert!(!valid_fixed_build_root("D:/relocated", true));
        assert_eq!(
            format!("{FIXED_BUILD_ROOT_WINDOWS}/worktree"),
            "M:/marty-cdla-build-v1/worktree"
        );
        let global = run_validity_protocol().global_preimages;
        assert_eq!(
            global.fixed_binary_build_input_role_literals,
            [
                "cargo_configuration",
                "cargo_dependency_source",
                "cargo_executable",
                "executable_path_input",
                "rustc_executable",
                "rustc_sysroot_file",
                "target_archiver_executable",
                "target_linker_executable",
                "tool_dynamic_dependency",
                "windows_runtime_input",
            ]
        );
        assert_eq!(
            field_names(&global.fixed_binary_build_environment_entry_fields),
            ["name", "value_kind", "resolved_value"]
        );
        assert_eq!(
            field_names(&global.fixed_binary_build_input_inventory_entry_fields),
            ["role", "relative_path", "file_mode", "fingerprint"]
        );
    }

    #[test]
    fn fixed_build_input_inventory_rejects_duplicates_escapes_and_oversize() {
        let target_triple = "x86_64-unknown-linux-gnu";
        let inventory = canonical_build_input_inventory(false, target_triple);
        let mut duplicate = inventory.clone();
        duplicate.entries.push(duplicate.entries[0].clone());
        duplicate.entries.sort_by(|left, right| {
            (left.role.as_bytes(), left.relative_path.as_bytes())
                .cmp(&(right.role.as_bytes(), right.relative_path.as_bytes()))
        });
        refresh_build_input_inventory_projection(&mut duplicate);
        assert!(!valid_build_input_inventory(
            &duplicate,
            false,
            target_triple
        ));

        let mut escape = inventory.clone();
        escape.entries[0].relative_path = "../escape".to_owned();
        assert!(!valid_build_input_inventory(&escape, false, target_triple));

        let mut nested_cargo_config = inventory.clone();
        nested_cargo_config
            .entries
            .iter_mut()
            .find(|entry| entry.role == "cargo_configuration")
            .unwrap()
            .relative_path = "cargo-home/config/config.toml".to_owned();
        assert!(!valid_build_input_inventory(
            &nested_cargo_config,
            false,
            target_triple,
        ));

        let mut missing_cargo_config = inventory.clone();
        missing_cargo_config
            .entries
            .retain(|entry| entry.role != "cargo_configuration");
        refresh_build_input_inventory_projection(&mut missing_cargo_config);
        assert!(!valid_build_input_inventory(
            &missing_cargo_config,
            false,
            target_triple,
        ));

        let mut git_admin = inventory.clone();
        git_admin.entries[0].relative_path = "cargo-home/.GIT/config".to_owned();
        assert!(!valid_build_input_inventory(
            &git_admin,
            false,
            target_triple
        ));

        let mut wrong_mode = inventory.clone();
        let cargo = wrong_mode
            .entries
            .iter()
            .position(|entry| entry.role == "cargo_executable")
            .unwrap();
        wrong_mode.entries[cargo].file_mode = "100644".to_owned();
        assert!(!valid_build_input_inventory(
            &wrong_mode,
            false,
            target_triple
        ));

        let mut oversized = inventory;
        let increase = MAX_FIXED_BUILD_INPUT_BYTES - oversized.archive_fingerprint.byte_length + 1;
        oversized.entries[0].fingerprint.byte_length += increase;
        refresh_build_input_inventory_projection(&mut oversized);
        assert!(!valid_build_input_inventory(
            &oversized,
            false,
            target_triple
        ));
    }

    fn assert_build_archive_member_mutations(
        fixture: &GoldenBuildInputArchiveFixture,
        target_triple: &str,
    ) {
        let mut changed_contents = fixture.contents.clone();
        changed_contents[0][0] ^= 1;
        let changed_archive = encode_build_input_archive(&changed_contents);
        let changed_archive_fingerprint = source_archive_fingerprint(&changed_archive);
        let mut changed_inventory = fixture.inventory.clone();
        changed_inventory.archive_fingerprint = changed_archive_fingerprint.clone();
        let changed_inventory_fingerprint =
            source_archive_fingerprint(&canonical_build_input_inventory_bytes(&changed_inventory));
        assert!(!valid_build_input_archive_bytes(
            &changed_archive,
            &changed_inventory,
            &changed_inventory_fingerprint,
            &changed_archive_fingerprint,
            false,
            target_triple,
        ));

        let mut changed_length_prefix = fixture.archive.clone();
        let first_length = FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len();
        changed_length_prefix[first_length..first_length + 8].copy_from_slice(&8_u64.to_be_bytes());
        let changed_length_prefix_fingerprint = source_archive_fingerprint(&changed_length_prefix);
        let mut changed_length_prefix_inventory = fixture.inventory.clone();
        changed_length_prefix_inventory.archive_fingerprint =
            changed_length_prefix_fingerprint.clone();
        let changed_length_prefix_inventory_fingerprint = source_archive_fingerprint(
            &canonical_build_input_inventory_bytes(&changed_length_prefix_inventory),
        );
        assert!(!valid_build_input_archive_bytes(
            &changed_length_prefix,
            &changed_length_prefix_inventory,
            &changed_length_prefix_inventory_fingerprint,
            &changed_length_prefix_fingerprint,
            false,
            target_triple,
        ));

        let mut changed_hash = fixture.inventory.clone();
        changed_hash.entries[0].fingerprint.sha256 = "F".repeat(64);
        let changed_hash_fingerprint =
            source_archive_fingerprint(&canonical_build_input_inventory_bytes(&changed_hash));
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &changed_hash,
            &changed_hash_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));

        let mut lengthened_contents = fixture.contents.clone();
        lengthened_contents[0].push(b'!');
        let lengthened_archive = encode_build_input_archive(&lengthened_contents);
        let lengthened_archive_fingerprint = source_archive_fingerprint(&lengthened_archive);
        let mut lengthened_inventory = fixture.inventory.clone();
        lengthened_inventory.entries[0].fingerprint.byte_length += 1;
        lengthened_inventory.archive_fingerprint = lengthened_archive_fingerprint.clone();
        refresh_build_input_inventory_projection(&mut lengthened_inventory);
        let lengthened_inventory_fingerprint = source_archive_fingerprint(
            &canonical_build_input_inventory_bytes(&lengthened_inventory),
        );
        assert!(!valid_build_input_archive_bytes(
            &lengthened_archive,
            &lengthened_inventory,
            &lengthened_inventory_fingerprint,
            &lengthened_archive_fingerprint,
            false,
            target_triple,
        ));

        let mut changed_mode = fixture.inventory.clone();
        changed_mode.entries[0].file_mode = "100755".to_owned();
        let changed_mode_fingerprint =
            source_archive_fingerprint(&canonical_build_input_inventory_bytes(&changed_mode));
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &changed_mode,
            &changed_mode_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));
    }

    fn assert_literal_build_input_members(fixture: &GoldenBuildInputArchiveFixture) {
        let literal_members = [
            (
                "cargo_configuration",
                "cargo-home/config.toml",
                "100644",
                39,
                "C2908B2E3F2AF915DA9B6785B662E77DBD9F8FD33E89F23C384FC056E6D633F6",
            ),
            (
                "cargo_dependency_source",
                "cargo-home/registry/src/index/dep.rs",
                "100644",
                7,
                "A49FE3DA4ECF2003F746F5854DFBE245C5CF3C99C798DC5DD8A8D90B905B941A",
            ),
            (
                "cargo_executable",
                "toolchain/bin/cargo",
                "100755",
                9,
                "BB5FD492C34FA370722DB3271C64180D435FF4B2669B04F53D3532EA93A8B7AB",
            ),
            (
                "executable_path_input",
                "tools/runtime/path-helper",
                "100755",
                11,
                "BA21AFFB450AD5FCB57D501CB4D694D584743758E97AC43B43027538532287CB",
            ),
            (
                "rustc_executable",
                "toolchain/bin/rustc",
                "100755",
                9,
                "473CEBC43675DD8D54153123D7D6572C212978C8533BB21A1B8884F512673DE0",
            ),
            (
                "rustc_sysroot_file",
                "toolchain/lib/rustlib/libfixture.rlib",
                "100644",
                11,
                "CF8486D5DF371F16351895331021E3E707E0F1ACE29F702B805D4A72065808A2",
            ),
            (
                "target_archiver_executable",
                "tools/archiver/ar",
                "100755",
                6,
                "4DA7712C4D27B566122EB74EEE0552128E64725B1D65805D4B9225E1952F036F",
            ),
            (
                "target_linker_executable",
                "tools/linker/cc",
                "100755",
                8,
                "C335FBCC502407D726603E0476A7C3C260EE6092466ADACCAA5C5E4B8E6790DA",
            ),
        ];
        assert_eq!(fixture.inventory.entries.len(), literal_members.len());
        for (entry, expected) in fixture.inventory.entries.iter().zip(literal_members) {
            assert_eq!(
                (
                    entry.role.as_str(),
                    entry.relative_path.as_str(),
                    entry.file_mode.as_str(),
                    entry.fingerprint.byte_length,
                    entry.fingerprint.sha256.as_str(),
                ),
                expected,
            );
        }
    }

    fn assert_literal_build_input_inventory_fingerprint(fixture: &GoldenBuildInputArchiveFixture) {
        assert_eq!(
            (
                fixture.inventory_fingerprint.byte_length,
                fixture.inventory_fingerprint.sha256.as_str(),
            ),
            (
                2_702,
                "478B3DE94CB986562B9D27CBF3BCCEAB07CAEADB219ACF23676C295D739DCA46",
            )
        );
    }

    fn assert_build_input_inventory_fingerprint_mutations(
        fixture: &GoldenBuildInputArchiveFixture,
        target_triple: &str,
    ) {
        let wrong_inventory_fingerprint = ArtifactFingerprint {
            sha256: "0".repeat(64),
            byte_length: fixture.inventory_fingerprint.byte_length,
        };
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &fixture.inventory,
            &wrong_inventory_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));

        let mut rebound_mode_inventory = fixture.inventory.clone();
        rebound_mode_inventory
            .entries
            .iter_mut()
            .find(|entry| entry.role == "rustc_sysroot_file")
            .unwrap()
            .file_mode = "100755".to_owned();
        assert!(valid_build_input_inventory(
            &rebound_mode_inventory,
            false,
            target_triple,
        ));
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &rebound_mode_inventory,
            &fixture.inventory_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));
        let rebound_mode_inventory_fingerprint = source_archive_fingerprint(
            &canonical_build_input_inventory_bytes(&rebound_mode_inventory),
        );
        assert!(valid_build_input_archive_bytes(
            &fixture.archive,
            &rebound_mode_inventory,
            &rebound_mode_inventory_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));

        let mut mismatched_archive_inventory = fixture.inventory.clone();
        mismatched_archive_inventory.archive_fingerprint.sha256 = "F".repeat(64);
        let mismatched_archive_inventory_fingerprint = source_archive_fingerprint(
            &canonical_build_input_inventory_bytes(&mismatched_archive_inventory),
        );
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &mismatched_archive_inventory,
            &mismatched_archive_inventory_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));
    }

    fn assert_malformed_build_input_archives_reject(
        fixture: &GoldenBuildInputArchiveFixture,
        target_triple: &str,
    ) {
        for malformed_archive in [
            fixture.archive[..fixture.archive.len() - 1].to_vec(),
            {
                let mut trailing = fixture.archive.clone();
                trailing.push(0);
                trailing
            },
            {
                let mut extra_member = fixture.archive.clone();
                extra_member.extend_from_slice(&0_u64.to_be_bytes());
                extra_member
            },
        ] {
            let rebound = source_archive_fingerprint(&malformed_archive);
            let mut rebound_inventory = fixture.inventory.clone();
            rebound_inventory.archive_fingerprint = rebound.clone();
            let rebound_inventory_fingerprint = source_archive_fingerprint(
                &canonical_build_input_inventory_bytes(&rebound_inventory),
            );
            assert!(!valid_build_input_archive_bytes(
                &malformed_archive,
                &rebound_inventory,
                &rebound_inventory_fingerprint,
                &rebound,
                false,
                target_triple,
            ));
        }

        let mut missing_role = fixture.inventory.clone();
        let cargo = missing_role
            .entries
            .iter()
            .position(|entry| entry.role == "cargo_executable")
            .unwrap();
        missing_role.entries.remove(cargo);
        let mut missing_contents = fixture.contents.clone();
        missing_contents.remove(cargo);
        let missing_archive = encode_build_input_archive(&missing_contents);
        missing_role.archive_fingerprint = source_archive_fingerprint(&missing_archive);
        refresh_build_input_inventory_projection(&mut missing_role);
        let missing_inventory_fingerprint =
            source_archive_fingerprint(&canonical_build_input_inventory_bytes(&missing_role));
        assert!(!valid_build_input_archive_bytes(
            &missing_archive,
            &missing_role,
            &missing_inventory_fingerprint,
            &missing_role.archive_fingerprint,
            false,
            target_triple,
        ));
    }

    #[test]
    fn fixed_build_input_archive_binds_exact_members_modes_and_inventory() {
        let fixture = golden_build_input_archive_fixture();
        let target_triple = "x86_64-unknown-linux-gnu";
        assert!(valid_build_input_archive_bytes(
            &fixture.archive,
            &fixture.inventory,
            &fixture.inventory_fingerprint,
            &fixture.inventory.archive_fingerprint,
            false,
            target_triple,
        ));
        assert_eq!(fixture.inventory.total_byte_length, 100);
        assert_eq!(fixture.archive.len(), 200);
        assert_literal_build_input_members(&fixture);
        assert_literal_build_input_inventory_fingerprint(&fixture);
        assert!(build_input_archive_length_is_valid(
            MAX_FIXED_BUILD_INPUT_BYTES
        ));
        assert!(!build_input_archive_length_is_valid(
            MAX_FIXED_BUILD_INPUT_BYTES + 1
        ));
        assert_eq!(
            fixture.inventory.archive_fingerprint.sha256,
            "898733B52DD5A5F6CA5AD21A62D0C5CF60124C620C7363658D94A4A99C9912C1"
        );
        assert_build_archive_member_mutations(&fixture, target_triple);
        assert_build_input_inventory_fingerprint_mutations(&fixture, target_triple);
        assert_malformed_build_input_archives_reject(&fixture, target_triple);

        let wrong_outer = ArtifactFingerprint {
            sha256: "0".repeat(64),
            byte_length: fixture.inventory.archive_fingerprint.byte_length,
        };
        assert!(!valid_build_input_archive_bytes(
            &fixture.archive,
            &fixture.inventory,
            &fixture.inventory_fingerprint,
            &wrong_outer,
            false,
            target_triple,
        ));
    }

    #[test]
    fn artifact_index_acceptance_is_exact() {
        let manifest = manifest();
        let campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001";
        let route = canonical_artifact_index(&manifest, campaign_id, IndexArtifactKind::Route);
        let criterion =
            canonical_artifact_index(&manifest, campaign_id, IndexArtifactKind::Criterion);
        let route_fingerprints = route
            .entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        let criterion_fingerprints = criterion
            .entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        assert!(valid_artifact_index(
            &manifest,
            campaign_id,
            IndexArtifactKind::Route,
            &route,
            &route_fingerprints
        ));
        assert!(valid_artifact_index(
            &manifest,
            campaign_id,
            IndexArtifactKind::Criterion,
            &criterion,
            &criterion_fingerprints
        ));
        assert_ne!(route_fingerprints[0], criterion_fingerprints[0]);
        for (position, coordinate) in [(0, (0, 0, 0)), (528, (1, 0, 0)), (10_559, (19, 65, 7))] {
            assert_eq!(coordinate_at(position), Some(coordinate));
        }
        assert_eq!(
            scheduled_benchmark_id(&manifest, 0, 0, 0),
            Some(manifest.paired_cells[0].serial_id.as_str())
        );
        assert_eq!(
            scheduled_benchmark_id(&manifest, 1, 0, 0),
            Some(manifest.paired_cells[0].adaptive_id.as_str())
        );
        let interior = &criterion.entries[1_642];
        assert_eq!(interior.timing_process_id, "r03-c07-e2");
        assert_eq!(
            interior.full_benchmark_id,
            "sd_jwt_issuance/v2__s_fi__r_ac__p_s__d_0__n_0128"
        );
        assert_eq!(
            interior.relative_path,
            "criterion/r03_c07_e2/sd_jwt_issuance/v2__s_fi__r_ac__p_s__d_0__n_0128/new/estimates.json"
        );
    }

    #[test]
    fn artifact_index_mutations_fail_closed() {
        let manifest = manifest();
        let route_entries = canonical_index_entries(&manifest, IndexArtifactKind::Route);
        let criterion_entries = canonical_index_entries(&manifest, IndexArtifactKind::Criterion);
        let route_fingerprints = route_entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        let criterion_fingerprints = criterion_entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        let position = (3 * 66 + 7) * 8 + 2;
        let valid_route = &route_entries[position];
        for mutation in [
            "routes/r3_c07_e2.ndjson",
            "routes/r003_c07_e2.ndjson",
            "routes/r03-c07-e2.ndjson",
            "routes\\r03_c07_e2.ndjson",
            "routes/./r03_c07_e2.ndjson",
            "routes/../routes/r03_c07_e2.ndjson",
            "/routes/r03_c07_e2.ndjson",
            "C:/routes/r03_c07_e2.ndjson",
            "ROUTES/r03_c07_e2.ndjson",
            "routes/r03_c07_e2.ndjson.extra",
        ] {
            let mut changed = valid_route.clone();
            changed.relative_path = mutation.to_owned();
            assert!(!valid_index_entry(
                &manifest,
                position,
                IndexArtifactKind::Route,
                &changed,
                &route_fingerprints[position]
            ));
        }
        let mut wrong_coordinate = valid_route.clone();
        wrong_coordinate.global_round_ordinal = 20;
        assert!(!valid_index_entry(
            &manifest,
            position,
            IndexArtifactKind::Route,
            &wrong_coordinate,
            &route_fingerprints[position]
        ));
        let mut wrong_id = criterion_entries[position].clone();
        wrong_id.full_benchmark_id = manifest.paired_cells[8].serial_id.clone();
        assert!(!valid_index_entry(
            &manifest,
            position,
            IndexArtifactKind::Criterion,
            &wrong_id,
            &criterion_fingerprints[position]
        ));
        let mut wrong_criterion_path = criterion_entries[position].clone();
        wrong_criterion_path.relative_path = wrong_criterion_path
            .relative_path
            .replace("/new/estimates.json", "/base/benchmark.json");
        assert!(!valid_index_entry(
            &manifest,
            position,
            IndexArtifactKind::Criterion,
            &wrong_criterion_path,
            &criterion_fingerprints[position]
        ));
        let mut wrong_fingerprint = valid_route.clone();
        wrong_fingerprint.fingerprint.byte_length += 1;
        assert!(!valid_index_entry(
            &manifest,
            position,
            IndexArtifactKind::Route,
            &wrong_fingerprint,
            &route_fingerprints[position]
        ));
        assert!(!valid_index_entry(
            &manifest,
            position,
            IndexArtifactKind::Route,
            valid_route,
            &criterion_fingerprints[position]
        ));
    }

    #[test]
    fn artifact_index_sequence_mutations_fail_closed() {
        let manifest = manifest();
        let route_entries = canonical_index_entries(&manifest, IndexArtifactKind::Route);
        let route_fingerprints = route_entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        let mut missing = route_entries.clone();
        missing.pop();
        assert!(!valid_index_entries(
            &manifest,
            IndexArtifactKind::Route,
            &missing,
            &route_fingerprints
        ));
        let mut duplicate = route_entries.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(!valid_index_entries(
            &manifest,
            IndexArtifactKind::Route,
            &duplicate,
            &route_fingerprints
        ));
        let mut reordered = route_entries;
        reordered.swap(0, 1);
        assert!(!valid_index_entries(
            &manifest,
            IndexArtifactKind::Route,
            &reordered,
            &route_fingerprints
        ));
    }

    #[test]
    fn artifact_index_outer_contract_rejects_mutations() {
        let manifest = manifest();
        let campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001";
        let index = canonical_artifact_index(&manifest, campaign_id, IndexArtifactKind::Route);
        let fingerprints = index
            .entries
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect::<Vec<_>>();
        let valid = |value: &ArtifactIndexModel| {
            valid_artifact_index(
                &manifest,
                campaign_id,
                IndexArtifactKind::Route,
                value,
                &fingerprints,
            )
        };
        assert!(valid(&index));
        let mut wrong_schema = index.clone();
        wrong_schema.schema = IndexArtifactKind::Criterion.schema().to_owned();
        assert!(!valid(&wrong_schema));
        let mut wrong_campaign = index.clone();
        wrong_campaign.campaign_id.push('0');
        assert!(!valid(&wrong_campaign));
        let mut wrong_kind = index.clone();
        wrong_kind.artifact_kind = IndexArtifactKind::Criterion.literal().to_owned();
        assert!(!valid(&wrong_kind));
        let mut wrong_count = index.clone();
        wrong_count.entry_count -= 1;
        assert!(!valid(&wrong_count));
        let mut extra = index;
        extra.entries.push(extra.entries.last().unwrap().clone());
        extra.entry_count += 1;
        assert!(!valid(&extra));
    }

    fn anchor_publication_within(
        terminal: u64,
        receipt_observed: u64,
        ordinal_zero_session: &str,
        ordinal_zero_channel: u64,
        ordinal_one_session: &str,
        ordinal_one_channel: u64,
    ) -> bool {
        (ordinal_zero_session == ordinal_one_session)
            && receipt_observed
                .checked_sub(terminal)
                .and_then(|first| {
                    ordinal_one_channel
                        .checked_sub(ordinal_zero_channel)
                        .and_then(|second| first.checked_add(second))
                })
                .is_some_and(|delta| delta <= 300_000_000_000)
    }

    #[test]
    fn output_bounds_reject_mutations() {
        let output_within = |stdout: u64, stderr: u64| {
            stdout
                .checked_add(stderr)
                .is_some_and(|total| total <= 1_048_576)
        };
        assert!(output_within(1_048_575, 1));
        assert!(!output_within(1_048_576, 1));
        assert!(!output_within(u64::MAX, 1));
    }

    #[test]
    fn authenticated_anchor_bounds_reject_mutations() {
        assert!(anchor_publication_within(
            7,
            200_000_000_007,
            "clock-session-a",
            9,
            "clock-session-a",
            100_000_000_009
        ));
        assert!(!anchor_publication_within(
            7,
            200_000_000_007,
            "clock-session-a",
            9,
            "clock-session-b",
            100_000_000_009
        ));
        assert!(!anchor_publication_within(
            7,
            200_000_000_008,
            "clock-session-a",
            9,
            "clock-session-a",
            100_000_000_009
        ));
        assert!(!anchor_publication_within(
            8,
            7,
            "clock-session-a",
            9,
            "clock-session-a",
            10
        ));
        assert!(!anchor_publication_within(
            7,
            u64::MAX,
            "clock-session-a",
            9,
            "clock-session-a",
            u64::MAX
        ));
        let utc_values_are_not_cross_compared = |controller_utc: i64| {
            anchor_publication_within(
                7,
                200_000_000_007,
                "clock-session-a",
                9,
                "clock-session-a",
                100_000_000_009,
            ) && controller_utc.abs() <= 86_400
        };
        assert!(utc_values_are_not_cross_compared(-86_400));
        assert!(utc_values_are_not_cross_compared(86_400));
    }

    #[test]
    fn anchor_protocol_and_preimage_are_exact() {
        assert!(valid_receipt_id("receipt:0001-A_b.c"));
        assert!(!valid_receipt_id(""));
        assert!(!valid_receipt_id("receipt/0001"));
        assert!(!valid_receipt_id(&"a".repeat(129)));

        let completion = completion_protocol();
        assert_eq!(
            completion.external_anchor_channel_id,
            "marty-sd-jwt-issuance-anchor-v1"
        );
        assert_eq!(
            completion.external_anchor_log_id,
            "sd-jwt-issuance-qualification-v1"
        );
        assert_eq!(
            completion.external_anchor_connector_policy,
            "out_of_band_trust_root_authenticated_transport_v1"
        );
        assert_eq!(
            completion.external_anchor_signature_scheme,
            "ed25519_rfc8032_canonical_json_v1"
        );
        assert!(valid_uppercase_hex(&"A".repeat(64), 64));
        assert!(valid_uppercase_hex(&"B".repeat(128), 128));
        assert!(!valid_uppercase_hex(&"b".repeat(128), 128));
        assert!(field_names(&completion.external_anchor_fields).contains(&"log_id"));
        assert!(field_names(&completion.external_anchor_fields)
            .contains(&"terminal_observation_evidence_fingerprint"));
        assert!(completion
            .external_anchor_rule
            .contains("network_access_is_neither_used_nor_permitted"));
        assert!(completion
            .external_anchor_signed_preimage_rule
            .contains("MARTY-SD-JWT-TERMINAL-OBSERVATION-V1"));

        let unsigned = golden_terminal_unsigned();
        let unsigned_json = serde_json::to_vec(&unsigned).unwrap();
        let preimage =
            signed_json_preimage(b"MARTY-SD-JWT-TERMINAL-OBSERVATION-V1\0", &unsigned_json);
        assert_eq!(
            hex::encode_upper(Sha256::digest(&preimage)),
            "ADC9E1959318B44D2B192CC7D0200A3C5D4C130C726C222C2FC4AD4CA6DCF102"
        );
        let mut mutated = unsigned;
        mutated.controller_request_monotonic_nanoseconds += 1;
        let mutated_preimage = signed_json_preimage(
            b"MARTY-SD-JWT-TERMINAL-OBSERVATION-V1\0",
            &serde_json::to_vec(&mutated).unwrap(),
        );
        assert_ne!(preimage, mutated_preimage);
        assert_ne!(
            preimage,
            signed_json_preimage(b"MARTY-SD-JWT-COMPLETION-ANCHOR-V1\0", &unsigned_json)
        );
    }

    #[test]
    fn anchor_receipts_have_strict_ed25519_and_replay_vectors() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let (terminal, terminal_preimage) = signed_terminal_receipt(&signing_key);
        let (completion, completion_preimage) = signed_completion_anchor(&signing_key);
        let terminal_bytes = canonical_pretty_bytes(&terminal);
        let completion_bytes = canonical_pretty_bytes(&completion);
        assert!(valid_terminal_receipt_bytes(
            &terminal_bytes,
            &verifying_key
        ));
        assert!(valid_completion_anchor_bytes(
            &completion_bytes,
            &verifying_key
        ));
        assert_eq!(
            terminal.signature_uppercase_hex_512,
            "D311977F9FD74E2FA88B79127B51AB38A8FF67DA006267B53D99491B5740F32CE2B2B20287A19590D56AB6834D3DF2F8942A98D19BE7ADF282973AB182AF2F0C"
        );
        assert_eq!(
            completion.signature_uppercase_hex_512,
            "518D1B46F04CDFA02A61E8C080B62F5542C847B15CEB7806D4181188163E86F92795F2888CB5BFF93793377D5318D77075458F89E7478CC200670CE25C785E0C"
        );
        assert_eq!(
            source_archive_fingerprint(verifying_key.as_bytes()),
            ArtifactFingerprint {
                sha256: "3097E2DEE2CB4A34B53840CDB705AED71067C36F68DB0E0F559C3F3FA043315F"
                    .to_owned(),
                byte_length: 32,
            }
        );

        for (preimage, signature_hex) in [
            (
                &terminal_preimage,
                terminal.signature_uppercase_hex_512.as_str(),
            ),
            (
                &completion_preimage,
                completion.signature_uppercase_hex_512.as_str(),
            ),
        ] {
            for index in 0..preimage.len() {
                let mut changed = preimage.clone();
                changed[index] ^= 1;
                assert!(!strict_signature_verifies(
                    &verifying_key,
                    &changed,
                    signature_hex
                ));
            }
        }
        let wrong_key = SigningKey::from_bytes(&[0x43; 32]).verifying_key();
        assert!(!valid_terminal_receipt_bytes(&terminal_bytes, &wrong_key));
        let mut bad_signature = terminal.clone();
        let first_signature_byte =
            u8::from_str_radix(&bad_signature.signature_uppercase_hex_512[..2], 16).unwrap();
        bad_signature
            .signature_uppercase_hex_512
            .replace_range(0..2, &format!("{:02X}", first_signature_byte ^ 1));
        assert!(!valid_terminal_receipt_bytes(
            &canonical_pretty_bytes(&bad_signature),
            &verifying_key
        ));
        let mut high_scalar = terminal.clone();
        high_scalar.signature_uppercase_hex_512 = format!("{}{}", "00".repeat(32), "FF".repeat(32));
        assert!(!valid_terminal_receipt_bytes(
            &canonical_pretty_bytes(&high_scalar),
            &verifying_key
        ));
        let mut compact = serde_json::to_vec(&terminal).unwrap();
        compact.push(b'\n');
        assert!(!valid_terminal_receipt_bytes(&compact, &verifying_key));
        assert!(!valid_terminal_receipt_bytes(
            &vec![b' '; usize::try_from(MAX_EXTERNAL_ANCHOR_V1_BYTES).unwrap() + 1],
            &verifying_key
        ));
    }

    #[test]
    fn supplied_anchor_conflicts_compare_exact_signed_bytes() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let (terminal, _) = signed_terminal_receipt(&signing_key);
        let terminal_bytes = canonical_pretty_bytes(&terminal);
        let separately_retrieved_terminal_bytes = terminal_bytes.clone();
        assert!(terminal_receipt_set_has_no_conflict(
            &[
                terminal_bytes.as_slice(),
                separately_retrieved_terminal_bytes.as_slice(),
            ],
            &verifying_key,
        ));

        let mut conflicting_terminal = terminal;
        conflicting_terminal.challenge_uppercase_hex_256 = "D".repeat(64);
        resign_terminal_receipt(&mut conflicting_terminal, &signing_key);
        let conflicting_bytes = canonical_pretty_bytes(&conflicting_terminal);
        assert!(valid_terminal_receipt_bytes(
            &conflicting_bytes,
            &verifying_key
        ));
        let retained_wire: TerminalObservationReceiptWire =
            serde_json::from_slice(&terminal_bytes).unwrap();
        let conflicting_wire: TerminalObservationReceiptWire =
            serde_json::from_slice(&conflicting_bytes).unwrap();
        assert_eq!(
            (
                &retained_wire.channel_id,
                &retained_wire.log_id,
                &retained_wire.campaign_id,
                retained_wire.campaign_append_ordinal,
                &retained_wire.channel_receipt_id,
            ),
            (
                &conflicting_wire.channel_id,
                &conflicting_wire.log_id,
                &conflicting_wire.campaign_id,
                conflicting_wire.campaign_append_ordinal,
                &conflicting_wire.channel_receipt_id,
            )
        );
        assert!(!terminal_receipt_set_has_no_conflict(
            &[terminal_bytes.as_slice(), conflicting_bytes.as_slice()],
            &verifying_key,
        ));
    }

    #[test]
    fn source_archive_format_is_golden() {
        let fixture = golden_source_archive_fixture();
        let fingerprint = source_archive_fingerprint(&fixture.archive);
        assert!(valid_source_archive_bytes(
            &fixture.archive,
            &fingerprint,
            &fixture.cargo_lock_fingerprint
        ));
        assert_eq!(fixture.archive.len(), 1_162);
        assert_eq!(
            fingerprint.sha256,
            "3135A38DA0213D5639724160B757A319DDB5C9D685D16298B5754EA13EBD18F1"
        );
        assert_eq!(
            fixture.manifest.source_tree,
            "a8cad0707387a1afbdb5f57738d607d6fde4ab45"
        );
        assert_eq!(
            fixture.manifest.source_commit,
            "9b9421c2c50f037a66f2cb2f22819289437c35b2"
        );
    }

    #[test]
    fn source_archive_rejects_framing_mutations() {
        let fixture = golden_source_archive_fixture();
        let mut trailing = fixture.archive.clone();
        trailing.push(0);
        assert!(!valid_source_archive_bytes(
            &trailing,
            &source_archive_fingerprint(&trailing),
            &fixture.cargo_lock_fingerprint
        ));
        let mut wrong_endian = fixture.archive.clone();
        let length_offset = b"MARTY-SD-JWT-SOURCE-ARCHIVE-V1\n".len();
        wrong_endian[length_offset..length_offset + 8].reverse();
        assert!(!valid_source_archive_bytes(
            &wrong_endian,
            &source_archive_fingerprint(&wrong_endian),
            &fixture.cargo_lock_fingerprint
        ));
        let mut oversized_length = fixture.archive.clone();
        oversized_length[length_offset..length_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(!valid_source_archive_bytes(
            &oversized_length,
            &source_archive_fingerprint(&oversized_length),
            &fixture.cargo_lock_fingerprint
        ));
        let manifest_length = usize::try_from(u64::from_be_bytes(
            fixture.archive[length_offset..length_offset + 8]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let commit_length_offset = length_offset + 8 + manifest_length;
        let mut oversized_commit = fixture.archive.clone();
        oversized_commit[commit_length_offset..commit_length_offset + 8]
            .copy_from_slice(&(MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES + 1).to_be_bytes());
        assert!(!valid_source_archive_bytes(
            &oversized_commit,
            &source_archive_fingerprint(&oversized_commit),
            &fixture.cargo_lock_fingerprint
        ));
        let mut changed_content = fixture.archive.clone();
        *changed_content.last_mut().unwrap() ^= 1;
        assert!(!valid_source_archive_bytes(
            &changed_content,
            &source_archive_fingerprint(&changed_content),
            &fixture.cargo_lock_fingerprint
        ));
        assert!(!valid_source_archive_bytes(
            &fixture.archive,
            &golden_fingerprint(1),
            &fixture.cargo_lock_fingerprint
        ));
    }

    #[test]
    fn source_archive_rejects_git_and_external_lock_mutations() {
        let fixture = golden_source_archive_fixture();
        let mut wrong_blob = fixture.manifest.clone();
        wrong_blob.entries[1].git_object_id = "0".repeat(40);
        let archive = encode_source_archive(&wrong_blob, &fixture.commit, &fixture.contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
        let mut wrong_tree = fixture.manifest.clone();
        wrong_tree.source_tree = "0".repeat(40);
        let archive = encode_source_archive(&wrong_tree, &fixture.commit, &fixture.contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
        let mut wrong_commit = fixture.manifest.clone();
        wrong_commit.source_commit = "0".repeat(40);
        let archive = encode_source_archive(&wrong_commit, &fixture.commit, &fixture.contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
        let wrong_header_commit = fixture.commit.split(|byte| *byte == b'\n').skip(1).fold(
            format!("tree {}\n", "0".repeat(40)).into_bytes(),
            |mut value, line| {
                value.extend_from_slice(line);
                value.push(b'\n');
                value
            },
        );
        let mut wrong_header_manifest = fixture.manifest.clone();
        wrong_header_manifest.source_commit =
            hex::encode(git_object_id("commit", &wrong_header_commit));
        let archive = encode_source_archive(
            &wrong_header_manifest,
            &wrong_header_commit,
            &fixture.contents,
        );
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
        let mut changed_contents = fixture.contents;
        changed_contents[1] = b"pub fn changed() {}\n";
        let mut changed_manifest = fixture.manifest.clone();
        changed_manifest.entries[1].artifact_fingerprint =
            source_archive_fingerprint(changed_contents[1]);
        let archive = encode_source_archive(&changed_manifest, &fixture.commit, &changed_contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
        assert!(!valid_source_archive_bytes(
            &fixture.archive,
            &source_archive_fingerprint(&fixture.archive),
            &golden_fingerprint(9)
        ));
    }

    #[test]
    fn source_archive_committer_timestamp_is_unique_and_canonical() {
        let fixture = golden_source_archive_fixture();
        let source_tree = fixture.manifest.source_tree.as_str();
        assert_eq!(
            git_commit_committer_timestamp(&fixture.commit, source_tree),
            Some(1_700_000_123)
        );
        let text = String::from_utf8(fixture.commit.clone()).unwrap();
        let rejects = |changed: String| {
            let archive = source_archive_with_rebound_commit(&fixture, changed.as_bytes());
            !valid_source_archive_bytes(
                &archive,
                &source_archive_fingerprint(&archive),
                &fixture.cargo_lock_fingerprint,
            )
        };
        assert!(rejects(text.replacen("committer ", "x-committer ", 1)));
        assert!(rejects(text.replacen(
            "committer Marty Fixture <fixture@example.invalid> 1700000123 +0530\n",
            "committer Marty Fixture <fixture@example.invalid> 1700000123 +0530\ncommitter Marty Fixture <fixture@example.invalid> 1700000123 +0530\n",
            1,
        )));
        for replacement in [
            "-1 +0530",
            "01700000123 +0530",
            "1700000123 +2400",
            "1700000123 +0060",
            "1700000123 -0000",
        ] {
            assert!(rejects(text.replacen(
                "1700000123 +0530\n\n",
                &format!("{replacement}\n\n"),
                1
            )));
        }
        let maximum_timestamp =
            text.replacen("1700000123 +0530\n\n", "18446744073709551615 +0530\n\n", 1);
        assert_eq!(
            git_commit_committer_timestamp(maximum_timestamp.as_bytes(), source_tree),
            Some(u64::MAX)
        );
        assert!(rejects(text.replacen(
            "1700000123 +0530\n\n",
            "18446744073709551616 +0530\n\n",
            1,
        )));
        let mut non_ascii_timestamp = fixture.commit.clone();
        let timestamp_offset = non_ascii_timestamp
            .windows(b"1700000123 +0530".len())
            .rposition(|window| window == b"1700000123 +0530")
            .unwrap();
        non_ascii_timestamp[timestamp_offset] = 0xff;
        assert_eq!(
            git_commit_committer_timestamp(&non_ascii_timestamp, source_tree),
            None
        );

        let changed_author = text.replacen(
            "author Marty Fixture <fixture@example.invalid> 1700000000 -0700",
            "author Marty Fixture <fixture@example.invalid> 99 -0700",
            1,
        );
        assert_eq!(
            git_commit_committer_timestamp(changed_author.as_bytes(), source_tree),
            Some(1_700_000_123)
        );
        let archive = source_archive_with_rebound_commit(&fixture, changed_author.as_bytes());
        assert!(valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));

        let mut non_utf8_message = format!(
            "tree {source_tree}\nauthor Marty Fixture <fixture@example.invalid> 1700000000 -0700\ncommitter Marty Fixture <fixture@example.invalid> 1700000123 +0530\nencoding ISO-8859-1\n\nopaque-"
        )
        .into_bytes();
        non_utf8_message.extend_from_slice(&[0xff, 0xfe, b'\n']);
        assert_eq!(
            git_commit_committer_timestamp(&non_utf8_message, source_tree),
            Some(1_700_000_123)
        );
        let archive = source_archive_with_rebound_commit(&fixture, &non_utf8_message);
        assert!(valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
    }

    #[test]
    fn source_archive_rejects_nonportable_and_colliding_paths() {
        let fixture = golden_source_archive_fixture();
        let mut reordered_manifest = fixture.manifest.clone();
        reordered_manifest.entries.swap(0, 1);
        let reordered =
            encode_source_archive(&reordered_manifest, &fixture.commit, &fixture.contents);
        assert!(!valid_source_archive_bytes(
            &reordered,
            &source_archive_fingerprint(&reordered),
            &fixture.cargo_lock_fingerprint
        ));
        for path in [
            "src/../lib.rs",
            "C:/escape",
            "C:escape",
            "file:stream",
            "CON",
            "NUL.txt",
            "trailing.",
            "caf\u{00e9}.rs",
            "cafe\u{0301}.rs",
            "a/b/../../escape",
            ".git",
            ".GIT/config",
            "src/.Git/hooks/pre-commit",
        ] {
            let mut manifest = fixture.manifest.clone();
            manifest.entries[1].repository_relative_path = path.to_owned();
            let archive = encode_source_archive(&manifest, &fixture.commit, &fixture.contents);
            assert!(!valid_source_archive_bytes(
                &archive,
                &source_archive_fingerprint(&archive),
                &fixture.cargo_lock_fingerprint
            ));
        }
        let mut collision = fixture.manifest;
        collision.entries[1].repository_relative_path = "cargo.LOCK".to_owned();
        let archive = encode_source_archive(&collision, &fixture.commit, &fixture.contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));
    }

    #[test]
    fn source_archive_rejects_path_bounds_and_prefix_conflicts() {
        let fixture = golden_source_archive_fixture();
        for path in [
            std::iter::repeat_n("a", 257).collect::<Vec<_>>().join("/"),
            "a".repeat(256),
        ] {
            let mut manifest = fixture.manifest.clone();
            manifest.entries[1].repository_relative_path = path;
            let archive = encode_source_archive(&manifest, &fixture.commit, &fixture.contents);
            assert!(!valid_source_archive_bytes(
                &archive,
                &source_archive_fingerprint(&archive),
                &fixture.cargo_lock_fingerprint
            ));
        }
        let prefix_content = b"prefix\n".as_slice();
        let mut prefix_manifest = fixture.manifest.clone();
        prefix_manifest.entries.insert(
            1,
            SourceArchiveEntryWire {
                repository_relative_path: "src".to_owned(),
                git_mode: "100644".to_owned(),
                git_object_id: hex::encode(git_object_id("blob", prefix_content)),
                artifact_fingerprint: source_archive_fingerprint(prefix_content),
            },
        );
        prefix_manifest.entry_count = 3;
        let prefix_contents = [fixture.contents[0], prefix_content, fixture.contents[1]];
        assert!(!source_archive_paths_are_materializable(
            &prefix_manifest.entries
        ));
        let archive = encode_source_archive(&prefix_manifest, &fixture.commit, &prefix_contents);
        assert!(!valid_source_archive_bytes(
            &archive,
            &source_archive_fingerprint(&archive),
            &fixture.cargo_lock_fingerprint
        ));

        prefix_manifest.entries[1].repository_relative_path = "SRC".to_owned();
        assert!(!source_archive_paths_are_materializable(
            &prefix_manifest.entries
        ));

        let mut directory_aliases = fixture.manifest.entries;
        directory_aliases[0].repository_relative_path = "A/x".to_owned();
        directory_aliases[1].repository_relative_path = "a/y".to_owned();
        assert!(!source_archive_paths_are_materializable(&directory_aliases));
    }

    #[test]
    fn source_archive_derived_tree_limits_reject_fanout_and_depth() {
        let fixture = golden_source_archive_fixture();
        let mut fanout = fixture.manifest.entries.clone();
        fanout[0].repository_relative_path = "a/x".to_owned();
        fanout[1].repository_relative_path = "b/y".to_owned();
        assert!(reconstructed_source_tree_with_limits(&fanout, &fixture.contents, 3, 16).is_some());
        assert!(reconstructed_source_tree_with_limits(&fanout, &fixture.contents, 2, 16).is_none());

        let mut deep = fixture.manifest.entries;
        deep[0].repository_relative_path = "a/b/c/x".to_owned();
        deep[1].repository_relative_path = "z".to_owned();
        assert!(reconstructed_source_tree_with_limits(&deep, &fixture.contents, 4, 16).is_some());
        assert!(reconstructed_source_tree_with_limits(&deep, &fixture.contents, 3, 16).is_none());
        assert!(reconstructed_source_tree_with_limits(&deep, &fixture.contents, 4, 3).is_none());
    }

    #[test]
    fn plan_v3_schema_rejects_frozen_or_mixed_legacy_shapes() {
        let value = manifest();
        let bytes = canonical_manifest_bytes(&value);
        let plan = plan_for_manifest(&value, &bytes).expect("valid qualification plan");
        let encoded = String::from_utf8(
            serde_json::to_vec_pretty(&plan).expect("serialize qualification plan"),
        )
        .expect("qualification plan is UTF-8");
        assert!(encoded.contains("\"schema\": \"marty.performance/sd-jwt-issuance-plan/v3\""));
        assert!(encoded.contains("\"d_upper_percent_less_than\": -5.0"));
        assert!(!encoded.contains("\"d_upper_less_than\""));

        let plan_value = serde_json::to_value(&plan).expect("plan JSON value");
        let mut missing_completion = plan_value.clone();
        missing_completion["global_rounds"]["run_validity"]
            .as_object_mut()
            .expect("run-validity object")
            .remove("completion");
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(missing_completion).is_err(),
            "v3 must require the terminal completion contract"
        );

        let mut legacy_field_lists = plan_value.clone();
        legacy_field_lists["global_rounds"]["run_validity"]["required_header_bindings"] =
            serde_json::json!([]);
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(legacy_field_lists).is_err(),
            "v3 must reject the ambiguous legacy validity shape"
        );

        let mut v2_with_v3_fields = plan_value.clone();
        v2_with_v3_fields["schema"] =
            serde_json::json!("marty.performance/sd-jwt-issuance-plan/v2");
        let parsed_v2_with_v3_fields =
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(v2_with_v3_fields)
                .expect("v3 field shape is independently parseable");
        assert!(validate_plan_schema(&parsed_v2_with_v3_fields).is_err());

        let mut frozen_v2 = plan_value.clone();
        frozen_v2["schema"] = serde_json::json!("marty.performance/sd-jwt-issuance-plan/v2");
        frozen_v2
            .as_object_mut()
            .expect("plan object")
            .remove("global_rounds");
        let bootstrap = frozen_v2["bootstrap"]
            .as_object_mut()
            .expect("bootstrap object");
        for field in [
            "seed_is_initial_state",
            "rng_state_transition",
            "draws_per_replicate",
            "sampling_method",
            "uniform_index_rule",
            "stream_scope",
            "consumption_order",
            "rejected_output_rule",
            "common_index_scope",
            "primary_interval_rule",
            "diagnostic_o_interval_rule",
        ] {
            bootstrap.remove(field);
        }
        bootstrap.insert(
            "resampling_unit".to_owned(),
            serde_json::json!("whole_superblock"),
        );
        bootstrap.insert(
            "simultaneous_band".to_owned(),
            serde_json::json!("common_family_max_deviation_d_s_p"),
        );
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(frozen_v2.clone()).is_err(),
            "v2 evidence must not be silently reinterpreted as v3"
        );

        let mut frozen_v1 = frozen_v2;
        frozen_v1["schema"] = serde_json::json!("marty.performance/sd-jwt-issuance-plan/v1");
        let discovery = frozen_v1["discovery"]
            .as_object_mut()
            .expect("discovery object");
        discovery.remove("percent_transform");
        for (effect, value) in [("d", -0.05), ("s", 0.0), ("p", 0.0)] {
            discovery.remove(&format!("{effect}_upper_percent_less_than"));
            discovery.insert(
                format!("{effect}_upper_less_than"),
                serde_json::json!(value),
            );
        }
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(frozen_v1).is_err(),
            "v1 evidence must not be silently reinterpreted as v3"
        );

        let mut mixed_v3_fields = plan_value;
        mixed_v3_fields["discovery"]["d_upper_less_than"] = serde_json::json!(-0.05);
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(mixed_v3_fields).is_err(),
            "v3 must reject unknown legacy fields"
        );
    }

    #[test]
    fn plan_v3_nested_schemas_reject_unknown_fields() {
        let value = manifest();
        let bytes = canonical_manifest_bytes(&value);
        let plan = plan_for_manifest(&value, &bytes).expect("valid qualification plan");
        let plan_value = serde_json::to_value(plan).expect("plan JSON value");

        for child in ["criterion", "effects"] {
            let mut unknown_child = plan_value.clone();
            unknown_child[child]
                .as_object_mut()
                .expect("plan child object")
                .insert("unknown_field".to_owned(), serde_json::json!(true));
            assert!(
                serde_json::from_value::<SdJwtIssuanceQualificationPlan>(unknown_child).is_err(),
                "v3 must reject unknown fields in {child}"
            );
        }

        for path in [
            ["global_rounds", "run_validity", "global_preimages"],
            ["global_rounds", "run_validity", "route_artifact"],
            ["global_rounds", "run_validity", "artifact_indexes"],
        ] {
            let mut unknown_protocol = plan_value.clone();
            unknown_protocol[path[0]][path[1]][path[2]]
                .as_object_mut()
                .expect("nested protocol object")
                .insert("unknown_field".to_owned(), serde_json::json!(true));
            assert!(
                serde_json::from_value::<SdJwtIssuanceQualificationPlan>(unknown_protocol).is_err(),
                "v3 must reject unknown fields in {}",
                path[2]
            );
        }

        let mut unknown_anchor_channel = plan_value.clone();
        unknown_anchor_channel["global_rounds"]["run_validity"]["completion"]
            ["external_anchor_channel"]
            .as_object_mut()
            .expect("anchor channel protocol object")
            .insert("unknown_field".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(unknown_anchor_channel)
                .is_err(),
            "v3 must reject unknown external-anchor channel protocol fields"
        );

        let mut unknown_fingerprint = plan_value;
        unknown_fingerprint["manifest"]
            .as_object_mut()
            .expect("manifest fingerprint object")
            .insert("unknown_field".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(unknown_fingerprint).is_err(),
            "v3 must reject unknown fingerprint fields"
        );
    }

    #[test]
    fn real_emitted_manifest_is_accepted_with_all_id_grammars() {
        validate_canonical_json_bytes(REAL_EMITTED_MANIFEST)
            .expect("real manifest canonical bytes");
        let value = manifest();
        validate_manifest(&value).expect("real emitted manifest contract");
        assert_eq!(
            value.paired_cells[0].serial_id,
            "sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001"
        );
        assert_eq!(
            value.paired_cells[40].adaptive_id,
            "sd_jwt_issuance/v2__s_ea__r_ac__p_s__d_1__n_0001"
        );
        assert_eq!(
            value.paired_cells[60].serial_id,
            "sd_jwt_issuance/v2__s_ea__r_so__f_al_nested_obj_n0007"
        );
        assert_eq!(
            hex::encode_upper(Sha256::digest(REAL_EMITTED_MANIFEST)),
            "04EFEB5E52EF19A0278383F9FD8C574F0B0F24941CD5FCD764696A6E496EDC1F"
        );
        plan_for_manifest(&value, REAL_EMITTED_MANIFEST)
            .expect("real manifest must bind into a plan");
    }

    #[test]
    fn manifest_validation_rejects_activation_drift_and_identity_gaps() {
        let mut unknown_case = serde_json::to_value(manifest()).expect("manifest JSON value");
        unknown_case["cases"][0]
            .as_object_mut()
            .expect("manifest case object")
            .insert("unknown_field".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationManifest>(unknown_case).is_err()
        );

        let mut activated = manifest();
        activated.qualified_issuance_thresholds = Some(SdJwtIssuanceThresholds {
            min_jobs: 8,
            min_estimated_work_bytes: 1_024,
        });
        assert!(validate_manifest(&activated).is_err());

        let mut missing = manifest();
        missing.paired_cells[0].serial_id = missing.paired_cells[1].serial_id.clone();
        assert!(validate_manifest(&missing).is_err());

        let mut reordered = manifest();
        reordered.paired_cells.swap(0, 1);
        assert!(validate_manifest(&reordered).is_err());

        let mut registration_order = manifest();
        registration_order.criterion_ids.swap(0, 1);
        assert!(validate_manifest(&registration_order).is_err());

        let mut wrong_stage_identity = manifest();
        let wrong_id = "sd_jwt_issuance/v2__s_xx__r_so__p_s__d_0__n_0001".to_owned();
        wrong_stage_identity.paired_cells[0].serial_id = wrong_id.clone();
        wrong_stage_identity.criterion_ids[0] = wrong_id;
        assert!(validate_manifest(&wrong_stage_identity).is_err());

        let mut wrong_fixture_identity = manifest();
        let wrong_id = "sd_jwt_issuance/v2__s_ea__r_so__f_fixture_99".to_owned();
        wrong_fixture_identity.paired_cells[60].serial_id = wrong_id.clone();
        wrong_fixture_identity.criterion_ids[120] = wrong_id;
        assert!(validate_manifest(&wrong_fixture_identity).is_err());

        let mut wrong_route_identity = manifest();
        let wrong_id = "sd_jwt_issuance/v2__s_ea__r_xx__p_s__d_0__n_0001".to_owned();
        wrong_route_identity.paired_cells[0].serial_id = wrong_id.clone();
        wrong_route_identity.criterion_ids[0] = wrong_id;
        assert!(validate_manifest(&wrong_route_identity).is_err());

        let mut mismatched_count = manifest();
        mismatched_count.cases[0].disclosure_count = 8;
        assert!(validate_manifest(&mismatched_count).is_err());
    }

    #[test]
    fn plan_binding_rejects_manifest_value_and_byte_mismatch() {
        let value = manifest();
        let mut different_value = value.clone();
        different_value.worker_cap = 3;
        let different_bytes = canonical_manifest_bytes(&different_value);

        let error = plan_for_manifest(&value, &different_bytes)
            .expect_err("manifest value must match its bound bytes");
        assert!(error
            .to_string()
            .contains("manifest value and bound bytes differ"));
    }

    #[test]
    fn plan_writer_requires_canonical_input_and_preserves_existing_output() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let manifest_path = temporary.path().join("manifest.json");
        let output_path = temporary.path().join("plan.json");
        let value = manifest();
        fs::write(&manifest_path, canonical_manifest_bytes(&value)).expect("write manifest");

        write_plan(&manifest_path, &output_path).expect("write plan");
        let first = fs::read(&output_path).expect("plan bytes");
        let parsed: SdJwtIssuanceQualificationPlan =
            serde_json::from_slice(&first).expect("plan JSON");
        assert_eq!(parsed.schema, PLAN_SCHEMA);
        assert_eq!(parsed.total_processes, 10_560);

        let error = write_plan(&manifest_path, &output_path).expect_err("refuse replacement");
        assert!(error.to_string().contains("create qualification plan"));
        assert_eq!(fs::read(&output_path).expect("preserved plan"), first);

        let compact_path = temporary.path().join("compact.json");
        fs::write(
            &compact_path,
            serde_json::to_vec(&value).expect("compact JSON"),
        )
        .expect("write compact manifest");
        assert!(load_manifest(&compact_path).is_err());
    }
}

#[cfg(test)]
mod promoted_validation_primitives_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn promoted_primitives_are_bounded_and_fail_closed() {
        assert!(valid_source_archive_path("Cargo.lock"));
        assert!(!valid_source_archive_path("../Cargo.lock"));
        assert!(valid_utc_rfc3339_nanoseconds(
            "2024-02-29T23:59:59.123456789Z"
        ));
        assert!(!valid_utc_rfc3339_nanoseconds(
            "0000-01-01T00:00:00.000000000Z"
        ));
        assert!(!valid_route_wire_bytes(
            b"{}\n",
            "benchmark",
            "fixture",
            "stage",
            "serial",
            1,
            1,
        ));
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        assert!(!valid_terminal_receipt_bytes(
            b"{}\n",
            &signing_key.verifying_key(),
        ));
        assert!(!valid_completion_anchor_bytes(
            b"{}\n",
            &signing_key.verifying_key(),
        ));
    }
}

#[cfg(test)]
mod handle_bound_reader_tests {
    use super::*;

    #[test]
    #[allow(
        clippy::permissions_set_readonly_false,
        reason = "Windows read-only attributes must be cleared before deleting the temporary key"
    )]
    fn governed_inputs_reject_hardlinks_campaign_keys_and_short_reads() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let original = temporary.path().join("original.bin");
        let linked = temporary.path().join("linked.bin");
        fs::write(&original, b"bound bytes").expect("write original");
        fs::hard_link(&original, &linked).expect("create hard link");
        let error = open_absolute_file(&linked, 64, None, "hardlinked artifact")
            .expect_err("hard-linked input must reject")
            .to_string();
        assert_eq!(error, "analysis rejected: hardlinked artifact");
        assert!(!error.contains("linked.bin"));

        fs::remove_file(&linked).expect("remove hard link");
        let input = open_absolute_file(&original, 64, None, "short artifact")
            .expect("open single-linked input");
        assert!(ensure_exact_snapshot_byte_length(
            input.snapshot.byte_length - 1,
            input.snapshot,
            "short artifact",
        )
        .is_err());
        assert_eq!(
            read_bounded(&original, 64, "bounded artifact").expect("bounded read"),
            b"bound bytes"
        );

        let campaign_path = temporary.path().join("campaign");
        fs::create_dir(&campaign_path).expect("campaign directory");
        let campaign_key = campaign_path.join("key.bin");
        fs::write(&campaign_key, [0x42; 32]).expect("campaign key");
        let mut permissions = fs::metadata(&campaign_key)
            .expect("key metadata")
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&campaign_key, permissions).expect("readonly campaign key");
        let campaign = CampaignDirectory::open(&campaign_path).expect("open campaign");
        assert!(open_absolute_file(
            &campaign_key,
            32,
            Some(campaign.identity),
            "anchor trust root",
        )
        .is_err());
        #[cfg(windows)]
        {
            let mut cleanup_permissions = fs::metadata(&campaign_key)
                .expect("cleanup key metadata")
                .permissions();
            cleanup_permissions.set_readonly(false);
            fs::set_permissions(&campaign_key, cleanup_permissions)
                .expect("cleanup key permissions");
        }
    }

    #[test]
    fn exact_directory_inventory_rejects_extras_with_bounded_state() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let campaign_path = temporary.path().join("campaign");
        let anchors_path = campaign_path.join("anchors");
        fs::create_dir_all(&anchors_path).expect("anchor directory");
        let expected = [
            OsString::from("completion-anchor.json"),
            OsString::from("terminal-observation-evidence.json"),
            OsString::from("terminal-observation-receipt.json"),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        for name in &expected {
            fs::write(anchors_path.join(name), b"{}\n").expect("expected anchor");
        }
        let campaign = CampaignDirectory::open(&campaign_path).expect("open campaign");
        campaign
            .validate_exact_directory_entries(Path::new("anchors"), &expected, "anchor inventory")
            .expect("exact inventory");
        fs::write(anchors_path.join("junk.json"), b"{}\n").expect("junk anchor");
        let error = campaign
            .validate_exact_directory_entries(Path::new("anchors"), &expected, "anchor inventory")
            .expect_err("overfilled inventory must reject")
            .to_string();
        assert_eq!(error, "analysis rejected: anchor inventory");
        assert!(!error.contains("junk"));
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_directory_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let campaign_path = temporary.path().join("campaign");
        let outside_path = temporary.path().join("outside");
        fs::create_dir(&campaign_path).expect("campaign directory");
        fs::create_dir(&outside_path).expect("outside directory");
        fs::write(outside_path.join("artifact.json"), b"{}\n").expect("outside artifact");
        symlink(&outside_path, campaign_path.join("linked")).expect("directory symlink");
        let campaign = CampaignDirectory::open(&campaign_path).expect("open campaign");
        assert!(campaign
            .open_file(Path::new("linked/artifact.json"), 16, "linked artifact")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn governed_file_fifo_rejects_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        use rustix::fs::{mkfifoat, Mode};

        let temporary = tempfile::tempdir().expect("temporary directory");
        let parent = fs::File::open(temporary.path()).expect("open temporary directory");
        mkfifoat(&parent, "artifact.fifo", Mode::RUSR | Mode::WUSR).expect("create FIFO");
        let fifo_path = temporary.path().join("artifact.fifo");
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(open_absolute_file(&fifo_path, 16, None, "FIFO artifact").is_err())
                .ok();
        });
        assert_eq!(receiver.recv_timeout(Duration::from_secs(2)), Ok(true));
    }

    #[cfg(unix)]
    #[test]
    fn traversed_directory_fifo_rejects_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        use rustix::fs::{mkfifoat, Mode};

        let temporary = tempfile::tempdir().expect("temporary directory");
        let campaign_path = temporary.path().join("campaign");
        fs::create_dir(&campaign_path).expect("campaign directory");
        let parent = fs::File::open(&campaign_path).expect("open campaign directory");
        mkfifoat(&parent, "linked", Mode::RUSR | Mode::WUSR).expect("create FIFO");
        let campaign = CampaignDirectory::open(&campaign_path).expect("open campaign");
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(
                    campaign
                        .open_file(Path::new("linked/artifact.json"), 16, "FIFO directory")
                        .is_err(),
                )
                .ok();
        });
        assert_eq!(receiver.recv_timeout(Duration::from_secs(2)), Ok(true));
    }
}
