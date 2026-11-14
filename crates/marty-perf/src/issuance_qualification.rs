//! Frozen, deterministic planning for SD-JWT issuance qualification.

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
    ArtifactFingerprint, SdJwtIssuanceAnalysisStatus, SdJwtIssuanceArtifactIndexProtocol,
    SdJwtIssuanceBootstrapProtocol, SdJwtIssuanceCriterionHomeProtocol,
    SdJwtIssuanceCriterionProtocol, SdJwtIssuanceDiscoveryProtocol, SdJwtIssuanceEffectProtocol,
    SdJwtIssuanceEvidenceFieldProtocol, SdJwtIssuanceEvidenceJsonType,
    SdJwtIssuanceEvidenceRecordProtocol, SdJwtIssuanceFirstQuietWindowProtocol,
    SdJwtIssuanceGlobalPreimageProtocol, SdJwtIssuanceGlobalRoundProtocol,
    SdJwtIssuanceIndexedAnalysisReport, SdJwtIssuanceInvocationDescriptorProtocol,
    SdJwtIssuanceLaunchBarrierProtocol, SdJwtIssuanceLifecycleAnalysisReport,
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

#[allow(
    dead_code,
    reason = "the nonactivating artifact store is consumed by the next controller slice"
)]
mod artifact_store;
#[allow(
    dead_code,
    reason = "the nonactivating build-input archive kernel is future controller plumbing"
)]
mod build_input_archive;
mod evidence_validation;
#[allow(
    dead_code,
    reason = "the side-effect-free quiet-window kernel is controller plumbing and remains nonactivating"
)]
mod first_quiet_window;
#[allow(
    dead_code,
    reason = "the nonactivating fixed-build preparation capability is future controller plumbing"
)]
mod fixed_build;
#[allow(
    dead_code,
    reason = "the nonactivating fixed-build capture capability is future controller plumbing"
)]
mod fixed_build_capture;
mod lifecycle_validation;
mod protocol;
mod schedule;
#[allow(
    dead_code,
    reason = "the exporter is active while retained source materialization remains future controller plumbing"
)]
mod source_archive;
mod statistics;

use protocol::{bootstrap_protocol, criterion_protocol, global_round_protocol, observation_bounds};
#[cfg(test)]
use protocol::{
    completion_protocol, fixed_build_environment_allowlist, record_protocols, run_validity_protocol,
};

use schedule::{
    ABBA_EXPANSION, BAAB_EXPANSION, PAIRED_CELL_COUNT, PROCESSES_PER_SUPERBLOCK, SUPERBLOCK_ORDERS,
};

const MANIFEST_SCHEMA: &str = "sd_jwt_issuance_qualification_manifest_v1";
const PLAN_SCHEMA: &str = "marty.performance/sd-jwt-issuance-plan/v3";
const BENCHMARK_GROUP_ID: &str = "sd_jwt_issuance";
const ROUTE_SCHEMA: &str = "sd_jwt_issuance_route_v2";
const WORK_ESTIMATOR_VERSION: &str = "issuance_work_bytes_v1";
const STATIC_PARTITION_RULE_VERSION: &str = "contiguous_ceil_chunks_v1";
const FIXTURE_CASE_COUNT: usize = 33;
const BENCHMARK_ID_COUNT: usize = 132;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const QUIET_WINDOW_SECONDS: u64 = 45 * 60;
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
const FIXED_CARGO_CONFIGURATION_BYTES: &[u8] = b"[net]\noffline = true\n";
const SOURCE_ARCHIVE_MAGIC: &[u8] = b"MARTY-SD-JWT-SOURCE-ARCHIVE-V1\n";

/// Inputs for one approved, nonactivating exact-source export.
pub(crate) struct SourceArchiveExportRequest<'a> {
    /// Absolute root of a normal, clean Git worktree.
    pub repository: &'a Path,
    /// Exact lowercase SHA-1 commit object identifier approved for export.
    pub source_commit: &'a str,
    /// Exact lowercase SHA-1 tree object identifier approved for export.
    pub source_tree: &'a str,
    /// Absolute create-new `source/exact-tree.sar` destination.
    pub output: &'a Path,
    /// Explicit controller decision authorizing this source export.
    pub source_export_approved: bool,
}

/// Nonqualifying facts returned after an exact-source archive is persisted.
#[derive(Debug)]
pub(crate) struct SourceArchiveExportReceipt {
    /// SHA-256 and length of the complete source archive.
    pub archive_fingerprint: ArtifactFingerprint,
    /// Exact exported Git commit object identifier.
    pub source_commit: String,
    /// Exact reconstructed Git tree object identifier.
    pub source_tree: String,
    /// SHA-256 and length of the exact exported `Cargo.lock` bytes.
    pub cargo_lock_fingerprint: ArtifactFingerprint,
    /// Number of regular files exported from the exact tree.
    pub entry_count: u32,
}

/// Export one exact Git source tree without creating or qualifying a campaign.
pub(crate) fn export_source_archive(
    request: &SourceArchiveExportRequest<'_>,
) -> Result<SourceArchiveExportReceipt> {
    source_archive::export_exact_source_archive(request)
}

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
                    && segments
                        .iter()
                        .all(|segment| !segment.eq_ignore_ascii_case(".cargo"))
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
    member_ranges: Vec<ValidatedSourceArchiveMemberRange>,
    committer_timestamp: u64,
}

#[derive(Clone, Copy)]
struct ValidatedSourceArchiveMemberRange {
    offset: u64,
    byte_length: u64,
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
    let mut member_ranges = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let content_length = take_u64_be(bytes, &mut cursor)?;
        let content_offset = u64::try_from(cursor).ok()?;
        let content = take_bounded(bytes, &mut cursor, content_length, maximum_archive_bytes)?;
        let byte_length = u64::try_from(content.len()).ok()?;
        if byte_length != entry.artifact_fingerprint.byte_length
            || fingerprint(content).ok().as_ref() != Some(&entry.artifact_fingerprint)
        {
            return None;
        }
        contents.push(content);
        member_ranges.push(ValidatedSourceArchiveMemberRange {
            offset: content_offset,
            byte_length,
        });
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
            member_ranges,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildEnvironmentEntry {
    name: String,
    value_kind: String,
    resolved_value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildInputEntry {
    role: String,
    relative_path: String,
    file_mode: String,
    fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixedBinaryBuildReceiptWire {
    schema: String,
    campaign_id: String,
    controller_binary_fingerprint: ArtifactFingerprint,
    source_archive_fingerprint: ArtifactFingerprint,
    source_commit: String,
    source_tree: String,
    cargo_lock_fingerprint: ArtifactFingerprint,
    cargo_binary_fingerprint: ArtifactFingerprint,
    cargo_verbose_version: String,
    rustc_binary_fingerprint: ArtifactFingerprint,
    rustc_verbose_version: String,
    rustc_reported_sysroot: String,
    build_input_inventory_fingerprint: ArtifactFingerprint,
    build_input_archive_fingerprint: ArtifactFingerprint,
    target_triple: String,
    build_profile: String,
    materialized_build_root: String,
    working_directory: String,
    logical_argv: Vec<String>,
    enabled_features: Vec<String>,
    build_environment_policy: String,
    build_environment: Vec<BuildEnvironmentEntry>,
    offline_dependency_resolution_argv: Vec<String>,
    offline_dependency_resolution_succeeded: bool,
    build_started_monotonic_nanoseconds: u64,
    build_finished_monotonic_nanoseconds: u64,
    produced_binary_fingerprint: ArtifactFingerprint,
    installed_fixed_binary_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalAnchorChannelWire {
    schema: String,
    campaign_id: String,
    channel_id: String,
    channel_kind: String,
    endpoint_role: String,
    log_id: String,
    connector_authentication_policy: String,
    receipt_verification_scheme: String,
    signing_key_id: String,
    trust_root_fingerprint: ArtifactFingerprint,
    clock_policy: String,
    maximum_receipt_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerConfigurationWire {
    schema: String,
    campaign_id: String,
    plan_fingerprint: ArtifactFingerprint,
    artifact_layout_version: String,
    process_schedule_version: String,
    child_environment_policy_version: String,
    launch_transport_version: String,
    stdout_retention_policy: String,
    stderr_retention_policy: String,
    external_anchor_channel_id: String,
    external_anchor_policy_version: String,
    maximum_spawn_to_ready_seconds: u32,
    maximum_timing_process_seconds: u32,
    maximum_process_output_bytes: u64,
    maximum_anchor_publication_delay_seconds: u32,
    synthetic_data_only: bool,
    source_export_approved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MonitorConfigurationWire {
    schema: String,
    campaign_id: String,
    plan_fingerprint: ArtifactFingerprint,
    sample_interval_seconds: u32,
    maximum_sample_gap_seconds: u32,
    controller_clock_authoritative: bool,
    cpu_backend: String,
    memory_backend: String,
    frequency_backend: String,
    temperature_backend: String,
    throttle_backend: String,
    process_scope_policy: String,
    process_identity_scheme: String,
    process_identity_key_persisted: bool,
    raw_process_metadata_retained: bool,
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
struct ProcessCompletionWire {
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    full_benchmark_id: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionWire {
    schema: String,
    campaign_id: String,
    created_at_utc_rfc3339_nanoseconds: String,
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
    process_completions: Vec<ProcessCompletionWire>,
    criterion_artifact_set_fingerprint: ArtifactFingerprint,
    route_artifact_set_fingerprint: ArtifactFingerprint,
    first_quiet_window_evidence_fingerprint: ArtifactFingerprint,
    invalidating_event_count: u32,
    validity_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisHeaderWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    plan_fingerprint: ArtifactFingerprint,
    manifest_fingerprint: ArtifactFingerprint,
    fixed_binary_fingerprint: ArtifactFingerprint,
    fixed_binary_build_receipt_fingerprint: ArtifactFingerprint,
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
    first_quiet_window_evidence_fingerprint: ArtifactFingerprint,
    initial_test_window_attestation_fingerprint: ArtifactFingerprint,
    baseline_unrelated_process_set_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContinuationHeaderWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    previous_segment_fingerprint: ArtifactFingerprint,
    genesis_header_fingerprint: ArtifactFingerprint,
    active_test_window_attestation_fingerprint: ArtifactFingerprint,
    boot_identity_pseudonym: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValiditySampleWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    sample_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    boot_identity_pseudonym: String,
    timing_state: String,
    global_round_ordinal: RequiredNullable<u32>,
    cell_ordinal: RequiredNullable<u32>,
    expansion_position: RequiredNullable<u32>,
    timing_process_id: RequiredNullable<String>,
    total_cpu_percent: f64,
    monitor_cpu_percent: f64,
    benchmark_cpu_percent: f64,
    unrelated_cpu_percent: f64,
    available_memory_bytes: u64,
    cpu_frequency_hz: u64,
    maximum_temperature_millidegrees_celsius: i64,
    throttle_flags: Vec<String>,
    unrelated_process_set_fingerprint: ArtifactFingerprint,
    active_test_window_attestation_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIntentRecordWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    event_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    full_benchmark_id: String,
    invocation_descriptor_fingerprint: ArtifactFingerprint,
    criterion_home_initial_inventory_fingerprint: ArtifactFingerprint,
    launch_barrier_token_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessStartRecordWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    event_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    process_identity_pseudonym: String,
    full_benchmark_id: String,
    process_intent_record_fingerprint: ArtifactFingerprint,
    invocation_descriptor_fingerprint: ArtifactFingerprint,
    launch_barrier_token_fingerprint: ArtifactFingerprint,
    launch_barrier_ready_frame_fingerprint: ArtifactFingerprint,
    active_test_window_attestation_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessFinishRecordWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    event_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    process_identity_pseudonym: String,
    full_benchmark_id: String,
    exit_code: i32,
    termination_reason: String,
    elapsed_monotonic_nanoseconds: u64,
    stdout_after_ready_bytes: u64,
    stderr_bytes: u64,
    launch_barrier_receipt_fingerprint: ArtifactFingerprint,
    criterion_home_final_inventory_fingerprint: ArtifactFingerprint,
    criterion_artifact_fingerprint: ArtifactFingerprint,
    route_artifact_fingerprint: ArtifactFingerprint,
    artifacts_flushed_and_synced: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AttestationTransitionWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    event_ordinal: u64,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    previous_attestation_fingerprint: ArtifactFingerprint,
    next_attestation_fingerprint: ArtifactFingerprint,
    next_starts_at_rfc3339_nanoseconds: String,
    next_expires_at_rfc3339_nanoseconds: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SegmentFooterWire {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
    records_before_footer: u32,
    bytes_before_footer: u64,
    records_before_footer_fingerprint: ArtifactFingerprint,
    first_monotonic_nanoseconds: u64,
    last_monotonic_nanoseconds: u64,
    sample_count: u32,
    process_intent_count: u32,
    process_start_count: u32,
    process_finish_count: u32,
    attestation_transition_count: u32,
    closed_reason: String,
}

#[derive(Debug, Deserialize)]
struct SegmentRecordEnvelope {
    schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    record_ordinal: u32,
    utc_rfc3339_nanoseconds: String,
    monotonic_nanoseconds: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SegmentRecordCounts {
    sample: u32,
    process_intent: u32,
    process_start: u32,
    process_finish: u32,
    attestation_transition: u32,
}

impl SegmentRecordCounts {
    fn checked_total(self) -> Option<u32> {
        self.sample
            .checked_add(self.process_intent)?
            .checked_add(self.process_start)?
            .checked_add(self.process_finish)?
            .checked_add(self.attestation_transition)
    }
}

#[derive(Debug)]
struct SegmentInspection {
    fingerprint: ArtifactFingerprint,
    first_line: Vec<u8>,
    last_line: Vec<u8>,
    records_before_last: u32,
    bytes_before_last: u64,
    fingerprint_before_last: ArtifactFingerprint,
    header_schema: String,
    campaign_id: String,
    segment_ordinal: u32,
    header_monotonic_nanoseconds: u64,
    last_record_monotonic_nanoseconds: u64,
    record_counts: SegmentRecordCounts,
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

/// Inputs for one bounded offline artifact-integrity analysis.
pub(crate) struct IssuanceAnalysisRequest<'a> {
    /// Absolute root of the retained campaign evidence.
    pub campaign_root: &'a Path,
    /// Exact campaign-relative path of one selected route artifact.
    pub route_artifact: &'a Path,
    /// Out-of-band raw 32-byte Ed25519 public-key file.
    pub anchor_public_key: &'a Path,
    /// Absolute create-new report destination.
    pub output: &'a Path,
}

#[derive(Serialize)]
struct IssuanceAnalysisReport {
    schema: &'static str,
    analysis_scope: &'static str,
    campaign_id: String,
    manifest: ArtifactFingerprint,
    plan: ArtifactFingerprint,
    selected_route_benchmark_id: String,
    selected_route_artifact: ArtifactFingerprint,
    source_archive: ArtifactFingerprint,
    cargo_lock: ArtifactFingerprint,
    hardware_profile: ArtifactFingerprint,
    build_receipt: ArtifactFingerprint,
    build_input_inventory: ArtifactFingerprint,
    build_input_archive: ArtifactFingerprint,
    fixed_binary: ArtifactFingerprint,
    terminal_observation_receipt: ArtifactFingerprint,
    terminal_observation_evidence: ArtifactFingerprint,
    completion: ArtifactFingerprint,
    completion_anchor: ArtifactFingerprint,
    checks: Vec<&'static str>,
    artifact_integrity_status: &'static str,
    campaign_qualification_status: &'static str,
    production_threshold_activation: bool,
    limitations: Vec<&'static str>,
}

fn concrete_target_linker_environment_name(target_triple: &str) -> Option<String> {
    if target_triple.is_empty()
        || target_triple.len() > 128
        || matches!(target_triple, "." | ".." | "host-tuple")
        || target_triple.to_ascii_lowercase().ends_with(".json")
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
                char::from(byte.to_ascii_uppercase())
            } else {
                '_'
            }
        })
        .collect::<String>();
    Some(format!("CARGO_TARGET_{mapped}_LINKER"))
}

fn canonical_build_environment(
    windows: bool,
    target_triple: &str,
    committer_timestamp: u64,
    target_linker_relative_path: &str,
    target_archiver_relative_path: &str,
) -> Option<Vec<BuildEnvironmentEntry>> {
    let root = if windows {
        FIXED_BUILD_ROOT_WINDOWS
    } else {
        FIXED_BUILD_ROOT_NON_WINDOWS
    };
    canonical_build_environment_at_root(
        root,
        windows,
        target_triple,
        committer_timestamp,
        target_linker_relative_path,
        target_archiver_relative_path,
    )
}

fn canonical_build_environment_at_root(
    root: &str,
    windows: bool,
    target_triple: &str,
    committer_timestamp: u64,
    target_linker_relative_path: &str,
    target_archiver_relative_path: &str,
) -> Option<Vec<BuildEnvironmentEntry>> {
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
    let archiver = format!("{root}/inputs/{target_archiver_relative_path}");
    let linker_name = concrete_target_linker_environment_name(target_triple)?;
    let mut entries = vec![
        BuildEnvironmentEntry {
            name: "AR".to_owned(),
            value_kind: "inventoried_absolute_path".to_owned(),
            resolved_value: archiver,
        },
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
    target_archiver_relative_path: &str,
) -> bool {
    canonical_build_environment(
        windows,
        target_triple,
        committer_timestamp,
        target_linker_relative_path,
        target_archiver_relative_path,
    )
    .is_some_and(|expected| entries == expected)
}

fn valid_fixed_build_root(root: &str, windows: bool) -> bool {
    root == if windows {
        FIXED_BUILD_ROOT_WINDOWS
    } else {
        FIXED_BUILD_ROOT_NON_WINDOWS
    }
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
            artifact_fingerprint: ArtifactFingerprint {
                sha256: "0".repeat(64),
                byte_length: 0,
            },
        })
        .collect::<Vec<_>>();
    source_archive_paths_are_materializable(&projected)
}

fn build_input_executable_parent_directories(entries: &[BuildInputEntry]) -> BTreeSet<&str> {
    entries
        .iter()
        .filter(|entry| entry.role != "tool_dynamic_dependency" && entry.file_mode == "100755")
        .filter_map(|entry| build_input_parent_directory(&entry.relative_path))
        .collect()
}

fn build_input_dynamic_dependencies_resolve_with(
    entries: &[BuildInputEntry],
    mut executable_parent_exists: impl FnMut(&str) -> bool,
) -> bool {
    entries
        .iter()
        .filter(|entry| entry.role == "tool_dynamic_dependency")
        .all(|dependency| {
            let Some(parent) = build_input_parent_directory(&dependency.relative_path) else {
                return false;
            };
            (parent == "tools/runtime" || parent.starts_with("tools/runtime/"))
                || executable_parent_exists(parent)
        })
}

fn build_input_dynamic_dependencies_resolve(entries: &[BuildInputEntry]) -> bool {
    let executable_parents = build_input_executable_parent_directories(entries);
    build_input_dynamic_dependencies_resolve_with(entries, |parent| {
        executable_parents.contains(parent)
    })
}

fn valid_build_input_inventory(
    inventory: &BuildInputInventory,
    windows: bool,
    expected_target_triple: &str,
    expected_campaign_id: &str,
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
    let exact_cargo_configuration = fingerprint(FIXED_CARGO_CONFIGURATION_BYTES).ok();
    inventory.schema == "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2"
        && inventory.campaign_id == expected_campaign_id
        && inventory.target_triple == expected_target_triple
        && (1..=MAX_FIXED_BUILD_INPUT_ENTRIES).contains(&inventory.entry_count)
        && u32::try_from(inventory.entries.len()) == Ok(inventory.entry_count)
        && total == Some(inventory.total_byte_length)
        && archive_byte_length == Some(inventory.archive_fingerprint.byte_length)
        && inventory.archive_fingerprint.byte_length <= MAX_FIXED_BUILD_INPUT_BYTES
        && valid_artifact_fingerprint(&inventory.archive_fingerprint)
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
                && valid_artifact_fingerprint(&entry.fingerprint)
                && (entry.role != "cargo_configuration"
                    || exact_cargo_configuration.as_ref() == Some(&entry.fingerprint))
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
    expected_campaign_id: &str,
) -> bool {
    if !valid_build_input_inventory(inventory, windows, target_triple, expected_campaign_id) {
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
    let Some(target_archiver_relative_path) = inventory
        .entries
        .iter()
        .find(|entry| entry.role == "target_archiver_executable")
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
        target_archiver_relative_path,
    ) {
        return false;
    }
    let root = if windows {
        FIXED_BUILD_ROOT_WINDOWS
    } else {
        FIXED_BUILD_ROOT_NON_WINDOWS
    };
    let absolute_entry = |entry: &BuildInputEntry| format!("{root}/inputs/{}", entry.relative_path);
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
                .is_some_and(|suffix| format!("{system_root}/{suffix}") == absolute_entry(entry))
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

fn valid_campaign_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| {
        uuid.get_variant() == Variant::RFC4122 && uuid.get_version() == Some(Version::Random)
    })
}

fn valid_optional_hardware_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    })
}

fn valid_hardware_profile(profile: &HardwareProfileWire) -> bool {
    let bounds = observation_bounds();
    profile.schema == "marty.performance/sd-jwt-issuance-hardware-profile/v1"
        && valid_campaign_id(&profile.campaign_id)
        && matches!(
            profile.operating_system_family.as_str(),
            "windows" | "linux" | "macos"
        )
        && valid_optional_hardware_text(profile.operating_system_version.as_deref())
        && valid_optional_hardware_text(profile.kernel_version.as_deref())
        && matches!(profile.architecture.as_str(), "x86_64" | "aarch64")
        && valid_optional_hardware_text(profile.cpu_vendor.as_deref())
        && valid_optional_hardware_text(profile.cpu_model.as_deref())
        && profile
            .physical_core_count
            .is_none_or(|count| (1..=65_536).contains(&count))
        && (1..=bounds.maximum_logical_cpu_count).contains(&profile.logical_cpu_count)
        && (1..=profile.logical_cpu_count).contains(&profile.host_available_parallelism)
        && profile
            .numa_node_count
            .is_none_or(|count| (1..=65_536).contains(&count))
        && (1..=bounds.maximum_total_memory_bytes).contains(&profile.total_memory_bytes)
        && profile.nominal_cpu_frequency_hz.is_none_or(|frequency| {
            (bounds.minimum_cpu_frequency_hz..=bounds.maximum_cpu_frequency_hz).contains(&frequency)
        })
        && matches!(
            profile.virtualization_kind.as_str(),
            "bare_metal" | "virtual_machine" | "containerized_host" | "unknown"
        )
        && matches!(
            profile.power_policy.as_str(),
            "performance" | "balanced" | "platform_default" | "custom_locked"
        )
}

fn target_matches_hardware(target_triple: &str, profile: &HardwareProfileWire) -> bool {
    let components = target_triple.split('-').collect::<Vec<_>>();
    let operating_system_matches = [
        (components.contains(&"windows"), "windows"),
        (
            components.contains(&"apple") && components.contains(&"darwin"),
            "macos",
        ),
        (components.contains(&"linux"), "linux"),
    ];
    let mut recognized = operating_system_matches
        .into_iter()
        .filter_map(|(matches, family)| matches.then_some(family));
    let expected_operating_system = recognized.next();
    target_triple
        .split('-')
        .next()
        .is_some_and(|architecture| architecture == profile.architecture)
        && expected_operating_system == Some(profile.operating_system_family.as_str())
        && recognized.next().is_none()
}

fn valid_controller_configuration(
    configuration: &ControllerConfigurationWire,
    campaign_id: &str,
    plan_fingerprint: &ArtifactFingerprint,
    plan: &SdJwtIssuanceQualificationPlan,
) -> bool {
    let limits = &plan.global_rounds.run_validity.limits;
    configuration.schema == "marty.performance/sd-jwt-issuance-controller-config/v1"
        && configuration.campaign_id == campaign_id
        && configuration.plan_fingerprint == *plan_fingerprint
        && configuration.artifact_layout_version == "sd_jwt_issuance_artifact_layout_v1"
        && configuration.process_schedule_version == "global_round_manifest_cell_expansion_v1"
        && configuration.child_environment_policy_version == "cleared_allowlist_v1"
        && configuration.launch_transport_version == "stdio_ready_release_v1"
        && configuration.stdout_retention_policy == "persist_ready_only_drain_discard_rest_v1"
        && configuration.stderr_retention_policy == "bounded_drain_discard_v1"
        && configuration.external_anchor_channel_id == "marty-sd-jwt-issuance-anchor-v1"
        && configuration.external_anchor_policy_version == "signed_offline_receipts_v1"
        && configuration.maximum_spawn_to_ready_seconds == limits.maximum_spawn_to_ready_seconds
        && configuration.maximum_timing_process_seconds == limits.maximum_timing_process_seconds
        && configuration.maximum_process_output_bytes == limits.maximum_process_output_bytes
        && configuration.maximum_anchor_publication_delay_seconds
            == limits.maximum_anchor_publication_delay_seconds
        && configuration.synthetic_data_only
        && configuration.source_export_approved
}

fn valid_monitor_configuration(
    configuration: &MonitorConfigurationWire,
    campaign_id: &str,
    plan_fingerprint: &ArtifactFingerprint,
    plan: &SdJwtIssuanceQualificationPlan,
) -> bool {
    let validity = &plan.global_rounds.run_validity;
    configuration.schema == "marty.performance/sd-jwt-issuance-monitor-config/v1"
        && configuration.campaign_id == campaign_id
        && configuration.plan_fingerprint == *plan_fingerprint
        && configuration.sample_interval_seconds == validity.sample_interval_seconds
        && configuration.maximum_sample_gap_seconds == validity.maximum_sample_gap_seconds
        && configuration.controller_clock_authoritative
        && configuration.cpu_backend == "controller_observed_total_cpu_percent_v1"
        && configuration.memory_backend == "controller_observed_available_memory_bytes_v1"
        && configuration.frequency_backend == "controller_observed_cpu_frequency_hz_v1"
        && configuration.temperature_backend
            == "controller_observed_maximum_temperature_millidegrees_celsius_v1"
        && configuration.throttle_backend == "controller_observed_throttle_flags_v1"
        && configuration.process_scope_policy == "exact_baseline_match_v1"
        && configuration.process_identity_scheme == "hmac_sha256_campaign_ephemeral_process_set_v1"
        && !configuration.process_identity_key_persisted
        && !configuration.raw_process_metadata_retained
}

fn valid_tool_version(value: &str) -> bool {
    (1..=4_096).contains(&value.len())
        && value.ends_with('\n')
        && !value.ends_with("\n\n")
        && value
            .bytes()
            .all(|byte| byte == b'\n' || byte.is_ascii_graphic() || byte == b' ')
}

fn expected_build_argv(target_triple: &str) -> Vec<String> {
    [
        "cargo",
        "build",
        "--frozen",
        "--offline",
        "--profile",
        "bench",
        "--no-default-features",
        "--features",
        "issuance_bench",
        "--bench",
        "sd_jwt_issuance",
        "--target",
        target_triple,
        "--message-format",
        "json-render-diagnostics",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn expected_offline_probe_argv() -> Vec<String> {
    [
        "cargo",
        "metadata",
        "--frozen",
        "--offline",
        "--locked",
        "--format-version",
        "1",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn unique_role_fingerprint<'a>(
    inventory: &'a BuildInputInventory,
    role: &str,
) -> Option<&'a ArtifactFingerprint> {
    let mut matches = inventory.entries.iter().filter(|entry| entry.role == role);
    let fingerprint = &matches.next()?.fingerprint;
    matches.next().is_none().then_some(fingerprint)
}

struct BuildReceiptValidation<'a> {
    inventory: &'a BuildInputInventory,
    source: &'a ValidatedSourceArchive,
    source_archive_fingerprint: &'a ArtifactFingerprint,
    cargo_lock_fingerprint: &'a ArtifactFingerprint,
    inventory_fingerprint: &'a ArtifactFingerprint,
    archive_fingerprint: &'a ArtifactFingerprint,
    controller_fingerprint: &'a ArtifactFingerprint,
    fixed_binary_fingerprint: &'a ArtifactFingerprint,
}

fn validate_build_receipt(
    receipt: &FixedBinaryBuildReceiptWire,
    validation: &BuildReceiptValidation<'_>,
) -> bool {
    let inventory = validation.inventory;
    let source = validation.source;
    let windows = receipt
        .target_triple
        .split('-')
        .any(|component| component == "windows");
    receipt.schema == "marty.performance/sd-jwt-issuance-fixed-binary-build/v2"
        && valid_campaign_id(&receipt.campaign_id)
        && receipt.controller_binary_fingerprint == *validation.controller_fingerprint
        && receipt.source_archive_fingerprint == *validation.source_archive_fingerprint
        && receipt.source_commit == source.manifest.source_commit
        && receipt.source_tree == source.manifest.source_tree
        && receipt.cargo_lock_fingerprint == *validation.cargo_lock_fingerprint
        && unique_role_fingerprint(inventory, "cargo_executable")
            == Some(&receipt.cargo_binary_fingerprint)
        && valid_tool_version(&receipt.cargo_verbose_version)
        && unique_role_fingerprint(inventory, "rustc_executable")
            == Some(&receipt.rustc_binary_fingerprint)
        && valid_tool_version(&receipt.rustc_verbose_version)
        && receipt.build_input_inventory_fingerprint == *validation.inventory_fingerprint
        && receipt.build_input_archive_fingerprint == *validation.archive_fingerprint
        && valid_build_input_inventory(
            inventory,
            windows,
            &receipt.target_triple,
            &receipt.campaign_id,
        )
        && receipt.build_profile == "bench"
        && valid_fixed_build_root(&receipt.materialized_build_root, windows)
        && receipt.working_directory == format!("{}/worktree", receipt.materialized_build_root)
        && receipt.logical_argv == expected_build_argv(&receipt.target_triple)
        && receipt.enabled_features == ["issuance_bench".to_owned()]
        && receipt.build_environment_policy
            == "trusted_controller_inventoried_inputs_cleared_offline_sandbox_v1"
        && valid_build_layout(
            &receipt.build_environment,
            inventory,
            windows,
            &receipt.target_triple,
            source.committer_timestamp,
            &receipt.rustc_reported_sysroot,
            &receipt.campaign_id,
        )
        && receipt.offline_dependency_resolution_argv == expected_offline_probe_argv()
        && receipt.offline_dependency_resolution_succeeded
        && receipt.build_finished_monotonic_nanoseconds
            >= receipt.build_started_monotonic_nanoseconds
        && receipt.produced_binary_fingerprint == *validation.fixed_binary_fingerprint
        && receipt.installed_fixed_binary_fingerprint == *validation.fixed_binary_fingerprint
}

fn canonical_json_envelope(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && !bytes.starts_with(&[0xef, 0xbb, 0xbf])
        && std::str::from_utf8(bytes).is_ok()
        && !bytes.contains(&b'\r')
        && bytes.ends_with(b"\n")
        && !bytes.ends_with(b"\n\n")
}

fn parse_canonical_pretty<T>(bytes: &[u8], role: &'static str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    anyhow::ensure!(canonical_json_envelope(bytes), "analysis rejected: {role}");
    let value: T =
        serde_json::from_slice(bytes).with_context(|| format!("analysis rejected: {role}"))?;
    let canonical =
        canonical_pretty_bytes(&value).with_context(|| format!("analysis rejected: {role}"))?;
    anyhow::ensure!(canonical == bytes, "analysis rejected: {role}");
    Ok(value)
}

fn parse_canonical_compact_line<T>(bytes: &[u8], role: &'static str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    anyhow::ensure!(canonical_json_envelope(bytes), "analysis rejected: {role}");
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| anyhow::anyhow!("analysis rejected: {role}"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
    deserializer
        .end()
        .map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
    let mut canonical =
        serde_json::to_vec(&value).map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
    canonical.push(b'\n');
    anyhow::ensure!(canonical == bytes, "analysis rejected: {role}");
    Ok(value)
}

fn validate_lifecycle_record_payload(bytes: &[u8], schema: &str, role: &'static str) -> Result<()> {
    match schema {
        "marty.performance/sd-jwt-issuance-validity-continuation/v1" => {
            let _: ContinuationHeaderWire = parse_canonical_compact_line(bytes, role)?;
        }
        "marty.performance/sd-jwt-issuance-validity-sample/v1" => {
            let _: ValiditySampleWire = parse_canonical_compact_line(bytes, role)?;
        }
        "marty.performance/sd-jwt-issuance-validity-process-intent/v1" => {
            let _: ProcessIntentRecordWire = parse_canonical_compact_line(bytes, role)?;
        }
        "marty.performance/sd-jwt-issuance-validity-process-start/v1" => {
            let _: ProcessStartRecordWire = parse_canonical_compact_line(bytes, role)?;
        }
        "marty.performance/sd-jwt-issuance-validity-process-finish/v1" => {
            let _: ProcessFinishRecordWire = parse_canonical_compact_line(bytes, role)?;
        }
        "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1" => {
            let _: AttestationTransitionWire = parse_canonical_compact_line(bytes, role)?;
        }
        _ => anyhow::bail!("analysis rejected: {role}"),
    }
    Ok(())
}

#[derive(Default)]
struct SegmentPrefixState {
    header: Option<SegmentRecordEnvelope>,
    last_monotonic_nanoseconds: Option<u64>,
    records_seen: u32,
    counts: SegmentRecordCounts,
}

impl SegmentPrefixState {
    fn observe(&mut self, bytes: &[u8], role: &'static str) -> Result<()> {
        let body = bytes
            .strip_suffix(b"\n")
            .ok_or_else(|| anyhow::anyhow!("analysis rejected: {role}"))?;
        let mut deserializer = serde_json::Deserializer::from_slice(body);
        let envelope = SegmentRecordEnvelope::deserialize(&mut deserializer)
            .map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
        deserializer
            .end()
            .map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
        anyhow::ensure!(
            valid_utc_rfc3339_nanoseconds(&envelope.utc_rfc3339_nanoseconds)
                && envelope.record_ordinal == self.records_seen
                && self
                    .last_monotonic_nanoseconds
                    .is_none_or(|previous| envelope.monotonic_nanoseconds >= previous),
            "analysis rejected: {role}"
        );
        let monotonic_nanoseconds = envelope.monotonic_nanoseconds;

        if let Some(header) = &self.header {
            anyhow::ensure!(
                envelope.campaign_id == header.campaign_id
                    && envelope.segment_ordinal == header.segment_ordinal,
                "analysis rejected: {role}"
            );
            let count = match envelope.schema.as_str() {
                "marty.performance/sd-jwt-issuance-validity-sample/v1" => &mut self.counts.sample,
                "marty.performance/sd-jwt-issuance-validity-process-intent/v1" => {
                    &mut self.counts.process_intent
                }
                "marty.performance/sd-jwt-issuance-validity-process-start/v1" => {
                    &mut self.counts.process_start
                }
                "marty.performance/sd-jwt-issuance-validity-process-finish/v1" => {
                    &mut self.counts.process_finish
                }
                "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1" => {
                    &mut self.counts.attestation_transition
                }
                _ => return Err(anyhow::anyhow!("analysis rejected: {role}")),
            };
            validate_lifecycle_record_payload(bytes, &envelope.schema, role)?;
            *count = count
                .checked_add(1)
                .context("analysis rejected: segment record count")?;
        } else {
            anyhow::ensure!(
                valid_campaign_id(&envelope.campaign_id)
                    && envelope.record_ordinal == 0
                    && if envelope.segment_ordinal == 0 {
                        envelope.schema == "marty.performance/sd-jwt-issuance-validity-genesis/v1"
                    } else {
                        envelope.schema
                            == "marty.performance/sd-jwt-issuance-validity-continuation/v1"
                    },
                "analysis rejected: {role}"
            );
            if envelope.segment_ordinal != 0 {
                validate_lifecycle_record_payload(bytes, &envelope.schema, role)?;
            }
            self.header = Some(envelope);
        }
        self.last_monotonic_nanoseconds = Some(monotonic_nanoseconds);
        self.records_seen = self
            .records_seen
            .checked_add(1)
            .context("analysis rejected: segment record count")?;
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded streaming parser keeps snapshot, line, canonicality, and observer ordering visible"
)]
fn inspect_segment_with_observer(
    input: OpenedInput,
    role: &'static str,
    mut observe: impl FnMut(&[u8]) -> Result<()>,
) -> Result<SegmentInspection> {
    const MAXIMUM_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
    const MAXIMUM_LINE_BYTES: u64 = 64 * 1024;
    const MAXIMUM_RECORDS: u32 = 65_536;

    anyhow::ensure!(
        input.snapshot.byte_length <= MAXIMUM_SEGMENT_BYTES,
        "analysis rejected: {role}"
    );
    let snapshot = input.snapshot;
    let mut reader = BufReader::new(input.file);
    let mut total_hasher = Sha256::new();
    let mut prefix_hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    let mut prefix_bytes = 0_u64;
    let mut first_line = None;
    let mut previous_line: Option<Vec<u8>> = None;
    let mut record_count = 0_u32;
    let mut prefix_state = SegmentPrefixState::default();
    loop {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take(MAXIMUM_LINE_BYTES + 1)
            .read_until(b'\n', &mut line)
            .with_context(|| format!("analysis rejected: {role}"))?;
        if read == 0 {
            break;
        }
        anyhow::ensure!(
            u64::try_from(read).is_ok_and(|length| length <= MAXIMUM_LINE_BYTES)
                && line.ends_with(b"\n")
                && !line.contains(&b'\r'),
            "analysis rejected: {role}"
        );
        record_count = record_count
            .checked_add(1)
            .context("analysis rejected: segment record count")?;
        anyhow::ensure!(record_count <= MAXIMUM_RECORDS, "analysis rejected: {role}");
        let line_length = u64::try_from(line.len()).context("analysis rejected: segment bytes")?;
        total_bytes = total_bytes
            .checked_add(line_length)
            .context("analysis rejected: segment bytes")?;
        anyhow::ensure!(
            total_bytes <= MAXIMUM_SEGMENT_BYTES,
            "analysis rejected: {role}"
        );
        total_hasher.update(&line);
        if first_line.is_none() {
            first_line = Some(line.clone());
        }
        if let Some(previous) = previous_line.replace(line) {
            prefix_state.observe(&previous, role)?;
            observe(&previous).map_err(|_| anyhow::anyhow!("analysis rejected: {role}"))?;
            prefix_hasher.update(&previous);
            prefix_bytes = prefix_bytes
                .checked_add(
                    u64::try_from(previous.len()).context("analysis rejected: segment bytes")?,
                )
                .context("analysis rejected: segment bytes")?;
        }
    }
    let first_line = first_line.context("analysis rejected: empty segment")?;
    let last_line = previous_line.context("analysis rejected: empty segment")?;
    let records_before_last = record_count
        .checked_sub(1)
        .context("analysis rejected: empty segment")?;
    let header = prefix_state
        .header
        .context("analysis rejected: segment header")?;
    let counted_records = prefix_state
        .counts
        .checked_total()
        .and_then(|count| count.checked_add(1))
        .context("analysis rejected: segment record count")?;
    anyhow::ensure!(
        prefix_state.records_seen == records_before_last && counted_records == records_before_last,
        "analysis rejected: {role}"
    );
    let last_record_monotonic_nanoseconds = prefix_state
        .last_monotonic_nanoseconds
        .context("analysis rejected: segment header")?;
    ensure_exact_snapshot_byte_length(total_bytes, snapshot, role)?;
    ensure_file_unchanged(reader.get_ref(), snapshot, role)?;
    Ok(SegmentInspection {
        fingerprint: ArtifactFingerprint {
            sha256: hex::encode_upper(total_hasher.finalize()),
            byte_length: total_bytes,
        },
        first_line,
        last_line,
        records_before_last,
        bytes_before_last: prefix_bytes,
        fingerprint_before_last: ArtifactFingerprint {
            sha256: hex::encode_upper(prefix_hasher.finalize()),
            byte_length: prefix_bytes,
        },
        header_schema: header.schema,
        campaign_id: header.campaign_id,
        segment_ordinal: header.segment_ordinal,
        header_monotonic_nanoseconds: header.monotonic_nanoseconds,
        last_record_monotonic_nanoseconds,
        record_counts: prefix_state.counts,
    })
}

fn inspect_segment(input: OpenedInput, role: &'static str) -> Result<SegmentInspection> {
    inspect_segment_with_observer(input, role, |_| Ok(()))
}

fn inspect_campaign_segment(
    budget: &mut AnalysisReadBudget,
    campaign: &CampaignDirectory,
    relative: &Path,
    role: &'static str,
) -> Result<SegmentInspection> {
    let input = campaign.open_file(relative, 64 * 1024 * 1024, role)?;
    budget.charge(&input)?;
    inspect_segment(input, role)
}

fn inspect_campaign_segment_with_observer(
    budget: &mut AnalysisReadBudget,
    campaign: &CampaignDirectory,
    relative: &Path,
    role: &'static str,
    observe: impl FnMut(&[u8]) -> Result<()>,
) -> Result<SegmentInspection> {
    let input = campaign.open_file(relative, 64 * 1024 * 1024, role)?;
    budget.charge(&input)?;
    inspect_segment_with_observer(input, role, observe)
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

fn read_exact_role(reader: &mut impl Read, bytes: &mut [u8], role: &'static str) -> Result<()> {
    reader
        .read_exact(bytes)
        .with_context(|| format!("analysis rejected: {role}"))
}

fn hash_exact_member(
    reader: &mut impl Read,
    length: u64,
    role: &'static str,
) -> Result<ArtifactFingerprint> {
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .context("analysis rejected: build-input member")?;
        read_exact_role(reader, &mut buffer[..take], role)?;
        hasher.update(&buffer[..take]);
        remaining -= u64::try_from(take).context("analysis rejected: build-input member")?;
    }
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(hasher.finalize()),
        byte_length: length,
    })
}

struct FingerprintingReader<'a, R> {
    inner: &'a mut R,
    hasher: Sha256,
    byte_length: u64,
}

impl<'a, R> FingerprintingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            byte_length: 0,
        }
    }

    fn finish(self) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: hex::encode_upper(self.hasher.finalize()),
            byte_length: self.byte_length,
        }
    }
}

impl<R: Read> Read for FingerprintingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.byte_length = self
            .byte_length
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("build-input archive byte count overflow"))?;
        Ok(read)
    }
}

fn validate_build_input_archive_stream(
    reader: &mut impl Read,
    inventory: &BuildInputInventory,
) -> Result<ArtifactFingerprint> {
    let mut reader = FingerprintingReader::new(reader);
    let mut magic = [0_u8; FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len()];
    read_exact_role(&mut reader, &mut magic, "build-input archive")?;
    anyhow::ensure!(
        magic == FIXED_BUILD_INPUT_ARCHIVE_MAGIC,
        "analysis rejected: build-input archive"
    );
    let mut member_total = 0_u64;
    for entry in &inventory.entries {
        let mut encoded_length = [0_u8; 8];
        read_exact_role(&mut reader, &mut encoded_length, "build-input archive")?;
        let length = u64::from_be_bytes(encoded_length);
        anyhow::ensure!(
            length == entry.fingerprint.byte_length,
            "analysis rejected: build-input archive"
        );
        let member = if entry.role == "cargo_configuration" {
            anyhow::ensure!(
                entry.relative_path == "cargo-home/config.toml"
                    && length == u64::try_from(FIXED_CARGO_CONFIGURATION_BYTES.len())?,
                "analysis rejected: build-input archive"
            );
            let mut exact = vec![0_u8; FIXED_CARGO_CONFIGURATION_BYTES.len()];
            read_exact_role(&mut reader, &mut exact, "build-input archive")?;
            anyhow::ensure!(
                exact == FIXED_CARGO_CONFIGURATION_BYTES,
                "analysis rejected: build-input archive"
            );
            fingerprint(&exact).context("analysis rejected: build-input archive")?
        } else {
            hash_exact_member(&mut reader, length, "build-input archive")?
        };
        anyhow::ensure!(
            member == entry.fingerprint,
            "analysis rejected: build-input archive"
        );
        member_total = member_total
            .checked_add(length)
            .context("analysis rejected: build-input archive")?;
    }
    let mut trailing = [0_u8; 1];
    anyhow::ensure!(
        reader
            .read(&mut trailing)
            .context("analysis rejected: build-input archive")?
            == 0
            && member_total == inventory.total_byte_length,
        "analysis rejected: build-input archive"
    );
    Ok(reader.finish())
}

fn validate_build_input_archive_file(
    mut input: OpenedInput,
    inventory: &BuildInputInventory,
    expected_archive: &ArtifactFingerprint,
) -> Result<()> {
    let actual = fingerprint_reader(
        &mut input.file,
        MAX_FIXED_BUILD_INPUT_BYTES,
        "build-input archive",
    )?;
    ensure_exact_snapshot_byte_length(actual.byte_length, input.snapshot, "build-input archive")?;
    anyhow::ensure!(
        actual == *expected_archive && inventory.archive_fingerprint == actual,
        "analysis rejected: build-input archive"
    );
    input
        .file
        .seek(SeekFrom::Start(0))
        .context("analysis rejected: build-input archive")?;
    let parsed = validate_build_input_archive_stream(&mut input.file, inventory)?;
    anyhow::ensure!(parsed == actual, "analysis rejected: build-input archive");
    ensure_file_unchanged(&input.file, input.snapshot, "build-input archive")
}

#[cfg(test)]
fn valid_build_input_archive_bytes(
    bytes: &[u8],
    inventory: &BuildInputInventory,
    expected_inventory_fingerprint: &ArtifactFingerprint,
    expected_archive_fingerprint: &ArtifactFingerprint,
    windows: bool,
    expected_target_triple: &str,
    expected_campaign_id: &str,
) -> bool {
    u64::try_from(bytes.len()).is_ok_and(|length| length <= MAX_FIXED_BUILD_INPUT_BYTES)
        && fingerprint(bytes).ok().as_ref() == Some(expected_archive_fingerprint)
        && inventory.archive_fingerprint == *expected_archive_fingerprint
        && canonical_pretty_bytes(inventory)
            .and_then(|encoded| fingerprint(&encoded).ok())
            .as_ref()
            == Some(expected_inventory_fingerprint)
        && valid_build_input_inventory(
            inventory,
            windows,
            expected_target_triple,
            expected_campaign_id,
        )
        && validate_build_input_archive_stream(&mut std::io::Cursor::new(bytes), inventory).is_ok()
}

fn monotonic_duration_within_seconds(first: u64, last: u64, maximum_seconds: u32) -> bool {
    last.checked_sub(first).is_some_and(|duration| {
        u64::from(maximum_seconds)
            .checked_mul(1_000_000_000)
            .is_some_and(|maximum| duration <= maximum)
    })
}

fn validate_completion(
    completion: &CompletionWire,
    campaign_id: &str,
    schedule: &schedule::QualificationSchedule<'_>,
    plan: &ArtifactFingerprint,
    manifest: &ArtifactFingerprint,
    anchor_configuration: &ArtifactFingerprint,
    maximum_campaign_seconds: u32,
) -> bool {
    completion.schema == "marty.performance/sd-jwt-issuance-validity-completion/v1"
        && completion.campaign_id == campaign_id
        && valid_utc_rfc3339_nanoseconds(&completion.created_at_utc_rfc3339_nanoseconds)
        && completion.plan_fingerprint == *plan
        && completion.manifest_fingerprint == *manifest
        && completion.external_anchor_channel_configuration_fingerprint == *anchor_configuration
        && (1..=16).contains(&completion.segment_count)
        && usize::try_from(completion.segment_count)
            == Ok(completion.ordered_segment_fingerprints.len())
        && completion.ordered_segment_fingerprints.last()
            == Some(&completion.terminal_segment_fingerprint)
        && completion
            .ordered_segment_fingerprints
            .iter()
            .all(valid_artifact_fingerprint)
        && (1..=16).contains(
            &completion
                .ordered_test_window_attestation_fingerprints
                .len(),
        )
        && completion
            .ordered_test_window_attestation_fingerprints
            .iter()
            .all(valid_artifact_fingerprint)
        && [
            &completion.genesis_header_fingerprint,
            &completion.terminal_segment_fingerprint,
            &completion.terminal_observation_evidence_fingerprint,
            &completion.criterion_artifact_set_fingerprint,
            &completion.route_artifact_set_fingerprint,
            &completion.first_quiet_window_evidence_fingerprint,
        ]
        .into_iter()
        .all(valid_artifact_fingerprint)
        && completion.first_monotonic_nanoseconds <= completion.last_monotonic_nanoseconds
        && monotonic_duration_within_seconds(
            completion.first_monotonic_nanoseconds,
            completion.last_monotonic_nanoseconds,
            maximum_campaign_seconds,
        )
        && completion.last_monotonic_nanoseconds <= completion.created_at_monotonic_nanoseconds
        && completion.process_intent_count == schedule::TOTAL_PROCESS_COUNT
        && completion.process_start_count == schedule::TOTAL_PROCESS_COUNT
        && completion.process_finish_count == schedule::TOTAL_PROCESS_COUNT
        && completion.process_completions.len() == schedule.iter().len()
        && completion.invalidating_event_count == 0
        && completion.validity_status == "valid"
        && completion
            .process_completions
            .iter()
            .zip(schedule.iter())
            .all(|(entry, expected)| {
                entry.global_round_ordinal == expected.coordinate.global_round
                    && entry.cell_ordinal == expected.coordinate.cell
                    && entry.expansion_position == expected.coordinate.expansion
                    && entry.timing_process_id == expected.timing_process_id
                    && entry.full_benchmark_id == expected.full_benchmark_id
                    && [
                        &entry.process_intent_record_fingerprint,
                        &entry.process_start_record_fingerprint,
                        &entry.process_finish_record_fingerprint,
                        &entry.invocation_descriptor_fingerprint,
                        &entry.launch_barrier_receipt_fingerprint,
                        &entry.criterion_home_initial_inventory_fingerprint,
                        &entry.criterion_home_final_inventory_fingerprint,
                        &entry.criterion_artifact_fingerprint,
                        &entry.route_artifact_fingerprint,
                    ]
                    .into_iter()
                    .all(valid_artifact_fingerprint)
            })
}

struct GenesisValidation<'a> {
    campaign_id: &'a str,
    plan: &'a ArtifactFingerprint,
    manifest: &'a ArtifactFingerprint,
    fixed_binary: &'a ArtifactFingerprint,
    build_receipt: &'a ArtifactFingerprint,
    monitor_binary: &'a ArtifactFingerprint,
    controller_binary: &'a ArtifactFingerprint,
    controller_configuration: &'a ArtifactFingerprint,
    monitor_configuration: &'a ArtifactFingerprint,
    anchor_configuration: &'a ArtifactFingerprint,
    source_archive: &'a ArtifactFingerprint,
    cargo_lock: &'a ArtifactFingerprint,
    hardware_profile: &'a ArtifactFingerprint,
    source: &'a ValidatedSourceArchive,
    build: &'a FixedBinaryBuildReceiptWire,
    first_monotonic_nanoseconds: u64,
}

fn validate_genesis(genesis: &GenesisHeaderWire, expected: &GenesisValidation<'_>) -> bool {
    genesis.schema == "marty.performance/sd-jwt-issuance-validity-genesis/v1"
        && genesis.campaign_id == expected.campaign_id
        && genesis.segment_ordinal == 0
        && genesis.record_ordinal == 0
        && valid_utc_rfc3339_nanoseconds(&genesis.utc_rfc3339_nanoseconds)
        && genesis.monotonic_nanoseconds == expected.first_monotonic_nanoseconds
        && expected.build.build_finished_monotonic_nanoseconds <= genesis.monotonic_nanoseconds
        && genesis.plan_fingerprint == *expected.plan
        && genesis.manifest_fingerprint == *expected.manifest
        && genesis.fixed_binary_fingerprint == *expected.fixed_binary
        && genesis.fixed_binary_build_receipt_fingerprint == *expected.build_receipt
        && genesis.monitor_binary_fingerprint == *expected.monitor_binary
        && genesis.controller_binary_fingerprint == *expected.controller_binary
        && genesis.controller_configuration_fingerprint == *expected.controller_configuration
        && genesis.monitor_configuration_fingerprint == *expected.monitor_configuration
        && genesis.external_anchor_channel_configuration_fingerprint
            == *expected.anchor_configuration
        && genesis.source_commit == expected.source.manifest.source_commit
        && genesis.source_tree == expected.source.manifest.source_tree
        && genesis.source_archive_fingerprint == *expected.source_archive
        && genesis.cargo_lock_fingerprint == *expected.cargo_lock
        && genesis.rustc_verbose_version == expected.build.rustc_verbose_version
        && genesis.target_triple == expected.build.target_triple
        && genesis.build_profile == expected.build.build_profile
        && valid_artifact_fingerprint(&genesis.host_identity_fingerprint)
        && valid_uppercase_hex(&genesis.boot_identity_pseudonym, 64)
        && genesis.hardware_profile_fingerprint == *expected.hardware_profile
        && valid_artifact_fingerprint(&genesis.validity_thresholds_fingerprint)
        && valid_artifact_fingerprint(&genesis.first_quiet_window_evidence_fingerprint)
        && valid_artifact_fingerprint(&genesis.initial_test_window_attestation_fingerprint)
        && valid_artifact_fingerprint(&genesis.baseline_unrelated_process_set_fingerprint)
}

fn validate_terminal_footer(
    footer: &SegmentFooterWire,
    inspection: &SegmentInspection,
    expected_campaign_id: &str,
    expected_segment_ordinal: u32,
    expected_last_monotonic_nanoseconds: u64,
    maximum_segment_seconds: u32,
) -> bool {
    footer.schema == "marty.performance/sd-jwt-issuance-validity-segment-footer/v1"
        && footer.campaign_id == expected_campaign_id
        && footer.campaign_id == inspection.campaign_id
        && valid_utc_rfc3339_nanoseconds(&footer.utc_rfc3339_nanoseconds)
        && footer.segment_ordinal == expected_segment_ordinal
        && footer.segment_ordinal == inspection.segment_ordinal
        && if footer.segment_ordinal == 0 {
            inspection.header_schema == "marty.performance/sd-jwt-issuance-validity-genesis/v1"
        } else {
            inspection.header_schema == "marty.performance/sd-jwt-issuance-validity-continuation/v1"
        }
        && footer.record_ordinal == footer.records_before_footer
        && footer.records_before_footer == inspection.records_before_last
        && footer.bytes_before_footer == inspection.bytes_before_last
        && footer.records_before_footer_fingerprint == inspection.fingerprint_before_last
        && footer.first_monotonic_nanoseconds == inspection.header_monotonic_nanoseconds
        && inspection.last_record_monotonic_nanoseconds <= footer.monotonic_nanoseconds
        && monotonic_duration_within_seconds(
            footer.first_monotonic_nanoseconds,
            footer.monotonic_nanoseconds,
            maximum_segment_seconds,
        )
        && footer.last_monotonic_nanoseconds == footer.monotonic_nanoseconds
        && footer.monotonic_nanoseconds == expected_last_monotonic_nanoseconds
        && footer.sample_count == inspection.record_counts.sample
        && footer.process_intent_count == inspection.record_counts.process_intent
        && footer.process_start_count == inspection.record_counts.process_start
        && footer.process_finish_count == inspection.record_counts.process_finish
        && footer.attestation_transition_count == inspection.record_counts.attestation_transition
        && footer.closed_reason == "campaign_complete"
}

fn valid_analysis_output_file_name(value: &std::ffi::OsStr) -> bool {
    value.to_str().is_some_and(|value| {
        (1..=255).contains(&value.len())
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && !windows_reserved_device_stem(value)
    })
}

fn write_analysis_report(
    output_path: &Path,
    forbidden_directory: Option<FileIdentity>,
    report: &impl Serialize,
) -> Result<()> {
    anyhow::ensure!(output_path.is_absolute(), "analysis rejected: output");
    let parent = output_path.parent().context("analysis rejected: output")?;
    let file_name = output_path
        .file_name()
        .filter(|name| valid_analysis_output_file_name(name))
        .context("analysis rejected: output")?;
    let parent_directory =
        open_absolute_directory_excluding(parent, forbidden_directory, "output")?;
    let parent_identity = verified_directory_identity(&parent_directory, "output")?;
    let mut bytes = serde_json::to_vec_pretty(report).context("analysis rejected: output")?;
    bytes.push(b'\n');
    let output_length = u64::try_from(bytes.len()).context("analysis rejected: output")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("analysis rejected: output")?;
    anyhow::ensure!(
        verified_directory_identity(
            &open_absolute_directory_excluding(parent, forbidden_directory, "output")?,
            "output",
        )? == parent_identity,
        "analysis rejected: output"
    );
    temporary
        .write_all(&bytes)
        .context("analysis rejected: output")?;
    temporary.flush().context("analysis rejected: output")?;
    temporary
        .as_file()
        .sync_all()
        .context("analysis rejected: output")?;
    let output = temporary
        .persist_noclobber(output_path)
        .map_err(|_| anyhow::anyhow!("analysis rejected: output"))?;
    output.sync_all().context("analysis rejected: output")?;
    let output_snapshot = verified_file_snapshot(&output, output_length, "output")?;
    anyhow::ensure!(
        output_snapshot.byte_length == output_length,
        "analysis rejected: output"
    );
    let retained_output = open_child_file(&parent_directory, file_name, output_length, "output")?;
    let retained_snapshot = retained_output.snapshot;
    anyhow::ensure!(
        retained_snapshot == output_snapshot
            && verified_directory_identity(
                &open_absolute_directory_excluding(parent, forbidden_directory, "output")?,
                "output",
            )? == parent_identity,
        "analysis rejected: output"
    );
    #[cfg(unix)]
    parent_directory
        .sync_all()
        .context("analysis rejected: output")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum AnalysisScope {
    SelectedRoute,
    IndexedTimingArtifacts,
    Lifecycle,
}

/// Validate the bounded offline artifact-integrity slice of one V3 campaign.
pub(crate) fn analyze(request: &IssuanceAnalysisRequest<'_>) -> Result<()> {
    analyze_with_scope(request, AnalysisScope::SelectedRoute)
}

/// Validate and analyze every indexed route and Criterion estimate artifact.
pub(crate) fn analyze_indexed(request: &IssuanceAnalysisRequest<'_>) -> Result<()> {
    analyze_with_scope(request, AnalysisScope::IndexedTimingArtifacts)
}

/// Validate every retained validity segment and its lifecycle record semantics.
pub(crate) fn analyze_lifecycle(request: &IssuanceAnalysisRequest<'_>) -> Result<()> {
    analyze_with_scope(request, AnalysisScope::Lifecycle)
}

#[allow(
    clippy::too_many_lines,
    reason = "the ordered fail-closed verification pipeline keeps every cross-artifact binding visible"
)]
fn analyze_with_scope(request: &IssuanceAnalysisRequest<'_>, scope: AnalysisScope) -> Result<()> {
    let coordinate = schedule::QualificationSchedule::parse_route_path(request.route_artifact)
        .context("analysis rejected: route artifact role")?;
    let campaign = CampaignDirectory::open(request.campaign_root)?;
    let mut read_budget = AnalysisReadBudget::default();

    let manifest_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("inputs/qualification-manifest.json"),
        MAX_MANIFEST_BYTES,
        "manifest",
    )?;
    let manifest: SdJwtIssuanceQualificationManifest =
        parse_canonical_pretty(&manifest_bytes, "manifest")?;
    validate_manifest(&manifest).context("analysis rejected: manifest")?;
    let manifest_fingerprint = fingerprint(&manifest_bytes)?;

    let plan_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("inputs/qualification-plan.json"),
        MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
        "plan",
    )?;
    let plan: SdJwtIssuanceQualificationPlan = parse_canonical_pretty(&plan_bytes, "plan")?;
    let expected_plan =
        plan_for_manifest(&manifest, &manifest_bytes).context("analysis rejected: plan binding")?;
    anyhow::ensure!(plan == expected_plan, "analysis rejected: plan binding");
    let schedule = schedule::QualificationSchedule::new(&plan, &manifest)
        .context("analysis rejected: schedule")?;
    let plan_fingerprint = fingerprint(&plan_bytes)?;

    let hardware_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("profiles/hardware.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "hardware profile",
    )?;
    let hardware: HardwareProfileWire =
        parse_canonical_pretty(&hardware_bytes, "hardware profile")?;
    anyhow::ensure!(
        valid_hardware_profile(&hardware),
        "analysis rejected: hardware profile"
    );
    let hardware_fingerprint = fingerprint(&hardware_bytes)?;

    let route_expectation = schedule
        .get(coordinate)
        .context("analysis rejected: route identity")?;
    let route_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        request.route_artifact,
        1024 * 1024,
        "route artifact",
    )?;
    anyhow::ensure!(
        valid_route_wire_bytes(
            &route_bytes,
            route_expectation.full_benchmark_id,
            route_expectation.fixture_id,
            route_expectation.stage,
            route_expectation.requested,
            u64::try_from(plan.worker_cap).context("analysis rejected: route worker cap")?,
            u64::from(hardware.host_available_parallelism),
        ),
        "analysis rejected: route artifact"
    );
    let route_fingerprint = fingerprint(&route_bytes)?;

    let cargo_lock_fingerprint = fingerprint_campaign_file(
        &mut read_budget,
        &campaign,
        Path::new("inputs/Cargo.lock"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "Cargo.lock",
    )?;

    let build_receipt_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("build/fixed-benchmark.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "build receipt",
    )?;
    let build_receipt: FixedBinaryBuildReceiptWire =
        parse_canonical_pretty(&build_receipt_bytes, "build receipt")?;
    anyhow::ensure!(
        valid_campaign_id(&build_receipt.campaign_id)
            && hardware.campaign_id == build_receipt.campaign_id
            && target_matches_hardware(&build_receipt.target_triple, &hardware),
        "analysis rejected: campaign identity"
    );

    let source_archive_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("source/exact-tree.sar"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "source archive",
    )?;
    let source_archive_fingerprint = fingerprint(&source_archive_bytes)?;
    let validated_source = validate_source_archive_bytes(
        &source_archive_bytes,
        &build_receipt.source_archive_fingerprint,
        &cargo_lock_fingerprint,
    )
    .context("analysis rejected: source archive")?;

    let inventory_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("build/input-inventory.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "build-input inventory",
    )?;
    let inventory: BuildInputInventory =
        parse_canonical_pretty(&inventory_bytes, "build-input inventory")?;
    let inventory_fingerprint = fingerprint(&inventory_bytes)?;

    let build_archive_input = campaign.open_file(
        Path::new("build/input-files.bia"),
        MAX_FIXED_BUILD_INPUT_BYTES,
        "build-input archive",
    )?;
    read_budget.charge(&build_archive_input)?;
    validate_build_input_archive_file(
        build_archive_input,
        &inventory,
        &build_receipt.build_input_archive_fingerprint,
    )?;
    let build_archive_fingerprint = build_receipt.build_input_archive_fingerprint.clone();

    let windows = build_receipt
        .target_triple
        .split('-')
        .any(|component| component == "windows");
    let controller_relative = if windows {
        "bin/controller.exe"
    } else {
        "bin/controller"
    };
    let monitor_relative = if windows {
        "bin/monitor.exe"
    } else {
        "bin/monitor"
    };
    let fixed_binary_relative = if windows {
        "bin/fixed-benchmark.exe"
    } else {
        "bin/fixed-benchmark"
    };
    let controller_fingerprint = fingerprint_campaign_file(
        &mut read_budget,
        &campaign,
        Path::new(controller_relative),
        MAX_FIXED_BUILD_INPUT_BYTES,
        "controller binary",
    )?;
    let fixed_binary_fingerprint = fingerprint_campaign_file(
        &mut read_budget,
        &campaign,
        Path::new(fixed_binary_relative),
        MAX_FIXED_BUILD_INPUT_BYTES,
        "fixed binary",
    )?;
    let monitor_fingerprint = fingerprint_campaign_file(
        &mut read_budget,
        &campaign,
        Path::new(monitor_relative),
        MAX_FIXED_BUILD_INPUT_BYTES,
        "monitor binary",
    )?;
    anyhow::ensure!(
        validate_build_receipt(
            &build_receipt,
            &BuildReceiptValidation {
                inventory: &inventory,
                source: &validated_source,
                source_archive_fingerprint: &source_archive_fingerprint,
                cargo_lock_fingerprint: &cargo_lock_fingerprint,
                inventory_fingerprint: &inventory_fingerprint,
                archive_fingerprint: &build_archive_fingerprint,
                controller_fingerprint: &controller_fingerprint,
                fixed_binary_fingerprint: &fixed_binary_fingerprint,
            },
        ),
        "analysis rejected: build receipt"
    );
    let build_receipt_fingerprint = fingerprint(&build_receipt_bytes)?;

    let controller_configuration_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("configuration/controller.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "controller configuration",
    )?;
    let controller_configuration: ControllerConfigurationWire =
        parse_canonical_pretty(&controller_configuration_bytes, "controller configuration")?;
    anyhow::ensure!(
        valid_controller_configuration(
            &controller_configuration,
            &build_receipt.campaign_id,
            &plan_fingerprint,
            &plan,
        ),
        "analysis rejected: controller configuration"
    );
    let controller_configuration_fingerprint = fingerprint(&controller_configuration_bytes)?;

    let monitor_configuration_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("configuration/monitor.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "monitor configuration",
    )?;
    let monitor_configuration: MonitorConfigurationWire =
        parse_canonical_pretty(&monitor_configuration_bytes, "monitor configuration")?;
    anyhow::ensure!(
        valid_monitor_configuration(
            &monitor_configuration,
            &build_receipt.campaign_id,
            &plan_fingerprint,
            &plan,
        ),
        "analysis rejected: monitor configuration"
    );
    let monitor_configuration_fingerprint = fingerprint(&monitor_configuration_bytes)?;

    let anchor_key_input = open_absolute_file(
        request.anchor_public_key,
        32,
        Some(campaign.identity),
        "anchor trust root",
    )?;
    anyhow::ensure!(
        anchor_key_input.snapshot.readonly,
        "analysis rejected: anchor trust root"
    );
    let anchor_key_bytes = read_opened_input(anchor_key_input, 32, "anchor trust root")?;
    let anchor_key: [u8; 32] = anchor_key_bytes
        .as_slice()
        .try_into()
        .context("analysis rejected: anchor trust root")?;
    let verifying_key =
        VerifyingKey::from_bytes(&anchor_key).context("analysis rejected: anchor trust root")?;
    let anchor_key_fingerprint = fingerprint(&anchor_key_bytes)?;

    let anchor_configuration_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("configuration/external-anchor-channel.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "anchor configuration",
    )?;
    let anchor_configuration: ExternalAnchorChannelWire =
        parse_canonical_pretty(&anchor_configuration_bytes, "anchor configuration")?;
    anyhow::ensure!(
        anchor_configuration.schema
            == "marty.performance/sd-jwt-issuance-external-anchor-channel/v1"
            && anchor_configuration.campaign_id == build_receipt.campaign_id
            && anchor_configuration.channel_id == "marty-sd-jwt-issuance-anchor-v1"
            && anchor_configuration.channel_kind == "signed_create_only_log_v1"
            && anchor_configuration.endpoint_role == "preconfigured_primary_anchor_connector"
            && anchor_configuration.log_id == "sd-jwt-issuance-qualification-v1"
            && anchor_configuration.connector_authentication_policy
                == "out_of_band_trust_root_authenticated_transport_v1"
            && anchor_configuration.receipt_verification_scheme
                == "ed25519_rfc8032_canonical_json_v1"
            && anchor_configuration.signing_key_id == "marty-sd-jwt-issuance-anchor-ed25519-v1"
            && anchor_configuration.trust_root_fingerprint == anchor_key_fingerprint
            && anchor_configuration.clock_policy
                == "signed_nonrollback_monotonic_session_si_nanoseconds_v1"
            && anchor_configuration.maximum_receipt_bytes == MAX_EXTERNAL_ANCHOR_V1_BYTES,
        "analysis rejected: anchor configuration"
    );
    let anchor_configuration_fingerprint = fingerprint(&anchor_configuration_bytes)?;

    let expected_anchor_entries = [
        OsString::from("completion-anchor.json"),
        OsString::from("terminal-observation-evidence.json"),
        OsString::from("terminal-observation-receipt.json"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    campaign.validate_exact_directory_entries(
        Path::new("anchors"),
        &expected_anchor_entries,
        "anchor inventory",
    )?;

    let terminal_receipt_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("anchors/terminal-observation-receipt.json"),
        MAX_EXTERNAL_ANCHOR_V1_BYTES,
        "terminal receipt",
    )?;
    anyhow::ensure!(
        valid_terminal_receipt_bytes(&terminal_receipt_bytes, &verifying_key),
        "analysis rejected: terminal receipt"
    );
    let terminal_receipt: TerminalObservationReceiptWire =
        serde_json::from_slice(&terminal_receipt_bytes)
            .context("analysis rejected: terminal receipt")?;
    let terminal_receipt_fingerprint = fingerprint(&terminal_receipt_bytes)?;

    let terminal_evidence_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("anchors/terminal-observation-evidence.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "terminal observation evidence",
    )?;
    let terminal_evidence: TerminalObservationEvidenceWire =
        parse_canonical_pretty(&terminal_evidence_bytes, "terminal observation evidence")?;
    let terminal_evidence_fingerprint = fingerprint(&terminal_evidence_bytes)?;

    let completion_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("completion.json"),
        32 * 1024 * 1024,
        "completion",
    )?;
    let completion: CompletionWire = parse_canonical_pretty(&completion_bytes, "completion")?;
    anyhow::ensure!(
        validate_completion(
            &completion,
            &build_receipt.campaign_id,
            &schedule,
            &plan_fingerprint,
            &manifest_fingerprint,
            &anchor_configuration_fingerprint,
            plan.global_rounds
                .run_validity
                .limits
                .maximum_campaign_seconds,
        ),
        "analysis rejected: completion"
    );
    let completion_fingerprint = fingerprint(&completion_bytes)?;
    let genesis_segment = inspect_campaign_segment(
        &mut read_budget,
        &campaign,
        Path::new("segments/segment-0000.ndjson"),
        "genesis segment",
    )?;
    let genesis: GenesisHeaderWire =
        parse_canonical_compact_line(&genesis_segment.first_line, "genesis header")?;
    let genesis_fingerprint = fingerprint(&genesis_segment.first_line)?;
    anyhow::ensure!(
        completion.ordered_segment_fingerprints.first() == Some(&genesis_segment.fingerprint)
            && completion.genesis_header_fingerprint == genesis_fingerprint
            && completion.first_quiet_window_evidence_fingerprint
                == genesis.first_quiet_window_evidence_fingerprint
            && completion
                .ordered_test_window_attestation_fingerprints
                .first()
                == Some(&genesis.initial_test_window_attestation_fingerprint)
            && validate_genesis(
                &genesis,
                &GenesisValidation {
                    campaign_id: &build_receipt.campaign_id,
                    plan: &plan_fingerprint,
                    manifest: &manifest_fingerprint,
                    fixed_binary: &fixed_binary_fingerprint,
                    build_receipt: &build_receipt_fingerprint,
                    monitor_binary: &monitor_fingerprint,
                    controller_binary: &controller_fingerprint,
                    controller_configuration: &controller_configuration_fingerprint,
                    monitor_configuration: &monitor_configuration_fingerprint,
                    anchor_configuration: &anchor_configuration_fingerprint,
                    source_archive: &source_archive_fingerprint,
                    cargo_lock: &cargo_lock_fingerprint,
                    hardware_profile: &hardware_fingerprint,
                    source: &validated_source,
                    build: &build_receipt,
                    first_monotonic_nanoseconds: completion.first_monotonic_nanoseconds,
                },
            ),
        "analysis rejected: genesis binding"
    );
    let terminal_segment = if completion.segment_count == 1 {
        genesis_segment
    } else {
        let terminal_segment_relative = format!(
            "segments/segment-{:04}.ndjson",
            completion.segment_count - 1
        );
        inspect_campaign_segment(
            &mut read_budget,
            &campaign,
            Path::new(&terminal_segment_relative),
            "terminal segment",
        )?
    };
    let terminal_footer: SegmentFooterWire =
        parse_canonical_compact_line(&terminal_segment.last_line, "terminal footer")?;
    let terminal_segment_fingerprint = terminal_segment.fingerprint.clone();
    let route_position = schedule
        .iter()
        .position(|process| process.coordinate == coordinate)
        .context("analysis rejected: route coordinate")?;
    anyhow::ensure!(
        completion.terminal_segment_fingerprint == terminal_segment_fingerprint
            && validate_terminal_footer(
                &terminal_footer,
                &terminal_segment,
                &build_receipt.campaign_id,
                completion.segment_count - 1,
                completion.last_monotonic_nanoseconds,
                plan.global_rounds
                    .run_validity
                    .limits
                    .maximum_segment_seconds,
            )
            && completion.terminal_observation_evidence_fingerprint
                == terminal_evidence_fingerprint
            && completion.process_completions[route_position].full_benchmark_id
                == route_expectation.full_benchmark_id
            && completion.process_completions[route_position].route_artifact_fingerprint
                == route_fingerprint,
        "analysis rejected: completion binding"
    );

    let completion_anchor_bytes = read_campaign_input(
        &mut read_budget,
        &campaign,
        Path::new("anchors/completion-anchor.json"),
        MAX_EXTERNAL_ANCHOR_V1_BYTES,
        "completion anchor",
    )?;
    anyhow::ensure!(
        valid_completion_anchor_bytes(&completion_anchor_bytes, &verifying_key),
        "analysis rejected: completion anchor"
    );
    let completion_anchor: CompletionAnchorWire = serde_json::from_slice(&completion_anchor_bytes)
        .context("analysis rejected: completion anchor")?;
    let completion_anchor_fingerprint = fingerprint(&completion_anchor_bytes)?;
    let controller_delay = terminal_evidence
        .controller_receipt_observed_monotonic_nanoseconds
        .checked_sub(terminal_receipt.terminal_footer_monotonic_nanoseconds)
        .context("analysis rejected: anchor chronology")?;
    let channel_delay = completion_anchor
        .channel_monotonic_nanoseconds
        .checked_sub(terminal_receipt.channel_monotonic_nanoseconds)
        .context("analysis rejected: anchor chronology")?;
    let publication_delay = controller_delay
        .checked_add(channel_delay)
        .context("analysis rejected: anchor chronology")?;
    let maximum_publication_delay = u64::from(
        plan.global_rounds
            .run_validity
            .limits
            .maximum_anchor_publication_delay_seconds,
    )
    .checked_mul(1_000_000_000)
    .context("analysis rejected: anchor chronology")?;
    anyhow::ensure!(
        terminal_receipt.campaign_id == build_receipt.campaign_id
            && completion_anchor.campaign_id == build_receipt.campaign_id
            && terminal_evidence.schema
                == "marty.performance/sd-jwt-issuance-terminal-observation-evidence/v1"
            && terminal_evidence.campaign_id == build_receipt.campaign_id
            && terminal_evidence.terminal_observation_receipt_fingerprint
                == terminal_receipt_fingerprint
            && terminal_receipt.terminal_segment_fingerprint == terminal_segment_fingerprint
            && terminal_receipt.terminal_footer_monotonic_nanoseconds
                == terminal_footer.monotonic_nanoseconds
            && completion_anchor.terminal_segment_fingerprint == terminal_segment_fingerprint
            && completion_anchor.terminal_observation_evidence_fingerprint
                == terminal_evidence_fingerprint
            && completion_anchor.completion_fingerprint == completion_fingerprint
            && terminal_receipt.channel_clock_session_id
                == completion_anchor.channel_clock_session_id
            && terminal_receipt.challenge_uppercase_hex_256
                != completion_anchor.challenge_uppercase_hex_256
            && terminal_receipt.controller_request_monotonic_nanoseconds
                >= terminal_receipt.terminal_footer_monotonic_nanoseconds
            && terminal_evidence.controller_receipt_observed_monotonic_nanoseconds
                >= terminal_receipt.controller_request_monotonic_nanoseconds
            && completion.created_at_monotonic_nanoseconds
                >= terminal_evidence.controller_receipt_observed_monotonic_nanoseconds
            && publication_delay <= maximum_publication_delay,
        "analysis rejected: anchor binding"
    );

    match scope {
        AnalysisScope::SelectedRoute => {
            let report = IssuanceAnalysisReport {
                schema: "marty.performance/sd-jwt-issuance-analysis/v1",
                analysis_scope: "offline_artifact_integrity_subset_v1",
                campaign_id: build_receipt.campaign_id,
                manifest: manifest_fingerprint,
                plan: plan_fingerprint,
                selected_route_benchmark_id: route_expectation.full_benchmark_id.to_owned(),
                selected_route_artifact: route_fingerprint,
                source_archive: source_archive_fingerprint,
                cargo_lock: cargo_lock_fingerprint,
                hardware_profile: hardware_fingerprint,
                build_receipt: build_receipt_fingerprint,
                build_input_inventory: inventory_fingerprint,
                build_input_archive: build_archive_fingerprint,
                fixed_binary: fixed_binary_fingerprint,
                terminal_observation_receipt: terminal_receipt_fingerprint,
                terminal_observation_evidence: terminal_evidence_fingerprint,
                completion: completion_fingerprint,
                completion_anchor: completion_anchor_fingerprint,
                checks: vec![
                    "v3_plan_and_manifest_binding",
                    "selected_route_identity_and_invariants",
                    "source_archive_git_tree_commit_and_cargo_lock",
                    "build_input_inventory_and_streamed_archive",
                    "anchored_genesis_build_receipt_and_binary_binding",
                    "terminal_segment_structural_envelope_and_footer_summary_binding",
                    "inspected_genesis_and_terminal_segment_lifecycle_payload_shape_and_canonicality",
                    "offline_ed25519_anchor_signatures_and_chronology",
                ],
                artifact_integrity_status: "valid",
                campaign_qualification_status: "not_evaluated",
                production_threshold_activation: false,
                limitations: vec![
                    "one_selected_route_artifact_only",
                    "intermediate_segment_chain_and_lifecycle_payload_semantics_not_analyzed",
                    "first_quiet_window_evidence_content_and_build_order_not_analyzed",
                    "retained_build_tree_offline_probe_not_reexecuted",
                    "operator_selected_anchor_key_trust_provenance_not_established",
                    "cross_file_consistency_requires_quiescent_or_snapshotted_campaign",
                    "output_parent_ancestry_requires_quiescent_namespace",
                    "failed_post_publication_verification_may_leave_a_nonactivating_create_new_report",
                    "report_publication_crash_durability_depends_on_operating_system_and_filesystem",
                    "no_performance_or_threshold_claim",
                ],
            };
            write_analysis_report(request.output, Some(campaign.identity), &report)?;
            println!(
                "Validated the bounded offline artifact-integrity slice; campaign qualification remains not evaluated."
            );
        }
        AnalysisScope::IndexedTimingArtifacts => {
            let timing = evidence_validation::validate_indexed_timing_artifacts(
                &campaign,
                &manifest,
                &plan,
                &completion,
                &hardware,
                &mut read_budget,
            )?;
            let timing_estimate_count = u32::try_from(timing.medians_nanoseconds.len())
                .context("analysis rejected: timing estimate count")?;
            let cell_effects =
                statistics::analyze_cells(&timing.medians_nanoseconds, &manifest, &plan)
                    .context("analysis rejected: indexed statistics")?;
            anyhow::ensure!(
                timing_estimate_count == schedule::TOTAL_PROCESS_COUNT
                    && timing.criterion_artifact_count == schedule::TOTAL_PROCESS_COUNT
                    && timing.route_artifact_count == schedule::TOTAL_PROCESS_COUNT
                    && cell_effects.len() == schedule::PAIRED_CELL_COUNT,
                "analysis rejected: indexed result cardinality"
            );
            let report = SdJwtIssuanceIndexedAnalysisReport {
                schema: "marty.performance/sd-jwt-issuance-indexed-analysis/v1".to_owned(),
                analysis_scope:
                    "all_indexed_route_and_criterion_estimate_artifacts_v1".to_owned(),
                campaign_id: build_receipt.campaign_id,
                manifest: manifest_fingerprint,
                plan: plan_fingerprint,
                target_triple: build_receipt.target_triple,
                hardware_profile: hardware_fingerprint,
                source_archive: source_archive_fingerprint,
                cargo_lock: cargo_lock_fingerprint,
                build_receipt: build_receipt_fingerprint,
                build_input_inventory: inventory_fingerprint,
                build_input_archive: build_archive_fingerprint,
                fixed_binary: fixed_binary_fingerprint,
                terminal_observation_receipt: terminal_receipt_fingerprint,
                terminal_observation_evidence: terminal_evidence_fingerprint,
                completion: completion_fingerprint,
                completion_anchor: completion_anchor_fingerprint,
                criterion_artifact_index: timing.criterion_index_fingerprint,
                criterion_artifact_count: timing.criterion_artifact_count,
                criterion_artifact_bytes: timing.criterion_artifact_bytes,
                route_artifact_index: timing.route_index_fingerprint,
                route_artifact_count: timing.route_artifact_count,
                route_artifact_bytes: timing.route_artifact_bytes,
                timing_estimate_count,
                primary_statistic:
                    "criterion_0_5_1_median_point_estimate_nanoseconds".to_owned(),
                effect_math_implementation: statistics::EFFECT_MATH_IMPLEMENTATION.to_owned(),
                bootstrap_replicates: plan.bootstrap.replicates,
                bootstrap_seed: plan.bootstrap.seed,
                bootstrap_confidence_level: plan.bootstrap.confidence_level,
                cell_effects,
                individual_operation_latency_p50: SdJwtIssuanceAnalysisStatus::NotEvaluated,
                individual_operation_latency_p95: SdJwtIssuanceAnalysisStatus::NotEvaluated,
                individual_operation_latency_p99: SdJwtIssuanceAnalysisStatus::NotEvaluated,
                throughput: SdJwtIssuanceAnalysisStatus::NotEvaluated,
                allocation_evidence: SdJwtIssuanceAnalysisStatus::NotMeasured,
                simd_lane_utilization: SdJwtIssuanceAnalysisStatus::NotMeasured,
                artifact_integrity_status: "valid".to_owned(),
                campaign_qualification_status: "not_evaluated".to_owned(),
                production_threshold_activation: false,
                production_activation_separate: true,
                qualified_issuance_thresholds: None,
                limitations: vec![
                    "criterion_medians_are_estimator_outputs_not_individual_operation_percentiles"
                        .to_owned(),
                    "intermediate_segment_chain_and_lifecycle_payload_semantics_not_analyzed"
                        .to_owned(),
                    "first_quiet_window_evidence_content_and_build_order_not_analyzed".to_owned(),
                    "retained_build_tree_offline_probe_not_reexecuted".to_owned(),
                    "complete_criterion_artifact_homes_not_traversed".to_owned(),
                    "tail_latency_and_throughput_not_evaluated_allocation_and_lane_utilization_not_measured"
                        .to_owned(),
                    "operator_selected_anchor_key_trust_provenance_not_established".to_owned(),
                    "cross_file_consistency_requires_quiescent_or_snapshotted_campaign".to_owned(),
                    "output_parent_ancestry_requires_quiescent_namespace".to_owned(),
                    "failed_post_publication_verification_may_leave_a_nonactivating_create_new_report"
                        .to_owned(),
                    "report_publication_crash_durability_depends_on_operating_system_and_filesystem"
                        .to_owned(),
                    "target_campaigns_threshold_discovery_and_activation_remain_separate"
                        .to_owned(),
                ],
            };
            write_analysis_report(request.output, Some(campaign.identity), &report)?;
            println!(
                "Analyzed all indexed Criterion median estimates and route artifacts; campaign qualification and production activation remain not evaluated."
            );
        }
        AnalysisScope::Lifecycle => {
            let lifecycle = lifecycle_validation::validate_campaign_lifecycle(
                &campaign,
                &mut read_budget,
                &schedule,
                &completion,
                &genesis,
                &hardware,
                &plan,
                &terminal_receipt,
                &completion_anchor,
            )?;
            let report = SdJwtIssuanceLifecycleAnalysisReport {
                schema: "marty.performance/sd-jwt-issuance-lifecycle-analysis/v1".to_owned(),
                analysis_scope: "complete_segment_chain_and_embedded_lifecycle_semantics_v1"
                    .to_owned(),
                campaign_id: build_receipt.campaign_id,
                manifest: manifest_fingerprint,
                plan: plan_fingerprint,
                selected_route_benchmark_id: route_expectation.full_benchmark_id.to_owned(),
                selected_route_artifact: route_fingerprint,
                target_triple: build_receipt.target_triple,
                hardware_profile: hardware_fingerprint,
                host_identity: lifecycle.host_identity_fingerprint,
                controller_binary: controller_fingerprint,
                monitor_binary: monitor_fingerprint,
                controller_configuration: controller_configuration_fingerprint,
                monitor_configuration: monitor_configuration_fingerprint,
                external_anchor_channel_configuration: anchor_configuration_fingerprint,
                source_archive: source_archive_fingerprint,
                cargo_lock: cargo_lock_fingerprint,
                build_receipt: build_receipt_fingerprint,
                build_input_inventory: inventory_fingerprint,
                build_input_archive: build_archive_fingerprint,
                fixed_binary: fixed_binary_fingerprint,
                terminal_observation_receipt: terminal_receipt_fingerprint,
                terminal_observation_evidence: terminal_evidence_fingerprint,
                completion: completion_fingerprint,
                completion_anchor: completion_anchor_fingerprint,
                ordered_segment_fingerprints: lifecycle.ordered_segment_fingerprints,
                ordered_test_window_attestation_fingerprints: lifecycle
                    .ordered_test_window_attestation_fingerprints,
                validity_thresholds: lifecycle.validity_thresholds_fingerprint,
                baseline_unrelated_process_set: lifecycle
                    .baseline_unrelated_process_set_fingerprint,
                segment_count: lifecycle.segment_count,
                segment_bytes: lifecycle.segment_bytes,
                record_count: lifecycle.record_count,
                sample_count: lifecycle.sample_count,
                lifecycle_event_count: lifecycle.lifecycle_event_count,
                process_intent_count: lifecycle.process_intent_count,
                process_start_count: lifecycle.process_start_count,
                process_finish_count: lifecycle.process_finish_count,
                attestation_transition_count: lifecycle.attestation_transition_count,
                first_monotonic_nanoseconds: lifecycle.first_monotonic_nanoseconds,
                last_monotonic_nanoseconds: lifecycle.last_monotonic_nanoseconds,
                artifact_integrity_status: "valid".to_owned(),
                embedded_lifecycle_semantics_status: "valid".to_owned(),
                campaign_qualification_status: "not_evaluated".to_owned(),
                production_threshold_activation: false,
                production_activation_separate: true,
                qualified_issuance_thresholds: None,
                limitations: vec![
                    "nonselected_route_artifact_contents_not_traversed".to_owned(),
                    "criterion_estimate_artifact_contents_not_traversed".to_owned(),
                    "criterion_and_route_artifact_indexes_not_traversed".to_owned(),
                    "invocation_launch_barrier_and_criterion_inventory_preimage_contents_not_traversed"
                        .to_owned(),
                    "complete_criterion_artifact_homes_not_traversed".to_owned(),
                    "first_quiet_window_attestation_content_not_traversed".to_owned(),
                    "first_quiet_window_evidence_content_and_build_order_not_analyzed".to_owned(),
                    "retained_build_tree_offline_probe_not_reexecuted".to_owned(),
                    "nonterminal_close_reason_counterfactual_precedence_not_reconstructed"
                        .to_owned(),
                    "operator_authorization_raw_target_mapping_and_shutdown_recheck_not_independently_reauthenticated"
                        .to_owned(),
                    "cross_role_nonce_and_pseudonym_uniqueness_not_fully_reconstructed"
                        .to_owned(),
                    "operator_selected_anchor_key_trust_provenance_not_established".to_owned(),
                    "cross_file_consistency_requires_quiescent_or_snapshotted_campaign"
                        .to_owned(),
                    "output_parent_ancestry_requires_quiescent_namespace".to_owned(),
                    "failed_post_publication_verification_may_leave_a_nonactivating_create_new_report"
                        .to_owned(),
                    "report_publication_crash_durability_depends_on_operating_system_and_filesystem"
                        .to_owned(),
                    "no_performance_threshold_or_activation_claim".to_owned(),
                ],
            };
            write_analysis_report(request.output, Some(campaign.identity), &report)?;
            println!(
                "Validated the complete segment chain and embedded lifecycle semantics; campaign qualification and production activation remain not evaluated."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
