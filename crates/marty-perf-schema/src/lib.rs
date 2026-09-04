//! Versioned, serializable evidence contracts used by the performance runner.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Authoritative pre-parse cap for a V3 issuance qualification plan.
///
/// An analyzer must enforce this compiled constant before UTF-8 or JSON parsing;
/// a limit learned from the plan itself is not a safe allocation boundary.
pub const MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES: u64 = 1_048_576;

/// Public Marty release manifest consumed by the runner.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StackManifest {
    /// Must be `marty.stack/v1`.
    pub schema: String,
    /// Marty UI aggregate release identifier.
    pub release: String,
    /// Optional generation timestamp supplied by the release pipeline.
    #[serde(default)]
    pub generated_at: Option<String>,
    /// Immutable components in the release.
    pub components: Vec<StackComponent>,
}

/// One component represented in a stack manifest.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StackComponent {
    /// Stable component name.
    pub name: String,
    /// GitHub repository in owner/name form.
    pub repository: String,
    /// Published component version.
    pub version: String,
    /// Full source commit.
    pub commit: String,
    /// Immutable published artifacts.
    pub artifacts: Vec<StackArtifact>,
}

/// One published component artifact.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StackArtifact {
    /// Artifact kind such as `oci`, `crate`, or `release`.
    #[serde(rename = "type")]
    pub artifact_type: String,
    /// Artifact location. OCI locations contain no tag or digest.
    pub uri: String,
    /// SHA-256 content or OCI digest.
    pub digest: String,
    /// Optional SBOM evidence URL.
    #[serde(default)]
    pub sbom: Option<String>,
    /// Optional provenance evidence URL.
    #[serde(default)]
    pub provenance: Option<String>,
}

/// Validated stack input retained beside performance results.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreparedStack {
    /// Evidence schema identifier.
    pub schema: String,
    /// Time at which the input was prepared.
    pub prepared_at: String,
    /// User-provided source manifest path.
    pub source_manifest: String,
    /// Digest of the complete source manifest bytes.
    pub source_manifest_sha256: String,
    /// Marty aggregate release identifier.
    pub release: String,
    /// Digest-qualified images keyed by Compose environment variable.
    pub images: BTreeMap<String, String>,
    /// All source components retained for provenance.
    pub components: Vec<StackComponent>,
}

/// Hardware and tool evidence collected before a run.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DoctorReport {
    /// Evidence schema identifier.
    pub schema: String,
    /// Collection time.
    pub collected_at: String,
    /// Whether required execution capabilities are present.
    pub valid: bool,
    /// Whether the observed machine is currently quiet enough for comparison.
    pub comparable: bool,
    /// Host hardware and operating system evidence.
    pub host: HostEvidence,
    /// Docker client and server evidence.
    pub docker: DockerEvidence,
    /// Selected k6 execution mechanism.
    pub k6: K6Evidence,
    /// Conditions that may invalidate comparative results.
    pub warnings: Vec<String>,
}

/// Host facts that materially affect performance measurements.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostEvidence {
    /// Operating system name.
    pub operating_system: String,
    /// Host compilation architecture.
    pub architecture: String,
    /// Operating system version when available.
    pub operating_system_version: Option<String>,
    /// Kernel version when available.
    pub kernel_version: Option<String>,
    /// Processor brand reported by the OS.
    pub cpu_brand: String,
    /// Logical processor count visible to the runner.
    pub logical_cpus: usize,
    /// Physical processor core count when available.
    pub physical_cores: Option<usize>,
    /// Total host memory in bytes.
    pub total_memory_bytes: u64,
}

/// Docker facts used to establish the actual execution envelope.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DockerEvidence {
    /// Whether a Docker server is reachable.
    pub available: bool,
    /// Docker client version.
    pub client_version: Option<String>,
    /// Docker server version.
    pub server_version: Option<String>,
    /// Server operating system.
    pub server_os: Option<String>,
    /// Server architecture.
    pub server_arch: Option<String>,
    /// Server kernel.
    pub server_kernel: Option<String>,
    /// CPUs visible to Docker.
    pub server_cpus: Option<usize>,
    /// Memory visible to Docker in bytes.
    pub server_memory_bytes: Option<u64>,
    /// Total number of running containers observed by doctor.
    pub running_containers: Option<usize>,
    /// Running containers accepted as part of the declared test environment.
    pub allowed_running_containers: Option<usize>,
    /// Running containers outside the declared test environment.
    pub unrelated_running_containers: Option<usize>,
    /// Prefixes used to classify intended test containers.
    #[serde(default)]
    pub allowed_container_prefixes: Vec<String>,
    /// Diagnostic detail when Docker could not be queried.
    pub error: Option<String>,
}

/// k6 execution capability evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct K6Evidence {
    /// `local` or `container`.
    pub mode: String,
    /// Repository-approved k6 version.
    pub configured_version: String,
    /// Version output for local k6, if installed.
    pub local_version: Option<String>,
    /// Whether local k6 exactly matches the repository-approved version.
    pub local_compatible: bool,
    /// Digest-pinned fallback image.
    pub container_image: String,
}

/// Metadata retained beside each load-generator result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RunMetadata {
    /// Evidence schema identifier.
    pub schema: String,
    /// Unique run identifier.
    pub run_id: String,
    /// Result classification such as `migration-preview`.
    pub result_class: String,
    /// Scenario name.
    pub scenario: String,
    /// Start time.
    pub started_at: String,
    /// Sanitized target origin.
    pub base_url: String,
    /// k6 execution mode.
    pub k6_mode: String,
    /// Exact tool image when container execution is used.
    pub k6_image: Option<String>,
    /// Final process exit code.
    pub exit_code: Option<i32>,
    /// Whether correctness and runner thresholds passed.
    pub successful: bool,
    /// Extra stable run dimensions.
    #[serde(default)]
    pub dimensions: BTreeMap<String, String>,
}

/// A versioned k6 workload contract and its supported execution profiles.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkloadContract {
    /// Must be `marty.performance/workload/v1`.
    pub schema: String,
    /// Stable low-cardinality workload name.
    pub name: String,
    /// Revision changed whenever workload behavior changes.
    pub revision: String,
    /// JavaScript entry point relative to the contract file.
    pub script: String,
    /// Fixture schema accepted by the workload.
    pub fixture_schema: String,
    /// Stable operations emitted by the workload.
    pub operations: Vec<OperationContract>,
    /// Named execution profiles.
    pub profiles: BTreeMap<String, ExecutionProfile>,
}

/// A stable HTTP operation represented in workload evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationContract {
    /// Low-cardinality operation tag.
    pub name: String,
    /// HTTP method.
    pub method: String,
    /// Route template without concrete resource identifiers.
    pub route: String,
}

/// One k6 scenario executor configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionProfile {
    /// Supported k6 executor name.
    pub executor: String,
    /// Fixed virtual users for per-VU iteration profiles.
    #[serde(default)]
    pub vus: Option<u32>,
    /// Iterations performed by each virtual user.
    #[serde(default)]
    pub iterations: Option<u64>,
    /// Initial arrival rate for ramping profiles.
    #[serde(default)]
    pub start_rate: Option<u64>,
    /// Fixed arrival rate for constant profiles.
    #[serde(default)]
    pub rate: Option<u64>,
    /// Unit used by an arrival-rate executor.
    #[serde(default)]
    pub time_unit: Option<String>,
    /// Execution duration for fixed profiles.
    #[serde(default)]
    pub duration: Option<String>,
    /// Initial VU pool for arrival-rate profiles.
    #[serde(default)]
    pub pre_allocated_vus: Option<u32>,
    /// Maximum VU pool for arrival-rate profiles.
    #[serde(default)]
    pub max_vus: Option<u32>,
    /// Ramping arrival-rate stages.
    #[serde(default)]
    pub stages: Vec<ExecutionStage>,
    /// Maximum time allowed for iterations to finish.
    #[serde(default)]
    pub graceful_stop: Option<String>,
}

/// One target and duration in a ramping execution profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionStage {
    /// Stage duration in k6 duration syntax.
    pub duration: String,
    /// Target iterations per configured time unit.
    pub target: u64,
}

/// Deterministic synthetic inputs used to seed the management lifecycle.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LifecycleFixture {
    /// Must be `marty.performance/lifecycle-fixture/v1`.
    pub schema: String,
    /// Caller-selected deterministic seed.
    pub seed: String,
    /// Stable suffix derived from the seed.
    pub suffix: String,
    /// Synthetic organization name.
    pub organization_name: String,
    /// Synthetic organization display name.
    pub organization_display_name: String,
    /// Synthetic trust-profile name.
    pub trust_profile_name: String,
    /// Synthetic credential-template name.
    pub credential_template_name: String,
    /// Synthetic presentation-policy name.
    pub presentation_policy_name: String,
    /// Synthetic deployment-profile name.
    pub deployment_profile_name: String,
    /// Synthetic deployment site identifier.
    pub site_id: String,
}

/// Human-provided proof that a safe performance test window is active.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestWindowAttestation {
    /// Must be `marty.performance/test-window/v1`.
    pub schema: String,
    /// Normalized gateway origin authorized for the test.
    pub target_origin: String,
    /// RFC 3339 start of the authorized test window.
    pub starts_at: String,
    /// RFC 3339 end of the authorized test window.
    pub expires_at: String,
    /// Non-secret change or incident reference.
    pub change_reference: String,
    /// Production traffic has been drained from the stack hardware.
    pub production_traffic_drained: bool,
    /// Public ingress is disabled while synthetic testing is active.
    pub public_ingress_disabled: bool,
    /// Only synthetic data and identities will be used.
    pub synthetic_data_only: bool,
}

/// SHA-256 and byte-length binding for one immutable qualification artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFingerprint {
    /// Uppercase hexadecimal SHA-256 without a prefix.
    pub sha256: String,
    /// Exact number of bytes hashed.
    pub byte_length: u64,
}

/// Canonical issuance matrix exported by the benchmarked SD-JWT crate.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceQualificationManifest {
    /// Must be `sd_jwt_issuance_qualification_manifest_v1`.
    pub schema: String,
    /// Criterion benchmark group containing every full benchmark ID.
    pub benchmark_group_id: String,
    /// Number of deterministic fixture cases.
    pub fixture_case_count: usize,
    /// Number of full Criterion benchmark IDs.
    pub benchmark_id_count: usize,
    /// Number of serial/adaptive stage pairs.
    pub paired_cell_count: usize,
    /// Ordered deterministic fixture cases.
    pub cases: Vec<SdJwtIssuanceQualificationCase>,
    /// Ordered full Criterion IDs in registration order.
    pub criterion_ids: Vec<String>,
    /// Ordered serial/adaptive cells used by the paired campaign.
    pub paired_cells: Vec<SdJwtIssuanceQualificationCell>,
    /// Route-evidence schema emitted by the benchmark binary.
    pub route_schema: String,
    /// Work-estimator version bound into route evidence.
    pub work_estimator_version: String,
    /// Static-partition version bound into route evidence.
    pub static_partition_rule_version: String,
    /// Maximum native worker count used by the benchmark selector.
    pub worker_cap: usize,
    /// Mechanical benchmark-only selector thresholds.
    pub mechanical_benchmark_thresholds: SdJwtIssuanceThresholds,
    /// Evidence-qualified production thresholds, absent before activation.
    pub qualified_issuance_thresholds: Option<SdJwtIssuanceThresholds>,
}

/// One deterministic SD-JWT issuance fixture in manifest order.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceQualificationCase {
    /// Stable non-personal fixture identifier.
    pub fixture_id: String,
    /// Number of real disclosures planned by the fixture.
    pub disclosure_count: usize,
}

/// One stage-specific serial/adaptive benchmark pair.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceQualificationCell {
    /// Stable fixture identifier shared by both routes.
    pub fixture_id: String,
    /// `executor_assembly` or `full_issuance`.
    pub stage: String,
    /// Full Criterion ID for the serial oracle.
    pub serial_id: String,
    /// Full Criterion ID for the adaptive candidate.
    pub adaptive_id: String,
}

/// Count and estimated-work cutoffs used by an issuance selector.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceThresholds {
    /// Minimum jobs required before considering parallel work.
    pub min_jobs: usize,
    /// Minimum estimated work in bytes.
    pub min_estimated_work_bytes: usize,
}

/// Status for a metric that this analysis intentionally does not claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SdJwtIssuanceAnalysisStatus {
    /// The retained evidence is not sufficient to evaluate this metric.
    NotEvaluated,
    /// This campaign protocol did not measure this metric.
    NotMeasured,
}

/// One observed paired log effect and its predeclared confidence interval.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceEffectInterval {
    /// `simultaneous_common_max_deviation_95_percent` or
    /// `marginal_type_7_95_percent`.
    pub interval_method: String,
    /// Mean observed log ratio across the twenty bound global rounds.
    pub point_estimate_log_ratio: f64,
    /// Lower confidence endpoint in log-ratio units.
    pub lower_log_ratio: f64,
    /// Upper confidence endpoint in log-ratio units.
    pub upper_log_ratio: f64,
    /// Monotonic `100 * (exp(effect) - 1)` transform of the point estimate.
    pub point_estimate_relative_percent: f64,
    /// Monotonic relative-percent transform of the lower endpoint.
    pub lower_relative_percent: f64,
    /// Monotonic relative-percent transform of the upper endpoint.
    pub upper_relative_percent: f64,
}

/// Ordered paired-effect result for one manifest cell.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceCellEffects {
    /// Zero-based position in the manifest's paired-cell array.
    pub cell_ordinal: u32,
    /// Stable synthetic fixture identifier.
    pub fixture_id: String,
    /// `executor_assembly` or `full_issuance`.
    pub stage: String,
    /// Full Criterion ID of the serial oracle.
    pub serial_benchmark_id: String,
    /// Full Criterion ID of the adaptive candidate.
    pub adaptive_benchmark_id: String,
    /// Combined route effect, adaptive over serial.
    pub d: SdJwtIssuanceEffectInterval,
    /// Serial-first paired effect, adaptive over serial.
    pub s: SdJwtIssuanceEffectInterval,
    /// Adaptive-first paired effect, adaptive over serial.
    pub p: SdJwtIssuanceEffectInterval,
    /// Disclosed order diagnostic, `S - P`.
    pub o: SdJwtIssuanceEffectInterval,
}

/// Nonactivating analysis of every indexed SD-JWT issuance timing estimate.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceIndexedAnalysisReport {
    /// Must be `marty.performance/sd-jwt-issuance-indexed-analysis/v1`.
    pub schema: String,
    /// Must be `all_indexed_route_and_criterion_estimate_artifacts_v1`.
    pub analysis_scope: String,
    /// Bound campaign UUID.
    pub campaign_id: String,
    /// Exact canonical qualification manifest.
    pub manifest: ArtifactFingerprint,
    /// Exact canonical V3 qualification plan.
    pub plan: ArtifactFingerprint,
    /// Fixed-build target; results from different targets are never pooled.
    pub target_triple: String,
    /// Exact retained hardware profile.
    pub hardware_profile: ArtifactFingerprint,
    /// Exact approved source archive used for the fixed build.
    pub source_archive: ArtifactFingerprint,
    /// Exact Cargo lockfile used for the fixed build.
    pub cargo_lock: ArtifactFingerprint,
    /// Exact fixed-build receipt.
    pub build_receipt: ArtifactFingerprint,
    /// Exact fixed-build input inventory.
    pub build_input_inventory: ArtifactFingerprint,
    /// Exact fixed-build input archive.
    pub build_input_archive: ArtifactFingerprint,
    /// Installed fixed benchmark binary.
    pub fixed_binary: ArtifactFingerprint,
    /// Exact signed terminal-observation receipt.
    pub terminal_observation_receipt: ArtifactFingerprint,
    /// Exact controller-observed terminal evidence wrapper.
    pub terminal_observation_evidence: ArtifactFingerprint,
    /// Exact campaign completion manifest that binds the artifact indexes.
    pub completion: ArtifactFingerprint,
    /// Exact signed completion anchor that authenticates the completion manifest.
    pub completion_anchor: ArtifactFingerprint,
    /// Canonical Criterion artifact index.
    pub criterion_artifact_index: ArtifactFingerprint,
    /// Exact number of indexed Criterion estimate artifacts.
    pub criterion_artifact_count: u32,
    /// Checked sum of the indexed Criterion estimate artifact byte lengths.
    pub criterion_artifact_bytes: u64,
    /// Canonical route artifact index.
    pub route_artifact_index: ArtifactFingerprint,
    /// Exact number of indexed route artifacts.
    pub route_artifact_count: u32,
    /// Checked sum of the indexed route artifact byte lengths.
    pub route_artifact_bytes: u64,
    /// Exact number of ordered Criterion median estimates analyzed.
    pub timing_estimate_count: u32,
    /// Literal estimator selected from each Criterion 0.5.1 artifact.
    pub primary_statistic: String,
    /// Pinned software implementation used for logarithms and exponentials.
    pub effect_math_implementation: String,
    /// Plan-bound deterministic bootstrap replicate count.
    pub bootstrap_replicates: u32,
    /// Plan-bound initial `SplitMix64` state.
    pub bootstrap_seed: u64,
    /// Plan-bound family-wise confidence level.
    pub bootstrap_confidence_level: f64,
    /// Exactly 66 results in manifest paired-cell order.
    pub cell_effects: Vec<SdJwtIssuanceCellEffects>,
    /// Individual-operation p50 latency is not inferred from Criterion medians.
    pub individual_operation_latency_p50: SdJwtIssuanceAnalysisStatus,
    /// Individual-operation p95 latency is not inferred from Criterion medians.
    pub individual_operation_latency_p95: SdJwtIssuanceAnalysisStatus,
    /// Individual-operation p99 latency is not inferred from Criterion medians.
    pub individual_operation_latency_p99: SdJwtIssuanceAnalysisStatus,
    /// End-to-end throughput is outside this microbenchmark evidence.
    pub throughput: SdJwtIssuanceAnalysisStatus,
    /// Allocation evidence is outside this retained timing matrix.
    pub allocation_evidence: SdJwtIssuanceAnalysisStatus,
    /// SIMD or lane utilization is outside this retained timing matrix.
    pub simd_lane_utilization: SdJwtIssuanceAnalysisStatus,
    /// Integrity result for the bounded artifacts traversed by this command.
    pub artifact_integrity_status: String,
    /// Complete campaign qualification remains a separate phase.
    pub campaign_qualification_status: String,
    /// This report can never activate a production threshold.
    pub production_threshold_activation: bool,
    /// Activation requires a later, separately reviewed change.
    pub production_activation_separate: bool,
    /// Always absent from this nonactivating analysis schema.
    pub qualified_issuance_thresholds: Option<SdJwtIssuanceThresholds>,
    /// Truthful boundaries on what this analysis establishes.
    pub limitations: Vec<String>,
}

/// Nonactivating validation of every retained validity segment and lifecycle
/// record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceLifecycleAnalysisReport {
    /// Must be `marty.performance/sd-jwt-issuance-lifecycle-analysis/v1`.
    pub schema: String,
    /// Must be `complete_segment_chain_and_embedded_lifecycle_semantics_v1`.
    pub analysis_scope: String,
    /// Bound campaign UUID.
    pub campaign_id: String,
    /// Exact canonical qualification manifest.
    pub manifest: ArtifactFingerprint,
    /// Exact canonical V3 qualification plan.
    pub plan: ArtifactFingerprint,
    /// Full benchmark ID of the route witness used by the common analyzer pipeline.
    pub selected_route_benchmark_id: String,
    /// Exact selected route witness.
    pub selected_route_artifact: ArtifactFingerprint,
    /// Fixed-build target; results from different targets are never pooled.
    pub target_triple: String,
    /// Exact retained hardware profile used for observation bounds.
    pub hardware_profile: ArtifactFingerprint,
    /// Exact retained host-identity profile bound by genesis.
    pub host_identity: ArtifactFingerprint,
    /// Exact controller binary bound by genesis.
    pub controller_binary: ArtifactFingerprint,
    /// Exact monitor binary bound by genesis.
    pub monitor_binary: ArtifactFingerprint,
    /// Exact controller configuration bound by genesis.
    pub controller_configuration: ArtifactFingerprint,
    /// Exact monitor configuration bound by genesis.
    pub monitor_configuration: ArtifactFingerprint,
    /// Exact external-anchor channel configuration bound by genesis and completion.
    pub external_anchor_channel_configuration: ArtifactFingerprint,
    /// Exact approved source archive used for the fixed build.
    pub source_archive: ArtifactFingerprint,
    /// Exact Cargo lockfile used for the fixed build.
    pub cargo_lock: ArtifactFingerprint,
    /// Exact fixed-build receipt.
    pub build_receipt: ArtifactFingerprint,
    /// Exact fixed-build input inventory.
    pub build_input_inventory: ArtifactFingerprint,
    /// Exact fixed-build input archive.
    pub build_input_archive: ArtifactFingerprint,
    /// Installed fixed benchmark binary.
    pub fixed_binary: ArtifactFingerprint,
    /// Exact signed terminal-observation receipt.
    pub terminal_observation_receipt: ArtifactFingerprint,
    /// Exact controller-observed terminal evidence wrapper.
    pub terminal_observation_evidence: ArtifactFingerprint,
    /// Exact campaign completion manifest.
    pub completion: ArtifactFingerprint,
    /// Exact signed completion anchor.
    pub completion_anchor: ArtifactFingerprint,
    /// Complete ordered validity-segment chain validated by this report.
    pub ordered_segment_fingerprints: Vec<ArtifactFingerprint>,
    /// Complete ordered actual timing-window attestation chain.
    pub ordered_test_window_attestation_fingerprints: Vec<ArtifactFingerprint>,
    /// Exact validity-threshold preimage applied to every sample.
    pub validity_thresholds: ArtifactFingerprint,
    /// Exact baseline and sole content-addressed unrelated-process set required
    /// by every sample.
    pub baseline_unrelated_process_set: ArtifactFingerprint,
    /// Number of chained segments.
    pub segment_count: u32,
    /// Checked sum of exact segment byte lengths.
    pub segment_bytes: u64,
    /// Checked number of records including headers and footers.
    pub record_count: u64,
    /// Number of contiguous monitor samples.
    pub sample_count: u64,
    /// Number of process and attestation-transition event records.
    pub lifecycle_event_count: u64,
    /// Number of process-intent records.
    pub process_intent_count: u32,
    /// Number of process-start records.
    pub process_start_count: u32,
    /// Number of process-finish records.
    pub process_finish_count: u32,
    /// Number of actual timing-window attestation transitions.
    pub attestation_transition_count: u32,
    /// Genesis controller-monotonic timestamp.
    pub first_monotonic_nanoseconds: u64,
    /// Terminal-footer controller-monotonic timestamp.
    pub last_monotonic_nanoseconds: u64,
    /// Integrity result for every artifact traversed by this command.
    pub artifact_integrity_status: String,
    /// Result of the bounded segment and lifecycle state-machine replay.
    pub embedded_lifecycle_semantics_status: String,
    /// Complete campaign qualification remains a separate phase.
    pub campaign_qualification_status: String,
    /// This report can never activate a production threshold.
    pub production_threshold_activation: bool,
    /// Activation requires a later, separately reviewed change.
    pub production_activation_separate: bool,
    /// Always absent from this nonactivating analysis schema.
    pub qualified_issuance_thresholds: Option<SdJwtIssuanceThresholds>,
    /// Truthful boundaries on what this analysis establishes.
    pub limitations: Vec<String>,
}

/// Frozen pre-analysis protocol for one SD-JWT issuance campaign.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceQualificationPlan {
    /// Must be `marty.performance/sd-jwt-issuance-plan/v3`.
    pub schema: String,
    /// Fingerprint of the canonical upstream-portable manifest bytes.
    pub manifest: ArtifactFingerprint,
    /// Manifest schema accepted by this protocol.
    pub manifest_schema: String,
    /// Route schema accepted by this protocol.
    pub route_schema: String,
    /// Work-estimator version required in every route record.
    pub work_estimator_version: String,
    /// Static-partition version required in every route record.
    pub static_partition_rule_version: String,
    /// Worker cap required in every route record.
    pub worker_cap: usize,
    /// Number of fixture cases bound into this campaign.
    pub fixture_case_count: usize,
    /// Number of paired stage cells bound into this campaign.
    pub paired_cell_count: usize,
    /// Number of full benchmark IDs bound into this campaign.
    pub benchmark_id_count: usize,
    /// Required quiet-window duration before each protected phase.
    pub quiet_window_seconds: u64,
    /// Ordered names of the two independently observed quiet windows.
    pub quiet_windows: Vec<String>,
    /// Whether one same-HEAD fixed executable is mandatory for all timing.
    pub fixed_binary_same_head: bool,
    /// Criterion process parameters fixed before observing results.
    pub criterion: SdJwtIssuanceCriterionProtocol,
    /// Twenty predeclared superblock labels aligned by global-round ordinal.
    pub superblock_orders: Vec<String>,
    /// Eight routes used by an `ABBA_FIRST` superblock.
    pub abba_expansion: Vec<String>,
    /// Eight routes used by a `BAAB_FIRST` superblock.
    pub baab_expansion: Vec<String>,
    /// Number of global rounds, and therefore superblocks per paired cell.
    pub superblocks_per_cell: u32,
    /// Number of fresh processes in one superblock.
    pub processes_per_superblock: u32,
    /// Number of fresh processes for one paired cell.
    pub processes_per_cell: u32,
    /// Total fresh processes in the complete campaign.
    pub total_processes: u32,
    /// Global-round execution and run-validity contract.
    pub global_rounds: SdJwtIssuanceGlobalRoundProtocol,
    /// Bootstrap and simultaneous-band protocol.
    pub bootstrap: SdJwtIssuanceBootstrapProtocol,
    /// Predeclared paired-effect definitions.
    pub effects: SdJwtIssuanceEffectProtocol,
    /// Predeclared threshold-discovery rule.
    pub discovery: SdJwtIssuanceDiscoveryProtocol,
    /// Whether production activation requires a later isolated change.
    pub production_activation_separate: bool,
}

/// Campaign-wide cluster alignment required by the common bootstrap.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceGlobalRoundProtocol {
    /// Exact nesting order for every fresh timing process.
    pub execution_nesting: String,
    /// How one ordinal aligns superblocks across all paired cells.
    pub ordinal_alignment: String,
    /// Number of paired cells completed in every global round.
    pub cells_per_round: u32,
    /// Number of fresh Criterion processes completed in every global round.
    pub processes_per_round: u32,
    /// Timing processes permitted to run concurrently.
    pub concurrent_timing_processes: u32,
    /// Uninterrupted continuous run-validity evidence contract.
    pub run_validity: SdJwtIssuanceRunValidityProtocol,
}

/// Continuous evidence required to keep a multi-day campaign valid.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceRunValidityProtocol {
    /// Must be `marty.performance/sd-jwt-issuance-run-validity/v1`.
    pub schema: String,
    /// Durable segmented evidence representation.
    pub artifact_format: String,
    /// Exact JSON lexical normalization used by every validity artifact.
    pub canonicalization_rule: String,
    /// Exact representation required for every UTC timestamp string.
    pub utc_format_rule: String,
    /// Single-process monotonic origin and observation-time rule.
    pub monotonic_clock_rule: String,
    /// Deterministic relative paths and safe artifact-resolution behavior.
    pub artifact_inventory_rule: String,
    /// Closed schemas, fixed role paths, and privacy rules for global preimages.
    pub global_preimages: SdJwtIssuanceGlobalPreimageProtocol,
    /// Integrity boundary assumed by the unkeyed evidence chain.
    pub threat_model: String,
    /// Exact beginning and end of required monitor coverage.
    pub coverage: String,
    /// Clean monitor coverage required before the first timing process.
    pub pre_timing_quiet_seconds: u32,
    /// Target interval between monitor samples.
    pub sample_interval_seconds: u32,
    /// Largest permitted monotonic-clock gap between samples.
    pub maximum_sample_gap_seconds: u32,
    /// Parser, storage, process, and campaign limits.
    pub limits: SdJwtIssuanceRunValidityLimits,
    /// Hash and monotonic-time continuity rule between segments.
    pub segment_chain_rule: String,
    /// Ordinal rule for every record inside a segment.
    pub record_ordinal_rule: String,
    /// Ordinal rule shared by all lifecycle-event variants.
    pub event_ordinal_rule: String,
    /// Closed reasons permitted in a segment footer.
    pub segment_close_reason_literals: Vec<String>,
    /// Exact coupling between each footer reason and its close trigger.
    pub segment_close_reason_rule: String,
    /// Required coordinate order and start/finish state machine.
    pub process_schedule_rule: String,
    /// Test-window renewal rule across the complete campaign.
    pub attestation_chain_rule: String,
    /// Typed proof for the first pre-build quiet window.
    pub first_quiet_window: SdJwtIssuanceFirstQuietWindowProtocol,
    /// Typed, non-secret per-process invocation descriptor.
    pub invocation_descriptor: SdJwtIssuanceInvocationDescriptorProtocol,
    /// Cooperative launch-gate token and child-receipt contract.
    pub launch_barrier: SdJwtIssuanceLaunchBarrierProtocol,
    /// Unique Criterion-home inventory and freshness contract.
    pub criterion_home: SdJwtIssuanceCriterionHomeProtocol,
    /// Selected-ID route-evidence record emitted by each timing process.
    pub route_artifact: SdJwtIssuanceRouteArtifactProtocol,
    /// Canonical coordinate-to-artifact indexes bound by completion.
    pub artifact_indexes: SdJwtIssuanceArtifactIndexProtocol,
    /// Exact versioned record variants permitted in segment files.
    pub records: SdJwtIssuanceRunValidityRecordProtocols,
    /// Separately created terminal artifact and external anchor contract.
    pub completion: SdJwtIssuanceRunValidityCompletionProtocol,
    /// Events that make the campaign invalid.
    pub invalidating_events: Vec<String>,
    /// Fail-closed scope applied to any event or continuity gap.
    pub invalidation_rule: String,
}

/// Resource and cardinality limits for one issuance campaign.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceRunValidityLimits {
    /// Compiled pre-parse cap that this plan must repeat exactly.
    pub maximum_plan_bytes: u64,
    /// Maximum duration of one chained segment.
    pub maximum_segment_seconds: u32,
    /// Maximum encoded size of one segment.
    pub maximum_segment_bytes: u64,
    /// Maximum encoded size of one validity-segment NDJSON record including LF.
    pub maximum_line_bytes: u32,
    /// Maximum records in one segment including header and footer.
    pub maximum_records_per_segment: u32,
    /// Maximum segments in the completed campaign.
    pub maximum_segment_count: u32,
    /// Maximum encoded size of the completion manifest.
    pub maximum_completion_manifest_bytes: u64,
    /// Hard pre-parse limit for the independently supplied completion anchor.
    pub maximum_external_anchor_bytes: u64,
    /// Fallback cap for auxiliary preimages without a dedicated size limit.
    pub maximum_auxiliary_preimage_bytes: u64,
    /// Maximum size of one selected-ID route artifact including LF.
    pub maximum_route_artifact_bytes: u64,
    /// Maximum bytes across all selected-ID route artifacts.
    pub maximum_total_route_artifact_bytes: u64,
    /// Maximum bytes in one complete Criterion home.
    pub maximum_criterion_home_bytes: u64,
    /// Maximum bytes across all complete Criterion homes.
    pub maximum_total_criterion_home_bytes: u64,
    /// Maximum bytes in the complete retained fixed-build input archive.
    pub maximum_build_input_bytes: u64,
    /// Maximum bytes in one launch ready or release frame including LF.
    pub maximum_launch_frame_bytes: u32,
    /// Maximum seconds from successful spawn to a validated ready frame.
    pub maximum_spawn_to_ready_seconds: u32,
    /// Maximum drained stdout plus stderr bytes for one timing process.
    pub maximum_process_output_bytes: u64,
    /// Maximum bytes across all bound campaign evidence.
    pub maximum_total_evidence_bytes: u64,
    /// Maximum records across all segments.
    pub maximum_total_records: u64,
    /// Maximum elapsed monotonic duration of the campaign.
    pub maximum_campaign_seconds: u32,
    /// Maximum elapsed monotonic duration of one timing process.
    pub maximum_timing_process_seconds: u32,
    /// Maximum proved delay from terminal footer to final anchor publication.
    pub maximum_anchor_publication_delay_seconds: u32,
    /// Maximum actual test-window attestations in the completed chain.
    pub maximum_test_window_attestations: u32,
    /// Exact number of scheduled global rounds.
    pub exact_global_rounds: u32,
    /// Exact number of cells in each global round.
    pub exact_cells_per_round: u32,
    /// Exact number of expansion positions in each cell.
    pub exact_expansion_positions_per_cell: u32,
    /// Exact number of successful timing-process completions.
    pub exact_timing_processes: u32,
    /// Streaming, pre-allocation, and aggregate-size enforcement rule.
    pub validation_rule: String,
}

/// Exact schemas for every record permitted in a validity segment.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceRunValidityRecordProtocols {
    /// First record of segment zero.
    pub genesis_header: SdJwtIssuanceEvidenceRecordProtocol,
    /// First record of every later segment.
    pub continuation_header: SdJwtIssuanceEvidenceRecordProtocol,
    /// Periodic host and process observation.
    pub sample: SdJwtIssuanceEvidenceRecordProtocol,
    /// PID-free launch intent durably recorded before process creation.
    pub process_intent: SdJwtIssuanceEvidenceRecordProtocol,
    /// Timing-process start transition.
    pub process_start: SdJwtIssuanceEvidenceRecordProtocol,
    /// Timing-process terminal transition.
    pub process_finish: SdJwtIssuanceEvidenceRecordProtocol,
    /// Actual test-window attestation renewal.
    pub attestation_transition: SdJwtIssuanceEvidenceRecordProtocol,
    /// Last record of every segment.
    pub segment_footer: SdJwtIssuanceEvidenceRecordProtocol,
}

/// One versioned NDJSON record contract.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceEvidenceRecordProtocol {
    /// Exact value of the record's `schema` field.
    pub schema: String,
    /// Fields in mandatory canonical JSON key order.
    pub fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Required number and ordering of this record variant.
    pub cardinality: String,
    /// Cross-field and lifecycle constraints.
    pub semantic_rule: String,
}

/// One field in a versioned validity-evidence record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceEvidenceFieldProtocol {
    /// Canonical JSON key.
    pub name: String,
    /// JSON representation required for the value.
    pub json_type: SdJwtIssuanceEvidenceJsonType,
    /// Whether JSON `null` is permitted for this required key.
    pub nullable: bool,
}

/// Closed JSON representations used by validity-evidence fields.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SdJwtIssuanceEvidenceJsonType {
    /// JSON string.
    String,
    /// Unsigned 32-bit JSON integer.
    U32,
    /// Unsigned 64-bit JSON integer.
    U64,
    /// Signed 32-bit JSON integer.
    I32,
    /// Signed 64-bit JSON integer.
    I64,
    /// Finite JSON number represented as an IEEE-754 binary64 value.
    F64,
    /// JSON boolean.
    Boolean,
    /// JSON array of strings.
    StringArray,
    /// Ordered JSON array of privacy-preserving environment-entry objects.
    NameValueArray,
    /// `ArtifactFingerprint` JSON object.
    ArtifactFingerprint,
    /// JSON array of `ArtifactFingerprint` objects.
    ArtifactFingerprintArray,
    /// Ordered JSON array of completed-process objects.
    ProcessCompletionArray,
    /// Ordered JSON array of first-window sample objects.
    QuietWindowSampleArray,
    /// Ordered JSON array of Criterion-home inventory entries.
    ArtifactInventoryEntryArray,
    /// Ordered JSON array of issuance-route ready-batch objects.
    RouteReadyBatchArray,
    /// Ordered JSON array of issuance-route static-chunk objects.
    RouteStaticChunkArray,
    /// Ordered JSON array of coordinate-to-artifact index entries.
    CoordinateArtifactArray,
    /// Ordered JSON array of privacy-preserving process-identity entries.
    ProcessIdentityArray,
    /// Ordered JSON array of exact-source-tree archive manifest entries.
    SourceArchiveEntryArray,
}

/// Closed campaign-wide fingerprint-preimage and privacy contract.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceGlobalPreimageProtocol {
    /// Canonical representation and durability rule for typed JSON preimages.
    pub artifact_format: String,
    /// Fixed role path for every global preimage and safe-resolution behavior.
    pub resolution_rule: String,
    /// Secret-free controller configuration retained with the campaign.
    pub controller_configuration: SdJwtIssuanceEvidenceRecordProtocol,
    /// Secret-free monitor configuration retained with the campaign.
    pub monitor_configuration: SdJwtIssuanceEvidenceRecordProtocol,
    /// Campaign-scoped opaque host identity.
    pub host_identity: SdJwtIssuanceEvidenceRecordProtocol,
    /// Shareable performance-relevant hardware projection.
    pub hardware_profile: SdJwtIssuanceEvidenceRecordProtocol,
    /// Exact numeric domain shared by hardware, thresholds, and observations.
    pub observation_bounds: SdJwtIssuanceObservationBounds,
    /// Closed operating-system family values in hardware evidence.
    pub operating_system_family_literals: Vec<String>,
    /// Closed architecture values in hardware evidence.
    pub architecture_literals: Vec<String>,
    /// Closed virtualization values in hardware evidence.
    pub virtualization_kind_literals: Vec<String>,
    /// Closed power-policy values in hardware evidence.
    pub power_policy_literals: Vec<String>,
    /// Closed throttle-flag values in thresholds and observations.
    pub throttle_flag_literals: Vec<String>,
    /// Closed host-validity threshold document.
    pub validity_thresholds: SdJwtIssuanceEvidenceRecordProtocol,
    /// Baseline and sampled privacy-preserving unrelated-process sets.
    pub unrelated_process_set: SdJwtIssuanceEvidenceRecordProtocol,
    /// Fields in each ordered opaque process-identity entry.
    pub process_identity_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Privacy-preserving projection of one authorized test window.
    pub test_window_attestation: SdJwtIssuanceEvidenceRecordProtocol,
    /// Closed non-endpoint roles for test-window targets.
    pub test_window_target_role_literals: Vec<String>,
    /// Trusted-controller receipt linking the installed fixed binary to source and build inputs.
    pub fixed_binary_build_receipt: SdJwtIssuanceEvidenceRecordProtocol,
    /// Complete typed inventory of dependency, toolchain, linker, and runtime build inputs.
    pub fixed_binary_build_input_inventory: SdJwtIssuanceEvidenceRecordProtocol,
    /// Fields in each ordered fixed-build input-inventory entry.
    pub fixed_binary_build_input_inventory_entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Closed role literals for fixed-build input-inventory entries.
    pub fixed_binary_build_input_role_literals: Vec<String>,
    /// Exact role roots and cardinalities for the fixed-build input inventory.
    pub fixed_binary_build_input_role_rule: String,
    /// Portable path grammar and ordered executable-directory reconstruction rule.
    pub fixed_binary_build_input_path_rule: String,
    /// Closed portable logical modes for retained fixed-build input members.
    pub fixed_binary_build_input_mode_literals: Vec<String>,
    /// Deterministic retained fixed-build input archive representation.
    pub fixed_binary_build_input_archive_format: String,
    /// Exact archive, inventory, member, and materialization binding rule.
    pub fixed_binary_build_input_archive_rule: String,
    /// Hard maximum members in the retained fixed-build input archive.
    pub maximum_fixed_binary_build_input_entries: u32,
    /// Fields in each ordered fixed-build environment entry.
    pub fixed_binary_build_environment_entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Complete case-sensitive fixed-build parent-environment allowlist.
    pub fixed_binary_build_environment_allowlist: Vec<String>,
    /// Exact platform mapping for every fixed-build environment entry.
    pub fixed_binary_build_environment_mapping_rule: String,
    /// Canonical absolute sandbox root used for Windows fixed builds.
    pub fixed_binary_build_root_windows: String,
    /// Canonical absolute sandbox root used for non-Windows fixed builds.
    pub fixed_binary_build_root_non_windows: String,
    /// Exact build command, environment, output-selection, and binary-linkage rule.
    pub fixed_binary_build_rule: String,
    /// Schema of the canonical exact-source-tree archive manifest.
    pub source_archive_manifest_schema: String,
    /// Fields in the canonical exact-source-tree archive manifest.
    pub source_archive_manifest_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered source-tree manifest entry.
    pub source_archive_entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Hard maximum bytes in the complete source archive.
    pub maximum_source_archive_bytes: u64,
    /// Hard maximum bytes in the canonical source manifest including LF.
    pub maximum_source_archive_manifest_bytes: u64,
    /// Hard maximum bytes in the raw Git commit content.
    pub maximum_source_archive_commit_bytes: u64,
    /// Hard maximum source entries in one archive.
    pub maximum_source_archive_entries: u32,
    /// Hard maximum encoded ASCII bytes in one repository-relative path.
    pub maximum_source_archive_path_bytes: u32,
    /// Hard maximum encoded ASCII bytes in one path segment.
    pub maximum_source_archive_path_segment_bytes: u32,
    /// Hard maximum segments in one repository-relative path.
    pub maximum_source_archive_path_segments: u32,
    /// Hard maximum nodes in the bounded derived source-directory arena.
    pub maximum_source_archive_derived_directory_nodes: u32,
    /// Hard maximum logical component bytes cloned into the derived path arena.
    pub maximum_source_archive_derived_component_bytes: u64,
    /// Deterministic archive representation and parser bounds.
    pub source_archive_format: String,
    /// Exact-tree, commit-object, membership, and no-extra-object rule.
    pub source_archive_rule: String,
    /// Campaign-wide prohibition on secrets and identifying host metadata.
    pub privacy_rule: String,
}

/// Closed numeric ranges used by captured hardware and host observations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceObservationBounds {
    /// Inclusive minimum finite CPU percentage.
    pub minimum_cpu_percent: f64,
    /// Inclusive maximum finite CPU percentage.
    pub maximum_cpu_percent: f64,
    /// Inclusive minimum nonzero CPU frequency.
    pub minimum_cpu_frequency_hz: u64,
    /// Inclusive maximum CPU frequency.
    pub maximum_cpu_frequency_hz: u64,
    /// Inclusive minimum temperature observation.
    pub minimum_temperature_millidegrees_celsius: i64,
    /// Inclusive maximum temperature observation or threshold.
    pub maximum_temperature_millidegrees_celsius: i64,
    /// Inclusive maximum physical memory size represented by the protocol.
    pub maximum_total_memory_bytes: u64,
    /// Inclusive maximum logical CPU count.
    pub maximum_logical_cpu_count: u32,
    /// Inclusive maximum unrelated-process count.
    pub maximum_unrelated_process_count: u32,
}

/// Canonical first-window proof created before correctness and build work.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceFirstQuietWindowProtocol {
    /// Exact value of the artifact's `schema` field.
    pub schema: String,
    /// Canonical create-new representation and durability rule.
    pub artifact_format: String,
    /// Fields in mandatory canonical JSON key order.
    pub fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered `samples` array entry.
    pub sample_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Duration, cadence, provenance, and fail-closed validation rule.
    pub validity_rule: String,
}

/// Canonical descriptor for one cleared, allowlisted child invocation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceInvocationDescriptorProtocol {
    /// Exact value of the descriptor's `schema` field.
    pub schema: String,
    /// Canonical create-new representation and durability rule.
    pub artifact_format: String,
    /// Fields in mandatory canonical JSON key order.
    pub fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered `environment` array entry.
    pub environment_entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Complete case-sensitive environment allowlist.
    pub environment_allowlist: Vec<String>,
    /// Closed `value_kind` domain for environment entries.
    pub environment_value_kind_literals: Vec<String>,
    /// Exact platform-specific name, kind, and portable-value mapping.
    pub environment_mapping_rule: String,
    /// Exact coordinate, command, environment, and fresh-home constraints.
    pub semantic_rule: String,
    /// Deterministic descriptor and Criterion-home discovery rule.
    pub resolution_rule: String,
}

/// Cooperative standard-stream barrier that holds a spawned child before Criterion setup.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceLaunchBarrierProtocol {
    /// Exact value of the release token's `schema` field.
    pub token_schema: String,
    /// Fields in a canonical release token.
    pub token_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact grammar and campaign-wide uniqueness rule for token nonces.
    pub nonce_rule: String,
    /// Exact grammar, independence, and campaign-wide uniqueness rule for process aliases.
    pub process_identity_pseudonym_rule: String,
    /// Exact value of the child's ready-frame `schema` field.
    pub ready_frame_schema: String,
    /// Fields in the canonical child ready frame.
    pub ready_frame_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact value of the controller's release-frame `schema` field.
    pub release_frame_schema: String,
    /// Fields in the canonical controller release frame.
    pub release_frame_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact value of the child's receipt `schema` field.
    pub receipt_schema: String,
    /// Fields in a canonical child receipt.
    pub receipt_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact lexical representation and persistence rule for tokens, frames, and receipts.
    pub artifact_format: String,
    /// Standard-stream framing, closure, and rejection behavior.
    pub transport_rule: String,
    /// Creation, synchronization, observation, and ordering constraints.
    pub semantic_rule: String,
}

/// Canonical inventories proving that every Criterion home begins empty.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceCriterionHomeProtocol {
    /// Exact value of each inventory's `schema` field.
    pub inventory_schema: String,
    /// Fields in an initial or final inventory.
    pub inventory_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered `entries` array element.
    pub entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Raw-byte hashing and parser scope for Criterion-owned files.
    pub opaque_artifact_rule: String,
    /// Exact typed projection required from Criterion's `benchmark.json`.
    pub benchmark_json_projection_rule: String,
    /// Exact typed projection required from Criterion's `estimates.json`.
    pub estimates_json_projection_rule: String,
    /// Empty-home, path, artifact, and lifecycle freshness constraints.
    pub freshness_rule: String,
}

/// One selected benchmark route record emitted outside Criterion timing.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceRouteArtifactProtocol {
    /// Exact `schema` value in the one retained route record.
    pub record_schema: String,
    /// Exact locked serialization and create-new persistence representation.
    pub artifact_format: String,
    /// Fields in mandatory route-record key order.
    pub record_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each non-null ordered `ready_batches` element.
    pub ready_batch_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each non-null ordered `static_chunks` element.
    pub static_chunk_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Closed `stage` string domain.
    pub stage_literals: Vec<String>,
    /// Closed `requested` route string domain.
    pub requested_literals: Vec<String>,
    /// Closed `effective` route string domain.
    pub effective_literals: Vec<String>,
    /// Closed `work_estimate_status` string domain.
    pub work_estimate_status_literals: Vec<String>,
    /// Closed `budget_acquisition_result` string domain.
    pub budget_acquisition_result_literals: Vec<String>,
    /// Closed `selected_mode` string domain.
    pub selected_mode_literals: Vec<String>,
    /// Closed `selection_reason` string domain.
    pub selection_reason_literals: Vec<String>,
    /// Full-matrix validation and selected-ID retention rule.
    pub selected_record_rule: String,
    /// Record-level nullability, count, and effective-route equations.
    pub record_invariant_rule: String,
    /// Ready-batch selector decision tree and field couplings.
    pub ready_batch_invariant_rule: String,
    /// Native static-chunk cardinality, ordinal, and sum equations.
    pub static_chunk_invariant_rule: String,
}

/// Canonical indexes mapping every process coordinate to one selected artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceArtifactIndexProtocol {
    /// Schema for `indexes/criterion-artifacts.json`.
    pub criterion_schema: String,
    /// Schema for `indexes/route-artifacts.json`.
    pub route_schema: String,
    /// Exact canonical create-new representation and durability rule.
    pub artifact_format: String,
    /// Fields in each index artifact.
    pub fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered `entries` element.
    pub entry_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact `artifact_kind` literal for the Criterion index.
    pub criterion_artifact_kind: String,
    /// Exact `artifact_kind` literal for the route index.
    pub route_artifact_kind: String,
    /// Exact slash-normalized Criterion artifact path formatter.
    pub criterion_path_rule: String,
    /// Exact slash-normalized route artifact path formatter.
    pub route_path_rule: String,
    /// Exact cardinality, order, path, and fingerprint constraints.
    pub validity_rule: String,
}

/// Terminal manifest that commits the completed forward evidence chain.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceRunValidityCompletionProtocol {
    /// Exact value of the completion manifest's `schema` field.
    pub schema: String,
    /// Canonical create-new representation and durability rule.
    pub artifact_format: String,
    /// Fields in mandatory canonical JSON key order.
    pub fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Fields in each ordered `process_completions` array entry.
    pub process_completion_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact successful-campaign content and cardinality rule.
    pub validity_rule: String,
    /// Exact schema of the signed ordinal-zero terminal observation receipt.
    pub terminal_observation_receipt_schema: String,
    /// Fields in the signed terminal observation receipt.
    pub terminal_observation_receipt_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact schema of the Marty-owned controller observation wrapper.
    pub terminal_observation_evidence_schema: String,
    /// Fields in the Marty-owned controller observation wrapper.
    pub terminal_observation_evidence_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Exact schema of the independently delivered completion anchor.
    pub external_anchor_schema: String,
    /// Fields in the independently delivered completion anchor.
    pub external_anchor_fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    /// Canonical representation of the independent anchor.
    pub external_anchor_format: String,
    /// Out-of-band authenticated append-only channel configuration contract.
    pub external_anchor_channel: SdJwtIssuanceEvidenceRecordProtocol,
    /// Exact non-secret channel identifier required by v1.
    pub external_anchor_channel_id: String,
    /// Exact non-secret append-only log identifier required by v1.
    pub external_anchor_log_id: String,
    /// Exact out-of-band authenticated connector trust policy required by v1.
    pub external_anchor_connector_policy: String,
    /// Exact offline receipt signature scheme required by v1.
    pub external_anchor_signature_scheme: String,
    /// Exact signing-key identifier required by v1.
    pub external_anchor_signing_key_id: String,
    /// Exact signed-byte preimages for terminal and completion receipts.
    pub external_anchor_signed_preimage_rule: String,
    /// Closed grammar and size bound for a channel receipt locator.
    pub external_anchor_receipt_id_rule: String,
    /// Campaign uniqueness, equivocation, and replay behavior for anchor receipts.
    pub external_anchor_replay_rule: String,
    /// Independent expected-digest requirement that anchors the final head.
    pub external_anchor_rule: String,
}

/// Fixed Criterion arguments for every fresh timing process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceCriterionProtocol {
    /// Exact portable logical argv vector in process-launch order.
    pub logical_argv: Vec<String>,
    /// Criterion sample size.
    pub sample_size: u32,
    /// Criterion bootstrap resamples used for its diagnostic estimates.
    pub nresamples: u32,
    /// Criterion warm-up time in seconds.
    pub warm_up_seconds: u32,
    /// Criterion measurement time in seconds.
    pub measurement_seconds: u32,
    /// Criterion confidence level.
    pub confidence_level: f64,
    /// Criterion sampling mode selected by the fixed benchmark.
    pub sampling_mode: String,
    /// Criterion baseline behavior used by every fresh home.
    pub baseline_mode: String,
    /// Criterion baseline directory name.
    pub baseline_name: String,
    /// Whether plot generation is disabled.
    pub no_plot: bool,
    /// Statistic read from each Criterion estimates file.
    pub primary_statistic: String,
}

/// Fixed campaign-wide global-round bootstrap protocol.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceBootstrapProtocol {
    /// Number of bootstrap replicates.
    pub replicates: u32,
    /// Family-wise confidence level for simultaneous endpoints.
    pub confidence_level: f64,
    /// Deterministic pseudo-random generator name.
    pub rng: String,
    /// Unsigned generator seed.
    pub seed: u64,
    /// Whether the seed is used directly as the initial generator state.
    pub seed_is_initial_state: bool,
    /// Exact `SplitMix64` state transition and output transform.
    pub rng_state_transition: String,
    /// Number of round ordinals sampled for every replicate.
    pub draws_per_replicate: u32,
    /// Whether round ordinals are sampled with replacement.
    pub sampling_method: String,
    /// Exact rejection and modulo rule for an unbiased round index.
    pub uniform_index_rule: String,
    /// Lifetime of the generator state across all replicates.
    pub stream_scope: String,
    /// Fixed nesting used to consume accepted draws.
    pub consumption_order: String,
    /// State-consumption behavior for a rejected output.
    pub rejected_output_rule: String,
    /// Quantile interpolation rule.
    pub quantile_method: String,
    /// Atomic bootstrap resampling unit.
    pub resampling_unit: String,
    /// Scope receiving one common sampled round-index vector per replicate.
    pub common_index_scope: String,
    /// Common simultaneous-band construction for the primary effect family.
    pub simultaneous_band: String,
    /// Confidence-interval construction for primary effects.
    pub primary_interval_rule: String,
    /// Marginal interval construction for disclosure-only `O`.
    pub diagnostic_o_interval_rule: String,
}

/// Index pairs and formulas defining the four paired log effects.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceEffectProtocol {
    /// Sign convention for every ordered log-median difference.
    pub orientation: String,
    /// `ABBA_FIRST` serial-first ordered index pairs.
    pub abba_serial_first_pairs: Vec<[u8; 2]>,
    /// `ABBA_FIRST` adaptive-first normalized index pairs.
    pub abba_adaptive_first_pairs: Vec<[u8; 2]>,
    /// `BAAB_FIRST` serial-first ordered index pairs.
    pub baab_serial_first_pairs: Vec<[u8; 2]>,
    /// `BAAB_FIRST` adaptive-first normalized index pairs.
    pub baab_adaptive_first_pairs: Vec<[u8; 2]>,
    /// Formula for the serial-first summary `S`.
    pub s_definition: String,
    /// Formula for the adaptive-first summary `P`.
    pub p_definition: String,
    /// Formula for the combined route effect `D`.
    pub d_definition: String,
    /// Formula for the disclosed order diagnostic `O`.
    pub o_definition: String,
    /// Effects receiving simultaneous confidence endpoints.
    pub primary_effects: Vec<String>,
    /// Effects disclosed without gating.
    pub disclosure_only_effects: Vec<String>,
}

/// Frozen discovery rule applied only after valid campaign analysis.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtIssuanceDiscoveryProtocol {
    /// Exact ready-batch count eligible for threshold discovery.
    pub required_ready_batch_count: usize,
    /// Stages that must pass simultaneously for a fixture.
    pub required_stages: Vec<String>,
    /// Exact relative-percent transform applied to each log effect.
    pub percent_transform: String,
    /// Strict percentage-point upper bound for transformed `D`.
    pub d_upper_percent_less_than: f64,
    /// Strict percentage-point upper bound for transformed `S`.
    pub s_upper_percent_less_than: f64,
    /// Strict percentage-point upper bound for transformed `P`.
    pub p_upper_percent_less_than: f64,
    /// Rule for resolving the set of passing candidate thresholds.
    pub selection_rule: String,
}
