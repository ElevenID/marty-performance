//! Versioned, serializable evidence contracts used by the performance runner.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
pub struct ArtifactFingerprint {
    /// Uppercase hexadecimal SHA-256 without a prefix.
    pub sha256: String,
    /// Exact number of bytes hashed.
    pub byte_length: u64,
}

/// Canonical issuance matrix exported by the benchmarked SD-JWT crate.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
pub struct SdJwtIssuanceQualificationCase {
    /// Stable non-personal fixture identifier.
    pub fixture_id: String,
    /// Number of real disclosures planned by the fixture.
    pub disclosure_count: usize,
}

/// One stage-specific serial/adaptive benchmark pair.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
pub struct SdJwtIssuanceThresholds {
    /// Minimum jobs required before considering parallel work.
    pub min_jobs: usize,
    /// Minimum estimated work in bytes.
    pub min_estimated_work_bytes: usize,
}

/// Frozen pre-analysis protocol for one SD-JWT issuance campaign.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SdJwtIssuanceQualificationPlan {
    /// Must be `marty.performance/sd-jwt-issuance-plan/v1`.
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
    /// Twenty predeclared superblock order labels.
    pub superblock_orders: Vec<String>,
    /// Eight routes used by an `ABBA_FIRST` superblock.
    pub abba_expansion: Vec<String>,
    /// Eight routes used by a `BAAB_FIRST` superblock.
    pub baab_expansion: Vec<String>,
    /// Number of superblocks executed for each paired cell.
    pub superblocks_per_cell: u32,
    /// Number of fresh processes in one superblock.
    pub processes_per_superblock: u32,
    /// Number of fresh processes for one paired cell.
    pub processes_per_cell: u32,
    /// Total fresh processes in the complete campaign.
    pub total_processes: u32,
    /// Bootstrap and simultaneous-band protocol.
    pub bootstrap: SdJwtIssuanceBootstrapProtocol,
    /// Predeclared paired-effect definitions.
    pub effects: SdJwtIssuanceEffectProtocol,
    /// Predeclared threshold-discovery rule.
    pub discovery: SdJwtIssuanceDiscoveryProtocol,
    /// Whether production activation requires a later isolated change.
    pub production_activation_separate: bool,
}

/// Fixed Criterion arguments for every fresh timing process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SdJwtIssuanceCriterionProtocol {
    /// Criterion sample size.
    pub sample_size: u32,
    /// Criterion warm-up time in seconds.
    pub warm_up_seconds: u32,
    /// Criterion measurement time in seconds.
    pub measurement_seconds: u32,
    /// Criterion confidence level.
    pub confidence_level: f64,
    /// Whether plot generation is disabled.
    pub no_plot: bool,
    /// Statistic read from each Criterion estimates file.
    pub primary_statistic: String,
}

/// Fixed whole-superblock bootstrap protocol.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SdJwtIssuanceBootstrapProtocol {
    /// Number of bootstrap replicates.
    pub replicates: u32,
    /// Family-wise confidence level for simultaneous endpoints.
    pub confidence_level: f64,
    /// Deterministic pseudo-random generator name.
    pub rng: String,
    /// Unsigned generator seed.
    pub seed: u64,
    /// Quantile interpolation rule.
    pub quantile_method: String,
    /// Atomic bootstrap resampling unit.
    pub resampling_unit: String,
    /// Common simultaneous-band construction for the primary effect family.
    pub simultaneous_band: String,
}

/// Index pairs and formulas defining the four paired log effects.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
pub struct SdJwtIssuanceDiscoveryProtocol {
    /// Exact ready-batch count eligible for threshold discovery.
    pub required_ready_batch_count: usize,
    /// Stages that must pass simultaneously for a fixture.
    pub required_stages: Vec<String>,
    /// Strict upper endpoint bound for `D`.
    pub d_upper_less_than: f64,
    /// Strict upper endpoint bound for `S`.
    pub s_upper_less_than: f64,
    /// Strict upper endpoint bound for `P`.
    pub p_upper_less_than: f64,
    /// Rule for resolving the set of passing candidate thresholds.
    pub selection_rule: String,
}
