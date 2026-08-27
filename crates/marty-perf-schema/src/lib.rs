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
