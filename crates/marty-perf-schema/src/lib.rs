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
    /// Number of unrelated running containers observed by doctor.
    pub running_containers: Option<usize>,
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
