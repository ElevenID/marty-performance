//! k6 scenario execution and run provenance.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result};
use chrono::Utc;
use marty_perf_schema::{DoctorReport, PreparedStack, RunMetadata};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::Uuid;

use crate::tooling;

const RESULT_CLASSES: &[&str] = &[
    "migration-preview",
    "local-comparable",
    "diagnostic",
    "k8s-canonical",
];
const RUN_ARTIFACTS: &[&str] = &[
    "run.json",
    "summary.json",
    "samples.json",
    "k6.stdout.log",
    "k6.stderr.log",
    "runner.error.log",
];

pub(crate) fn smoke(
    base_url: &str,
    output_dir: &Path,
    result_class: &str,
    stack_input: Option<&Path>,
    doctor_report: Option<&Path>,
    allow_remote_target: bool,
    force: bool,
) -> Result<()> {
    anyhow::ensure!(
        RESULT_CLASSES.contains(&result_class),
        "unsupported result class {result_class}"
    );
    anyhow::ensure!(
        result_class != "k8s-canonical",
        "k8s-canonical evidence requires the future Kubernetes runner"
    );
    let origin = validate_origin(base_url)?;
    ensure_target_allowed(&origin, allow_remote_target)?;
    let metadata_path = output_dir.join("run.json");
    prepare_output_directory(output_dir, force)?;

    let tools = tooling::configuration()?;
    let local_k6 = tooling::local_k6_version();
    let local_compatible = tooling::compatible_local_k6(local_k6.as_deref(), &tools.k6.version);
    let mode = if local_compatible {
        "local"
    } else {
        "container"
    };
    let run_id = Uuid::new_v4().to_string();
    let mut dimensions = BTreeMap::from([
        ("vus".to_owned(), "1".to_owned()),
        ("iterations".to_owned(), "10".to_owned()),
        (
            "telemetry_mode".to_owned(),
            telemetry_mode(result_class).to_owned(),
        ),
        ("k6_version".to_owned(), tools.k6.version.clone()),
    ]);
    bind_evidence(result_class, stack_input, doctor_report, &mut dimensions)?;
    let mut metadata = RunMetadata {
        schema: "marty.performance/run/v1".to_owned(),
        run_id,
        result_class: result_class.to_owned(),
        scenario: "gateway-smoke".to_owned(),
        started_at: Utc::now().to_rfc3339(),
        base_url: origin.to_string().trim_end_matches('/').to_owned(),
        k6_mode: mode.to_owned(),
        k6_image: (mode == "container").then(|| tools.k6.image.clone()),
        exit_code: None,
        successful: false,
        dimensions,
    };
    write_metadata(&metadata_path, &metadata)?;

    let result = if mode == "local" {
        run_local(&origin, output_dir)
    } else {
        run_container(&origin, output_dir, &tools.k6.image)
    };
    match result {
        Ok(output) => {
            fs::write(output_dir.join("k6.stdout.log"), &output.stdout)
                .context("write k6 stdout")?;
            fs::write(output_dir.join("k6.stderr.log"), &output.stderr)
                .context("write k6 stderr")?;
            metadata.exit_code = output.status.code();
            metadata.successful = output.status.success();
            write_metadata(&metadata_path, &metadata)?;
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            anyhow::ensure!(output.status.success(), "gateway smoke scenario failed");
        }
        Err(error) => {
            metadata.exit_code = None;
            metadata.successful = false;
            write_metadata(&metadata_path, &metadata)?;
            fs::write(output_dir.join("runner.error.log"), format!("{error:#}\n"))
                .context("write runner error")?;
            return Err(error);
        }
    }
    println!("Smoke evidence written to {}.", output_dir.display());
    Ok(())
}

fn telemetry_mode(result_class: &str) -> &'static str {
    if result_class == "diagnostic" {
        "diagnostic"
    } else {
        "comparable"
    }
}

fn prepare_output_directory(output_dir: &Path, force: bool) -> Result<()> {
    let existing: Vec<_> = RUN_ARTIFACTS
        .iter()
        .map(|name| output_dir.join(name))
        .filter(|path| path.exists())
        .collect();
    anyhow::ensure!(
        force || existing.is_empty(),
        "{} already contains run artifacts; pass --force to replace them",
        output_dir.display()
    );
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    if force {
        for path in existing {
            fs::remove_file(&path)
                .with_context(|| format!("remove stale run artifact {}", path.display()))?;
        }
    }
    Ok(())
}

fn bind_evidence(
    result_class: &str,
    stack_input: Option<&Path>,
    doctor_report: Option<&Path>,
    dimensions: &mut BTreeMap<String, String>,
) -> Result<()> {
    if result_class != "migration-preview" {
        anyhow::ensure!(
            stack_input.is_some() && doctor_report.is_some(),
            "{result_class} runs require --stack-input and --doctor-report"
        );
    }
    if let Some(path) = stack_input {
        let (stack, digest): (PreparedStack, String) = read_evidence(path)?;
        anyhow::ensure!(
            stack.schema == "marty.performance/stack-input/v1",
            "unsupported prepared stack schema {}",
            stack.schema
        );
        dimensions.insert("stack_release".to_owned(), stack.release);
        dimensions.insert(
            "stack_manifest_sha256".to_owned(),
            stack.source_manifest_sha256,
        );
        dimensions.insert("stack_input_sha256".to_owned(), digest);
    } else {
        dimensions.insert("stack_evidence".to_owned(), "unbound".to_owned());
    }
    if let Some(path) = doctor_report {
        let (doctor, digest): (DoctorReport, String) = read_evidence(path)?;
        anyhow::ensure!(
            doctor.schema == "marty.performance/doctor/v1" && doctor.valid,
            "doctor evidence is invalid"
        );
        if result_class == "local-comparable" {
            anyhow::ensure!(
                doctor.comparable,
                "doctor evidence does not qualify a comparable run"
            );
        }
        dimensions.insert("doctor_sha256".to_owned(), digest);
    }
    Ok(())
}

fn read_evidence<T: DeserializeOwned>(path: &Path) -> Result<(T, String)> {
    let bytes = fs::read(path).with_context(|| format!("read evidence {}", path.display()))?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse evidence {}", path.display()))?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    Ok((value, digest))
}

fn run_local(origin: &Url, output_dir: &Path) -> Result<Output> {
    let scenario = scenario_path()?;
    let summary = absolute_output(&output_dir.join("summary.json"))?;
    let samples = absolute_output(&output_dir.join("samples.json"))?;
    Command::new("k6")
        .args([
            "run",
            "--summary-export",
            summary.to_str().context("summary path is not Unicode")?,
            "--out",
            &format!("json={}", samples.display()),
        ])
        .env("BASE_URL", origin.as_str().trim_end_matches('/'))
        .arg(scenario)
        .output()
        .context("execute local k6")
}

fn run_container(origin: &Url, output_dir: &Path, image: &str) -> Result<Output> {
    tooling::successful_stdout("docker", &["version", "--format", "{{.Server.Version}}"])
        .context("Docker is required because local k6 is unavailable")?;
    let scenario = scenario_path()?;
    let scenario_dir = scenario.parent().context("scenario has no parent")?;
    let output_dir = absolute_output(output_dir)?;
    let scenario_mount = docker_mount_path(scenario_dir);
    let output_mount = docker_mount_path(&output_dir);
    let container_origin = docker_origin(origin)?;
    Command::new("docker")
        .args(["run", "--rm", "--network", "host"])
        .args(["--env", &format!("BASE_URL={container_origin}")])
        .args(["--volume", &format!("{scenario_mount}:/scripts:ro")])
        .args(["--volume", &format!("{output_mount}:/results")])
        .arg(image)
        .args([
            "run",
            "--summary-export",
            "/results/summary.json",
            "--out",
            "json=/results/samples.json",
            "/scripts/gateway.js",
        ])
        .output()
        .context("execute k6 container")
}

fn validate_origin(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("base URL must be an absolute HTTP(S) URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "base URL must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "base URL must not contain credentials"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "base URL must not contain a query or fragment"
    );
    anyhow::ensure!(
        url.path() == "/" || url.path().is_empty(),
        "base URL must be an origin without a path"
    );
    url.set_path("");
    Ok(url)
}

fn ensure_target_allowed(origin: &Url, allow_remote_target: bool) -> Result<()> {
    let local = match origin.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => {
            domain.eq_ignore_ascii_case("localhost")
                || domain.eq_ignore_ascii_case("host.docker.internal")
        }
        None => false,
    };
    anyhow::ensure!(
        local || allow_remote_target,
        "remote targets require --allow-remote-target; never use production traffic or personal data"
    );
    Ok(())
}

fn docker_origin(origin: &Url) -> Result<String> {
    docker_origin_for_host(origin, std::env::consts::OS)
}

fn docker_origin_for_host(origin: &Url, host_os: &str) -> Result<String> {
    let mut url = origin.clone();
    if matches!(host_os, "windows" | "macos")
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
    {
        url.set_host(Some("host.docker.internal"))
            .context("replace loopback hostname for the k6 container")?;
    }
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn scenario_path() -> Result<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios/smoke/gateway.js")
        .canonicalize()
        .context("locate gateway smoke scenario")?;
    Ok(path)
}

fn absolute_output(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path.canonicalize().context("canonicalize output path");
    }
    let parent = path.parent().context("output path has no parent")?;
    let parent = parent
        .canonicalize()
        .context("canonicalize output directory")?;
    Ok(parent.join(path.file_name().context("output path has no file name")?))
}

fn docker_mount_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{path}");
    }
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
}

fn write_metadata(path: &Path, metadata: &RunMetadata) -> Result<()> {
    let serialized = serde_json::to_string_pretty(metadata).context("serialize run metadata")?;
    fs::write(path, format!("{serialized}\n")).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rejects_credentials_and_paths() {
        assert!(validate_origin("https://user@example.com").is_err());
        assert!(validate_origin("https://example.com/api").is_err());
    }

    #[test]
    fn remote_targets_require_explicit_authorization() {
        let remote = validate_origin("https://performance.example.com").expect("remote origin");
        assert!(ensure_target_allowed(&remote, false).is_err());
        ensure_target_allowed(&remote, true).expect("explicit remote target");

        let local = validate_origin("http://127.0.0.1:28080").expect("local origin");
        ensure_target_allowed(&local, false).expect("loopback target");
    }

    #[test]
    fn loopback_is_rewritten_only_for_container_access() {
        let url = validate_origin("http://127.0.0.1:28000").expect("valid origin");
        assert_eq!(
            docker_origin_for_host(&url, "windows").expect("container origin"),
            "http://host.docker.internal:28000"
        );
        assert_eq!(
            docker_origin_for_host(&url, "linux").expect("Linux host origin"),
            "http://127.0.0.1:28000"
        );
        let remote = validate_origin("https://perf.example.com").expect("valid origin");
        assert_eq!(
            docker_origin_for_host(&remote, "windows").expect("remote origin"),
            "https://perf.example.com"
        );
    }

    #[test]
    fn windows_extended_paths_are_safe_for_docker_mounts() {
        let path = Path::new(r"\\?\C:\work\marty-performance\scenarios");
        assert_eq!(
            docker_mount_path(path),
            r"C:\work\marty-performance\scenarios"
        );
    }

    #[test]
    fn comparable_runs_require_bound_evidence() {
        let mut dimensions = BTreeMap::new();
        let error = bind_evidence("local-comparable", None, None, &mut dimensions)
            .expect_err("unbound comparison must fail");
        assert!(error.to_string().contains("--stack-input"));
    }

    #[test]
    fn force_removes_only_known_stale_run_artifacts() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        fs::write(temporary.path().join("summary.json"), "stale").expect("stale summary");
        fs::write(temporary.path().join("keep.txt"), "keep").expect("unrelated file");

        assert!(prepare_output_directory(temporary.path(), false).is_err());
        prepare_output_directory(temporary.path(), true).expect("clean known artifacts");
        assert!(!temporary.path().join("summary.json").exists());
        assert!(temporary.path().join("keep.txt").exists());
    }

    #[test]
    fn diagnostic_runs_are_not_labeled_comparable() {
        assert_eq!(telemetry_mode("diagnostic"), "diagnostic");
        assert_eq!(telemetry_mode("local-comparable"), "comparable");
    }
}
