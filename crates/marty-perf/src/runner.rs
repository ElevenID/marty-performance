//! k6 scenario execution and run provenance.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use marty_perf_schema::{
    DoctorReport, ExecutionProfile, LifecycleFixture, PreparedStack, RunMetadata,
    TestWindowAttestation,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::Uuid;

use crate::{contract, fixture, tooling};

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

/// Inputs for one contract-defined workload run.
pub(crate) struct WorkloadRun<'a> {
    pub(crate) contract_path: &'a Path,
    pub(crate) profile_name: &'a str,
    pub(crate) fixture_path: &'a Path,
    pub(crate) session_file: &'a Path,
    pub(crate) base_url: &'a str,
    pub(crate) output_dir: &'a Path,
    pub(crate) result_class: &'a str,
    pub(crate) stack_input: Option<&'a Path>,
    pub(crate) doctor_report: Option<&'a Path>,
    pub(crate) target_environment: &'a str,
    pub(crate) test_window: &'a Path,
    pub(crate) allow_remote_target: bool,
    pub(crate) force: bool,
}

/// Inputs for one gateway smoke validation.
pub(crate) struct SmokeRun<'a> {
    pub(crate) base_url: &'a str,
    pub(crate) output_dir: &'a Path,
    pub(crate) result_class: &'a str,
    pub(crate) stack_input: Option<&'a Path>,
    pub(crate) doctor_report: Option<&'a Path>,
    pub(crate) allow_remote_target: bool,
    pub(crate) target_environment: &'a str,
    pub(crate) test_window: Option<&'a Path>,
    pub(crate) force: bool,
}

pub(crate) fn smoke(settings: &SmokeRun<'_>) -> Result<()> {
    anyhow::ensure!(
        RESULT_CLASSES.contains(&settings.result_class),
        "unsupported result class {}",
        settings.result_class
    );
    anyhow::ensure!(
        settings.result_class != "k8s-canonical",
        "k8s-canonical evidence requires the future Kubernetes runner"
    );
    let origin = validate_origin(settings.base_url)?;
    ensure_target_allowed(
        &origin,
        settings.target_environment,
        settings.allow_remote_target,
    )?;
    let metadata_path = settings.output_dir.join("run.json");

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
            telemetry_mode(settings.result_class).to_owned(),
        ),
        ("k6_version".to_owned(), tools.k6.version.clone()),
        (
            "target_environment".to_owned(),
            settings.target_environment.to_owned(),
        ),
    ]);
    if settings.target_environment == "production" {
        bind_test_window(
            settings
                .test_window
                .context("production smoke requires --test-window")?,
            &origin,
            &mut dimensions,
        )?;
    } else {
        anyhow::ensure!(
            settings.test_window.is_none(),
            "--test-window is only accepted for a production smoke target"
        );
    }
    bind_evidence(
        settings.result_class,
        settings.stack_input,
        settings.doctor_report,
        &mut dimensions,
    )?;
    prepare_output_directory(settings.output_dir, settings.force)?;
    let mut metadata = RunMetadata {
        schema: "marty.performance/run/v1".to_owned(),
        run_id,
        result_class: settings.result_class.to_owned(),
        scenario: "gateway-smoke".to_owned(),
        started_at: Utc::now().to_rfc3339(),
        base_url: normalized_origin(&origin),
        k6_mode: mode.to_owned(),
        k6_image: (mode == "container").then(|| tools.k6.image.clone()),
        exit_code: None,
        successful: false,
        dimensions,
    };
    write_metadata(&metadata_path, &metadata)?;

    let result = if mode == "local" {
        run_local(&origin, settings.output_dir)
    } else {
        run_container(&origin, settings.output_dir, &tools.k6.image)
    };
    finish_run(
        result,
        &mut metadata,
        &metadata_path,
        settings.output_dir,
        "gateway smoke scenario",
    )?;
    println!(
        "Smoke evidence written to {}.",
        settings.output_dir.display()
    );
    Ok(())
}

pub(crate) fn workload(settings: &WorkloadRun<'_>) -> Result<()> {
    anyhow::ensure!(
        RESULT_CLASSES.contains(&settings.result_class),
        "unsupported result class {}",
        settings.result_class
    );
    anyhow::ensure!(
        settings.result_class != "k8s-canonical",
        "k8s-canonical evidence requires the future Kubernetes runner"
    );
    let origin = validate_origin(settings.base_url)?;
    ensure_target_allowed(
        &origin,
        settings.target_environment,
        settings.allow_remote_target,
    )?;
    let resolved = contract::load(settings.contract_path)?;
    let profile = resolved
        .contract
        .profiles
        .get(settings.profile_name)
        .with_context(|| format!("unknown workload profile {}", settings.profile_name))?;
    let profile_json = serde_json::to_string(profile).context("serialize workload profile")?;
    let (fixture, fixture_digest) = fixture::load(settings.fixture_path)?;
    anyhow::ensure!(
        resolved.contract.fixture_schema == fixture.schema,
        "workload and fixture schemas do not match"
    );
    validate_session_file(settings.session_file)?;

    let tools = tooling::configuration()?;
    let local_k6 = tooling::local_k6_version();
    let local_compatible = tooling::compatible_local_k6(local_k6.as_deref(), &tools.k6.version);
    let mode = if local_compatible {
        "local"
    } else {
        "container"
    };
    let dimensions = workload_dimensions(
        settings,
        &resolved,
        profile,
        &fixture,
        fixture_digest,
        &tools.k6.version,
        &origin,
    )?;
    prepare_output_directory(settings.output_dir, settings.force)?;

    let metadata_path = settings.output_dir.join("run.json");
    let mut metadata = RunMetadata {
        schema: "marty.performance/run/v1".to_owned(),
        run_id: Uuid::new_v4().to_string(),
        result_class: settings.result_class.to_owned(),
        scenario: resolved.contract.name.clone(),
        started_at: Utc::now().to_rfc3339(),
        base_url: normalized_origin(&origin),
        k6_mode: mode.to_owned(),
        k6_image: (mode == "container").then(|| tools.k6.image.clone()),
        exit_code: None,
        successful: false,
        dimensions,
    };
    write_metadata(&metadata_path, &metadata)?;

    let result = if mode == "local" {
        run_local_workload(
            &origin,
            settings.output_dir,
            &resolved.script,
            settings.fixture_path,
            settings.session_file,
            &profile_json,
        )
    } else {
        run_container_workload(
            &origin,
            settings.output_dir,
            &resolved.script,
            settings.fixture_path,
            settings.session_file,
            &profile_json,
            &tools.k6.image,
        )
    };
    finish_run(
        result,
        &mut metadata,
        &metadata_path,
        settings.output_dir,
        "workload scenario",
    )?;
    println!(
        "Workload evidence written to {}.",
        settings.output_dir.display()
    );
    Ok(())
}

fn workload_dimensions(
    settings: &WorkloadRun<'_>,
    resolved: &contract::ResolvedContract,
    profile: &ExecutionProfile,
    fixture: &LifecycleFixture,
    fixture_digest: String,
    k6_version: &str,
    origin: &Url,
) -> Result<BTreeMap<String, String>> {
    let mut dimensions = BTreeMap::from([
        (
            "telemetry_mode".to_owned(),
            telemetry_mode(settings.result_class).to_owned(),
        ),
        ("k6_version".to_owned(), k6_version.to_owned()),
        (
            "target_environment".to_owned(),
            settings.target_environment.to_owned(),
        ),
        (
            "workload_revision".to_owned(),
            resolved.contract.revision.clone(),
        ),
        (
            "workload_contract_sha256".to_owned(),
            resolved.digest.clone(),
        ),
        ("profile".to_owned(), settings.profile_name.to_owned()),
        ("executor".to_owned(), profile.executor.clone()),
        ("fixture_sha256".to_owned(), fixture_digest),
        ("fixture_seed".to_owned(), fixture.seed.clone()),
    ]);
    insert_profile_dimensions(profile, &mut dimensions)?;
    bind_evidence(
        settings.result_class,
        settings.stack_input,
        settings.doctor_report,
        &mut dimensions,
    )?;
    let expires_at = bind_test_window(settings.test_window, origin, &mut dimensions)?;
    ensure_window_covers_profile(profile, expires_at, &mut dimensions)?;
    Ok(dimensions)
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

fn bind_test_window(
    path: &Path,
    origin: &Url,
    dimensions: &mut BTreeMap<String, String>,
) -> Result<DateTime<Utc>> {
    let (attestation, digest): (TestWindowAttestation, String) = read_evidence(path)?;
    anyhow::ensure!(
        attestation.schema == "marty.performance/test-window/v1",
        "unsupported test-window schema"
    );
    anyhow::ensure!(
        attestation.production_traffic_drained
            && attestation.public_ingress_disabled
            && attestation.synthetic_data_only,
        "test window must attest drained production traffic, disabled public ingress, and synthetic-only data"
    );
    let attested_origin = validate_origin(&attestation.target_origin)
        .context("test-window target_origin is invalid")?;
    anyhow::ensure!(
        normalized_origin(&attested_origin) == normalized_origin(origin),
        "test-window target does not match the requested gateway origin"
    );
    let starts_at = DateTime::parse_from_rfc3339(&attestation.starts_at)
        .context("test-window starts_at must be RFC 3339")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&attestation.expires_at)
        .context("test-window expires_at must be RFC 3339")?
        .with_timezone(&Utc);
    let now = Utc::now();
    anyhow::ensure!(
        starts_at <= now && now < expires_at,
        "test window is not currently active"
    );
    anyhow::ensure!(
        expires_at.signed_duration_since(starts_at).num_seconds() <= 12 * 60 * 60,
        "test window may not exceed 12 hours"
    );
    anyhow::ensure!(
        !attestation.change_reference.trim().is_empty()
            && attestation.change_reference.len() <= 128
            && !attestation.change_reference.chars().any(char::is_control),
        "test-window change_reference is invalid"
    );
    dimensions.insert("test_window_sha256".to_owned(), digest);
    dimensions.insert("test_window_starts_at".to_owned(), starts_at.to_rfc3339());
    dimensions.insert("test_window_expires_at".to_owned(), expires_at.to_rfc3339());
    dimensions.insert(
        "test_window_change_reference".to_owned(),
        attestation.change_reference,
    );
    Ok(expires_at)
}

fn insert_profile_dimensions(
    profile: &ExecutionProfile,
    dimensions: &mut BTreeMap<String, String>,
) -> Result<()> {
    let serialized = serde_json::to_vec(profile).context("serialize execution profile evidence")?;
    dimensions.insert(
        "execution_profile_sha256".to_owned(),
        format!("sha256:{}", hex::encode(Sha256::digest(&serialized))),
    );
    for (name, value) in [
        ("vus", profile.vus.map(|value| value.to_string())),
        (
            "iterations",
            profile.iterations.map(|value| value.to_string()),
        ),
        (
            "start_rate",
            profile.start_rate.map(|value| value.to_string()),
        ),
        ("rate", profile.rate.map(|value| value.to_string())),
        ("time_unit", profile.time_unit.clone()),
        ("duration", profile.duration.clone()),
        (
            "pre_allocated_vus",
            profile.pre_allocated_vus.map(|value| value.to_string()),
        ),
        ("max_vus", profile.max_vus.map(|value| value.to_string())),
        ("graceful_stop", profile.graceful_stop.clone()),
    ] {
        if let Some(value) = value {
            dimensions.insert(name.to_owned(), value);
        }
    }
    if !profile.stages.is_empty() {
        dimensions.insert(
            "stages".to_owned(),
            serde_json::to_string(&profile.stages).context("serialize execution stages")?,
        );
    }
    Ok(())
}

fn ensure_window_covers_profile(
    profile: &ExecutionProfile,
    expires_at: DateTime<Utc>,
    dimensions: &mut BTreeMap<String, String>,
) -> Result<()> {
    let main_seconds = match profile.executor.as_str() {
        "per-vu-iterations" => 5 * 60,
        "constant-arrival-rate" => duration_seconds(
            profile
                .duration
                .as_deref()
                .context("constant workload duration is missing")?,
        )?,
        "ramping-arrival-rate" => profile.stages.iter().try_fold(0_i64, |total, stage| {
            duration_seconds(&stage.duration).and_then(|seconds| {
                total
                    .checked_add(seconds)
                    .context("profile duration overflow")
            })
        })?,
        _ => anyhow::bail!("unsupported executor {}", profile.executor),
    };
    let graceful_seconds = profile
        .graceful_stop
        .as_deref()
        .map(duration_seconds)
        .transpose()?
        .unwrap_or_default();
    let expected_seconds = main_seconds
        .checked_add(graceful_seconds)
        .and_then(|seconds| seconds.checked_add(5 * 60))
        .context("profile duration overflow")?;
    anyhow::ensure!(
        expires_at.signed_duration_since(Utc::now()).num_seconds() >= expected_seconds,
        "test window expires before the workload, setup, and teardown can finish"
    );
    dimensions.insert(
        "expected_window_seconds".to_owned(),
        expected_seconds.to_string(),
    );
    Ok(())
}

fn duration_seconds(value: &str) -> Result<i64> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    let amount = amount
        .parse::<i64>()
        .context("duration amount is invalid")?;
    match unit {
        "ms" => Ok((amount + 999) / 1_000),
        "s" => Ok(amount),
        "m" => amount.checked_mul(60).context("duration overflow"),
        "h" => amount.checked_mul(60 * 60).context("duration overflow"),
        _ => anyhow::bail!("duration unit is invalid"),
    }
}

fn validate_session_file(path: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read session file {}", path.display()))?;
    anyhow::ensure!(bytes.len() <= 4_096, "session file is unexpectedly large");
    let value = std::str::from_utf8(&bytes)
        .context("session file must be UTF-8")?
        .trim();
    anyhow::ensure!(
        (16..=4_096).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b';'),
        "session file must contain one cookie-safe session ID"
    );
    Ok(())
}

fn run_local_workload(
    origin: &Url,
    output_dir: &Path,
    script: &Path,
    fixture_path: &Path,
    session_file: &Path,
    profile_json: &str,
) -> Result<Output> {
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
        .env("BASE_URL", normalized_origin(origin))
        .env("MARTY_PROFILE_JSON", profile_json)
        .env("FIXTURE_FILE", canonical_unicode(fixture_path)?)
        .env("SESSION_FILE", canonical_unicode(session_file)?)
        .arg(script)
        .output()
        .context("execute local k6 workload")
}

#[allow(clippy::too_many_arguments)]
fn run_container_workload(
    origin: &Url,
    output_dir: &Path,
    script: &Path,
    fixture_path: &Path,
    session_file: &Path,
    profile_json: &str,
    image: &str,
) -> Result<Output> {
    tooling::successful_stdout("docker", &["version", "--format", "{{.Server.Version}}"])
        .context("Docker is required because local k6 is unavailable")?;
    let script_dir = script.parent().context("workload script has no parent")?;
    let script_name = script
        .file_name()
        .and_then(|name| name.to_str())
        .context("workload script name is not Unicode")?;
    let output_dir = absolute_output(output_dir)?;
    let fixture_path = fixture_path
        .canonicalize()
        .context("canonicalize lifecycle fixture")?;
    let session_file = session_file
        .canonicalize()
        .context("canonicalize session file")?;
    let container_origin = docker_origin(origin)?;
    Command::new("docker")
        .args(["run", "--rm", "--network", "host"])
        .args(["--env", &format!("BASE_URL={container_origin}")])
        .args(["--env", &format!("MARTY_PROFILE_JSON={profile_json}")])
        .args(["--env", "FIXTURE_FILE=/fixtures/lifecycle.json"])
        .args(["--env", "SESSION_FILE=/run/secrets/session-id"])
        .args([
            "--volume",
            &format!("{}:/scripts:ro", docker_mount_path(script_dir)),
        ])
        .args([
            "--volume",
            &format!("{}:/results", docker_mount_path(&output_dir)),
        ])
        .args([
            "--volume",
            &format!(
                "{}:/fixtures/lifecycle.json:ro",
                docker_mount_path(&fixture_path)
            ),
        ])
        .args([
            "--volume",
            &format!(
                "{}:/run/secrets/session-id:ro",
                docker_mount_path(&session_file)
            ),
        ])
        .arg(image)
        .args([
            "run",
            "--summary-export",
            "/results/summary.json",
            "--out",
            "json=/results/samples.json",
            &format!("/scripts/{script_name}"),
        ])
        .output()
        .context("execute k6 workload container")
}

fn finish_run(
    result: Result<Output>,
    metadata: &mut RunMetadata,
    metadata_path: &Path,
    output_dir: &Path,
    label: &str,
) -> Result<()> {
    match result {
        Ok(output) => {
            fs::write(output_dir.join("k6.stdout.log"), &output.stdout)
                .context("write k6 stdout")?;
            fs::write(output_dir.join("k6.stderr.log"), &output.stderr)
                .context("write k6 stderr")?;
            metadata.exit_code = output.status.code();
            metadata.successful = output.status.success();
            write_metadata(metadata_path, metadata)?;
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            anyhow::ensure!(output.status.success(), "{label} failed");
        }
        Err(error) => {
            metadata.exit_code = None;
            metadata.successful = false;
            write_metadata(metadata_path, metadata)?;
            fs::write(output_dir.join("runner.error.log"), format!("{error:#}\n"))
                .context("write runner error")?;
            return Err(error);
        }
    }
    Ok(())
}

fn canonical_unicode(path: &Path) -> Result<String> {
    path.canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?
        .to_str()
        .map(ToOwned::to_owned)
        .context("path is not Unicode")
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

fn ensure_target_allowed(
    origin: &Url,
    target_environment: &str,
    allow_remote_target: bool,
) -> Result<()> {
    anyhow::ensure!(
        matches!(target_environment, "local" | "isolated-test" | "production"),
        "unsupported target environment {target_environment}"
    );
    let local = is_local_origin(origin);
    anyhow::ensure!(
        target_environment != "local" || local,
        "a remote target cannot be declared as local"
    );
    anyhow::ensure!(
        local || allow_remote_target,
        "remote targets require --allow-remote-target; never use production traffic or personal data"
    );
    Ok(())
}

fn is_local_origin(origin: &Url) -> bool {
    match origin.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => {
            domain.eq_ignore_ascii_case("localhost")
                || domain.eq_ignore_ascii_case("host.docker.internal")
        }
        None => false,
    }
}

fn normalized_origin(origin: &Url) -> String {
    origin.to_string().trim_end_matches('/').to_owned()
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
    Ok(normalized_origin(&url))
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
        assert!(ensure_target_allowed(&remote, "isolated-test", false).is_err());
        assert!(ensure_target_allowed(&remote, "local", true).is_err());
        ensure_target_allowed(&remote, "isolated-test", true).expect("explicit remote target");

        let local = validate_origin("http://127.0.0.1:28080").expect("local origin");
        ensure_target_allowed(&local, "local", false).expect("loopback target");
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

    #[test]
    fn active_test_window_must_match_target_and_shutdown_conditions() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("window.json");
        let now = Utc::now();
        let attestation = TestWindowAttestation {
            schema: "marty.performance/test-window/v1".to_owned(),
            target_origin: "http://127.0.0.1:28000".to_owned(),
            starts_at: (now - chrono::Duration::minutes(5)).to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(55)).to_rfc3339(),
            change_reference: "perf-window-001".to_owned(),
            production_traffic_drained: true,
            public_ingress_disabled: true,
            synthetic_data_only: true,
        };
        fs::write(
            &path,
            serde_json::to_vec(&attestation).expect("attestation JSON"),
        )
        .expect("write attestation");
        let origin = validate_origin("http://127.0.0.1:28000").expect("origin");
        let mut dimensions = BTreeMap::new();
        bind_test_window(&path, &origin, &mut dimensions).expect("active test window");
        assert!(dimensions.contains_key("test_window_sha256"));

        let other = validate_origin("http://127.0.0.1:28001").expect("other origin");
        assert!(bind_test_window(&path, &other, &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn session_file_rejects_multiple_or_unsafe_values() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("session-id");
        fs::write(&path, "0123456789abcdef\n").expect("session file");
        validate_session_file(&path).expect("cookie-safe session");
        fs::write(&path, "0123456789abcdef;other=value").expect("unsafe session file");
        assert!(validate_session_file(&path).is_err());
    }

    #[test]
    fn test_window_must_cover_profile_setup_execution_and_teardown() {
        let mut profile = ExecutionProfile {
            executor: "constant-arrival-rate".to_owned(),
            vus: None,
            iterations: None,
            start_rate: None,
            rate: Some(10),
            time_unit: Some("1s".to_owned()),
            duration: Some("2h".to_owned()),
            pre_allocated_vus: Some(10),
            max_vus: Some(50),
            stages: Vec::new(),
            graceful_stop: Some("1m".to_owned()),
        };
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        assert!(ensure_window_covers_profile(&profile, expires_at, &mut BTreeMap::new()).is_err());

        profile.duration = Some("10m".to_owned());
        let mut dimensions = BTreeMap::new();
        ensure_window_covers_profile(&profile, expires_at, &mut dimensions)
            .expect("short profile fits the window");
        assert_eq!(dimensions["expected_window_seconds"], "960");
        insert_profile_dimensions(&profile, &mut dimensions).expect("profile dimensions");
        assert_eq!(dimensions["rate"], "10");
        assert!(dimensions.contains_key("execution_profile_sha256"));
    }
}
