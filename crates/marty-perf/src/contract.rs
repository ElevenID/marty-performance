//! Workload-contract loading and validation.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use marty_perf_schema::{ExecutionProfile, WorkloadContract};
use sha2::{Digest, Sha256};

const CONTRACT_SCHEMA: &str = "marty.performance/workload/v1";
const FIXTURE_SCHEMA: &str = "marty.performance/lifecycle-fixture/v1";
const EXECUTORS: &[&str] = &[
    "per-vu-iterations",
    "constant-arrival-rate",
    "ramping-arrival-rate",
];

/// A validated contract with its resolved script and content digest.
pub(crate) struct ResolvedContract {
    pub(crate) contract: WorkloadContract,
    pub(crate) script: PathBuf,
    pub(crate) digest: String,
}

pub(crate) fn load(path: &Path) -> Result<ResolvedContract> {
    let scenario_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios")
        .canonicalize()
        .context("canonicalize repository scenario directory")?;
    let contract_path = path
        .canonicalize()
        .with_context(|| format!("canonicalize workload contract {}", path.display()))?;
    anyhow::ensure!(
        contract_path.starts_with(&scenario_root),
        "workload contract must be a reviewed file under the repository scenarios directory"
    );
    let bytes = fs::read(&contract_path)
        .with_context(|| format!("read workload contract {}", contract_path.display()))?;
    let contract: WorkloadContract = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse workload contract {}", contract_path.display()))?;
    validate(&contract)?;

    let directory = contract_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .context("canonicalize workload contract directory")?;
    let script = directory
        .join(&contract.script)
        .canonicalize()
        .context("locate workload script")?;
    anyhow::ensure!(
        script.starts_with(&directory),
        "workload script must remain inside the contract directory"
    );
    anyhow::ensure!(
        script.extension().and_then(|value| value.to_str()) == Some("js"),
        "workload script must be JavaScript"
    );

    Ok(ResolvedContract {
        contract,
        script,
        digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
    })
}

pub(crate) fn validate(contract: &WorkloadContract) -> Result<()> {
    anyhow::ensure!(
        contract.schema == CONTRACT_SCHEMA,
        "unsupported workload schema"
    );
    ensure_identifier(&contract.name, "workload name")?;
    ensure_identifier(&contract.revision, "workload revision")?;
    anyhow::ensure!(
        contract.fixture_schema == FIXTURE_SCHEMA,
        "unsupported fixture schema {}",
        contract.fixture_schema
    );
    anyhow::ensure!(
        !contract.operations.is_empty(),
        "workload operations are required"
    );
    anyhow::ensure!(
        !contract.profiles.is_empty(),
        "workload profiles are required"
    );

    let mut operation_names = BTreeSet::new();
    for operation in &contract.operations {
        ensure_identifier(&operation.name, "operation name")?;
        anyhow::ensure!(
            operation_names.insert(&operation.name),
            "duplicate operation {}",
            operation.name
        );
        anyhow::ensure!(
            matches!(
                operation.method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
            ),
            "unsupported method for {}",
            operation.name
        );
        anyhow::ensure!(
            operation.route.starts_with('/')
                && !operation.route.contains("//")
                && !operation.route.contains('?'),
            "{} must use a low-cardinality route template",
            operation.name
        );
    }

    for (name, profile) in &contract.profiles {
        ensure_identifier(name, "profile name")?;
        validate_profile(name, profile)?;
    }
    Ok(())
}

fn validate_profile(name: &str, profile: &ExecutionProfile) -> Result<()> {
    anyhow::ensure!(
        EXECUTORS.contains(&profile.executor.as_str()),
        "profile {name} uses unsupported executor {}",
        profile.executor
    );
    if let Some(value) = &profile.graceful_stop {
        validate_duration(value).with_context(|| format!("profile {name} graceful_stop"))?;
    }
    match profile.executor.as_str() {
        "per-vu-iterations" => {
            anyhow::ensure!(
                profile.vus.is_some_and(|value| value > 0)
                    && profile.iterations.is_some_and(|value| value > 0),
                "profile {name} requires positive vus and iterations"
            );
            anyhow::ensure!(
                profile.start_rate.is_none()
                    && profile.rate.is_none()
                    && profile.time_unit.is_none()
                    && profile.duration.is_none()
                    && profile.pre_allocated_vus.is_none()
                    && profile.max_vus.is_none()
                    && profile.stages.is_empty(),
                "profile {name} contains fields that per-vu-iterations ignores"
            );
        }
        "constant-arrival-rate" => {
            validate_arrival_pool(name, profile)?;
            anyhow::ensure!(
                profile.rate.is_some_and(|value| value > 0),
                "profile {name} requires a positive rate"
            );
            validate_duration(
                profile
                    .duration
                    .as_deref()
                    .context("constant profile duration is required")?,
            )
            .with_context(|| format!("profile {name} duration"))?;
            anyhow::ensure!(
                profile.vus.is_none()
                    && profile.iterations.is_none()
                    && profile.start_rate.is_none()
                    && profile.stages.is_empty(),
                "profile {name} contains fields that constant-arrival-rate ignores"
            );
        }
        "ramping-arrival-rate" => {
            validate_arrival_pool(name, profile)?;
            anyhow::ensure!(
                profile.start_rate.is_some(),
                "profile {name} requires start_rate"
            );
            anyhow::ensure!(!profile.stages.is_empty(), "profile {name} requires stages");
            anyhow::ensure!(
                profile.stages.iter().any(|stage| stage.target > 0),
                "profile {name} must contain a positive stage target"
            );
            for stage in &profile.stages {
                validate_duration(&stage.duration)
                    .with_context(|| format!("profile {name} stage duration"))?;
            }
            anyhow::ensure!(
                profile.vus.is_none()
                    && profile.iterations.is_none()
                    && profile.rate.is_none()
                    && profile.duration.is_none(),
                "profile {name} contains fields that ramping-arrival-rate ignores"
            );
        }
        _ => unreachable!("executor was checked above"),
    }
    Ok(())
}

fn validate_arrival_pool(name: &str, profile: &ExecutionProfile) -> Result<()> {
    validate_duration(
        profile
            .time_unit
            .as_deref()
            .context("arrival-rate time_unit is required")?,
    )
    .with_context(|| format!("profile {name} time_unit"))?;
    let initial = profile
        .pre_allocated_vus
        .context("arrival-rate pre_allocated_vus is required")?;
    let maximum = profile
        .max_vus
        .context("arrival-rate max_vus is required")?;
    anyhow::ensure!(
        initial > 0 && maximum >= initial,
        "profile {name} has an invalid VU pool"
    );
    Ok(())
}

fn validate_duration(value: &str) -> Result<()> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    anyhow::ensure!(
        !amount.is_empty()
            && amount.parse::<u64>().is_ok_and(|number| number > 0)
            && matches!(unit, "ms" | "s" | "m" | "h"),
        "invalid duration {value}"
    );
    Ok(())
}

fn ensure_identifier(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{label} must contain only lowercase letters, digits, and hyphens"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_perf_schema::{ExecutionStage, OperationContract};
    use std::collections::BTreeMap;

    fn contract() -> WorkloadContract {
        WorkloadContract {
            schema: CONTRACT_SCHEMA.to_owned(),
            name: "management-lifecycle".to_owned(),
            revision: "v1".to_owned(),
            script: "gateway.js".to_owned(),
            fixture_schema: FIXTURE_SCHEMA.to_owned(),
            operations: vec![OperationContract {
                name: "organization-list".to_owned(),
                method: "GET".to_owned(),
                route: "/v1/organizations".to_owned(),
            }],
            profiles: BTreeMap::from([
                (
                    "smoke".to_owned(),
                    ExecutionProfile {
                        executor: "per-vu-iterations".to_owned(),
                        vus: Some(1),
                        iterations: Some(1),
                        start_rate: None,
                        rate: None,
                        time_unit: None,
                        duration: None,
                        pre_allocated_vus: None,
                        max_vus: None,
                        stages: Vec::new(),
                        graceful_stop: Some("30s".to_owned()),
                    },
                ),
                (
                    "stress".to_owned(),
                    ExecutionProfile {
                        executor: "ramping-arrival-rate".to_owned(),
                        vus: None,
                        iterations: None,
                        start_rate: Some(1),
                        rate: None,
                        time_unit: Some("1s".to_owned()),
                        duration: None,
                        pre_allocated_vus: Some(2),
                        max_vus: Some(4),
                        stages: vec![ExecutionStage {
                            duration: "1m".to_owned(),
                            target: 4,
                        }],
                        graceful_stop: None,
                    },
                ),
            ]),
        }
    }

    #[test]
    fn accepts_supported_profiles_and_stable_operations() {
        validate(&contract()).expect("valid contract");
    }

    #[test]
    fn rejects_dynamic_operation_urls_and_invalid_vu_pools() {
        let mut value = contract();
        value.operations[0].route = "/v1/organizations/123?secret=true".to_owned();
        assert!(validate(&value).is_err());

        let mut value = contract();
        value
            .profiles
            .get_mut("stress")
            .expect("profile")
            .pre_allocated_vus = Some(10);
        assert!(validate(&value).is_err());
    }

    #[test]
    fn rejects_executor_fields_that_k6_would_silently_ignore() {
        let mut value = contract();
        value.profiles.get_mut("smoke").expect("profile").rate = Some(10);
        assert!(validate(&value).is_err());

        let mut value = contract();
        let profile = value.profiles.get_mut("stress").expect("profile");
        profile.rate = Some(10);
        assert!(validate(&value).is_err());

        let mut value = contract();
        let profile = value.profiles.get_mut("stress").expect("profile");
        for stage in &mut profile.stages {
            stage.target = 0;
        }
        assert!(validate(&value).is_err());
    }

    #[test]
    fn loader_rejects_unreviewed_external_contracts() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("contract.json");
        fs::write(
            &path,
            serde_json::to_vec(&contract()).expect("contract JSON"),
        )
        .expect("external contract");
        assert!(load(&path).is_err());
    }
}
