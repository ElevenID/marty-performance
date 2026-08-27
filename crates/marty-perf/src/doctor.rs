//! Host and execution-environment diagnostics.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::Utc;
use marty_perf_schema::{DockerEvidence, DoctorReport, HostEvidence, K6Evidence};
use sysinfo::System;

use crate::tooling;

pub(crate) fn run(
    output: &Path,
    force: bool,
    require_comparable: bool,
    allowed_container_prefixes: &[String],
) -> Result<()> {
    ensure_writable(output, force)?;
    let tools = tooling::configuration()?;
    let allowed_container_prefixes = validate_container_prefixes(allowed_container_prefixes)?;
    let mut system = System::new_all();
    system.refresh_all();

    let host = HostEvidence {
        operating_system: System::name().unwrap_or_else(|| std::env::consts::OS.to_owned()),
        architecture: std::env::consts::ARCH.to_owned(),
        operating_system_version: System::long_os_version(),
        kernel_version: System::kernel_version(),
        cpu_brand: system
            .cpus()
            .first()
            .map(|cpu| cpu.brand().trim().to_owned())
            .filter(|brand| !brand.is_empty())
            .unwrap_or_else(|| "unknown".to_owned()),
        logical_cpus: system.cpus().len(),
        physical_cores: System::physical_core_count(),
        total_memory_bytes: system.total_memory(),
    };

    let docker = docker_evidence(&allowed_container_prefixes);
    let local_k6 = tooling::local_k6_version();
    let local_compatible = tooling::compatible_local_k6(local_k6.as_deref(), &tools.k6.version);
    let k6 = K6Evidence {
        mode: if local_compatible {
            "local".to_owned()
        } else {
            "container".to_owned()
        },
        configured_version: tools.k6.version,
        local_version: local_k6,
        local_compatible,
        container_image: tools.k6.image,
    };

    let mut warnings = Vec::new();
    if let Some(count) = docker
        .unrelated_running_containers
        .filter(|count| *count > 0)
    {
        warnings.push(format!(
            "{count} unrelated container(s) are running; stop them or declare an intended name prefix before a comparable run"
        ));
    }
    if k6.local_version.is_some() && !k6.local_compatible {
        warnings.push(format!(
            "local k6 does not match configured version {}; the pinned container will be used",
            k6.configured_version
        ));
    }
    if docker
        .server_cpus
        .is_some_and(|cpus| cpus < host.logical_cpus)
    {
        warnings.push("Docker sees fewer logical CPUs than the host".to_owned());
    }
    if docker
        .server_memory_bytes
        .is_some_and(|memory| memory < host.total_memory_bytes)
    {
        warnings.push(
            "Docker memory is capped below host memory; retain the cap in run provenance"
                .to_owned(),
        );
    }

    let valid = docker.available;
    let comparable = valid && docker.unrelated_running_containers == Some(0);
    let report = DoctorReport {
        schema: "marty.performance/doctor/v1".to_owned(),
        collected_at: Utc::now().to_rfc3339(),
        valid,
        comparable,
        host,
        docker,
        k6,
        warnings,
    };
    write_json(output, &report)?;
    println!(
        "Wrote {} host profile to {} (valid={}, comparable={}).",
        report.k6.mode,
        output.display(),
        report.valid,
        report.comparable
    );
    anyhow::ensure!(
        report.valid,
        "Docker server is required for stack performance runs"
    );
    anyhow::ensure!(
        !require_comparable || report.comparable,
        "host is not currently suitable for a comparable run; inspect doctor warnings"
    );
    Ok(())
}

fn docker_evidence(allowed_container_prefixes: &[String]) -> DockerEvidence {
    const VERSION_FORMAT: &str = "{{.Client.Version}}|{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}|{{.Server.KernelVersion}}";
    const INFO_FORMAT: &str = "{{.NCPU}}|{{.MemTotal}}";

    let version =
        match tooling::successful_stdout("docker", &["version", "--format", VERSION_FORMAT]) {
            Ok(value) => value,
            Err(error) => {
                return DockerEvidence {
                    error: Some(format!("{error:#}")),
                    allowed_container_prefixes: allowed_container_prefixes.to_vec(),
                    ..DockerEvidence::default()
                };
            }
        };
    let fields: Vec<_> = version.split('|').collect();
    if fields.len() != 5 {
        return DockerEvidence {
            error: Some("Docker returned an unexpected version record".to_owned()),
            allowed_container_prefixes: allowed_container_prefixes.to_vec(),
            ..DockerEvidence::default()
        };
    }

    let info = tooling::successful_stdout("docker", &["info", "--format", INFO_FORMAT]).ok();
    let info_fields: Vec<_> = info.as_deref().unwrap_or_default().split('|').collect();
    let running = tooling::successful_stdout("docker", &["ps", "--format", "{{.Names}}"]).ok();
    let container_counts = running
        .as_deref()
        .map(|value| classify_running_containers(value, allowed_container_prefixes));

    DockerEvidence {
        available: true,
        client_version: Some(fields[0].to_owned()),
        server_version: Some(fields[1].to_owned()),
        server_os: Some(fields[2].to_owned()),
        server_arch: Some(fields[3].to_owned()),
        server_kernel: Some(fields[4].to_owned()),
        server_cpus: info_fields.first().and_then(|value| value.parse().ok()),
        server_memory_bytes: info_fields.get(1).and_then(|value| value.parse().ok()),
        running_containers: container_counts.map(|counts| counts.0),
        allowed_running_containers: container_counts.map(|counts| counts.1),
        unrelated_running_containers: container_counts.map(|counts| counts.2),
        allowed_container_prefixes: allowed_container_prefixes.to_vec(),
        error: None,
    }
}

fn validate_container_prefixes(prefixes: &[String]) -> Result<Vec<String>> {
    let mut validated = prefixes.to_vec();
    for prefix in &validated {
        anyhow::ensure!(
            prefix.len() >= 4 && prefix.trim() == prefix,
            "allowed container prefixes must contain at least four characters and have no surrounding whitespace"
        );
        anyhow::ensure!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "allowed container prefix {prefix:?} contains unsupported characters"
        );
    }
    validated.sort();
    validated.dedup();
    Ok(validated)
}

fn classify_running_containers(names: &str, allowed_prefixes: &[String]) -> (usize, usize, usize) {
    let names: Vec<_> = names
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    let allowed = names
        .iter()
        .filter(|name| {
            allowed_prefixes
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .count();
    (names.len(), allowed, names.len().saturating_sub(allowed))
}

fn ensure_writable(path: &Path, force: bool) -> Result<()> {
    anyhow::ensure!(
        force || !path.exists(),
        "{} already exists; pass --force to replace it",
        path.display()
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let serialized = serde_json::to_string_pretty(value).context("serialize doctor evidence")?;
    fs::write(path, format!("{serialized}\n")).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intended_test_containers_are_not_counted_as_unrelated() {
        let counts = classify_running_containers(
            "marty-perf-gateway-1\nmarty-perf-postgres-1\nunrelated-service\n",
            &["marty-perf-".to_owned()],
        );
        assert_eq!(counts, (3, 2, 1));
    }

    #[test]
    fn empty_or_ambiguous_container_prefixes_are_rejected() {
        assert!(validate_container_prefixes(&[String::new()]).is_err());
        assert!(validate_container_prefixes(&["m".to_owned()]).is_err());
        assert!(validate_container_prefixes(&["marty perf".to_owned()]).is_err());
    }
}
