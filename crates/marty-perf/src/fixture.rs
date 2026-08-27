//! Deterministic synthetic lifecycle fixture generation.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use marty_perf_schema::LifecycleFixture;
use sha2::{Digest, Sha256};

const FIXTURE_SCHEMA: &str = "marty.performance/lifecycle-fixture/v1";

pub(crate) fn generate(seed: &str, output: &Path, force: bool) -> Result<()> {
    validate_seed(seed)?;
    anyhow::ensure!(
        force || !output.exists(),
        "{} already exists; pass --force to replace it",
        output.display()
    );
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create fixture directory {}", parent.display()))?;
    }
    let fixture = from_seed(seed);
    let serialized =
        serde_json::to_string_pretty(&fixture).context("serialize lifecycle fixture")?;
    fs::write(output, format!("{serialized}\n"))
        .with_context(|| format!("write {}", output.display()))?;
    println!(
        "Synthetic lifecycle fixture written to {}.",
        output.display()
    );
    Ok(())
}

pub(crate) fn load(path: &Path) -> Result<(LifecycleFixture, String)> {
    let bytes =
        fs::read(path).with_context(|| format!("read lifecycle fixture {}", path.display()))?;
    let fixture: LifecycleFixture = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse lifecycle fixture {}", path.display()))?;
    validate(&fixture)?;
    Ok((
        fixture,
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
    ))
}

fn from_seed(seed: &str) -> LifecycleFixture {
    let digest = hex::encode(Sha256::digest(seed.as_bytes()));
    let suffix = digest[..12].to_owned();
    LifecycleFixture {
        schema: FIXTURE_SCHEMA.to_owned(),
        seed: seed.to_owned(),
        suffix: suffix.clone(),
        organization_name: format!("perf-org-{suffix}"),
        organization_display_name: format!("Synthetic Performance Organization {suffix}"),
        trust_profile_name: format!("perf-trust-{suffix}"),
        credential_template_name: format!("perf-employee-badge-{suffix}"),
        presentation_policy_name: format!("perf-employee-access-{suffix}"),
        deployment_profile_name: format!("perf-deployment-{suffix}"),
        site_id: format!("perf-site-{suffix}"),
    }
}

fn validate(fixture: &LifecycleFixture) -> Result<()> {
    anyhow::ensure!(
        fixture.schema == FIXTURE_SCHEMA,
        "unsupported lifecycle fixture schema"
    );
    validate_seed(&fixture.seed)?;
    let expected = from_seed(&fixture.seed);
    anyhow::ensure!(
        fixture.suffix == expected.suffix
            && fixture.organization_name == expected.organization_name
            && fixture.organization_display_name == expected.organization_display_name
            && fixture.trust_profile_name == expected.trust_profile_name
            && fixture.credential_template_name == expected.credential_template_name
            && fixture.presentation_policy_name == expected.presentation_policy_name
            && fixture.deployment_profile_name == expected.deployment_profile_name
            && fixture.site_id == expected.site_id,
        "lifecycle fixture contents do not match its seed"
    );
    Ok(())
}

fn validate_seed(seed: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=64).contains(&seed.len())
            && seed.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_')),
        "seed must contain 1-64 lowercase letters, digits, hyphens, or underscores"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_produces_deterministic_synthetic_names() {
        let first = from_seed("campaign-001");
        let second = from_seed("campaign-001");
        assert_eq!(first.organization_name, second.organization_name);
        assert!(first.organization_name.starts_with("perf-org-"));
        validate(&first).expect("valid deterministic fixture");
    }

    #[test]
    fn changed_or_personal_seed_content_is_rejected() {
        let mut fixture = from_seed("campaign-001");
        fixture.site_id = "unexpected".to_owned();
        assert!(validate(&fixture).is_err());
        assert!(validate_seed("Person Name").is_err());
    }
}
