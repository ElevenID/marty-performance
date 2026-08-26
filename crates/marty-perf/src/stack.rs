//! Immutable stack-manifest validation and rendering.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use chrono::Utc;
use marty_perf_schema::{PreparedStack, StackManifest};
use sha2::{Digest, Sha256};
use url::Url;

const REQUIRED_IMAGES: &[(&str, &str)] = &[
    ("MARTY_UI_IMAGE", "ui"),
    ("MARTY_SERVICES_IMAGE", "services"),
    ("MARTY_MIGRATIONS_IMAGE", "migrations"),
    ("MARTY_ISSUANCE_IMAGE", "marty-credentials-issuance"),
];
const FORBIDDEN_MARKERS: &[&str] = &[
    "square",
    "subscription",
    "billing",
    "product-catalog",
    "product_catalog",
];

pub(crate) fn prepare(manifest_path: &Path, output_dir: &Path, force: bool) -> Result<()> {
    let bytes = fs::read(manifest_path)
        .with_context(|| format!("read stack manifest {}", manifest_path.display()))?;
    let manifest: StackManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse stack manifest {}", manifest_path.display()))?;
    validate(&manifest, &bytes)?;
    let images = image_map(&manifest)?;

    let env_path = output_dir.join("stack.env");
    let evidence_path = output_dir.join("stack-input.json");
    if !force {
        anyhow::ensure!(
            !env_path.exists() && !evidence_path.exists(),
            "{} already contains prepared stack files; pass --force to replace them",
            output_dir.display()
        );
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;

    let source_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let prepared = PreparedStack {
        schema: "marty.performance/stack-input/v1".to_owned(),
        prepared_at: Utc::now().to_rfc3339(),
        source_manifest: manifest_path.display().to_string(),
        source_manifest_sha256: source_digest,
        release: manifest.release.clone(),
        images: images.clone(),
        components: manifest.components,
    };
    let evidence = serde_json::to_string_pretty(&prepared).context("serialize prepared stack")?;
    fs::write(&evidence_path, format!("{evidence}\n"))
        .with_context(|| format!("write {}", evidence_path.display()))?;
    let environment = images
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&env_path, format!("{environment}\n"))
        .with_context(|| format!("write {}", env_path.display()))?;

    println!(
        "Prepared {} with {} immutable image roles in {}.",
        prepared.release,
        prepared.images.len(),
        output_dir.display()
    );
    Ok(())
}

fn validate(manifest: &StackManifest, original: &[u8]) -> Result<()> {
    anyhow::ensure!(
        manifest.schema == "marty.stack/v1",
        "manifest schema must be marty.stack/v1"
    );
    anyhow::ensure!(
        manifest.release.starts_with("marty-ui@"),
        "release must start with marty-ui@"
    );
    anyhow::ensure!(
        !manifest.components.is_empty(),
        "manifest components must not be empty"
    );
    let serialized = String::from_utf8_lossy(original).to_ascii_lowercase();
    for marker in FORBIDDEN_MARKERS {
        anyhow::ensure!(
            !serialized.contains(marker),
            "forbidden commerce marker in public stack manifest: {marker}"
        );
    }

    let mut names = BTreeSet::new();
    for component in &manifest.components {
        anyhow::ensure!(
            !component.name.trim().is_empty(),
            "component name is required"
        );
        anyhow::ensure!(
            names.insert(&component.name),
            "duplicate component name {}",
            component.name
        );
        anyhow::ensure!(
            component.repository.split_once('/').is_some(),
            "{} repository must be owner/name",
            component.name
        );
        anyhow::ensure!(
            is_lower_hex(&component.commit, 40),
            "{} commit must be a full lowercase SHA",
            component.name
        );
        anyhow::ensure!(
            !component.artifacts.is_empty(),
            "{} must contain an artifact",
            component.name
        );
        for artifact in &component.artifacts {
            anyhow::ensure!(
                matches!(
                    artifact.artifact_type.as_str(),
                    "crate" | "python" | "npm" | "oci" | "release"
                ),
                "{} contains unsupported artifact type {}",
                component.name,
                artifact.artifact_type
            );
            anyhow::ensure!(
                is_digest(&artifact.digest),
                "{} contains an invalid SHA-256 digest",
                component.name
            );
            if artifact.artifact_type == "oci" {
                validate_oci_uri(&artifact.uri)
                    .with_context(|| format!("{} contains an invalid OCI URI", component.name))?;
            } else {
                validate_https(&artifact.uri).with_context(|| {
                    format!("{} contains an invalid artifact URL", component.name)
                })?;
            }
            validate_https(
                artifact
                    .sbom
                    .as_deref()
                    .context("artifact SBOM URL is required")?,
            )
            .with_context(|| format!("{} contains an invalid SBOM URL", component.name))?;
            validate_https(
                artifact
                    .provenance
                    .as_deref()
                    .context("artifact provenance URL is required")?,
            )
            .with_context(|| format!("{} contains an invalid provenance URL", component.name))?;
        }
    }
    Ok(())
}

fn image_map(manifest: &StackManifest) -> Result<BTreeMap<String, String>> {
    let images: Vec<_> = manifest
        .components
        .iter()
        .flat_map(|component| component.artifacts.iter())
        .filter(|artifact| artifact.artifact_type == "oci")
        .collect();
    let mut result = BTreeMap::new();
    for (variable, repository) in REQUIRED_IMAGES {
        let matches: Vec<_> = images
            .iter()
            .filter(|artifact| artifact.uri.rsplit('/').next() == Some(*repository))
            .collect();
        anyhow::ensure!(
            matches.len() == 1,
            "expected exactly one OCI image named {repository}, found {}",
            matches.len()
        );
        let artifact = matches[0];
        result.insert(
            (*variable).to_owned(),
            format!("{}@{}", artifact.uri, artifact.digest),
        );
    }
    Ok(result)
}

fn validate_oci_uri(uri: &str) -> Result<()> {
    anyhow::ensure!(!uri.contains("://"), "OCI URI must not contain a scheme");
    anyhow::ensure!(!uri.contains('@'), "OCI URI must not contain a digest");
    let (registry, path) = uri
        .split_once('/')
        .context("OCI URI must be registry/path")?;
    anyhow::ensure!(
        !registry.is_empty() && !path.is_empty(),
        "OCI URI must be registry/path"
    );
    anyhow::ensure!(
        !path.rsplit('/').next().unwrap_or_default().contains(':'),
        "OCI URI must not contain a mutable tag"
    );
    anyhow::ensure!(
        uri.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || b"./_-".contains(&byte)),
        "OCI URI contains unsupported characters"
    );
    Ok(())
}

fn validate_https(value: &str) -> Result<()> {
    let url = Url::parse(value).context("evidence URL must be absolute")?;
    anyhow::ensure!(url.scheme() == "https", "evidence URL must use HTTPS");
    anyhow::ensure!(url.host_str().is_some(), "evidence URL must contain a host");
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "evidence URL must not contain credentials"
    );
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_perf_schema::{StackArtifact, StackComponent};

    fn component(name: &str, image: &str, digit: char) -> StackComponent {
        StackComponent {
            name: name.to_owned(),
            repository: "ElevenID/example".to_owned(),
            version: "1.0.0".to_owned(),
            commit: digit.to_string().repeat(40),
            artifacts: vec![StackArtifact {
                artifact_type: "oci".to_owned(),
                uri: format!("ghcr.io/elevenid/{image}"),
                digest: format!("sha256:{}", digit.to_string().repeat(64)),
                sbom: None,
                provenance: None,
            }],
        }
    }

    fn manifest() -> StackManifest {
        StackManifest {
            schema: "marty.stack/v1".to_owned(),
            release: "marty-ui@1.2.3".to_owned(),
            generated_at: None,
            components: vec![
                component("ui", "ui", '1'),
                component("services", "services", '2'),
                component("migrations", "migrations", '3'),
                component("issuance", "marty-credentials-issuance", '4'),
            ],
        }
    }

    #[test]
    fn maps_required_images_to_digest_only_inputs() {
        let images = image_map(&manifest()).expect("valid image map");
        assert_eq!(images.len(), 4);
        assert_eq!(
            images["MARTY_SERVICES_IMAGE"],
            format!("ghcr.io/elevenid/services@sha256:{}", "2".repeat(64))
        );
    }

    #[test]
    fn mutable_image_tag_is_rejected() {
        let error = validate_oci_uri("ghcr.io/elevenid/services:latest")
            .expect_err("mutable tag must fail");
        assert!(error.to_string().contains("mutable tag"));
    }

    #[test]
    fn duplicate_image_role_is_rejected() {
        let mut value = manifest();
        value
            .components
            .push(component("services-copy", "services", '5'));
        let error = image_map(&value).expect_err("duplicate role must fail");
        assert!(error.to_string().contains("found 2"));
    }

    #[test]
    fn prepares_versioned_evidence_and_environment() {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/stack-manifest.json");
        let temporary = tempfile::tempdir().expect("temporary directory");
        prepare(&fixture, temporary.path(), false).expect("prepare fixture");

        let environment =
            fs::read_to_string(temporary.path().join("stack.env")).expect("stack environment");
        assert!(environment
            .contains("MARTY_SERVICES_IMAGE=ghcr.io/elevenid/marty-ui-oss/services@sha256:"));
        let evidence: PreparedStack = serde_json::from_slice(
            &fs::read(temporary.path().join("stack-input.json")).expect("stack evidence"),
        )
        .expect("valid prepared stack");
        assert_eq!(evidence.schema, "marty.performance/stack-input/v1");
        assert_eq!(evidence.release, "marty-ui@1.2.3");
        assert!(is_digest(&evidence.source_manifest_sha256));
    }
}
