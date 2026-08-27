//! Tool configuration and process helpers.

use std::process::{Command, Output};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct ToolConfiguration {
    pub(crate) schema: String,
    pub(crate) k6: K6Configuration,
}

#[derive(Debug, Deserialize)]
pub(crate) struct K6Configuration {
    pub(crate) version: String,
    pub(crate) image: String,
}

pub(crate) fn configuration() -> Result<ToolConfiguration> {
    let configuration: ToolConfiguration = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/tools.json"
    )))
    .context("parse embedded tool configuration")?;
    anyhow::ensure!(
        configuration.schema == "marty.performance/tools/v1",
        "unsupported tool configuration schema {}",
        configuration.schema
    );
    let (_, digest) = configuration
        .k6
        .image
        .rsplit_once("@sha256:")
        .context("k6 image must be digest pinned")?;
    anyhow::ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "k6 image must contain a valid lowercase SHA-256 digest"
    );
    Ok(configuration)
}

pub(crate) fn local_k6_version() -> Option<String> {
    successful_stdout("k6", &["version"]).ok()
}

pub(crate) fn compatible_local_k6(detected: Option<&str>, configured: &str) -> bool {
    let expected = format!("v{configured}");
    detected.is_some_and(|value| {
        value
            .split(|character: char| character.is_whitespace() || character == ',')
            .any(|token| token == configured || token == expected)
    })
}

pub(crate) fn output(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("execute {program}"))
}

pub(crate) fn successful_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = output(program, args)?;
    anyhow::ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_k6_requires_the_configured_version() {
        assert!(compatible_local_k6(
            Some("k6.exe v1.3.0 (commit/go1.25)"),
            "1.3.0"
        ));
        assert!(!compatible_local_k6(
            Some("k6 v1.2.0 (commit/go1.24)"),
            "1.3.0"
        ));
        assert!(!compatible_local_k6(None, "1.3.0"));
    }
}
