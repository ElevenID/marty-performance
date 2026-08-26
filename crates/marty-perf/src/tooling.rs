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
    anyhow::ensure!(
        configuration.k6.image.contains("@sha256:"),
        "k6 image must be digest pinned"
    );
    Ok(configuration)
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
