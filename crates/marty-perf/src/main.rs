//! Command-line entry point for reproducible Marty performance runs.

mod doctor;
mod runner;
mod stack;
mod tooling;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "marty-perf", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Capture hardware and tool evidence before running a benchmark.
    Doctor(DoctorArgs),
    /// Work with immutable Marty stack inputs.
    Stack(StackArgs),
    /// Execute a performance scenario.
    Run(RunArgs),
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// JSON evidence destination.
    #[arg(long, default_value = "reports/doctor.json")]
    output: PathBuf,
    /// Replace an existing evidence file.
    #[arg(long)]
    force: bool,
    /// Exit unsuccessfully when unrelated containers make comparison unsafe.
    #[arg(long)]
    require_comparable: bool,
    /// Treat running containers whose names start with this prefix as intended.
    #[arg(long = "allow-container-prefix")]
    allowed_container_prefixes: Vec<String>,
}

#[derive(Debug, Args)]
struct StackArgs {
    #[command(subcommand)]
    command: StackCommand,
}

#[derive(Debug, Subcommand)]
enum StackCommand {
    /// Validate a release manifest and render digest-only stack inputs.
    Prepare(StackPrepareArgs),
}

#[derive(Debug, Args)]
struct StackPrepareArgs {
    /// Released `marty.stack/v1` manifest.
    #[arg(long)]
    manifest: PathBuf,
    /// Directory for stack.env and stack-input.json.
    #[arg(long, default_value = "reports/prepared-stack")]
    output_dir: PathBuf,
    /// Replace generated files in an existing output directory.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(subcommand)]
    command: RunCommand,
}

#[derive(Debug, Subcommand)]
enum RunCommand {
    /// Verify gateway health and full-stack readiness with a small k6 run.
    Smoke(SmokeArgs),
}

#[derive(Debug, Args)]
struct SmokeArgs {
    /// Gateway origin, without credentials, query, or fragment.
    #[arg(long)]
    base_url: String,
    /// Directory for metadata, samples, logs, and the k6 summary.
    #[arg(long, default_value = "reports/smoke")]
    output_dir: PathBuf,
    /// Result classification retained in metadata.
    #[arg(long, default_value = "migration-preview")]
    result_class: String,
    /// Prepared `stack-input.json` to bind into run provenance.
    #[arg(long)]
    stack_input: Option<PathBuf>,
    /// `doctor.json` used to qualify non-preview runs.
    #[arg(long)]
    doctor_report: Option<PathBuf>,
    /// Explicitly permit a non-loopback target such as an isolated test cluster.
    #[arg(long)]
    allow_remote_target: bool,
    /// Remove and replace known run artifacts in the output directory.
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor(args) => doctor::run(
            &args.output,
            args.force,
            args.require_comparable,
            &args.allowed_container_prefixes,
        ),
        Command::Stack(args) => match args.command {
            StackCommand::Prepare(args) => {
                stack::prepare(&args.manifest, &args.output_dir, args.force)
            }
        },
        Command::Run(args) => match args.command {
            RunCommand::Smoke(args) => runner::smoke(
                &args.base_url,
                &args.output_dir,
                &args.result_class,
                args.stack_input.as_deref(),
                args.doctor_report.as_deref(),
                args.allow_remote_target,
                args.force,
            ),
        },
    }
}
