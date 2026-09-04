//! Command-line entry point for reproducible Marty performance runs.

mod contract;
mod doctor;
mod fixture;
mod issuance_qualification;
mod runner;
mod stack;
mod tooling;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Work with deterministic synthetic fixtures.
    Fixture(FixtureArgs),
    /// Validate workload definitions without executing them.
    Scenario(ScenarioArgs),
    /// Execute a performance scenario.
    Run(Box<RunArgs>),
    /// Prepare or execute evidence-qualified microbenchmarks.
    Qualification(QualificationArgs),
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
    /// Execute a contract-defined authenticated workload.
    Workload(WorkloadArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TargetEnvironment {
    /// Loopback development or mock target.
    Local,
    /// Isolated non-production performance environment.
    IsolatedTest,
    /// Production hardware in an approved drained test window.
    Production,
}

impl TargetEnvironment {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::IsolatedTest => "isolated-test",
            Self::Production => "production",
        }
    }
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
    /// Declared target environment.
    #[arg(long, value_enum, default_value = "local")]
    target_environment: TargetEnvironment,
    /// Required test-window evidence when smoke targets production hardware.
    #[arg(long)]
    test_window: Option<PathBuf>,
    /// Remove and replace known run artifacts in the output directory.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct WorkloadArgs {
    /// Versioned workload contract JSON.
    #[arg(long)]
    contract: PathBuf,
    /// Named execution profile from the workload contract.
    #[arg(long)]
    profile: String,
    /// Deterministic synthetic lifecycle fixture JSON.
    #[arg(long)]
    fixture: PathBuf,
    /// File containing only a valid gateway session ID; never retained in evidence.
    #[arg(long)]
    session_file: PathBuf,
    /// Gateway origin, without credentials, query, or fragment.
    #[arg(long)]
    base_url: String,
    /// Directory for metadata, samples, logs, and the k6 summary.
    #[arg(long, default_value = "reports/workload")]
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
    /// Declared target environment.
    #[arg(long, value_enum)]
    target_environment: TargetEnvironment,
    /// Time-bounded proof that production traffic and ingress are disabled.
    #[arg(long)]
    test_window: PathBuf,
    /// Explicitly permit a non-loopback target such as isolated production hardware.
    #[arg(long)]
    allow_remote_target: bool,
    /// Remove and replace known run artifacts in the output directory.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct FixtureArgs {
    #[command(subcommand)]
    command: FixtureCommand,
}

#[derive(Debug, Subcommand)]
enum FixtureCommand {
    /// Generate a deterministic synthetic management-lifecycle fixture.
    Generate(FixtureGenerateArgs),
}

#[derive(Debug, Args)]
struct FixtureGenerateArgs {
    /// Stable non-personal campaign seed.
    #[arg(long)]
    seed: String,
    /// Fixture JSON destination.
    #[arg(long, default_value = "reports/fixtures/management-lifecycle.json")]
    output: PathBuf,
    /// Replace an existing fixture file.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct QualificationArgs {
    #[command(subcommand)]
    command: QualificationCommand,
}

#[derive(Debug, Subcommand)]
enum QualificationCommand {
    /// Work with the SD-JWT issuance qualification protocol.
    Issuance(IssuanceQualificationArgs),
}

#[derive(Debug, Args)]
struct IssuanceQualificationArgs {
    #[command(subcommand)]
    command: IssuanceQualificationCommand,
}

#[derive(Debug, Subcommand)]
enum IssuanceQualificationCommand {
    /// Validate a canonical manifest and freeze the pre-analysis plan.
    Plan(IssuanceQualificationPlanArgs),
    /// Validate the bounded offline artifact-integrity slice without qualifying it.
    Analyze(IssuanceQualificationAnalyzeArgs),
    /// Analyze every indexed route and Criterion median without activating thresholds.
    AnalyzeIndexed(IssuanceQualificationAnalyzeArgs),
    /// Work with an approved exact Git source archive without starting a campaign.
    SourceArchive(IssuanceSourceArchiveArgs),
}

#[derive(Debug, Args)]
struct IssuanceQualificationPlanArgs {
    /// Canonical manifest emitted by the fixed SD-JWT benchmark source.
    #[arg(long)]
    manifest: PathBuf,
    /// Absolute create-new destination for the frozen qualification plan.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct IssuanceQualificationAnalyzeArgs {
    /// Absolute root of the retained V3 campaign evidence.
    #[arg(long)]
    campaign_root: PathBuf,
    /// Exact campaign-relative route path, for example `routes/r00_c00_e0.ndjson`.
    #[arg(long)]
    route_artifact: PathBuf,
    /// Operator-selected, read-only file outside the campaign with 32 raw Ed25519 key bytes.
    #[arg(long)]
    anchor_public_key: PathBuf,
    /// Absolute create-new report destination outside the retained campaign root.
    #[arg(long)]
    output: PathBuf,
}

impl IssuanceQualificationAnalyzeArgs {
    fn analysis_request(&self) -> issuance_qualification::IssuanceAnalysisRequest<'_> {
        issuance_qualification::IssuanceAnalysisRequest {
            campaign_root: &self.campaign_root,
            route_artifact: &self.route_artifact,
            anchor_public_key: &self.anchor_public_key,
            output: &self.output,
        }
    }
}

#[derive(Debug, Args)]
struct IssuanceSourceArchiveArgs {
    #[command(subcommand)]
    command: IssuanceSourceArchiveCommand,
}

#[derive(Debug, Subcommand)]
enum IssuanceSourceArchiveCommand {
    /// Export one canonical `source/exact-tree.sar` from local Git objects.
    Export(IssuanceSourceArchiveExportArgs),
}

#[derive(Debug, Args)]
struct IssuanceSourceArchiveExportArgs {
    /// Absolute root of a normal, clean Git worktree.
    #[arg(long)]
    repository: PathBuf,
    /// Exact approved lowercase SHA-1 commit object identifier.
    #[arg(long)]
    source_commit: String,
    /// Exact approved lowercase SHA-1 tree object identifier.
    #[arg(long)]
    source_tree: String,
    /// Absolute create-new destination ending in `source/exact-tree.sar`.
    #[arg(long)]
    output: PathBuf,
    /// Explicitly authorize export of the exact source commit.
    #[arg(long)]
    approve_source_export: bool,
}

impl IssuanceSourceArchiveExportArgs {
    fn export_request(&self) -> issuance_qualification::SourceArchiveExportRequest<'_> {
        issuance_qualification::SourceArchiveExportRequest {
            repository: &self.repository,
            source_commit: &self.source_commit,
            source_tree: &self.source_tree,
            output: &self.output,
            source_export_approved: self.approve_source_export,
        }
    }
}

#[derive(Debug, Args)]
struct ScenarioArgs {
    #[command(subcommand)]
    command: ScenarioCommand,
}

#[derive(Debug, Subcommand)]
enum ScenarioCommand {
    /// Validate a workload contract and its referenced script.
    Validate(ScenarioValidateArgs),
}

#[derive(Debug, Args)]
struct ScenarioValidateArgs {
    /// Versioned workload contract JSON.
    #[arg(long)]
    contract: PathBuf,
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
        Command::Fixture(args) => match args.command {
            FixtureCommand::Generate(args) => {
                fixture::generate(&args.seed, &args.output, args.force)
            }
        },
        Command::Scenario(args) => match args.command {
            ScenarioCommand::Validate(args) => {
                let resolved = contract::load(&args.contract)?;
                println!(
                    "Validated {} revision {} with {} profiles.",
                    resolved.contract.name,
                    resolved.contract.revision,
                    resolved.contract.profiles.len()
                );
                Ok(())
            }
        },
        Command::Run(args) => match args.command {
            RunCommand::Smoke(args) => runner::smoke(&runner::SmokeRun {
                base_url: &args.base_url,
                output_dir: &args.output_dir,
                result_class: &args.result_class,
                stack_input: args.stack_input.as_deref(),
                doctor_report: args.doctor_report.as_deref(),
                allow_remote_target: args.allow_remote_target,
                target_environment: args.target_environment.as_str(),
                test_window: args.test_window.as_deref(),
                force: args.force,
            }),
            RunCommand::Workload(args) => runner::workload(&runner::WorkloadRun {
                contract_path: &args.contract,
                profile_name: &args.profile,
                fixture_path: &args.fixture,
                session_file: &args.session_file,
                base_url: &args.base_url,
                output_dir: &args.output_dir,
                result_class: &args.result_class,
                stack_input: args.stack_input.as_deref(),
                doctor_report: args.doctor_report.as_deref(),
                target_environment: args.target_environment.as_str(),
                test_window: &args.test_window,
                allow_remote_target: args.allow_remote_target,
                force: args.force,
            }),
        },
        Command::Qualification(args) => match args.command {
            QualificationCommand::Issuance(args) => match args.command {
                IssuanceQualificationCommand::Plan(args) => {
                    issuance_qualification::write_plan(&args.manifest, &args.output)
                }
                IssuanceQualificationCommand::Analyze(args) => {
                    issuance_qualification::analyze(&args.analysis_request())
                }
                IssuanceQualificationCommand::AnalyzeIndexed(args) => {
                    issuance_qualification::analyze_indexed(&args.analysis_request())
                }
                IssuanceQualificationCommand::SourceArchive(args) => match args.command {
                    IssuanceSourceArchiveCommand::Export(args) => {
                        let receipt =
                            issuance_qualification::export_source_archive(&args.export_request())?;
                        println!(
                            "Exported {} bytes (SHA-256 {}) for commit {} and tree {}; no campaign was created or qualified.",
                            receipt.archive_fingerprint.byte_length,
                            receipt.archive_fingerprint.sha256,
                            receipt.source_commit,
                            receipt.source_tree,
                        );
                        println!(
                            "Cargo.lock: {} bytes (SHA-256 {}); source members: {}.",
                            receipt.cargo_lock_fingerprint.byte_length,
                            receipt.cargo_lock_fingerprint.sha256,
                            receipt.entry_count,
                        );
                        Ok(())
                    }
                },
            },
        },
    }
}

#[cfg(test)]
mod qualification_analyze_cli_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn analyze_command_preserves_all_offline_inputs_through_dispatch() {
        let cli = Cli::try_parse_from([
            "marty-perf",
            "qualification",
            "issuance",
            "analyze",
            "--campaign-root",
            "/campaign-root",
            "--route-artifact",
            "routes/r00_c00_e0.ndjson",
            "--anchor-public-key",
            "/trust/anchor-public-key.bin",
            "--output",
            "/reports/analysis.json",
        ])
        .expect("parse analyzer command");
        let Command::Qualification(qualification) = cli.command else {
            panic!("qualification command")
        };
        let QualificationCommand::Issuance(issuance) = qualification.command;
        let IssuanceQualificationCommand::Analyze(args) = issuance.command else {
            panic!("analyze command")
        };

        let request = args.analysis_request();
        assert_eq!(request.campaign_root, Path::new("/campaign-root"));
        assert_eq!(
            request.route_artifact,
            Path::new("routes/r00_c00_e0.ndjson")
        );
        assert_eq!(
            request.anchor_public_key,
            Path::new("/trust/anchor-public-key.bin")
        );
        assert_eq!(request.output, Path::new("/reports/analysis.json"));
    }

    #[test]
    fn analyze_indexed_command_preserves_all_offline_inputs_through_dispatch() {
        let cli = Cli::try_parse_from([
            "marty-perf",
            "qualification",
            "issuance",
            "analyze-indexed",
            "--campaign-root",
            "/campaign-root",
            "--route-artifact",
            "routes/r00_c00_e0.ndjson",
            "--anchor-public-key",
            "/trust/anchor-public-key.bin",
            "--output",
            "/reports/indexed-analysis.json",
        ])
        .expect("parse indexed analyzer command");
        let Command::Qualification(qualification) = cli.command else {
            panic!("qualification command")
        };
        let QualificationCommand::Issuance(issuance) = qualification.command;
        let IssuanceQualificationCommand::AnalyzeIndexed(args) = issuance.command else {
            panic!("analyze-indexed command")
        };

        let request = args.analysis_request();
        assert_eq!(request.campaign_root, Path::new("/campaign-root"));
        assert_eq!(
            request.route_artifact,
            Path::new("routes/r00_c00_e0.ndjson")
        );
        assert_eq!(
            request.anchor_public_key,
            Path::new("/trust/anchor-public-key.bin")
        );
        assert_eq!(request.output, Path::new("/reports/indexed-analysis.json"));
    }

    #[test]
    fn source_archive_export_preserves_exact_pins_and_explicit_approval() {
        let cli = Cli::try_parse_from([
            "marty-perf",
            "qualification",
            "issuance",
            "source-archive",
            "export",
            "--repository",
            "/source-repository",
            "--source-commit",
            "c6199bfd61fb7e14b5d1a25a77ba9432cc36a0f7",
            "--source-tree",
            "10ca2f28172b555687ab244ace9569d71402b24a",
            "--output",
            "/retention/source/exact-tree.sar",
            "--approve-source-export",
        ])
        .expect("parse source archive export command");
        let Command::Qualification(qualification) = cli.command else {
            panic!("qualification command")
        };
        let QualificationCommand::Issuance(issuance) = qualification.command;
        let IssuanceQualificationCommand::SourceArchive(source_archive) = issuance.command else {
            panic!("source archive command")
        };
        let IssuanceSourceArchiveCommand::Export(args) = source_archive.command;

        let request = args.export_request();
        assert_eq!(request.repository, Path::new("/source-repository"));
        assert_eq!(
            request.source_commit,
            "c6199bfd61fb7e14b5d1a25a77ba9432cc36a0f7"
        );
        assert_eq!(
            request.source_tree,
            "10ca2f28172b555687ab244ace9569d71402b24a"
        );
        assert_eq!(
            request.output,
            Path::new("/retention/source/exact-tree.sar")
        );
        assert!(request.source_export_approved);
    }
}
