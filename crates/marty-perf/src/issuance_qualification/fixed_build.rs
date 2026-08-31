//! Nonactivating preparation for one fixed qualification build.

use std::fmt;
use std::path::Path;

use anyhow::Result;
use marty_perf_schema::ArtifactFingerprint;

use super::artifact_store::{MaterializedInputParent, TrustedMaterializationBoundary};
use super::build_input_archive::{
    materialize_fixed_build_inputs_in_parent, FixedBuildInputMetadata, MaterializedBuildInputTree,
    PersistedFixedBuildInputs,
};
use super::first_quiet_window::ValidatedFirstQuietWindow;
use super::source_archive::{
    materialize_retained_source_tree_in_parent, MaterializedSourceTree, RetainedSourceArchive,
};
use super::{
    canonical_build_environment_at_root, expected_build_argv, expected_offline_probe_argv,
    valid_artifact_fingerprint, valid_source_archive_path, valid_tool_version,
    BuildEnvironmentEntry, FIXED_BUILD_ROOT_NON_WINDOWS, FIXED_BUILD_ROOT_WINDOWS,
};

const PREPARATION_REJECTED: &str = "fixed build preparation rejected";
const RUSTC_SYSROOT_PROBE_ARGV: [&str; 3] = ["rustc", "--print", "sysroot"];

/// Non-cloneable proof that all immutable inputs for a future fixed build were jointly bound.
///
/// This capability never launches a process, performs network I/O, or publishes a build receipt.
pub(super) struct PreparedFixedBuild {
    first_window: ValidatedFirstQuietWindow,
    source: MaterializedSourceTree,
    inputs: MaterializedBuildInputTree,
    common_root: MaterializedInputParent,
    fields: PreparedFixedBuildFields,
}

impl fmt::Debug for PreparedFixedBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedFixedBuild")
            .finish_non_exhaustive()
    }
}

impl PreparedFixedBuild {
    /// Revalidates both immutable trees and permanently invalidates this capability on drift.
    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        (|| {
            self.source.ensure_unchanged()?;
            self.inputs.ensure_unchanged()?;
            self.common_root
                .ensure_joint(self.source.store(), self.inputs.store())?;
            self.inputs.ensure_unchanged()?;
            self.source.ensure_unchanged()
        })()
        .map_err(|_| anyhow::anyhow!(PREPARATION_REJECTED))
    }
}

pub(super) struct FixedBuildMaterializations {
    common_root: MaterializedInputParent,
    source: MaterializedSourceTree,
    inputs: MaterializedBuildInputTree,
}

pub(super) fn materialize_fixed_build(
    boundary: TrustedMaterializationBoundary,
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
) -> Result<FixedBuildMaterializations> {
    materialize_fixed_build_at(
        boundary,
        source,
        inputs,
        Path::new(expected_root(cfg!(windows))),
    )
}

fn materialize_fixed_build_at(
    boundary: TrustedMaterializationBoundary,
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
    absolute_root: &Path,
) -> Result<FixedBuildMaterializations> {
    materialize_fixed_build_at_inner(boundary, source, inputs, absolute_root, || {})
}

fn materialize_fixed_build_at_inner(
    boundary: TrustedMaterializationBoundary,
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
    absolute_root: &Path,
    between_trees: impl FnOnce(),
) -> Result<FixedBuildMaterializations> {
    source.ensure_materialization_preflight()?;
    inputs.ensure_materialization_preflight()?;
    let root = MaterializedInputParent::create_new(boundary, absolute_root)?;
    let source = materialize_retained_source_tree_in_parent(source, &root)?;
    root.ensure_root()?;
    between_trees();
    root.ensure_root()?;
    let inputs = materialize_fixed_build_inputs_in_parent(inputs, &root)?;
    root.ensure_root()?;
    root.ensure_joint(source.store(), inputs.store())?;
    Ok(FixedBuildMaterializations {
        common_root: root,
        source,
        inputs,
    })
}

#[cfg(test)]
pub(super) fn materialize_fixed_build_at_test_root(
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
    absolute_root: &Path,
) -> Result<FixedBuildMaterializations> {
    let boundary = TrustedMaterializationBoundary::issue_for_test(absolute_root)?;
    materialize_fixed_build_at(boundary, source, inputs, absolute_root)
}

#[cfg(all(test, unix))]
fn materialize_fixed_build_at_test_root_with_between_trees_hook(
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
    absolute_root: &Path,
    between_trees: impl FnOnce(),
) -> Result<FixedBuildMaterializations> {
    let boundary = TrustedMaterializationBoundary::issue_for_test(absolute_root)?;
    materialize_fixed_build_at_inner(boundary, source, inputs, absolute_root, between_trees)
}

#[derive(PartialEq)]
struct PreparedFixedBuildFields {
    campaign_id: String,
    first_quiet_window_evidence_fingerprint: ArtifactFingerprint,
    controller_binary_fingerprint: ArtifactFingerprint,
    rustc_verbose_version: String,
    source_archive_fingerprint: ArtifactFingerprint,
    source_commit: String,
    source_tree: String,
    cargo_lock_fingerprint: ArtifactFingerprint,
    build_input_inventory_fingerprint: ArtifactFingerprint,
    build_input_archive_fingerprint: ArtifactFingerprint,
    cargo_binary_fingerprint: ArtifactFingerprint,
    rustc_binary_fingerprint: ArtifactFingerprint,
    target_linker_fingerprint: ArtifactFingerprint,
    target_linker_relative_path: String,
    target_archiver_fingerprint: ArtifactFingerprint,
    target_archiver_relative_path: String,
    target_triple: String,
    windows: bool,
    materialized_build_root: String,
    working_directory: String,
    build_started_monotonic_nanoseconds: u64,
    build_environment: Vec<BuildEnvironmentEntry>,
    rustc_sysroot_probe_argv: Vec<String>,
    offline_dependency_resolution_argv: Vec<String>,
    logical_build_argv: Vec<String>,
}

struct PreparationProjection<'a> {
    campaign_id: &'a str,
    first_window_source_commit: &'a str,
    first_window_source_tree: &'a str,
    first_window_source_archive: &'a ArtifactFingerprint,
    first_window_cargo_lock: &'a ArtifactFingerprint,
    first_window_target_triple: &'a str,
    first_window_build_profile: &'a str,
    first_window_evidence: &'a ArtifactFingerprint,
    controller_binary_fingerprint: &'a ArtifactFingerprint,
    rustc_verbose_version: &'a str,
    first_window_ended_monotonic_nanoseconds: u64,
    source_campaign_id: &'a str,
    source_archive: &'a ArtifactFingerprint,
    source_commit: &'a str,
    source_tree: &'a str,
    cargo_lock: &'a ArtifactFingerprint,
    committer_timestamp: u64,
    input_metadata: &'a FixedBuildInputMetadata,
    build_started_monotonic_nanoseconds: u64,
    windows: bool,
}

fn expected_root(windows: bool) -> &'static str {
    if windows {
        FIXED_BUILD_ROOT_WINDOWS
    } else {
        FIXED_BUILD_ROOT_NON_WINDOWS
    }
}

fn projection_is_valid(projection: &PreparationProjection<'_>) -> bool {
    let metadata = projection.input_metadata;
    projection.campaign_id == projection.source_campaign_id
        && projection.campaign_id == metadata.campaign_id()
        && projection.first_window_source_commit == projection.source_commit
        && projection.first_window_source_tree == projection.source_tree
        && projection.first_window_source_archive == projection.source_archive
        && projection.first_window_cargo_lock == projection.cargo_lock
        && projection.first_window_target_triple == metadata.target_triple()
        && projection.first_window_build_profile == "bench"
        && projection.build_started_monotonic_nanoseconds
            > projection.first_window_ended_monotonic_nanoseconds
        && metadata
            .target_triple()
            .split('-')
            .any(|component| component == "windows")
            == projection.windows
        && metadata
            .target_linker_relative_path()
            .starts_with("tools/linker/")
        && valid_source_archive_path(metadata.target_linker_relative_path())
        && metadata
            .target_archiver_relative_path()
            .starts_with("tools/archiver/")
        && valid_source_archive_path(metadata.target_archiver_relative_path())
        && valid_tool_version(projection.rustc_verbose_version)
        && valid_artifact_fingerprint(projection.first_window_evidence)
        && [
            projection.source_archive,
            projection.cargo_lock,
            metadata.inventory_fingerprint(),
            metadata.archive_fingerprint(),
            metadata.cargo_binary_fingerprint(),
            metadata.rustc_binary_fingerprint(),
            metadata.target_linker_fingerprint(),
            metadata.target_archiver_fingerprint(),
            projection.controller_binary_fingerprint,
        ]
        .into_iter()
        .all(valid_artifact_fingerprint)
}

fn prepare_fields_at_root(
    projection: &PreparationProjection<'_>,
    root: &str,
) -> Result<PreparedFixedBuildFields> {
    anyhow::ensure!(projection_is_valid(projection), PREPARATION_REJECTED);
    let metadata = projection.input_metadata;
    let environment = canonical_build_environment_at_root(
        root,
        projection.windows,
        metadata.target_triple(),
        projection.committer_timestamp,
        metadata.target_linker_relative_path(),
        metadata.target_archiver_relative_path(),
    )
    .ok_or_else(|| anyhow::anyhow!(PREPARATION_REJECTED))?;
    Ok(PreparedFixedBuildFields {
        campaign_id: projection.campaign_id.to_owned(),
        first_quiet_window_evidence_fingerprint: projection.first_window_evidence.clone(),
        controller_binary_fingerprint: projection.controller_binary_fingerprint.clone(),
        rustc_verbose_version: projection.rustc_verbose_version.to_owned(),
        source_archive_fingerprint: projection.source_archive.clone(),
        source_commit: projection.source_commit.to_owned(),
        source_tree: projection.source_tree.to_owned(),
        cargo_lock_fingerprint: projection.cargo_lock.clone(),
        build_input_inventory_fingerprint: metadata.inventory_fingerprint().clone(),
        build_input_archive_fingerprint: metadata.archive_fingerprint().clone(),
        cargo_binary_fingerprint: metadata.cargo_binary_fingerprint().clone(),
        rustc_binary_fingerprint: metadata.rustc_binary_fingerprint().clone(),
        target_linker_fingerprint: metadata.target_linker_fingerprint().clone(),
        target_linker_relative_path: metadata.target_linker_relative_path().to_owned(),
        target_archiver_fingerprint: metadata.target_archiver_fingerprint().clone(),
        target_archiver_relative_path: metadata.target_archiver_relative_path().to_owned(),
        target_triple: metadata.target_triple().to_owned(),
        windows: projection.windows,
        materialized_build_root: root.to_owned(),
        working_directory: format!("{root}/worktree"),
        build_started_monotonic_nanoseconds: projection.build_started_monotonic_nanoseconds,
        build_environment: environment,
        rustc_sysroot_probe_argv: RUSTC_SYSROOT_PROBE_ARGV.map(str::to_owned).to_vec(),
        offline_dependency_resolution_argv: expected_offline_probe_argv(),
        logical_build_argv: expected_build_argv(metadata.target_triple()),
    })
}

fn prepare_fields(projection: &PreparationProjection<'_>) -> Result<PreparedFixedBuildFields> {
    prepare_fields_at_root(projection, expected_root(projection.windows))
}

fn roots_are_exact(source: &Path, inputs: &Path, required_root: &Path) -> bool {
    source == required_root.join("worktree") && inputs == required_root.join("inputs")
}

/// Jointly validates and seals the immutable preparation state for a future fixed build.
pub(super) fn prepare_fixed_build(
    first_window: ValidatedFirstQuietWindow,
    materializations: FixedBuildMaterializations,
    build_started_monotonic_nanoseconds: u64,
) -> Result<PreparedFixedBuild> {
    let windows = cfg!(windows);
    prepare_fixed_build_at_root(
        first_window,
        materializations,
        build_started_monotonic_nanoseconds,
        Path::new(expected_root(windows)),
        windows,
    )
}

fn prepare_fixed_build_at_root(
    first_window: ValidatedFirstQuietWindow,
    materializations: FixedBuildMaterializations,
    build_started_monotonic_nanoseconds: u64,
    required_root: &Path,
    windows: bool,
) -> Result<PreparedFixedBuild> {
    let FixedBuildMaterializations {
        common_root,
        source,
        inputs,
    } = materializations;
    let projection = PreparationProjection {
        campaign_id: first_window.campaign_id(),
        first_window_source_commit: first_window.source_commit(),
        first_window_source_tree: first_window.source_tree(),
        first_window_source_archive: first_window.source_archive_fingerprint(),
        first_window_cargo_lock: first_window.cargo_lock_fingerprint(),
        first_window_target_triple: first_window.target_triple(),
        first_window_build_profile: first_window.build_profile(),
        first_window_evidence: first_window.evidence_fingerprint(),
        controller_binary_fingerprint: first_window.controller_binary_fingerprint(),
        rustc_verbose_version: first_window.rustc_verbose_version(),
        first_window_ended_monotonic_nanoseconds: first_window.ended_at_monotonic_nanoseconds(),
        source_campaign_id: source.campaign_id(),
        source_archive: source.archive_fingerprint(),
        source_commit: source.source_commit(),
        source_tree: source.source_tree(),
        cargo_lock: source.cargo_lock_fingerprint(),
        committer_timestamp: source.committer_timestamp(),
        input_metadata: inputs.metadata(),
        build_started_monotonic_nanoseconds,
        windows,
    };
    let required_root_string = required_root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!(PREPARATION_REJECTED))?;
    let fields = prepare_fields_at_root(&projection, required_root_string)
        .map_err(|_| anyhow::anyhow!(PREPARATION_REJECTED))?;
    anyhow::ensure!(
        roots_are_exact(
            source.absolute_root(),
            inputs.absolute_root(),
            required_root
        ),
        PREPARATION_REJECTED
    );
    common_root
        .ensure_joint(source.store(), inputs.store())
        .map_err(|_| anyhow::anyhow!(PREPARATION_REJECTED))?;
    let prepared = PreparedFixedBuild {
        first_window,
        source,
        inputs,
        common_root,
        fields,
    };
    prepared.ensure_unchanged()?;
    Ok(prepared)
}

/// Test-only root override for exercising the same composition path on a temporary Unix root.
#[cfg(test)]
pub(super) fn prepare_fixed_build_at_test_root(
    first_window: ValidatedFirstQuietWindow,
    materializations: FixedBuildMaterializations,
    build_started_monotonic_nanoseconds: u64,
    absolute_root: &Path,
    windows: bool,
) -> Result<PreparedFixedBuild> {
    prepare_fixed_build_at_root(
        first_window,
        materializations,
        build_started_monotonic_nanoseconds,
        absolute_root,
        windows,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance_qualification::build_input_archive::FixedBuildInputMetadataForTest;

    const CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const SOURCE_TREE: &str = "89abcdef0123456789abcdef0123456789abcdef";

    #[cfg(unix)]
    fn artifact_tree_snapshot(
        root: &Path,
    ) -> std::collections::BTreeMap<std::path::PathBuf, (bool, u32, u64, u64, Vec<u8>)> {
        use std::os::unix::fs::MetadataExt as _;
        let mut result = std::collections::BTreeMap::new();
        let mut pending = vec![root.to_owned()];
        while let Some(path) = pending.pop() {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            assert!(metadata.is_dir() || metadata.is_file());
            let is_directory = metadata.is_dir();
            result.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (
                    is_directory,
                    metadata.mode(),
                    metadata.dev(),
                    metadata.ino(),
                    if is_directory {
                        Vec::new()
                    } else {
                        std::fs::read(&path).unwrap()
                    },
                ),
            );
            if is_directory {
                pending.extend(
                    std::fs::read_dir(&path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
            }
        }
        result
    }

    fn fingerprint(seed: char) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: seed.to_string().repeat(64),
            byte_length: 1,
        }
    }

    fn metadata(windows: bool) -> FixedBuildInputMetadata {
        metadata_with(
            CAMPAIGN_ID,
            if windows {
                "x86_64-pc-windows-msvc"
            } else {
                "x86_64-unknown-linux-gnu"
            },
            if windows {
                "tools/linker/link.exe"
            } else {
                "tools/linker/cc"
            },
            ['A', 'B', 'C', 'D', 'E'],
        )
    }

    fn metadata_with(
        campaign_id: &str,
        target_triple: &str,
        target_linker_relative_path: &str,
        seeds: [char; 5],
    ) -> FixedBuildInputMetadata {
        FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
            campaign_id: campaign_id.to_owned(),
            target_triple: target_triple.to_owned(),
            inventory_fingerprint: fingerprint(seeds[0]),
            archive_fingerprint: fingerprint(seeds[1]),
            cargo_binary_fingerprint: fingerprint(seeds[2]),
            rustc_binary_fingerprint: fingerprint(seeds[3]),
            target_linker_relative_path: target_linker_relative_path.to_owned(),
            target_linker_fingerprint: fingerprint(seeds[4]),
            target_archiver_relative_path:
                if target_triple.split('-').any(|part| part == "windows") {
                    "tools/archiver/lib.exe"
                } else {
                    "tools/archiver/ar"
                }
                .to_owned(),
            target_archiver_fingerprint: fingerprint('6'),
        })
    }

    fn fields(windows: bool) -> PreparedFixedBuildFields {
        let metadata = metadata(windows);
        fields_for_metadata(&metadata, windows)
    }

    fn fields_for_metadata(
        metadata: &FixedBuildInputMetadata,
        windows: bool,
    ) -> PreparedFixedBuildFields {
        let source_archive = fingerprint('F');
        let cargo_lock = fingerprint('9');
        let first_window = fingerprint('8');
        let controller = fingerprint('7');
        prepare_fields(&PreparationProjection {
            campaign_id: CAMPAIGN_ID,
            first_window_source_commit: SOURCE_COMMIT,
            first_window_source_tree: SOURCE_TREE,
            first_window_source_archive: &source_archive,
            first_window_cargo_lock: &cargo_lock,
            first_window_target_triple: metadata.target_triple(),
            first_window_build_profile: "bench",
            first_window_evidence: &first_window,
            controller_binary_fingerprint: &controller,
            rustc_verbose_version: "rustc 1.95.0 (synthetic)\n",
            first_window_ended_monotonic_nanoseconds: 100,
            source_campaign_id: CAMPAIGN_ID,
            source_archive: &source_archive,
            source_commit: SOURCE_COMMIT,
            source_tree: SOURCE_TREE,
            cargo_lock: &cargo_lock,
            committer_timestamp: 1_700_000_123,
            input_metadata: metadata,
            build_started_monotonic_nanoseconds: 101,
            windows,
        })
        .unwrap()
    }

    fn exact_environment(windows: bool) -> Vec<BuildEnvironmentEntry> {
        let root = expected_root(windows);
        let separator = if windows { ";" } else { ":" };
        let target = if windows {
            "X86_64_PC_WINDOWS_MSVC"
        } else {
            "X86_64_UNKNOWN_LINUX_GNU"
        };
        let linker = if windows {
            "tools/linker/link.exe"
        } else {
            "tools/linker/cc"
        };
        let archiver = if windows {
            "tools/archiver/lib.exe"
        } else {
            "tools/archiver/ar"
        };
        let linker_name = format!("CARGO_TARGET_{target}_LINKER");
        let mut entries = vec![
            (
                "AR",
                "inventoried_absolute_path",
                format!("{root}/inputs/{archiver}"),
            ),
            (
                "CARGO_HOME",
                "canonical_absolute_path",
                format!("{root}/inputs/cargo-home"),
            ),
            ("CARGO_INCREMENTAL", "literal", "0".to_owned()),
            ("CARGO_NET_OFFLINE", "literal", "true".to_owned()),
            (
                "CARGO_TARGET_DIR",
                "canonical_absolute_path",
                format!("{root}/target"),
            ),
            (
                linker_name.as_str(),
                "inventoried_absolute_path",
                format!("{root}/inputs/{linker}"),
            ),
            (
                "PATH",
                "ordered_absolute_path_list",
                [
                    "toolchain/bin",
                    "tools/linker",
                    "tools/archiver",
                    "tools/runtime",
                ]
                .map(|directory| format!("{root}/inputs/{directory}"))
                .join(separator),
            ),
            (
                "RUSTC",
                "inventoried_absolute_path",
                format!(
                    "{root}/inputs/toolchain/bin/{}",
                    if windows { "rustc.exe" } else { "rustc" }
                ),
            ),
            (
                "SOURCE_DATE_EPOCH",
                "commit_timestamp_decimal",
                "1700000123".to_owned(),
            ),
        ];
        if windows {
            entries.push((
                "SystemRoot",
                "canonical_absolute_path",
                format!("{root}/inputs/windows-runtime/SystemRoot"),
            ));
        }
        entries.extend([
            ("TEMP", "canonical_absolute_path", format!("{root}/tmp")),
            ("TMP", "canonical_absolute_path", format!("{root}/tmp")),
        ]);
        if windows {
            entries.push((
                "WINDIR",
                "canonical_absolute_path",
                format!("{root}/inputs/windows-runtime/SystemRoot"),
            ));
        }
        entries
            .into_iter()
            .map(|(name, value_kind, resolved_value)| BuildEnvironmentEntry {
                name: name.to_owned(),
                value_kind: value_kind.to_owned(),
                resolved_value,
            })
            .collect()
    }

    #[test]
    fn golden_linux_and_windows_projections_are_exact() {
        for windows in [false, true] {
            let fields = fields(windows);
            let root = expected_root(windows);
            assert_eq!(fields.materialized_build_root, root);
            assert_eq!(fields.campaign_id, CAMPAIGN_ID);
            assert_eq!(
                fields.first_quiet_window_evidence_fingerprint,
                fingerprint('8')
            );
            assert_eq!(fields.controller_binary_fingerprint, fingerprint('7'));
            assert_eq!(fields.rustc_verbose_version, "rustc 1.95.0 (synthetic)\n");
            assert_eq!(fields.source_archive_fingerprint, fingerprint('F'));
            assert_eq!(fields.source_commit, SOURCE_COMMIT);
            assert_eq!(fields.source_tree, SOURCE_TREE);
            assert_eq!(fields.cargo_lock_fingerprint, fingerprint('9'));
            assert_eq!(fields.build_input_inventory_fingerprint, fingerprint('A'));
            assert_eq!(fields.build_input_archive_fingerprint, fingerprint('B'));
            assert_eq!(fields.cargo_binary_fingerprint, fingerprint('C'));
            assert_eq!(fields.rustc_binary_fingerprint, fingerprint('D'));
            assert_eq!(fields.target_linker_fingerprint, fingerprint('E'));
            assert_eq!(fields.target_archiver_fingerprint, fingerprint('6'));
            assert_eq!(
                fields.target_triple,
                if windows {
                    "x86_64-pc-windows-msvc"
                } else {
                    "x86_64-unknown-linux-gnu"
                }
            );
            assert_eq!(
                fields.target_linker_relative_path,
                if windows {
                    "tools/linker/link.exe"
                } else {
                    "tools/linker/cc"
                }
            );
            assert_eq!(
                fields.target_archiver_relative_path,
                if windows {
                    "tools/archiver/lib.exe"
                } else {
                    "tools/archiver/ar"
                }
            );
            assert_eq!(fields.windows, windows);
            assert_eq!(fields.build_started_monotonic_nanoseconds, 101);
            assert_eq!(fields.working_directory, format!("{root}/worktree"));
            assert_eq!(
                fields.rustc_sysroot_probe_argv,
                ["rustc", "--print", "sysroot"]
            );
            assert_eq!(
                fields.offline_dependency_resolution_argv,
                expected_offline_probe_argv()
            );
            assert_eq!(
                fields.logical_build_argv,
                expected_build_argv(&fields.target_triple)
            );
            assert_eq!(
                fields.build_environment.len(),
                if windows { 13 } else { 11 }
            );
            assert_eq!(fields.build_environment[0].name, "AR");
            assert_eq!(
                fields.build_environment[0].resolved_value,
                format!("{root}/inputs/{}", fields.target_archiver_relative_path)
            );
            assert_eq!(fields.build_environment[1].name, "CARGO_HOME");
            assert_eq!(fields.build_environment[6].name, "PATH");
            assert_eq!(fields.build_environment[8].name, "SOURCE_DATE_EPOCH");
            assert_eq!(fields.build_environment[8].resolved_value, "1700000123");
            assert_eq!(fields.build_environment, exact_environment(windows));
        }
    }

    #[test]
    fn alternate_valid_archiver_projects_to_its_field_and_ar() {
        for (windows, archiver) in [
            (false, "tools/archiver/retained-ar"),
            (true, "tools/archiver/retained-lib.exe"),
        ] {
            let baseline = metadata(windows);
            let metadata = FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
                campaign_id: baseline.campaign_id().to_owned(),
                target_triple: baseline.target_triple().to_owned(),
                inventory_fingerprint: baseline.inventory_fingerprint().clone(),
                archive_fingerprint: baseline.archive_fingerprint().clone(),
                cargo_binary_fingerprint: baseline.cargo_binary_fingerprint().clone(),
                rustc_binary_fingerprint: baseline.rustc_binary_fingerprint().clone(),
                target_linker_relative_path: baseline.target_linker_relative_path().to_owned(),
                target_linker_fingerprint: baseline.target_linker_fingerprint().clone(),
                target_archiver_relative_path: archiver.to_owned(),
                target_archiver_fingerprint: fingerprint(if windows { '7' } else { '6' }),
            });
            let fields = fields_for_metadata(&metadata, windows);
            assert_eq!(fields.target_archiver_relative_path, archiver);
            assert_eq!(
                fields.target_archiver_fingerprint,
                fingerprint(if windows { '7' } else { '6' })
            );
            assert_eq!(
                fields.build_environment[0],
                BuildEnvironmentEntry {
                    name: "AR".to_owned(),
                    value_kind: "inventoried_absolute_path".to_owned(),
                    resolved_value: format!("{}/inputs/{archiver}", expected_root(windows)),
                }
            );
        }
    }

    #[test]
    fn projection_rejects_cross_capability_chronology_and_platform_mismatch_redacted() {
        let source_archive = fingerprint('F');
        let cargo_lock = fingerprint('9');
        let first_window = fingerprint('8');
        let metadata = metadata(false);
        let baseline = || PreparationProjection {
            campaign_id: CAMPAIGN_ID,
            first_window_source_commit: SOURCE_COMMIT,
            first_window_source_tree: SOURCE_TREE,
            first_window_source_archive: &source_archive,
            first_window_cargo_lock: &cargo_lock,
            first_window_target_triple: metadata.target_triple(),
            first_window_build_profile: "bench",
            first_window_evidence: &first_window,
            controller_binary_fingerprint: &first_window,
            rustc_verbose_version: "rustc 1.95.0 (synthetic)\n",
            first_window_ended_monotonic_nanoseconds: 100,
            source_campaign_id: CAMPAIGN_ID,
            source_archive: &source_archive,
            source_commit: SOURCE_COMMIT,
            source_tree: SOURCE_TREE,
            cargo_lock: &cargo_lock,
            committer_timestamp: 1,
            input_metadata: &metadata,
            build_started_monotonic_nanoseconds: 101,
            windows: false,
        };
        let assert_rejected = |candidate: PreparationProjection<'_>| {
            let Err(error) = prepare_fields(&candidate) else {
                panic!("invalid preparation was accepted")
            };
            assert_eq!(error.to_string(), PREPARATION_REJECTED);
        };
        assert_rejected(PreparationProjection {
            source_campaign_id: "different",
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_source_commit: "different",
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_source_tree: "different",
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_build_profile: "release",
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            build_started_monotonic_nanoseconds: 100,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            windows: true,
            ..baseline()
        });

        let different = fingerprint('7');
        let invalid_controller = fingerprint('g');
        assert_rejected(PreparationProjection {
            controller_binary_fingerprint: &invalid_controller,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            rustc_verbose_version: "missing newline",
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_source_archive: &different,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_cargo_lock: &different,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            source_archive: &different,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            cargo_lock: &different,
            ..baseline()
        });
        assert_rejected(PreparationProjection {
            first_window_target_triple: "aarch64-unknown-linux-gnu",
            ..baseline()
        });
        let invalid_evidence = ArtifactFingerprint {
            sha256: "not-a-digest".to_owned(),
            byte_length: 1,
        };
        assert_rejected(PreparationProjection {
            first_window_evidence: &invalid_evidence,
            ..baseline()
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the explicit independent negative matrix keeps all fixed-build metadata bindings visible"
    )]
    fn projection_rejects_every_materialized_input_metadata_mutation_redacted() {
        let source_archive = fingerprint('F');
        let cargo_lock = fingerprint('9');
        let first_window = fingerprint('8');
        let metadata = metadata(false);
        let baseline = || PreparationProjection {
            campaign_id: CAMPAIGN_ID,
            first_window_source_commit: SOURCE_COMMIT,
            first_window_source_tree: SOURCE_TREE,
            first_window_source_archive: &source_archive,
            first_window_cargo_lock: &cargo_lock,
            first_window_target_triple: metadata.target_triple(),
            first_window_build_profile: "bench",
            first_window_evidence: &first_window,
            controller_binary_fingerprint: &first_window,
            rustc_verbose_version: "rustc 1.95.0 (synthetic)\n",
            first_window_ended_monotonic_nanoseconds: 100,
            source_campaign_id: CAMPAIGN_ID,
            source_archive: &source_archive,
            source_commit: SOURCE_COMMIT,
            source_tree: SOURCE_TREE,
            cargo_lock: &cargo_lock,
            committer_timestamp: 1,
            input_metadata: &metadata,
            build_started_monotonic_nanoseconds: 101,
            windows: false,
        };
        let assert_rejected = |candidate: PreparationProjection<'_>| {
            let Err(error) = prepare_fields(&candidate) else {
                panic!("invalid preparation was accepted")
            };
            assert_eq!(error.to_string(), PREPARATION_REJECTED);
        };
        let wrong_campaign = metadata_with(
            "123e4567-e89b-42d3-a456-426614174001",
            metadata.target_triple(),
            metadata.target_linker_relative_path(),
            ['A', 'B', 'C', 'D', 'E'],
        );
        assert_rejected(PreparationProjection {
            input_metadata: &wrong_campaign,
            ..baseline()
        });
        let wrong_target = metadata_with(
            CAMPAIGN_ID,
            "aarch64-unknown-linux-gnu",
            metadata.target_linker_relative_path(),
            ['A', 'B', 'C', 'D', 'E'],
        );
        assert_rejected(PreparationProjection {
            input_metadata: &wrong_target,
            ..baseline()
        });
        for ordinal in 0..5 {
            let mut seeds = ['A', 'B', 'C', 'D', 'E'];
            seeds[ordinal] = 'g';
            let invalid_tool_fingerprint = metadata_with(
                CAMPAIGN_ID,
                metadata.target_triple(),
                metadata.target_linker_relative_path(),
                seeds,
            );
            assert_rejected(PreparationProjection {
                input_metadata: &invalid_tool_fingerprint,
                ..baseline()
            });
        }
        let invalid_archiver = FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
            campaign_id: CAMPAIGN_ID.to_owned(),
            target_triple: metadata.target_triple().to_owned(),
            inventory_fingerprint: fingerprint('A'),
            archive_fingerprint: fingerprint('B'),
            cargo_binary_fingerprint: fingerprint('C'),
            rustc_binary_fingerprint: fingerprint('D'),
            target_linker_relative_path: metadata.target_linker_relative_path().to_owned(),
            target_linker_fingerprint: fingerprint('E'),
            target_archiver_relative_path: "tools/archiver/ar".to_owned(),
            target_archiver_fingerprint: fingerprint('g'),
        });
        assert_rejected(PreparationProjection {
            input_metadata: &invalid_archiver,
            ..baseline()
        });

        let lowercase_hex_archiver =
            FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
                campaign_id: CAMPAIGN_ID.to_owned(),
                target_triple: metadata.target_triple().to_owned(),
                inventory_fingerprint: fingerprint('A'),
                archive_fingerprint: fingerprint('B'),
                cargo_binary_fingerprint: fingerprint('C'),
                rustc_binary_fingerprint: fingerprint('D'),
                target_linker_relative_path: metadata.target_linker_relative_path().to_owned(),
                target_linker_fingerprint: fingerprint('E'),
                target_archiver_relative_path: "tools/archiver/ar".to_owned(),
                target_archiver_fingerprint: fingerprint('a'),
            });
        assert_rejected(PreparationProjection {
            input_metadata: &lowercase_hex_archiver,
            ..baseline()
        });

        for invalid_linker_path in [
            "tools/linker/../cc",
            "tools/linker/cc\\escaped",
            "tools/linker/.",
            "tools/linker/CON",
        ] {
            let invalid_path = metadata_with(
                CAMPAIGN_ID,
                metadata.target_triple(),
                invalid_linker_path,
                ['A', 'B', 'C', 'D', 'E'],
            );
            assert_rejected(PreparationProjection {
                input_metadata: &invalid_path,
                ..baseline()
            });
        }
    }

    #[test]
    fn invalid_tool_projection_rejects_without_ambient_activity() {
        let mut invalid = metadata(false);
        invalid = FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
            campaign_id: CAMPAIGN_ID.to_owned(),
            target_triple: invalid.target_triple().to_owned(),
            inventory_fingerprint: invalid.inventory_fingerprint().clone(),
            archive_fingerprint: invalid.archive_fingerprint().clone(),
            cargo_binary_fingerprint: invalid.cargo_binary_fingerprint().clone(),
            rustc_binary_fingerprint: invalid.rustc_binary_fingerprint().clone(),
            target_linker_relative_path: "tools/runtime/cc".to_owned(),
            target_linker_fingerprint: invalid.target_linker_fingerprint().clone(),
            target_archiver_relative_path: invalid.target_archiver_relative_path().to_owned(),
            target_archiver_fingerprint: invalid.target_archiver_fingerprint().clone(),
        });
        let source_archive = fingerprint('F');
        let cargo_lock = fingerprint('9');
        let first_window = fingerprint('8');
        let projection = PreparationProjection {
            campaign_id: CAMPAIGN_ID,
            first_window_source_commit: SOURCE_COMMIT,
            first_window_source_tree: SOURCE_TREE,
            first_window_source_archive: &source_archive,
            first_window_cargo_lock: &cargo_lock,
            first_window_target_triple: invalid.target_triple(),
            first_window_build_profile: "bench",
            first_window_evidence: &first_window,
            controller_binary_fingerprint: &first_window,
            rustc_verbose_version: "rustc 1.95.0 (synthetic)\n",
            first_window_ended_monotonic_nanoseconds: 1,
            source_campaign_id: CAMPAIGN_ID,
            source_archive: &source_archive,
            source_commit: SOURCE_COMMIT,
            source_tree: SOURCE_TREE,
            cargo_lock: &cargo_lock,
            committer_timestamp: 1,
            input_metadata: &invalid,
            build_started_monotonic_nanoseconds: 2,
            windows: false,
        };
        let Err(error) = prepare_fields(&projection) else {
            panic!("invalid tool projection was accepted")
        };
        assert_eq!(error.to_string(), PREPARATION_REJECTED);

        let invalid_archiver_path =
            FixedBuildInputMetadata::for_test(FixedBuildInputMetadataForTest {
                campaign_id: CAMPAIGN_ID.to_owned(),
                target_triple: invalid.target_triple().to_owned(),
                inventory_fingerprint: fingerprint('A'),
                archive_fingerprint: fingerprint('B'),
                cargo_binary_fingerprint: fingerprint('C'),
                rustc_binary_fingerprint: fingerprint('D'),
                target_linker_relative_path: "tools/linker/cc".to_owned(),
                target_linker_fingerprint: fingerprint('E'),
                target_archiver_relative_path: "tools/archiver/../ar".to_owned(),
                target_archiver_fingerprint: fingerprint('6'),
            });
        let Err(error) = prepare_fields(&PreparationProjection {
            input_metadata: &invalid_archiver_path,
            ..projection
        }) else {
            panic!("invalid archiver path accepted")
        };
        assert_eq!(error.to_string(), PREPARATION_REJECTED);
    }

    #[test]
    fn fixed_roots_are_exact() {
        for windows in [false, true] {
            let root = expected_root(windows);
            assert!(roots_are_exact(
                &Path::new(root).join("worktree"),
                &Path::new(root).join("inputs"),
                Path::new(root)
            ));
            assert!(!roots_are_exact(
                &Path::new(root).join("other"),
                &Path::new(root).join("inputs"),
                Path::new(root)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the required literal 11-entry temporary-root environment vector stays inline with composition"
    )]
    fn unix_composition_uses_retained_capabilities_and_poisoned_source_drift_is_redacted() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;

        let (source_campaign, retained_source) =
            retained_fixture_for_fixed_build_composition_test();
        let first_window = ValidatedFirstQuietWindow::for_fixed_build_test(
            retained_source.campaign_id().to_owned(),
            retained_source.source_commit().to_owned(),
            retained_source.source_tree().to_owned(),
            retained_source.archive_fingerprint().clone(),
            retained_source.cargo_lock_fingerprint().clone(),
            "x86_64-unknown-linux-gnu".to_owned(),
        );
        let (input_campaign, persisted_inputs) =
            persisted_fixture_for_fixed_build_composition_test();
        let source_before = artifact_tree_snapshot(source_campaign.path());
        let inputs_before = artifact_tree_snapshot(input_campaign.path());
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("fixed-build");

        let materializations =
            materialize_fixed_build_at_test_root(retained_source, persisted_inputs, &root).unwrap();
        assert_eq!(
            materializations.source.absolute_root(),
            root.join("worktree")
        );
        assert_eq!(materializations.inputs.absolute_root(), root.join("inputs"));
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>(),
            [
                std::ffi::OsString::from("inputs"),
                std::ffi::OsString::from("worktree")
            ]
            .into_iter()
            .collect()
        );

        let mut prepared =
            prepare_fixed_build_at_test_root(first_window, materializations, 101, &root, false)
                .unwrap();
        prepared.ensure_unchanged().unwrap();
        assert_eq!(
            prepared.fields.materialized_build_root,
            root.to_string_lossy()
        );
        assert_eq!(
            prepared.fields.working_directory,
            root.join("worktree").to_string_lossy()
        );
        assert_eq!(prepared.fields.build_environment.len(), 11);
        let root_text = root.to_string_lossy();
        assert_eq!(
            prepared.fields.build_environment,
            vec![
                BuildEnvironmentEntry {
                    name: "AR".to_owned(),
                    value_kind: "inventoried_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/inputs/tools/archiver/ar"),
                },
                BuildEnvironmentEntry {
                    name: "CARGO_HOME".to_owned(),
                    value_kind: "canonical_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/inputs/cargo-home"),
                },
                BuildEnvironmentEntry {
                    name: "CARGO_INCREMENTAL".to_owned(),
                    value_kind: "literal".to_owned(),
                    resolved_value: "0".to_owned(),
                },
                BuildEnvironmentEntry {
                    name: "CARGO_NET_OFFLINE".to_owned(),
                    value_kind: "literal".to_owned(),
                    resolved_value: "true".to_owned(),
                },
                BuildEnvironmentEntry {
                    name: "CARGO_TARGET_DIR".to_owned(),
                    value_kind: "canonical_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/target"),
                },
                BuildEnvironmentEntry {
                    name: "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER".to_owned(),
                    value_kind: "inventoried_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/inputs/tools/linker/ld"),
                },
                BuildEnvironmentEntry {
                    name: "PATH".to_owned(),
                    value_kind: "ordered_absolute_path_list".to_owned(),
                    resolved_value: [
                        "toolchain/bin",
                        "tools/linker",
                        "tools/archiver",
                        "tools/runtime",
                    ]
                    .map(|relative| format!("{root_text}/inputs/{relative}"))
                    .join(":"),
                },
                BuildEnvironmentEntry {
                    name: "RUSTC".to_owned(),
                    value_kind: "inventoried_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/inputs/toolchain/bin/rustc"),
                },
                BuildEnvironmentEntry {
                    name: "SOURCE_DATE_EPOCH".to_owned(),
                    value_kind: "commit_timestamp_decimal".to_owned(),
                    resolved_value: "1700000123".to_owned(),
                },
                BuildEnvironmentEntry {
                    name: "TEMP".to_owned(),
                    value_kind: "canonical_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/tmp"),
                },
                BuildEnvironmentEntry {
                    name: "TMP".to_owned(),
                    value_kind: "canonical_absolute_path".to_owned(),
                    resolved_value: format!("{root_text}/tmp"),
                },
            ]
        );
        assert!(prepared.fields.build_environment.iter().all(|entry| {
            !entry.resolved_value.contains("/marty-cdla-build-v1")
                && (!entry.resolved_value.contains("fixed-build")
                    || entry.resolved_value.contains(&*root.to_string_lossy()))
        }));
        assert_eq!(
            artifact_tree_snapshot(source_campaign.path()),
            source_before
        );
        assert_eq!(artifact_tree_snapshot(input_campaign.path()), inputs_before);

        let original = prepared
            .source
            .overwrite_retained_archive_byte_for_test(b'X')
            .unwrap();
        let error = prepared.ensure_unchanged().unwrap_err();
        assert_eq!(error.to_string(), PREPARATION_REJECTED);
        assert!(!error.to_string().contains("worktree"));
        assert!(!error.to_string().contains("exact-tree.sar"));
        prepared
            .source
            .overwrite_retained_archive_byte_for_test(original)
            .unwrap();
        assert_eq!(
            prepared.ensure_unchanged().unwrap_err().to_string(),
            PREPARATION_REJECTED
        );
    }

    #[cfg(unix)]
    #[test]
    fn composed_prepared_build_rejects_retained_inventory_and_bia_drift_after_restore() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;
        use std::os::unix::fs::PermissionsExt as _;

        for relative in ["build/input-inventory.json", "build/input-files.bia"] {
            let (_source_campaign, retained_source) =
                retained_fixture_for_fixed_build_composition_test();
            let first_window = ValidatedFirstQuietWindow::for_fixed_build_test(
                retained_source.campaign_id().to_owned(),
                retained_source.source_commit().to_owned(),
                retained_source.source_tree().to_owned(),
                retained_source.archive_fingerprint().clone(),
                retained_source.cargo_lock_fingerprint().clone(),
                "x86_64-unknown-linux-gnu".to_owned(),
            );
            let (input_campaign, persisted_inputs) =
                persisted_fixture_for_fixed_build_composition_test();
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("fixed-build");
            let materializations =
                materialize_fixed_build_at_test_root(retained_source, persisted_inputs, &root)
                    .unwrap();
            let prepared =
                prepare_fixed_build_at_test_root(first_window, materializations, 101, &root, false)
                    .unwrap();
            prepared.ensure_unchanged().unwrap();

            let path = input_campaign.path().join("campaign").join(relative);
            let original = std::fs::read(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut changed = original.clone();
            changed[0] ^= 1;
            std::fs::write(&path, changed).unwrap();
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
            std::fs::write(&path, original).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn composed_prepared_build_rejects_input_root_and_build_replacement_after_restore_sticky() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;

        for replace_root in [true, false] {
            let (_source_campaign, retained_source) =
                retained_fixture_for_fixed_build_composition_test();
            let first_window = ValidatedFirstQuietWindow::for_fixed_build_test(
                retained_source.campaign_id().to_owned(),
                retained_source.source_commit().to_owned(),
                retained_source.source_tree().to_owned(),
                retained_source.archive_fingerprint().clone(),
                retained_source.cargo_lock_fingerprint().clone(),
                "x86_64-unknown-linux-gnu".to_owned(),
            );
            let (input_campaign, persisted_inputs) =
                persisted_fixture_for_fixed_build_composition_test();
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("fixed-build");
            let materializations =
                materialize_fixed_build_at_test_root(retained_source, persisted_inputs, &root)
                    .unwrap();
            let prepared =
                prepare_fixed_build_at_test_root(first_window, materializations, 101, &root, false)
                    .unwrap();
            prepared.ensure_unchanged().unwrap();

            let campaign = input_campaign.path().join("campaign");
            let original = if replace_root {
                campaign.clone()
            } else {
                campaign.join("build")
            };
            let displaced = if replace_root {
                input_campaign.path().join("displaced-campaign")
            } else {
                campaign.join("displaced-build")
            };
            std::fs::rename(&original, &displaced).unwrap();
            std::fs::create_dir(&original).unwrap();
            if replace_root {
                std::fs::create_dir(original.join("build")).unwrap();
            }
            if replace_root {
                std::fs::remove_dir(original.join("build")).unwrap();
            }
            std::fs::remove_dir(&original).unwrap();
            std::fs::rename(&displaced, &original).unwrap();
            // Detect replacement history after the original path has already been restored.
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn composed_prepared_build_rejects_fixed_input_role_replacement_after_restore() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;
        for relative in ["build/input-inventory.json", "build/input-files.bia"] {
            let (_source_campaign, retained_source) =
                retained_fixture_for_fixed_build_composition_test();
            let first_window = ValidatedFirstQuietWindow::for_fixed_build_test(
                retained_source.campaign_id().to_owned(),
                retained_source.source_commit().to_owned(),
                retained_source.source_tree().to_owned(),
                retained_source.archive_fingerprint().clone(),
                retained_source.cargo_lock_fingerprint().clone(),
                "x86_64-unknown-linux-gnu".to_owned(),
            );
            let (input_campaign, persisted_inputs) =
                persisted_fixture_for_fixed_build_composition_test();
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("fixed-build");
            let materializations =
                materialize_fixed_build_at_test_root(retained_source, persisted_inputs, &root)
                    .unwrap();
            let prepared =
                prepare_fixed_build_at_test_root(first_window, materializations, 101, &root, false)
                    .unwrap();
            let path = input_campaign.path().join("campaign").join(relative);
            let displaced = path.with_extension("displaced");
            let bytes = std::fs::read(&path).unwrap();
            std::fs::rename(&path, &displaced).unwrap();
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(displaced, path).unwrap();
            assert_eq!(
                prepared.ensure_unchanged().unwrap_err().to_string(),
                PREPARATION_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn composition_rejects_common_root_history_between_completed_trees() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;

        for mutation in ["root-swap-restore", "transient-child"] {
            let (_source_campaign, retained_source) =
                retained_fixture_for_fixed_build_composition_test();
            let (_input_campaign, persisted_inputs) =
                persisted_fixture_for_fixed_build_composition_test();
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("fixed-build");
            let displaced = temporary.path().join("displaced-fixed-build");
            let result = materialize_fixed_build_at_test_root_with_between_trees_hook(
                retained_source,
                persisted_inputs,
                &root,
                || match mutation {
                    "root-swap-restore" => {
                        std::fs::rename(&root, &displaced).unwrap();
                        std::fs::create_dir(&root).unwrap();
                        std::fs::remove_dir(&root).unwrap();
                        std::fs::rename(&displaced, &root).unwrap();
                    }
                    "transient-child" => {
                        let transient = root.join("transient");
                        std::fs::create_dir(&transient).unwrap();
                        std::fs::remove_dir(&transient).unwrap();
                    }
                    _ => unreachable!(),
                },
            );
            let Err(error) = result else {
                panic!("common-root history was accepted")
            };
            assert_eq!(error.to_string(), "materialization rejected");
            assert!(!root.join("inputs").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn sticky_source_and_joint_input_preflights_precede_destination_creation() {
        use crate::issuance_qualification::build_input_archive::tests::persisted_fixture_for_fixed_build_composition_test;
        use crate::issuance_qualification::source_archive::tests::retained_fixture_for_fixed_build_composition_test;

        for invalid_role in ["source", "inputs"] {
            let (source_campaign, retained_source) =
                retained_fixture_for_fixed_build_composition_test();
            let (input_campaign, persisted_inputs) =
                persisted_fixture_for_fixed_build_composition_test();
            let attacked = if invalid_role == "source" {
                source_campaign.path().join("campaign")
            } else {
                input_campaign.path().join("campaign")
            };
            let displaced = attacked.with_extension("displaced");
            std::fs::rename(&attacked, &displaced).unwrap();
            let preflight = if invalid_role == "source" {
                retained_source.ensure_materialization_preflight()
            } else {
                persisted_inputs.ensure_materialization_preflight()
            };
            let expected_error = if invalid_role == "source" {
                "source tree materialization rejected"
            } else {
                "materialization rejected"
            };
            assert_eq!(preflight.unwrap_err().to_string(), expected_error);
            std::fs::rename(&displaced, &attacked).unwrap();

            let destination = tempfile::tempdir().unwrap();
            let root = destination.path().join("fixed-build");
            assert!(
                materialize_fixed_build_at_test_root(retained_source, persisted_inputs, &root,)
                    .is_err()
            );
            assert!(!root.exists());
        }
    }
}
