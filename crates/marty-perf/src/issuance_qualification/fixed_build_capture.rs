//! Nonactivating composition of exact source and fixed-build input captures.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;

use super::artifact_store::{fingerprint_exact_source, CampaignArtifactStore};
use super::build_input_archive::{
    capture_fixed_build_inventory, ApprovedPublicBuildInput, LogicalBuildInputMode,
    PersistedFixedBuildInputs, PublicBuildInputRole,
};
use super::source_archive::{
    retain_approved_source_archive, RetainedSourceArchive, SourceExportApproval,
};
use super::{
    absolute_root_and_components, concrete_target_linker_environment_name, ensure_file_unchanged,
    handle_snapshot, open_child_directory, open_child_file, valid_artifact_fingerprint,
    valid_campaign_id, valid_lowercase_hex, valid_source_archive_path, FileIdentity, FileSnapshot,
    OpenedInput, SourceArchiveExportReceipt, MAX_FIXED_BUILD_INPUT_BYTES,
    MAX_SOURCE_ARCHIVE_V1_BYTES, MAX_SOURCE_ARCHIVE_V1_ENTRIES,
};

const CAPTURE_REJECTED: &str = "fixed build input composition rejected";
const SOURCE_ARCHIVE_RELATIVE_PATH: &str = "source/exact-tree.sar";
const MAX_ROOT_ANCESTORS: usize = 1_024;

struct RetainedAncestorEdge {
    parent: fs::File,
    parent_identity: FileIdentity,
    child_name: OsString,
    child_identity: FileIdentity,
}

/// Opaque, non-cloneable binding to one hardened staging root and its open handles.
pub(super) struct ApprovedInputRoot {
    root: fs::File,
    snapshot: FileSnapshot,
    ancestor_edges: Vec<RetainedAncestorEdge>,
    ancestry: Vec<FileIdentity>,
    invalid: Cell<bool>,
}

impl fmt::Debug for ApprovedInputRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedInputRoot")
            .finish_non_exhaustive()
    }
}

impl ApprovedInputRoot {
    /// Opens a hardened root once and retains that handle plus its handle-walked ancestry.
    pub(super) fn open(path: &Path) -> Result<Self> {
        let (mut root, components) = absolute_root_and_components(path, "approved input root")
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        anyhow::ensure!(
            !components.is_empty()
                && components
                    .len()
                    .checked_add(1)
                    .is_some_and(|length| length <= MAX_ROOT_ANCESTORS),
            CAPTURE_REJECTED
        );
        let mut ancestor_edges = Vec::with_capacity(components.len());
        for component in components {
            let parent_identity = handle_snapshot(&root, true, "approved input root")
                .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?
                .identity;
            let next = open_child_directory(&root, &component, "approved input root")
                .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
            let child_identity = handle_snapshot(&next, true, "approved input root")
                .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?
                .identity;
            ancestor_edges.push(RetainedAncestorEdge {
                parent: root,
                parent_identity,
                child_name: component,
                child_identity,
            });
            root = next;
        }
        let snapshot = handle_snapshot(&root, true, "approved input root")
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        let mut ancestry = Vec::with_capacity(ancestor_edges.len() + 1);
        ancestry.push(snapshot.identity);
        ancestry.extend(ancestor_edges.iter().rev().map(|edge| edge.parent_identity));
        let unique = ancestry.iter().copied().collect::<BTreeSet<_>>();
        anyhow::ensure!(
            ancestry.len() <= MAX_ROOT_ANCESTORS && unique.len() == ancestry.len(),
            CAPTURE_REJECTED
        );
        let approved = Self {
            root,
            snapshot,
            ancestor_edges,
            ancestry,
            invalid: Cell::new(false),
        };
        approved.ensure_unchanged()?;
        Ok(approved)
    }

    fn identity(&self) -> FileIdentity {
        self.snapshot.identity
    }

    fn disjoint_from(&self, other: &Self) -> bool {
        !self.ancestry.contains(&other.identity()) && !other.ancestry.contains(&self.identity())
    }

    fn ensure_unchanged(&self) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), CAPTURE_REJECTED);
        let result = (|| {
            anyhow::ensure!(
                handle_snapshot(&self.root, true, "approved input root")? == self.snapshot,
                CAPTURE_REJECTED
            );
            anyhow::ensure!(
                self.ancestor_edges.len() + 1 == self.ancestry.len()
                    && self.ancestor_edges.iter().all(|edge| {
                        handle_snapshot(&edge.parent, true, "approved input root ancestor")
                            .is_ok_and(|snapshot| snapshot.identity == edge.parent_identity)
                            && open_child_directory(
                                &edge.parent,
                                &edge.child_name,
                                "approved input root ancestor",
                            )
                            .and_then(|child| {
                                handle_snapshot(&child, true, "approved input root ancestor")
                            })
                            .is_ok_and(|snapshot| snapshot.identity == edge.child_identity)
                    }),
                CAPTURE_REJECTED
            );
            Ok(())
        })();
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))
    }

    fn matches_handle(&self, handle: &fs::File) -> bool {
        handle_snapshot(handle, true, "approved input root")
            .is_ok_and(|snapshot| snapshot.identity == self.identity())
    }

    /// Opens one explicit portable path relative to this retained root handle.
    pub(super) fn open_input(&self, relative_path: &str, maximum: u64) -> Result<OpenedInput> {
        self.ensure_unchanged()?;
        anyhow::ensure!(valid_source_archive_path(relative_path), CAPTURE_REJECTED);
        let mut components = relative_path
            .split('/')
            .map(OsString::from)
            .collect::<Vec<_>>();
        let file_name = components.pop().context(CAPTURE_REJECTED)?;
        let mut directory = self.root.try_clone().context(CAPTURE_REJECTED)?;
        for component in components {
            directory = open_child_directory(&directory, &component, "approved input root")
                .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        }
        let input = open_child_file(&directory, &file_name, maximum, "approved rooted input")
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        self.ensure_unchanged()?;
        Ok(input)
    }

    fn ensure_bound_input(
        &self,
        relative_path: &str,
        input: &OpenedInput,
        expected_fingerprint: &ArtifactFingerprint,
    ) -> Result<()> {
        self.ensure_unchanged()?;
        anyhow::ensure!(
            valid_artifact_fingerprint(expected_fingerprint)
                && expected_fingerprint.byte_length <= MAX_FIXED_BUILD_INPUT_BYTES
                && input.snapshot.readonly
                && input.snapshot.link_count == 1
                && input.snapshot.byte_length == expected_fingerprint.byte_length,
            CAPTURE_REJECTED
        );
        ensure_file_unchanged(&input.file, input.snapshot, "approved rooted input")
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        let reopened = self.open_input(relative_path, expected_fingerprint.byte_length)?;
        anyhow::ensure!(reopened.snapshot == input.snapshot, CAPTURE_REJECTED);
        let mut retained = input.file.try_clone().context(CAPTURE_REJECTED)?;
        let actual = fingerprint_exact_source(&mut retained, expected_fingerprint.byte_length)
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        let mut rebound = reopened.file;
        let rebound_fingerprint =
            fingerprint_exact_source(&mut rebound, expected_fingerprint.byte_length)
                .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        anyhow::ensure!(
            actual == *expected_fingerprint && rebound_fingerprint == actual,
            CAPTURE_REJECTED
        );
        ensure_file_unchanged(&input.file, input.snapshot, "approved rooted input")
            .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))?;
        self.ensure_unchanged()
    }
}

#[derive(Clone, Copy, Debug)]
enum ApprovedInputKind {
    GeneratedCargoConfiguration,
    Public(PublicBuildInputRole),
}

/// One explicit, hash-pinned, already-open public build-input approval.
pub(super) struct ApprovedFixedBuildInput {
    root_ordinal: usize,
    root_identity: FileIdentity,
    root_relative_path: String,
    kind: ApprovedInputKind,
    logical_relative_path: String,
    mode: LogicalBuildInputMode,
    expected_fingerprint: ArtifactFingerprint,
    input: OpenedInput,
}

impl fmt::Debug for ApprovedFixedBuildInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedFixedBuildInput")
            .finish_non_exhaustive()
    }
}

impl ApprovedFixedBuildInput {
    /// Binds one closed-role public build input to its staging root and exact bytes.
    #[allow(
        clippy::too_many_arguments,
        reason = "every approval coordinate is explicit"
    )]
    pub(super) fn bind_public(
        root_ordinal: usize,
        root: &ApprovedInputRoot,
        root_relative_path: String,
        role: PublicBuildInputRole,
        logical_relative_path: String,
        mode: LogicalBuildInputMode,
        expected_fingerprint: ArtifactFingerprint,
        input: OpenedInput,
    ) -> Result<Self> {
        Self::bind(
            root_ordinal,
            root,
            root_relative_path,
            ApprovedInputKind::Public(role),
            logical_relative_path,
            mode,
            expected_fingerprint,
            input,
        )
    }

    /// Binds the one generated, exact offline Cargo configuration input.
    pub(super) fn bind_generated_cargo_configuration(
        root_ordinal: usize,
        root: &ApprovedInputRoot,
        root_relative_path: String,
        expected_fingerprint: ArtifactFingerprint,
        input: OpenedInput,
    ) -> Result<Self> {
        Self::bind(
            root_ordinal,
            root,
            root_relative_path,
            ApprovedInputKind::GeneratedCargoConfiguration,
            "cargo-home/config.toml".to_owned(),
            LogicalBuildInputMode::Data,
            expected_fingerprint,
            input,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every approval coordinate is explicit"
    )]
    fn bind(
        root_ordinal: usize,
        root: &ApprovedInputRoot,
        root_relative_path: String,
        kind: ApprovedInputKind,
        logical_relative_path: String,
        mode: LogicalBuildInputMode,
        expected_fingerprint: ArtifactFingerprint,
        input: OpenedInput,
    ) -> Result<Self> {
        root.ensure_bound_input(&root_relative_path, &input, &expected_fingerprint)?;
        Ok(Self {
            root_ordinal,
            root_identity: root.identity(),
            root_relative_path,
            kind,
            logical_relative_path,
            mode,
            expected_fingerprint,
            input,
        })
    }

    fn ensure_unchanged(&self, roots: &[ApprovedInputRoot]) -> Result<()> {
        let root = roots.get(self.root_ordinal).context(CAPTURE_REJECTED)?;
        anyhow::ensure!(root.identity() == self.root_identity, CAPTURE_REJECTED);
        root.ensure_bound_input(
            &self.root_relative_path,
            &self.input,
            &self.expected_fingerprint,
        )
    }

    fn kernel_input(&self) -> Result<ApprovedPublicBuildInput> {
        let input = OpenedInput {
            file: self.input.file.try_clone().context(CAPTURE_REJECTED)?,
            snapshot: self.input.snapshot,
        };
        match self.kind {
            ApprovedInputKind::GeneratedCargoConfiguration => {
                ApprovedPublicBuildInput::bind_generated_cargo_configuration(
                    self.logical_relative_path.clone(),
                    input,
                )
            }
            ApprovedInputKind::Public(role) => ApprovedPublicBuildInput::bind(
                role,
                self.logical_relative_path.clone(),
                self.mode,
                input,
            ),
        }
        .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))
    }
}

/// All exact, nonambient inputs required to create one fixed-build capture capability.
pub(super) struct FixedBuildCaptureRequest<'a> {
    /// Absolute create-new campaign artifact root.
    pub campaign_root: &'a Path,
    /// Exact `UUIDv4` campaign identifier bound into every retained artifact.
    pub campaign_id: &'a str,
    /// Exact build target triple.
    pub target_triple: &'a str,
    /// Whether the target is Windows; this must agree with the target triple.
    pub windows: bool,
    /// Exact receipt returned by the source exporter in the same controller process.
    pub source_receipt: SourceArchiveExportReceipt,
    /// Retained staging-root capability from which the fixed source archive role is bound.
    pub source_root: ApprovedInputRoot,
    /// Already-open read-only `source/exact-tree.sar` handle.
    pub source_archive: OpenedInput,
    /// Explicit, retained roots from which approved build-input handles were bound.
    pub build_input_roots: Vec<ApprovedInputRoot>,
    /// Closed-role, exact-hash allowlist. No ambient discovery is performed.
    pub build_inputs: Vec<ApprovedFixedBuildInput>,
}

/// Opaque proof that exact source and build inputs were jointly captured under one fresh root.
pub(super) struct CapturedFixedBuildInputs {
    store: CampaignArtifactStore,
    campaign_root: ApprovedInputRoot,
    campaign_id: String,
    target_triple: String,
    source_receipt: SourceArchiveExportReceipt,
    source_root: ApprovedInputRoot,
    source_archive: OpenedInput,
    build_input_roots: Vec<ApprovedInputRoot>,
    build_inputs: Vec<ApprovedFixedBuildInput>,
    source: RetainedSourceArchive,
    inputs: PersistedFixedBuildInputs,
    invalid: Cell<bool>,
}

impl fmt::Debug for CapturedFixedBuildInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedFixedBuildInputs")
            .finish_non_exhaustive()
    }
}

impl CapturedFixedBuildInputs {
    fn ensure_unchanged_inner(&self) -> Result<()> {
        self.store.ensure_retained_root_unchanged()?;
        self.campaign_root.ensure_unchanged()?;
        anyhow::ensure!(
            roots_are_disjoint(
                &self.campaign_root,
                &self.source_root,
                &self.build_input_roots,
            ),
            CAPTURE_REJECTED
        );
        ensure_staging_unchanged(
            &self.source_root,
            &self.source_archive,
            &self.source_receipt,
            &self.build_input_roots,
            &self.build_inputs,
        )?;
        self.source.ensure_unchanged()?;
        ensure_source_matches_receipt(&self.source, &self.source_receipt, &self.campaign_id)?;
        self.inputs.ensure_materialization_preflight()?;
        self.inputs
            .ensure_capture_coordinates(&self.campaign_id, &self.target_triple)?;
        self.source.ensure_unchanged()?;
        self.store.ensure_retained_root_unchanged()
    }

    /// Revalidates every retained root, staging input, persisted byte, and exact coordinate.
    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), CAPTURE_REJECTED);
        let result = self.ensure_unchanged_inner();
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))
    }

    /// Consumes the capture proof into the two existing immutable materialization capabilities.
    pub(super) fn into_materialization_inputs(
        self,
    ) -> Result<(RetainedSourceArchive, PersistedFixedBuildInputs)> {
        self.ensure_unchanged()?;
        let Self { source, inputs, .. } = self;
        Ok((source, inputs))
    }
}

fn roots_are_disjoint(
    campaign_root: &ApprovedInputRoot,
    source_root: &ApprovedInputRoot,
    build_input_roots: &[ApprovedInputRoot],
) -> bool {
    campaign_root.disjoint_from(source_root)
        && build_input_roots
            .iter()
            .all(|root| campaign_root.disjoint_from(root) && source_root.disjoint_from(root))
        && build_input_roots.iter().enumerate().all(|(ordinal, root)| {
            build_input_roots
                .iter()
                .skip(ordinal + 1)
                .all(|other| root.disjoint_from(other))
        })
}

fn ensure_request_coordinates(request: &FixedBuildCaptureRequest<'_>) -> Result<()> {
    let receipt = &request.source_receipt;
    anyhow::ensure!(
        request.campaign_root.is_absolute()
            && valid_campaign_id(request.campaign_id)
            && concrete_target_linker_environment_name(request.target_triple).is_some()
            && request
                .target_triple
                .split('-')
                .any(|component| component == "windows")
                == request.windows
            && valid_artifact_fingerprint(&receipt.archive_fingerprint)
            && receipt.archive_fingerprint.byte_length <= MAX_SOURCE_ARCHIVE_V1_BYTES
            && valid_artifact_fingerprint(&receipt.cargo_lock_fingerprint)
            && valid_lowercase_hex(&receipt.source_commit, 40)
            && valid_lowercase_hex(&receipt.source_tree, 40)
            && (1..=MAX_SOURCE_ARCHIVE_V1_ENTRIES).contains(&receipt.entry_count)
            && !request.build_input_roots.is_empty()
            && !request.build_inputs.is_empty(),
        CAPTURE_REJECTED
    );
    let mut used_roots = BTreeSet::new();
    let mut input_identities = BTreeSet::new();
    for input in &request.build_inputs {
        let root = request
            .build_input_roots
            .get(input.root_ordinal)
            .context(CAPTURE_REJECTED)?;
        anyhow::ensure!(root.identity() == input.root_identity, CAPTURE_REJECTED);
        used_roots.insert(input.root_ordinal);
        anyhow::ensure!(
            input_identities.insert(input.input.snapshot.identity),
            CAPTURE_REJECTED
        );
        input.ensure_unchanged(&request.build_input_roots)?;
    }
    anyhow::ensure!(
        used_roots.len() == request.build_input_roots.len()
            && !input_identities.contains(&request.source_archive.snapshot.identity),
        CAPTURE_REJECTED
    );
    Ok(())
}

fn ensure_staging_unchanged(
    source_root: &ApprovedInputRoot,
    source_archive: &OpenedInput,
    receipt: &SourceArchiveExportReceipt,
    build_input_roots: &[ApprovedInputRoot],
    build_inputs: &[ApprovedFixedBuildInput],
) -> Result<()> {
    source_root.ensure_bound_input(
        SOURCE_ARCHIVE_RELATIVE_PATH,
        source_archive,
        &receipt.archive_fingerprint,
    )?;
    for root in build_input_roots {
        root.ensure_unchanged()?;
    }
    for input in build_inputs {
        input.ensure_unchanged(build_input_roots)?;
    }
    source_root.ensure_unchanged()
}

fn ensure_source_matches_receipt(
    source: &RetainedSourceArchive,
    receipt: &SourceArchiveExportReceipt,
    campaign_id: &str,
) -> Result<()> {
    anyhow::ensure!(
        source.campaign_id() == campaign_id
            && source.archive_fingerprint() == &receipt.archive_fingerprint
            && source.source_commit() == receipt.source_commit
            && source.source_tree() == receipt.source_tree
            && source.cargo_lock_fingerprint() == &receipt.cargo_lock_fingerprint
            && u32::try_from(source.member_count()) == Ok(receipt.entry_count),
        CAPTURE_REJECTED
    );
    source.ensure_unchanged()
}

#[allow(
    clippy::too_many_lines,
    reason = "the linear capture transaction keeps every preflight and postflight adjacent"
)]
fn capture_fixed_build_inputs_inner(
    request: FixedBuildCaptureRequest<'_>,
    after_preflight: impl FnOnce(),
    after_source_retention: impl FnOnce(),
) -> Result<CapturedFixedBuildInputs> {
    ensure_request_coordinates(&request)?;
    anyhow::ensure!(
        request
            .build_input_roots
            .iter()
            .all(|root| request.source_root.disjoint_from(root))
            && request
                .build_input_roots
                .iter()
                .enumerate()
                .all(|(ordinal, root)| {
                    request
                        .build_input_roots
                        .iter()
                        .skip(ordinal + 1)
                        .all(|other| root.disjoint_from(other))
                }),
        CAPTURE_REJECTED
    );
    ensure_staging_unchanged(
        &request.source_root,
        &request.source_archive,
        &request.source_receipt,
        &request.build_input_roots,
        &request.build_inputs,
    )?;
    after_preflight();
    ensure_staging_unchanged(
        &request.source_root,
        &request.source_archive,
        &request.source_receipt,
        &request.build_input_roots,
        &request.build_inputs,
    )?;

    let store = CampaignArtifactStore::create_new(request.campaign_root)
        .context("create fixed-build capture root")?;
    store
        .initialize_fixed_layout()
        .context("initialize fixed-build capture root")?;
    let campaign_root =
        ApprovedInputRoot::open(request.campaign_root).context("bind fixed-build capture root")?;
    let store_root = store.retained_root_handle()?;
    anyhow::ensure!(
        campaign_root.matches_handle(&store_root)
            && roots_are_disjoint(
                &campaign_root,
                &request.source_root,
                &request.build_input_roots,
            ),
        CAPTURE_REJECTED
    );
    ensure_staging_unchanged(
        &request.source_root,
        &request.source_archive,
        &request.source_receipt,
        &request.build_input_roots,
        &request.build_inputs,
    )?;

    let mut source_archive = request.source_archive;
    let source = retain_approved_source_archive(
        &store,
        request.campaign_id,
        SourceExportApproval::new(request.campaign_id.to_owned(), true),
        &mut source_archive,
        &request.source_receipt.archive_fingerprint,
        &request.source_receipt.cargo_lock_fingerprint,
    )
    .context("retain exact source archive")?;
    ensure_source_matches_receipt(&source, &request.source_receipt, request.campaign_id)?;
    after_source_retention();
    ensure_staging_unchanged(
        &request.source_root,
        &source_archive,
        &request.source_receipt,
        &request.build_input_roots,
        &request.build_inputs,
    )?;

    let kernel_inputs = request
        .build_inputs
        .iter()
        .map(ApprovedFixedBuildInput::kernel_input)
        .collect::<Result<Vec<_>>>()?;
    let inputs = capture_fixed_build_inventory(
        &store,
        request.campaign_id,
        request.target_triple,
        request.windows,
        kernel_inputs,
    )
    .context("capture exact build-input inventory")?;
    inputs.ensure_materialization_preflight()?;
    inputs.ensure_capture_coordinates(request.campaign_id, request.target_triple)?;
    source.ensure_unchanged()?;
    ensure_staging_unchanged(
        &request.source_root,
        &source_archive,
        &request.source_receipt,
        &request.build_input_roots,
        &request.build_inputs,
    )?;

    anyhow::ensure!(
        campaign_root.matches_handle(&store.retained_root_handle()?)
            && roots_are_disjoint(
                &campaign_root,
                &request.source_root,
                &request.build_input_roots,
            ),
        CAPTURE_REJECTED
    );
    let captured = CapturedFixedBuildInputs {
        store,
        campaign_root,
        campaign_id: request.campaign_id.to_owned(),
        target_triple: request.target_triple.to_owned(),
        source_receipt: request.source_receipt,
        source_root: request.source_root,
        source_archive,
        build_input_roots: request.build_input_roots,
        build_inputs: request.build_inputs,
        source,
        inputs,
        invalid: Cell::new(false),
    };
    captured
        .ensure_unchanged()
        .context("seal composed fixed-build inputs")?;
    Ok(captured)
}

/// Captures one exact source receipt and explicit public build-input allowlist.
pub(super) fn capture_fixed_build_inputs(
    request: FixedBuildCaptureRequest<'_>,
) -> Result<CapturedFixedBuildInputs> {
    capture_fixed_build_inputs_inner(request, || {}, || {})
        .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))
}

#[cfg(test)]
fn capture_fixed_build_inputs_with_hooks(
    request: FixedBuildCaptureRequest<'_>,
    after_preflight: impl FnOnce(),
    after_source_retention: impl FnOnce(),
) -> Result<CapturedFixedBuildInputs> {
    capture_fixed_build_inputs_inner(request, after_preflight, after_source_retention)
        .map_err(|_| anyhow::anyhow!(CAPTURE_REJECTED))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::*;
    #[cfg(unix)]
    use crate::issuance_qualification::fixed_build::materialize_fixed_build_at_test_root;
    #[cfg(unix)]
    use crate::issuance_qualification::{
        canonical_pretty_bytes, validate_build_input_archive_stream, BuildInputInventory,
    };
    use crate::issuance_qualification::{
        fingerprint, git_object_id, reconstructed_source_tree, SourceArchiveEntryWire,
        SourceArchiveManifestWire, FIXED_CARGO_CONFIGURATION_BYTES, SOURCE_ARCHIVE_MAGIC,
    };

    const CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const SECRET_SENTINEL: &[u8] = b"synthetic unlisted credential token";

    fn target() -> (&'static str, bool) {
        if cfg!(windows) {
            ("x86_64-pc-windows-msvc", true)
        } else {
            ("x86_64-unknown-linux-gnu", false)
        }
    }

    fn set_readonly(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[allow(
        clippy::permissions_set_readonly_false,
        reason = "fault injection restores the original read-only policy immediately"
    )]
    fn set_writable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }

    struct SourceFixture {
        bytes: Vec<u8>,
        receipt: SourceArchiveExportReceipt,
    }

    fn source_fixture() -> SourceFixture {
        let contents = vec![b"lock\n".to_vec(), b"pub fn fixture() {}\n".to_vec()];
        let mut manifest = SourceArchiveManifestWire {
            schema: "marty.performance/sd-jwt-issuance-source-archive-manifest/v1".to_owned(),
            git_object_format: "sha1".to_owned(),
            source_commit: String::new(),
            source_tree: String::new(),
            entry_count: 2,
            entries: vec![
                SourceArchiveEntryWire {
                    repository_relative_path: "Cargo.lock".to_owned(),
                    git_mode: "100644".to_owned(),
                    git_object_id: hex::encode(git_object_id("blob", &contents[0])),
                    artifact_fingerprint: fingerprint(&contents[0]).unwrap(),
                },
                SourceArchiveEntryWire {
                    repository_relative_path: "src/lib.rs".to_owned(),
                    git_mode: "100644".to_owned(),
                    git_object_id: hex::encode(git_object_id("blob", &contents[1])),
                    artifact_fingerprint: fingerprint(&contents[1]).unwrap(),
                },
            ],
        };
        let content_slices = contents.iter().map(Vec::as_slice).collect::<Vec<_>>();
        manifest.source_tree =
            hex::encode(reconstructed_source_tree(&manifest.entries, &content_slices).unwrap());
        let commit = format!(
            "tree {}\nauthor Marty Fixture <fixture@example.invalid> 1700000000 -0700\ncommitter Marty Fixture <fixture@example.invalid> 1700000123 +0530\n\nfixture\n",
            manifest.source_tree
        )
        .into_bytes();
        manifest.source_commit = hex::encode(git_object_id("commit", &commit));
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        manifest_bytes.push(b'\n');
        let mut bytes = SOURCE_ARCHIVE_MAGIC.to_vec();
        bytes.extend_from_slice(&u64::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&u64::try_from(commit.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&commit);
        for content in &contents {
            bytes.extend_from_slice(&u64::try_from(content.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(content);
        }
        SourceFixture {
            receipt: SourceArchiveExportReceipt {
                archive_fingerprint: fingerprint(&bytes).unwrap(),
                source_commit: manifest.source_commit,
                source_tree: manifest.source_tree,
                cargo_lock_fingerprint: fingerprint(&contents[0]).unwrap(),
                entry_count: 2,
            },
            bytes,
        }
    }

    fn write_readonly(root: &Path, relative_path: &str, bytes: &[u8]) {
        let path = root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, bytes).unwrap();
        set_readonly(&path);
    }

    #[allow(
        dead_code,
        reason = "Windows exercises preflight while durable capture runs in the offline Linux gate"
    )]
    struct ExpectedCapture {
        source_bytes: Vec<u8>,
        cargo_physical_path: PathBuf,
        cargo_logical_path: String,
    }

    fn public_approval(
        root: &ApprovedInputRoot,
        physical_path: &str,
        role: PublicBuildInputRole,
        logical_path: &str,
        mode: LogicalBuildInputMode,
        bytes: &[u8],
    ) -> ApprovedFixedBuildInput {
        let input = root
            .open_input(physical_path, MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        ApprovedFixedBuildInput::bind_public(
            0,
            root,
            physical_path.to_owned(),
            role,
            logical_path.to_owned(),
            mode,
            fingerprint(bytes).unwrap(),
            input,
        )
        .unwrap()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end fixture spells out every closed build-input role"
    )]
    fn complete_request<'a>(
        campaign_root: &'a Path,
        source_stage: &Path,
        build_stage: &Path,
    ) -> (FixedBuildCaptureRequest<'a>, ExpectedCapture) {
        fs::create_dir_all(source_stage).unwrap();
        fs::create_dir_all(build_stage).unwrap();
        let source = source_fixture();
        write_readonly(source_stage, SOURCE_ARCHIVE_RELATIVE_PATH, &source.bytes);

        let cargo_logical_path = if cfg!(windows) {
            "toolchain/bin/cargo.exe"
        } else {
            "toolchain/bin/cargo"
        };
        let rustc_logical_path = if cfg!(windows) {
            "toolchain/bin/rustc.exe"
        } else {
            "toolchain/bin/rustc"
        };
        let build_files = [
            ("configuration", FIXED_CARGO_CONFIGURATION_BYTES),
            (
                "dependency",
                b"pub const FIXTURE: bool = true;\n".as_slice(),
            ),
            ("cargo", b"synthetic cargo executable".as_slice()),
            ("path-helper", b"synthetic path helper".as_slice()),
            ("rustc", b"synthetic rustc executable".as_slice()),
            ("sysroot", b"synthetic rustc sysroot member".as_slice()),
            ("archiver", b"synthetic target archiver".as_slice()),
            ("linker", b"synthetic target linker".as_slice()),
            ("dynamic", b"synthetic runtime library".as_slice()),
        ];
        for (path, bytes) in build_files {
            write_readonly(build_stage, path, bytes);
        }
        if cfg!(windows) {
            write_readonly(build_stage, "windows-runtime", b"synthetic system runtime");
        }
        fs::write(build_stage.join("unlisted-secret"), SECRET_SENTINEL).unwrap();

        let source_root = ApprovedInputRoot::open(source_stage).unwrap();
        let source_archive = source_root
            .open_input(SOURCE_ARCHIVE_RELATIVE_PATH, MAX_SOURCE_ARCHIVE_V1_BYTES)
            .unwrap();
        let build_root = ApprovedInputRoot::open(build_stage).unwrap();
        let generated = build_root
            .open_input("configuration", MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        let mut inputs = vec![
            ApprovedFixedBuildInput::bind_generated_cargo_configuration(
                0,
                &build_root,
                "configuration".to_owned(),
                fingerprint(FIXED_CARGO_CONFIGURATION_BYTES).unwrap(),
                generated,
            )
            .unwrap(),
            public_approval(
                &build_root,
                "dependency",
                PublicBuildInputRole::CargoDependencySource,
                "cargo-home/registry/src/synthetic/lib.rs",
                LogicalBuildInputMode::Data,
                b"pub const FIXTURE: bool = true;\n",
            ),
            public_approval(
                &build_root,
                "cargo",
                PublicBuildInputRole::CargoExecutable,
                cargo_logical_path,
                LogicalBuildInputMode::Executable,
                b"synthetic cargo executable",
            ),
            public_approval(
                &build_root,
                "path-helper",
                PublicBuildInputRole::ExecutablePathInput,
                "tools/runtime/path-helper",
                LogicalBuildInputMode::Executable,
                b"synthetic path helper",
            ),
            public_approval(
                &build_root,
                "rustc",
                PublicBuildInputRole::RustcExecutable,
                rustc_logical_path,
                LogicalBuildInputMode::Executable,
                b"synthetic rustc executable",
            ),
            public_approval(
                &build_root,
                "sysroot",
                PublicBuildInputRole::RustcSysrootFile,
                "toolchain/lib/rustlib/libsynthetic.rlib",
                LogicalBuildInputMode::Data,
                b"synthetic rustc sysroot member",
            ),
            public_approval(
                &build_root,
                "archiver",
                PublicBuildInputRole::TargetArchiverExecutable,
                "tools/archiver/ar",
                LogicalBuildInputMode::Executable,
                b"synthetic target archiver",
            ),
            public_approval(
                &build_root,
                "linker",
                PublicBuildInputRole::TargetLinkerExecutable,
                "tools/linker/ld",
                LogicalBuildInputMode::Executable,
                b"synthetic target linker",
            ),
            public_approval(
                &build_root,
                "dynamic",
                PublicBuildInputRole::ToolDynamicDependency,
                "tools/runtime/libsynthetic.so",
                LogicalBuildInputMode::Data,
                b"synthetic runtime library",
            ),
        ];
        if cfg!(windows) {
            inputs.push(public_approval(
                &build_root,
                "windows-runtime",
                PublicBuildInputRole::WindowsRuntimeInput,
                "windows-runtime/SystemRoot/System32/synthetic.dll",
                LogicalBuildInputMode::Data,
                b"synthetic system runtime",
            ));
        }
        inputs.reverse();
        let (target_triple, windows) = target();
        (
            FixedBuildCaptureRequest {
                campaign_root,
                campaign_id: CAMPAIGN_ID,
                target_triple,
                windows,
                source_receipt: source.receipt,
                source_root,
                source_archive,
                build_input_roots: vec![build_root],
                build_inputs: inputs,
            },
            ExpectedCapture {
                source_bytes: source.bytes,
                cargo_physical_path: build_stage.join("cargo"),
                cargo_logical_path: cargo_logical_path.to_owned(),
            },
        )
    }

    fn staging_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let staging = tempfile::tempdir().unwrap();
        let source = staging.path().join("source-stage");
        let build = staging.path().join("build-stage");
        (staging, source, build)
    }

    #[cfg(unix)]
    #[test]
    fn exact_composition_is_canonical_secret_free_and_materializable() {
        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("campaign");
        let (request, expected) = complete_request(&campaign, &source_stage, &build_stage);

        let captured = capture_fixed_build_inputs(request).unwrap();
        captured.ensure_unchanged().unwrap();
        assert_eq!(format!("{captured:?}"), "CapturedFixedBuildInputs { .. }");
        assert_eq!(
            fs::read(campaign.join(SOURCE_ARCHIVE_RELATIVE_PATH)).unwrap(),
            expected.source_bytes
        );
        let inventory_bytes = fs::read(campaign.join("build/input-inventory.json")).unwrap();
        let inventory: BuildInputInventory = serde_json::from_slice(&inventory_bytes).unwrap();
        assert_eq!(canonical_pretty_bytes(&inventory).unwrap(), inventory_bytes);
        assert_eq!(inventory.campaign_id, CAMPAIGN_ID);
        assert_eq!(inventory.target_triple, target().0);
        assert!(inventory
            .entries
            .iter()
            .any(|entry| entry.relative_path == expected.cargo_logical_path));
        let cargo_entry = inventory
            .entries
            .iter()
            .find(|entry| entry.relative_path == expected.cargo_logical_path)
            .unwrap();
        assert_eq!(
            cargo_entry.fingerprint,
            fingerprint(b"synthetic cargo executable").unwrap()
        );
        let archive_bytes = fs::read(campaign.join("build/input-files.bia")).unwrap();
        assert!(validate_build_input_archive_stream(
            &mut std::io::Cursor::new(&archive_bytes),
            &inventory,
        )
        .is_ok());
        for bytes in [inventory_bytes, archive_bytes] {
            assert!(!bytes
                .windows(SECRET_SENTINEL.len())
                .any(|window| window == SECRET_SENTINEL));
        }

        let materialization_parent = tempfile::tempdir().unwrap();
        let materialization_root = materialization_parent.path().join("materialized");
        let (source, inputs) = captured.into_materialization_inputs().unwrap();
        materialize_fixed_build_at_test_root(source, inputs, &materialization_root).unwrap();
        assert_eq!(
            fs::read(materialization_root.join("worktree/Cargo.lock")).unwrap(),
            b"lock\n"
        );
        assert_eq!(
            fs::read(
                materialization_root
                    .join("inputs")
                    .join(expected.cargo_logical_path)
            )
            .unwrap(),
            b"synthetic cargo executable"
        );
    }

    #[test]
    fn source_receipt_campaign_and_target_mismatches_fail_closed() {
        enum Fault {
            Archive,
            CargoLock,
            Commit,
            Tree,
            MemberCount,
            Campaign,
            Target,
        }

        for fault in [
            Fault::Archive,
            Fault::CargoLock,
            Fault::Commit,
            Fault::Tree,
            Fault::MemberCount,
            Fault::Campaign,
            Fault::Target,
        ] {
            let (_staging, source_stage, build_stage) = staging_roots();
            let campaign_parent = tempfile::tempdir().unwrap();
            let campaign = campaign_parent.path().join("campaign");
            let (mut request, _) = complete_request(&campaign, &source_stage, &build_stage);
            match fault {
                Fault::Archive => {
                    request.source_receipt.archive_fingerprint.sha256 = "F".repeat(64);
                }
                Fault::CargoLock => {
                    request.source_receipt.cargo_lock_fingerprint.sha256 = "F".repeat(64);
                }
                Fault::Commit => request.source_receipt.source_commit = "f".repeat(40),
                Fault::Tree => request.source_receipt.source_tree = "f".repeat(40),
                Fault::MemberCount => request.source_receipt.entry_count += 1,
                Fault::Campaign => request.campaign_id = "not-a-campaign",
                Fault::Target => request.target_triple = "x86_64-unknown-linux-gnu.json",
            }
            let error = capture_fixed_build_inputs(request).unwrap_err();
            assert_eq!(error.to_string(), CAPTURE_REJECTED);
            assert!(!error.to_string().contains(CAMPAIGN_ID));
            assert!(!error.to_string().contains("Cargo.lock"));
        }
    }

    #[test]
    fn pins_mutability_hardlinks_and_duplicate_handles_reject_before_capture() {
        let temporary = tempfile::tempdir().unwrap();
        let root_path = temporary.path().join("root");
        fs::create_dir(&root_path).unwrap();
        write_readonly(&root_path, "member", b"approved bytes");
        let root = ApprovedInputRoot::open(&root_path).unwrap();
        let input = root
            .open_input("member", MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        let wrong = ArtifactFingerprint {
            sha256: "F".repeat(64),
            byte_length: b"approved bytes".len() as u64,
        };
        assert_eq!(
            ApprovedFixedBuildInput::bind_public(
                0,
                &root,
                "member".to_owned(),
                PublicBuildInputRole::RustcSysrootFile,
                "toolchain/lib/member".to_owned(),
                LogicalBuildInputMode::Data,
                wrong,
                input,
            )
            .unwrap_err()
            .to_string(),
            CAPTURE_REJECTED
        );

        let mutable_root = temporary.path().join("mutable-root");
        fs::create_dir(&mutable_root).unwrap();
        fs::write(mutable_root.join("member"), b"mutable").unwrap();
        let root = ApprovedInputRoot::open(&mutable_root).unwrap();
        let input = root
            .open_input("member", MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        assert!(ApprovedFixedBuildInput::bind_public(
            0,
            &root,
            "member".to_owned(),
            PublicBuildInputRole::RustcSysrootFile,
            "toolchain/lib/member".to_owned(),
            LogicalBuildInputMode::Data,
            fingerprint(b"mutable").unwrap(),
            input,
        )
        .is_err());

        let linked_root = temporary.path().join("linked-root");
        fs::create_dir(&linked_root).unwrap();
        write_readonly(&linked_root, "member", b"linked");
        fs::hard_link(linked_root.join("member"), linked_root.join("alias")).unwrap();
        let root = ApprovedInputRoot::open(&linked_root).unwrap();
        assert!(root
            .open_input("member", MAX_FIXED_BUILD_INPUT_BYTES)
            .is_err());
    }

    #[test]
    fn same_bytes_from_wrong_path_or_root_reject_before_campaign_creation() {
        let temporary = tempfile::tempdir().unwrap();
        let approved_path = temporary.path().join("approved-root");
        let other_path = temporary.path().join("other-root");
        fs::create_dir(&approved_path).unwrap();
        fs::create_dir(&other_path).unwrap();
        for path in [&approved_path, &other_path] {
            write_readonly(path, "expected", b"same approved bytes");
            write_readonly(path, "swapped", b"same approved bytes");
        }
        let approved_root = ApprovedInputRoot::open(&approved_path).unwrap();
        let other_root = ApprovedInputRoot::open(&other_path).unwrap();
        let expected_fingerprint = fingerprint(b"same approved bytes").unwrap();

        let wrong_path = approved_root
            .open_input("swapped", MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        assert_eq!(
            ApprovedFixedBuildInput::bind_public(
                0,
                &approved_root,
                "expected".to_owned(),
                PublicBuildInputRole::RustcSysrootFile,
                "toolchain/lib/expected".to_owned(),
                LogicalBuildInputMode::Data,
                expected_fingerprint.clone(),
                wrong_path,
            )
            .unwrap_err()
            .to_string(),
            CAPTURE_REJECTED
        );

        let wrong_root = other_root
            .open_input("expected", MAX_FIXED_BUILD_INPUT_BYTES)
            .unwrap();
        assert_eq!(
            ApprovedFixedBuildInput::bind_public(
                0,
                &approved_root,
                "expected".to_owned(),
                PublicBuildInputRole::RustcSysrootFile,
                "toolchain/lib/expected".to_owned(),
                LogicalBuildInputMode::Data,
                expected_fingerprint,
                wrong_root,
            )
            .unwrap_err()
            .to_string(),
            CAPTURE_REJECTED
        );

        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("campaign");
        let (mut request, expected) = complete_request(&campaign, &source_stage, &build_stage);
        write_readonly(&source_stage, "source/swapped.sar", &expected.source_bytes);
        request.source_archive = request
            .source_root
            .open_input("source/swapped.sar", MAX_SOURCE_ARCHIVE_V1_BYTES)
            .unwrap();

        assert_eq!(
            capture_fixed_build_inputs(request).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
        assert!(!campaign.exists());
    }

    #[test]
    fn equal_ancestor_and_campaign_nested_roots_reject() {
        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("campaign");
        let (mut request, _) = complete_request(&campaign, &source_stage, &build_stage);
        let duplicate = ApprovedInputRoot::open(&build_stage).unwrap();
        request.build_input_roots.push(duplicate);
        let last = request.build_inputs.last_mut().unwrap();
        last.root_ordinal = 1;
        last.root_identity = request.build_input_roots[1].identity();
        assert_eq!(
            capture_fixed_build_inputs(request).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
        assert!(!campaign.exists());

        let staging = tempfile::tempdir().unwrap();
        let source_stage = staging.path().join("source-stage");
        let build_stage = source_stage.join("nested-build-stage");
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("campaign");
        let (request, _) = complete_request(&campaign, &source_stage, &build_stage);
        assert_eq!(
            capture_fixed_build_inputs(request).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
        assert!(!campaign.exists());

        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign = source_stage.join("nested-campaign");
        let (request, _) = complete_request(&campaign, &source_stage, &build_stage);
        assert_eq!(
            capture_fixed_build_inputs(request).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
    }

    #[cfg(unix)]
    #[test]
    fn same_parent_sibling_roots_are_supported() {
        let staging = tempfile::tempdir().unwrap();
        let source_stage = staging.path().join("source-stage");
        let build_stage = staging.path().join("build-stage");
        let campaign = staging.path().join("campaign");
        let (request, _) = complete_request(&campaign, &source_stage, &build_stage);

        let captured = capture_fixed_build_inputs(request).unwrap();
        captured.ensure_unchanged().unwrap();
    }

    #[test]
    fn sibling_root_capabilities_survive_new_sibling_creation() {
        let staging = tempfile::tempdir().unwrap();
        let source_path = staging.path().join("source");
        let build_path = staging.path().join("build");
        fs::create_dir(&source_path).unwrap();
        fs::create_dir(&build_path).unwrap();
        let source_root = ApprovedInputRoot::open(&source_path).unwrap();
        let build_root = ApprovedInputRoot::open(&build_path).unwrap();

        fs::create_dir(staging.path().join("campaign")).unwrap();

        source_root.ensure_unchanged().unwrap();
        build_root.ensure_unchanged().unwrap();
        assert!(source_root.disjoint_from(&build_root));
    }

    #[cfg(windows)]
    #[test]
    fn valid_windows_composition_fails_closed_before_campaign_creation() {
        let staging = tempfile::tempdir().unwrap();
        let source_stage = staging.path().join("source-stage");
        let build_stage = staging.path().join("build-stage");
        let campaign = staging.path().join("campaign");
        let (request, _) = complete_request(&campaign, &source_stage, &build_stage);

        assert_eq!(
            capture_fixed_build_inputs(request).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
        assert!(!campaign.exists());
    }

    #[test]
    fn root_toctou_rejects_before_creating_a_campaign() {
        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("preflight-campaign");
        let (request, expected) = complete_request(&campaign, &source_stage, &build_stage);
        let member_fault = expected.cargo_physical_path;
        let error = capture_fixed_build_inputs_with_hooks(
            request,
            || {
                set_writable(&member_fault);
                fs::write(&member_fault, b"late mutation").unwrap();
            },
            || {},
        )
        .unwrap_err();
        assert_eq!(error.to_string(), CAPTURE_REJECTED);
        assert!(!campaign.exists());
    }

    #[cfg(unix)]
    #[test]
    fn member_toctou_rejects_and_partial_output_stays_poisoned() {
        let campaign_parent = tempfile::tempdir().unwrap();
        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign = campaign_parent.path().join("partial-campaign");
        let (request, expected) = complete_request(&campaign, &source_stage, &build_stage);
        let cargo_path = expected.cargo_physical_path.clone();
        let error = capture_fixed_build_inputs_with_hooks(
            request,
            || {},
            || {
                set_writable(&cargo_path);
                fs::write(&cargo_path, b"late mutation").unwrap();
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), CAPTURE_REJECTED);
        assert!(campaign.join(SOURCE_ARCHIVE_RELATIVE_PATH).exists());
        assert!(!campaign.join("build/input-inventory.json").exists());

        let (_retry_staging, retry_source, retry_build) = staging_roots();
        let (retry, _) = complete_request(&campaign, &retry_source, &retry_build);
        assert_eq!(
            capture_fixed_build_inputs(retry).unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
    }

    #[cfg(unix)]
    #[test]
    fn staging_mutation_permanently_invalidates_the_opaque_capability() {
        let (_staging, source_stage, build_stage) = staging_roots();
        let campaign_parent = tempfile::tempdir().unwrap();
        let campaign = campaign_parent.path().join("campaign");
        let (request, expected) = complete_request(&campaign, &source_stage, &build_stage);
        let captured = capture_fixed_build_inputs(request).unwrap();
        captured.ensure_unchanged().unwrap();

        set_writable(&expected.cargo_physical_path);
        fs::write(
            &expected.cargo_physical_path,
            b"different pinned cargo bytes",
        )
        .unwrap();
        set_readonly(&expected.cargo_physical_path);
        for _ in 0..2 {
            assert_eq!(
                captured.ensure_unchanged().unwrap_err().to_string(),
                CAPTURE_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn staging_root_replacement_and_restore_is_detected_sticky() {
        let temporary = tempfile::tempdir().unwrap();
        let root_path = temporary.path().join("root");
        let displaced_path = temporary.path().join("displaced-root");
        fs::create_dir(&root_path).unwrap();
        write_readonly(&root_path, "member", b"approved");
        let root = ApprovedInputRoot::open(&root_path).unwrap();
        root.ensure_unchanged().unwrap();

        fs::rename(&root_path, &displaced_path).unwrap();
        fs::create_dir(&root_path).unwrap();
        assert_eq!(
            root.ensure_unchanged().unwrap_err().to_string(),
            CAPTURE_REJECTED
        );
        fs::remove_dir(&root_path).unwrap();
        fs::rename(&displaced_path, &root_path).unwrap();
        for _ in 0..2 {
            assert_eq!(
                root.ensure_unchanged().unwrap_err().to_string(),
                CAPTURE_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn higher_ancestor_relocation_into_another_root_is_detected_sticky() {
        let source_area = tempfile::tempdir().unwrap();
        let build_area = tempfile::tempdir().unwrap();
        let moving_ancestor = source_area.path().join("moving-ancestor");
        let source_path = moving_ancestor.join("stable-parent/source");
        let build_path = build_area.path().join("build");
        let destination = build_path.join("deep/destination");
        fs::create_dir_all(&source_path).unwrap();
        fs::create_dir_all(&destination).unwrap();

        let source_root = ApprovedInputRoot::open(&source_path).unwrap();
        let build_root = ApprovedInputRoot::open(&build_path).unwrap();
        source_root.ensure_unchanged().unwrap();
        build_root.ensure_unchanged().unwrap();
        assert!(source_root.disjoint_from(&build_root));

        fs::rename(&moving_ancestor, destination.join("moved-ancestor")).unwrap();
        build_root.ensure_unchanged().unwrap();
        for _ in 0..2 {
            assert_eq!(
                source_root.ensure_unchanged().unwrap_err().to_string(),
                CAPTURE_REJECTED
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_fifo_members_reject_without_following_or_blocking() {
        use std::os::unix::fs::symlink;
        use std::sync::mpsc;
        use std::time::Duration;

        use rustix::fs::{mkfifoat, Mode};

        let temporary = tempfile::tempdir().unwrap();
        let root_path = temporary.path().join("root");
        fs::create_dir(&root_path).unwrap();
        write_readonly(&root_path, "target", b"target");
        symlink("target", root_path.join("linked")).unwrap();
        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("member"), b"outside").unwrap();
        symlink(&outside, root_path.join("linked-directory")).unwrap();
        let directory = fs::File::open(&root_path).unwrap();
        mkfifoat(&directory, "special", Mode::RUSR | Mode::WUSR).unwrap();
        let root = ApprovedInputRoot::open(&root_path).unwrap();
        assert!(root
            .open_input("linked", MAX_FIXED_BUILD_INPUT_BYTES)
            .is_err());
        assert!(root
            .open_input("linked-directory/member", MAX_FIXED_BUILD_INPUT_BYTES)
            .is_err());

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(
                    root.open_input("special", MAX_FIXED_BUILD_INPUT_BYTES)
                        .is_err(),
                )
                .ok();
        });
        assert_eq!(receiver.recv_timeout(Duration::from_secs(2)), Ok(true));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_member_rejects_when_windows_allows_test_symlink_creation() {
        use std::os::windows::fs::symlink_file;

        let temporary = tempfile::tempdir().unwrap();
        let root_path = temporary.path().join("root");
        fs::create_dir(&root_path).unwrap();
        write_readonly(&root_path, "target", b"target");
        if symlink_file(root_path.join("target"), root_path.join("linked")).is_err() {
            return;
        }
        let root = ApprovedInputRoot::open(&root_path).unwrap();
        assert!(root
            .open_input("linked", MAX_FIXED_BUILD_INPUT_BYTES)
            .is_err());
    }
}
