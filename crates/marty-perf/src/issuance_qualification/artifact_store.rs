//! Handle-relative, create-only storage for qualification campaign artifacts.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

use anyhow::{Context, Result};
use fs_at::{read_dir as read_dir_at, OpenOptions as AtOpenOptions, OpenOptionsWriteMode};
use marty_perf_schema::ArtifactFingerprint;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::schedule::{ArtifactPath, ArtifactRole, ScheduledProcess};
use super::{
    ensure_file_unchanged, handle_snapshot, open_absolute_directory, open_child_directory,
    open_child_file, verified_directory_identity, verified_file_snapshot, FileIdentity,
    FileSnapshot, OpenedInput, MAX_FIXED_BUILD_INPUT_BYTES, MAX_SOURCE_ARCHIVE_V1_BYTES,
};

const BUILD_INPUT_ARCHIVE_PATH: &str = "build/input-files.bia";
const BUILD_INPUT_INVENTORY_PATH: &str = "build/input-inventory.json";
pub(super) const SOURCE_ARCHIVE_PATH: &str = "source/exact-tree.sar";
const STREAM_BUFFER_BYTES: usize = 8 * 1024;
const MAX_MATERIALIZED_INPUT_MEMBERS: u32 = 65_536;

const FIXED_DIRECTORIES: &[&str] = &[
    "inputs",
    "bin",
    "build",
    "configuration",
    "source",
    "profiles",
    "observations",
    "observations/unrelated-process-sets",
    "tmp",
    "segments",
    "attestations",
    "invocations",
    "criterion",
    "barriers",
    "barrier-ready",
    "barrier-releases",
    "barrier-receipts",
    "inventories",
    "routes",
    "indexes",
    "anchors",
];

pub(super) struct ProcessArtifactPaths {
    pub(super) criterion_home: ArtifactPath,
    pub(super) temporary_directory: ArtifactPath,
}

pub(super) struct CampaignArtifactStore {
    absolute_root: PathBuf,
    root: fs::File,
    identity: FileIdentity,
}

struct MaterializedMemberBinding {
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
    executable: bool,
}

struct MaterializedInputTreeState {
    absolute_root: PathBuf,
    root: fs::File,
    identity: FileIdentity,
    maximum_members: usize,
    maximum_member_bytes: u64,
    directories: BTreeMap<Vec<OsString>, FileSnapshot>,
    members: BTreeMap<Vec<OsString>, MaterializedMemberBinding>,
}

/// Mutable create-only construction state; it is not a materialization capability.
pub(super) struct MaterializedInputStoreBuilder {
    tree: MaterializedInputTreeState,
    poisoned: bool,
}

/// Sealed proof that one exact bounded materialized tree remains unchanged.
pub(super) struct MaterializedInputStore {
    tree: MaterializedInputTreeState,
    sealed_root_snapshot: FileSnapshot,
    expected_children: BTreeMap<Vec<OsString>, BTreeSet<OsString>>,
    invalid: Cell<bool>,
    #[cfg(test)]
    full_tree_scan_count: Cell<usize>,
}

/// Lightweight receipt for one completed member write.
pub(super) struct MaterializedInputMember {
    fingerprint: ArtifactFingerprint,
}

impl MaterializedInputMember {
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }
}

impl MaterializedInputStoreBuilder {
    pub(super) fn create_new(
        absolute_root: &Path,
        maximum_members: u32,
        maximum_member_bytes: u64,
    ) -> Result<Self> {
        Self::create_new_inner(absolute_root, maximum_members, maximum_member_bytes)
            .map_err(|_| anyhow::anyhow!("materialization rejected"))
    }

    fn create_new_inner(
        absolute_root: &Path,
        maximum_members: u32,
        maximum_member_bytes: u64,
    ) -> Result<Self> {
        anyhow::ensure!(absolute_root.is_absolute(), "materialization rejected");
        anyhow::ensure!(
            (1..=MAX_MATERIALIZED_INPUT_MEMBERS).contains(&maximum_members),
            "materialization rejected"
        );
        anyhow::ensure!(
            maximum_member_bytes <= MAX_FIXED_BUILD_INPUT_BYTES,
            "materialization rejected"
        );
        let maximum_members =
            usize::try_from(maximum_members).context("materialization rejected")?;
        ensure_directory_durability_supported().context("materialization rejected")?;
        let parent_path = absolute_root.parent().context("materialization rejected")?;
        let name = absolute_root
            .file_name()
            .context("materialization rejected")?;
        anyhow::ensure!(
            matches!(
                absolute_root.components().next_back(),
                Some(Component::Normal(_))
            ) && !name.to_string_lossy().contains('\\'),
            "materialization rejected"
        );
        let parent = open_absolute_directory(parent_path, "materialization parent")?;
        let root = AtOpenOptions::default()
            .mkdir_at(&parent, name)
            .context("materialization rejected")?;
        set_private_directory_permissions(&root).context("materialization rejected")?;
        sync_directory(&root).context("materialization rejected")?;
        sync_directory(&parent).context("materialization rejected")?;
        let identity = verified_directory_identity(&root, "materialized input root")?;
        Ok(Self {
            tree: MaterializedInputTreeState {
                absolute_root: absolute_root.to_owned(),
                root,
                identity,
                maximum_members,
                maximum_member_bytes,
                directories: BTreeMap::new(),
                members: BTreeMap::new(),
            },
            poisoned: false,
        })
    }

    pub(super) fn seal(mut self) -> Result<MaterializedInputStore> {
        anyhow::ensure!(!self.poisoned, "materialization rejected");
        self.poisoned = true;
        self.seal_inner()
            .map_err(|_| anyhow::anyhow!("materialization rejected"))
    }

    fn seal_inner(mut self) -> Result<MaterializedInputStore> {
        verify_materialized_root_binding(&self.tree)?;
        let expected_children = expected_materialized_children(&self.tree)?;
        let paths = self.tree.directories.keys().cloned().collect::<Vec<_>>();
        for path in paths.into_iter().rev() {
            let directory = open_materialized_directory(&self.tree, &path)?;
            set_materialized_directory_permissions(&directory)?;
            sync_directory(&directory)?;
            if let Some((_name, parent_path)) = path.split_last() {
                let parent = open_materialized_directory(&self.tree, parent_path)?;
                sync_directory(&parent)?;
            }
            verify_materialized_directory_permissions(&directory)?;
            let snapshot = handle_snapshot(&directory, true, "materialized input directory")?;
            self.tree.directories.insert(path, snapshot);
        }
        set_materialized_directory_permissions(&self.tree.root)?;
        sync_directory(&self.tree.root)?;
        let parent_path = self
            .tree
            .absolute_root
            .parent()
            .context("materialization rejected")?;
        let parent = open_absolute_directory(parent_path, "materialization parent")?;
        sync_directory(&parent)?;
        verify_materialized_directory_permissions(&self.tree.root)?;
        let sealed_root_snapshot =
            handle_snapshot(&self.tree.root, true, "materialized input root")?;
        let store = MaterializedInputStore {
            tree: self.tree,
            sealed_root_snapshot,
            expected_children,
            invalid: Cell::new(false),
            #[cfg(test)]
            full_tree_scan_count: Cell::new(0),
        };
        store.verify_root()?;
        Ok(store)
    }

    fn directory_for_create(&mut self, components: &[OsString]) -> Result<fs::File> {
        let mut directory = self
            .tree
            .root
            .try_clone()
            .context("materialization rejected")?;
        let mut prefix = Vec::with_capacity(components.len());
        for component in components {
            prefix.push(component.clone());
            let expected = self.tree.directories.get(&prefix).copied();
            if let Some(expected) = expected {
                directory =
                    open_child_directory(&directory, component, "materialized input directory")
                        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
                anyhow::ensure!(
                    verified_directory_identity(&directory, "materialized input directory")?
                        == expected.identity,
                    "materialization rejected"
                );
            } else {
                anyhow::ensure!(
                    !self.tree.members.contains_key(&prefix),
                    "materialization rejected"
                );
                let created = AtOpenOptions::default()
                    .mkdir_at(&directory, component)
                    .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
                set_private_directory_permissions(&created).context("materialization rejected")?;
                sync_directory(&created).context("materialization rejected")?;
                sync_directory(&directory).context("materialization rejected")?;
                let snapshot = handle_snapshot(&created, true, "materialized input directory")?;
                self.tree.directories.insert(prefix.clone(), snapshot);
                directory = created;
            }
        }
        Ok(directory)
    }

    pub(super) fn write_member(
        &mut self,
        relative_path: &str,
        executable: bool,
        expected: &ArtifactFingerprint,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<MaterializedInputMember> {
        anyhow::ensure!(!self.poisoned, "materialization rejected");
        self.poisoned = true;
        let result = self.write_member_inner(relative_path, executable, expected, emit);
        if result.is_ok() {
            self.poisoned = false;
        }
        result.map_err(|_| anyhow::anyhow!("materialization rejected"))
    }

    fn write_member_inner(
        &mut self,
        relative_path: &str,
        executable: bool,
        expected: &ArtifactFingerprint,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<MaterializedInputMember> {
        anyhow::ensure!(
            self.tree.members.len() < self.tree.maximum_members,
            "materialization rejected"
        );
        anyhow::ensure!(
            expected.byte_length <= self.tree.maximum_member_bytes,
            "materialization rejected"
        );
        verify_materialized_root_binding(&self.tree)?;
        let mut components =
            validated_components(Path::new(relative_path)).context("materialization rejected")?;
        let name = components.pop().context("materialization rejected")?;
        let mut member_path = components.clone();
        member_path.push(name.clone());
        anyhow::ensure!(
            !self.tree.members.contains_key(&member_path)
                && !self.tree.directories.contains_key(&member_path),
            "materialization rejected"
        );
        let parent = self.directory_for_create(&components)?;
        let mut options = AtOpenOptions::default();
        options
            .read(true)
            .write(OpenOptionsWriteMode::Write)
            .create_new(true)
            .follow(false);
        let mut file = options
            .open_at(&parent, &name)
            .context("materialization rejected")?;
        let fingerprint = {
            let mut writer = ExactFingerprintWriter::new(
                &mut file,
                expected.byte_length,
                self.tree.maximum_member_bytes,
            )?;
            emit(&mut writer).context("materialization rejected")?;
            writer.finish().context("materialization rejected")?
        };
        anyhow::ensure!(&fingerprint == expected, "materialization rejected");
        set_materialized_file_permissions(&file, executable).context("materialization rejected")?;
        verify_materialized_file_permissions(&file, executable)
            .context("materialization rejected")?;
        file.flush().context("materialization rejected")?;
        file.sync_all().context("materialization rejected")?;
        sync_directory(&parent).context("materialization rejected")?;
        let snapshot = verified_file_snapshot(
            &file,
            self.tree.maximum_member_bytes,
            "materialized input member",
        )?;
        anyhow::ensure!(
            snapshot.readonly
                && snapshot.link_count == 1
                && snapshot.byte_length == expected.byte_length,
            "materialization rejected"
        );
        ensure_file_unchanged(&file, snapshot, "materialized input member")?;
        drop(file);
        let opened = open_child_file(
            &parent,
            &name,
            self.tree.maximum_member_bytes,
            "materialized input member",
        )
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        let mut retained = opened.file;
        let retained_snapshot = opened.snapshot;
        anyhow::ensure!(retained_snapshot == snapshot, "materialization rejected");
        let retained_fingerprint = fingerprint_exact_source(&mut retained, expected.byte_length)?;
        anyhow::ensure!(
            &retained_fingerprint == expected,
            "materialization rejected"
        );
        verify_materialized_file_permissions(&retained, executable)?;
        ensure_file_unchanged(&retained, snapshot, "materialized input member")?;
        drop(retained);
        self.tree.members.insert(
            member_path,
            MaterializedMemberBinding {
                snapshot,
                fingerprint: retained_fingerprint.clone(),
                executable,
            },
        );
        verify_materialized_root_binding(&self.tree)?;
        Ok(MaterializedInputMember {
            fingerprint: retained_fingerprint,
        })
    }

    #[cfg(test)]
    #[allow(
        clippy::unused_self,
        reason = "the per-builder assertion documents that construction never scans the tree"
    )]
    pub(super) fn full_tree_scan_count_for_test(&self) -> usize {
        0
    }

    #[cfg(test)]
    #[allow(
        clippy::unused_self,
        reason = "the per-builder assertion documents that bindings retain metadata, not handles"
    )]
    pub(super) fn retained_member_handle_count_for_test(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(super) fn is_poisoned_for_test(&self) -> bool {
        self.poisoned
    }
}

fn verify_materialized_root_binding(tree: &MaterializedInputTreeState) -> Result<()> {
    anyhow::ensure!(
        verified_directory_identity(&tree.root, "materialized input root")? == tree.identity,
        "materialization rejected"
    );
    let bound = open_absolute_directory(&tree.absolute_root, "materialized input root")
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    anyhow::ensure!(
        verified_directory_identity(&bound, "materialized input root")? == tree.identity,
        "materialization rejected"
    );
    Ok(())
}

fn open_materialized_directory(
    tree: &MaterializedInputTreeState,
    components: &[OsString],
) -> Result<fs::File> {
    let mut directory = tree.root.try_clone().context("materialization rejected")?;
    let mut prefix = Vec::with_capacity(components.len());
    for component in components {
        prefix.push(component.clone());
        let expected = tree
            .directories
            .get(&prefix)
            .copied()
            .context("materialization rejected")?;
        directory = open_child_directory(&directory, component, "materialized input directory")
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        anyhow::ensure!(
            verified_directory_identity(&directory, "materialized input directory")?
                == expected.identity,
            "materialization rejected"
        );
    }
    Ok(directory)
}

fn expected_materialized_children(
    tree: &MaterializedInputTreeState,
) -> Result<BTreeMap<Vec<OsString>, BTreeSet<OsString>>> {
    let mut children = BTreeMap::<Vec<OsString>, BTreeSet<OsString>>::new();
    children.entry(Vec::new()).or_default();
    for path in tree.directories.keys() {
        children.entry(path.clone()).or_default();
    }
    for path in tree.directories.keys().chain(tree.members.keys()) {
        let (name, parent) = path.split_last().context("materialization rejected")?;
        anyhow::ensure!(
            children
                .get_mut(parent)
                .context("materialization rejected")?
                .insert(name.clone()),
            "materialization rejected"
        );
    }
    Ok(children)
}

impl MaterializedInputStore {
    pub(super) fn verify_root(&self) -> Result<()> {
        self.verify_root_with_hook(|| {})
    }

    #[cfg(test)]
    pub(super) fn verify_root_with_post_scan_hook(&self, hook: impl FnOnce()) -> Result<()> {
        self.verify_root_with_hook(hook)
    }

    fn verify_root_with_hook(&self, hook: impl FnOnce()) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), "materialization rejected");
        let result = self.verify_root_inner(hook);
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!("materialization rejected"))
    }

    fn verify_root_inner(&self, hook: impl FnOnce()) -> Result<()> {
        self.verify_directory_bindings()?;
        self.verify_member_bindings(true)?;
        self.verify_exact_tree()?;
        hook();
        self.verify_member_bindings(false)?;
        self.verify_directory_bindings()?;
        Ok(())
    }

    fn verify_directory_bindings(&self) -> Result<()> {
        verify_materialized_root_binding(&self.tree)?;
        verify_materialized_directory_permissions(&self.tree.root)?;
        anyhow::ensure!(
            handle_snapshot(&self.tree.root, true, "materialized input root")?
                == self.sealed_root_snapshot,
            "materialization rejected"
        );
        for (path, expected) in &self.tree.directories {
            let directory = open_materialized_directory(&self.tree, path)?;
            verify_materialized_directory_permissions(&directory)?;
            anyhow::ensure!(
                handle_snapshot(&directory, true, "materialized input directory")? == *expected,
                "materialization rejected"
            );
        }
        Ok(())
    }

    fn verify_member_bindings(&self, rehash: bool) -> Result<()> {
        for (path, binding) in &self.tree.members {
            let (name, parents) = path.split_last().context("materialization rejected")?;
            let parent = open_materialized_directory(&self.tree, parents)?;
            let opened = open_child_file(
                &parent,
                name,
                self.tree.maximum_member_bytes,
                "materialized input member",
            )
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
            let mut file = opened.file;
            anyhow::ensure!(
                opened.snapshot == binding.snapshot,
                "materialization rejected"
            );
            verify_materialized_file_permissions(&file, binding.executable)?;
            if rehash {
                anyhow::ensure!(
                    fingerprint_exact_source(&mut file, binding.fingerprint.byte_length)?
                        == binding.fingerprint,
                    "materialization rejected"
                );
            }
            ensure_file_unchanged(&file, binding.snapshot, "materialized input member")?;
        }
        Ok(())
    }

    fn verify_exact_tree(&self) -> Result<()> {
        #[cfg(test)]
        self.full_tree_scan_count.set(
            self.full_tree_scan_count
                .get()
                .checked_add(1)
                .context("materialization rejected")?,
        );
        for (parent_path, expected) in &self.expected_children {
            let mut directory = open_materialized_directory(&self.tree, parent_path)?;
            let maximum_observed = expected
                .len()
                .checked_add(2)
                .context("materialization rejected")?;
            let mut actual = BTreeSet::new();
            let mut observed = 0_usize;
            for entry in read_dir_at(&mut directory)
                .map_err(|_| anyhow::anyhow!("materialization rejected"))?
            {
                observed = observed
                    .checked_add(1)
                    .context("materialization rejected")?;
                anyhow::ensure!(observed <= maximum_observed, "materialization rejected");
                let name = entry
                    .map_err(|_| anyhow::anyhow!("materialization rejected"))?
                    .name()
                    .to_owned();
                if name != "." && name != ".." {
                    anyhow::ensure!(
                        expected.contains(&name) && actual.insert(name),
                        "materialization rejected"
                    );
                }
            }
            anyhow::ensure!(&actual == expected, "materialization rejected");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn verify_exact_tree_for_test(&self) -> Result<()> {
        self.verify_root()
    }

    #[cfg(test)]
    pub(super) fn member_count_for_test(&self) -> usize {
        self.tree.members.len()
    }

    #[cfg(test)]
    #[allow(
        clippy::unused_self,
        reason = "the per-store assertion documents that sealed bindings retain metadata, not handles"
    )]
    pub(super) fn retained_member_handle_count_for_test(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(super) fn full_tree_scan_count_for_test(&self) -> usize {
        self.full_tree_scan_count.get()
    }
}

/// Store-bound proof that bytes were durably persisted at the fixed build-input archive role.
///
/// This capability attests only to persistence, identity, and fingerprinting. The later
/// build-input slice remains responsible for validating archive framing and member semantics.
pub(super) struct PersistedBuildInputArchiveBytes {
    root_identity: FileIdentity,
    file: fs::File,
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
}

/// Store-bound proof that canonical build-input inventory bytes were durably persisted.
pub(super) struct PersistedBuildInputInventoryBytes {
    root_identity: FileIdentity,
    file: fs::File,
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
}

struct BoundStreamedWrite {
    parent: fs::File,
    parent_identity: FileIdentity,
    file: fs::File,
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
}

/// Store-bound proof that exact source-archive bytes were durably persisted.
///
/// The retained root, source directory, and file handles remain bound to their fixed paths. This
/// capability attests only to create-new persistence, identity, and fingerprinting; source
/// semantics are validated by the source-archive layer before the capability is exposed.
pub(super) struct PersistedSourceArchiveBytes {
    absolute_root: PathBuf,
    root: fs::File,
    root_identity: FileIdentity,
    source_directory: fs::File,
    source_directory_identity: FileIdentity,
    file: fs::File,
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
}

impl PersistedBuildInputArchiveBytes {
    /// Returns the fingerprint of the durably retained archive bytes.
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    pub(super) fn retained_file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        ensure_file_unchanged(&self.file, self.snapshot, "build-input archive")
    }
}

impl PersistedBuildInputInventoryBytes {
    /// Returns the fingerprint of the durably retained inventory bytes.
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    pub(super) fn retained_file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        ensure_file_unchanged(&self.file, self.snapshot, "build-input inventory")
    }

    /// Confirms that inventory and archive persistence capabilities share one campaign store.
    pub(super) fn shares_store_with(&self, archive: &PersistedBuildInputArchiveBytes) -> bool {
        self.root_identity == archive.root_identity
            && self.snapshot.identity != archive.snapshot.identity
    }
}

impl PersistedSourceArchiveBytes {
    /// Returns the fingerprint of the exact durably retained source-archive bytes.
    pub(super) fn fingerprint(&self) -> &ArtifactFingerprint {
        &self.fingerprint
    }

    /// Returns the bound read-only handle for checked seeking by the source-archive layer.
    pub(super) fn retained_file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    fn verify_root_binding(&self) -> Result<()> {
        anyhow::ensure!(
            verified_directory_identity(&self.root, "source archive root")? == self.root_identity,
            "source archive root changed"
        );
        let reopened = open_absolute_directory(&self.absolute_root, "source archive root")?;
        anyhow::ensure!(
            verified_directory_identity(&reopened, "source archive root")? == self.root_identity,
            "source archive root binding changed"
        );
        Ok(())
    }

    fn reopen_bound_file(&self) -> Result<OpenedInput> {
        self.verify_root_binding()?;
        anyhow::ensure!(
            verified_directory_identity(&self.source_directory, "source archive directory")?
                == self.source_directory_identity,
            "source archive directory changed"
        );
        let source = open_child_directory(
            &self.root,
            &OsString::from("source"),
            "source archive directory",
        )?;
        anyhow::ensure!(
            verified_directory_identity(&source, "source archive directory")?
                == self.source_directory_identity,
            "source archive directory binding changed"
        );
        let opened = open_child_file(
            &source,
            std::ffi::OsStr::new("exact-tree.sar"),
            MAX_SOURCE_ARCHIVE_V1_BYTES,
            "source archive",
        )?;
        anyhow::ensure!(
            opened.snapshot == self.snapshot,
            "source archive file binding changed"
        );
        Ok(opened)
    }

    /// Reopens the fixed role and rehashes the same immutable file through a snapshot sandwich.
    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        let mut reopened = self.reopen_bound_file()?;
        ensure_file_unchanged(&self.file, self.snapshot, "source archive")?;
        let actual = fingerprint_exact_source(&mut reopened.file, self.snapshot.byte_length)?;
        anyhow::ensure!(actual == self.fingerprint, "source archive changed");
        ensure_file_unchanged(&reopened.file, self.snapshot, "source archive")?;
        ensure_file_unchanged(&self.file, self.snapshot, "source archive")?;
        self.verify_root_binding()?;
        let final_reopen = self.reopen_bound_file()?;
        ensure_file_unchanged(&final_reopen.file, self.snapshot, "source archive")
    }
}

#[derive(Clone, Copy)]
pub(super) enum FixedArtifactRole {
    FirstQuietAttestation,
    BaselineUnrelatedProcessSet,
    HardwareProfile,
    ValidityThresholds,
}

impl FixedArtifactRole {
    fn path(self) -> &'static str {
        match self {
            Self::FirstQuietAttestation => "attestations/first-quiet-window.json",
            Self::BaselineUnrelatedProcessSet => "profiles/baseline-unrelated-process-set.json",
            Self::HardwareProfile => "profiles/hardware.json",
            Self::ValidityThresholds => "profiles/validity-thresholds.json",
        }
    }
}

impl CampaignArtifactStore {
    pub(super) fn write_fixed_preimage(
        &self,
        role: FixedArtifactRole,
        bytes: &[u8],
        maximum: u64,
    ) -> Result<ArtifactFingerprint> {
        let path = ArtifactPath::canonical(role.path().into())?;
        self.write_create_new_synced(&path, bytes, maximum)
    }
    pub(super) fn write_first_quiet_window<T: Serialize>(
        &self,
        value: &T,
        maximum: u64,
    ) -> Result<ArtifactFingerprint> {
        let path = ArtifactPath::canonical("first-quiet-window.json".into())?;
        self.write_canonical_pretty_create_new(&path, value, maximum)
    }

    pub(super) fn write_build_input_archive(
        &self,
        expected_length: u64,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<PersistedBuildInputArchiveBytes> {
        let path = ArtifactPath::canonical(BUILD_INPUT_ARCHIVE_PATH.into())?;
        let BoundStreamedWrite {
            file,
            snapshot,
            fingerprint,
            ..
        } = self.write_streamed_create_new(
            &path,
            expected_length,
            MAX_FIXED_BUILD_INPUT_BYTES,
            emit,
        )?;
        Ok(PersistedBuildInputArchiveBytes {
            root_identity: self.identity,
            file,
            snapshot,
            fingerprint,
        })
    }

    pub(super) fn write_build_input_inventory(
        &self,
        bytes: &[u8],
    ) -> Result<PersistedBuildInputInventoryBytes> {
        let path = ArtifactPath::canonical(BUILD_INPUT_INVENTORY_PATH.into())?;
        let expected_length = u64::try_from(bytes.len()).context("artifact length overflow")?;
        let BoundStreamedWrite {
            file,
            snapshot,
            fingerprint,
            ..
        } = self.write_streamed_create_new(
            &path,
            expected_length,
            MAX_SOURCE_ARCHIVE_V1_BYTES,
            |writer| {
                writer.write_all(bytes)?;
                Ok(())
            },
        )?;
        Ok(PersistedBuildInputInventoryBytes {
            root_identity: self.identity,
            file,
            snapshot,
            fingerprint,
        })
    }

    /// Streams one exact source archive into its fixed create-new role and returns a bound handle.
    pub(super) fn write_source_archive<R: Read + ?Sized>(
        &self,
        source: &mut R,
        expected_length: u64,
    ) -> Result<PersistedSourceArchiveBytes> {
        self.write_source_archive_inner(source, expected_length, || {})
    }

    fn write_source_archive_inner<R: Read + ?Sized>(
        &self,
        source: &mut R,
        expected_length: u64,
        post_write: impl FnOnce(),
    ) -> Result<PersistedSourceArchiveBytes> {
        let path = ArtifactPath::canonical(SOURCE_ARCHIVE_PATH.into())?;
        let BoundStreamedWrite {
            parent: source_directory,
            parent_identity: source_directory_identity,
            file,
            snapshot,
            fingerprint,
        } = self.write_streamed_create_new(
            &path,
            expected_length,
            MAX_SOURCE_ARCHIVE_V1_BYTES,
            |writer| copy_exact_source(source, writer, expected_length),
        )?;
        post_write();
        let root = self.root.try_clone().context("clone source archive root")?;
        let root_identity = verified_directory_identity(&root, "source archive root")?;
        anyhow::ensure!(
            root_identity == self.identity,
            "source archive root identity changed"
        );
        let persisted = PersistedSourceArchiveBytes {
            absolute_root: self.absolute_root.clone(),
            root,
            root_identity,
            source_directory,
            source_directory_identity,
            file,
            snapshot,
            fingerprint,
        };
        persisted.ensure_unchanged()?;
        Ok(persisted)
    }

    #[cfg(test)]
    pub(super) fn write_source_archive_with_post_write_hook<R: Read + ?Sized>(
        &self,
        source: &mut R,
        expected_length: u64,
        post_write: impl FnOnce(),
    ) -> Result<PersistedSourceArchiveBytes> {
        self.write_source_archive_inner(source, expected_length, post_write)
    }

    pub(super) fn create_new(absolute_root: &Path) -> Result<Self> {
        anyhow::ensure!(
            absolute_root.is_absolute(),
            "campaign root must be absolute"
        );
        ensure_directory_durability_supported()?;
        let parent_path = absolute_root
            .parent()
            .context("campaign root must have a parent")?;
        let name = absolute_root
            .file_name()
            .context("campaign root must have a final component")?;
        anyhow::ensure!(
            matches!(
                absolute_root.components().next_back(),
                Some(Component::Normal(_))
            ) && !name.to_string_lossy().contains('\\'),
            "campaign root has an invalid final component"
        );
        let parent = open_absolute_directory(parent_path, "campaign root parent")?;
        let created = AtOpenOptions::default()
            .mkdir_at(&parent, name)
            .context("create campaign root")?;
        set_private_directory_permissions(&created)?;
        let created_identity = verified_directory_identity(&created, "campaign root")?;
        sync_directory(&created).context("sync campaign root")?;
        sync_directory(&parent).context("sync campaign root parent")?;
        drop(created);
        let root = open_child_directory(&parent, &name.to_os_string(), "campaign root")?;
        let identity = verified_directory_identity(&root, "campaign root")?;
        anyhow::ensure!(
            identity == created_identity,
            "campaign root identity changed"
        );
        Ok(Self {
            absolute_root: absolute_root.to_owned(),
            root,
            identity,
        })
    }

    fn verify_root(&self) -> Result<()> {
        anyhow::ensure!(
            verified_directory_identity(&self.root, "campaign root")? == self.identity,
            "campaign root identity changed"
        );
        let reopened = open_absolute_directory(&self.absolute_root, "campaign root")?;
        anyhow::ensure!(
            verified_directory_identity(&reopened, "campaign root")? == self.identity,
            "campaign root identity changed"
        );
        Ok(())
    }

    pub(super) fn initialize_fixed_layout(&self) -> Result<()> {
        self.verify_root()?;
        for relative in FIXED_DIRECTORIES {
            self.create_directory_path(Path::new(relative))?;
        }
        sync_directory(&self.root).context("sync campaign layout")
    }

    pub(super) fn prepare_process_directories(
        &self,
        process: &ScheduledProcess<'_>,
    ) -> Result<ProcessArtifactPaths> {
        self.verify_root()?;
        let criterion_home = process.artifact_path(ArtifactRole::CriterionHome)?;
        let temporary_directory = process.artifact_path(ArtifactRole::TemporaryDirectory)?;
        self.create_directory_path(criterion_home.as_path())?;
        self.create_directory_path(temporary_directory.as_path())?;
        Ok(ProcessArtifactPaths {
            criterion_home,
            temporary_directory,
        })
    }

    fn create_directory_path(&self, relative: &Path) -> Result<fs::File> {
        let mut components = validated_components(relative)?;
        let name = components.pop().context("empty campaign directory path")?;
        let parent = self.open_directory_components(&components)?;
        let directory = AtOpenOptions::default()
            .mkdir_at(&parent, &name)
            .context("create campaign directory")?;
        set_private_directory_permissions(&directory)?;
        sync_directory(&directory).context("sync campaign directory")?;
        sync_directory(&parent).context("sync campaign directory parent")?;
        Ok(directory)
    }

    fn open_directory_components(&self, components: &[OsString]) -> Result<fs::File> {
        let mut directory = self
            .root
            .try_clone()
            .context("clone campaign root handle")?;
        for component in components {
            directory = open_child_directory(&directory, component, "campaign directory")?;
        }
        Ok(directory)
    }

    pub(super) fn write_create_new_synced(
        &self,
        path: &ArtifactPath,
        bytes: &[u8],
        maximum: u64,
    ) -> Result<ArtifactFingerprint> {
        self.write_bounded_from(
            path,
            std::io::Cursor::new(bytes),
            u64::try_from(bytes.len()).context("artifact length overflow")?,
            maximum,
        )
    }

    pub(super) fn write_canonical_pretty_create_new<T: Serialize>(
        &self,
        path: &ArtifactPath,
        value: &T,
        maximum: u64,
    ) -> Result<ArtifactFingerprint> {
        let mut bounded = BoundedBytes::new(maximum);
        let mut serializer = serde_json::Serializer::pretty(&mut bounded);
        value
            .serialize(&mut serializer)
            .context("serialize campaign artifact")?;
        bounded
            .write_all(b"\n")
            .context("append campaign artifact LF")?;
        let bytes = bounded.into_inner();
        self.write_create_new_synced(path, &bytes, maximum)
    }

    fn write_bounded_from<R: Read>(
        &self,
        path: &ArtifactPath,
        mut reader: R,
        expected_length: u64,
        maximum: u64,
    ) -> Result<ArtifactFingerprint> {
        self.write_streamed_create_new(path, expected_length, maximum, |writer| {
            copy_exact_source(&mut reader, writer, expected_length)
        })
        .map(|written| written.fingerprint)
    }

    fn write_streamed_create_new(
        &self,
        path: &ArtifactPath,
        expected_length: u64,
        maximum: u64,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<BoundStreamedWrite> {
        anyhow::ensure!(
            expected_length <= maximum,
            "campaign artifact exceeds byte limit"
        );
        self.verify_root()?;
        let mut components = validated_components(path.as_path())?;
        let name = components.pop().context("empty campaign artifact path")?;
        let parent = self.open_directory_components(&components)?;
        let parent_identity = verified_directory_identity(&parent, "campaign artifact parent")?;
        let mut options = AtOpenOptions::default();
        options
            .read(true)
            .write(OpenOptionsWriteMode::Write)
            .create_new(true)
            .follow(false);
        let mut file = options
            .open_at(&parent, &name)
            .context("create campaign artifact")?;
        set_private_file_permissions(&file)?;
        let written_fingerprint = {
            let mut writer = ExactFingerprintWriter::new(&mut file, expected_length, maximum)?;
            emit(&mut writer).context("emit campaign artifact")?;
            writer.finish()?
        };
        file.flush().context("flush campaign artifact")?;
        file.sync_all().context("sync campaign artifact")?;
        sync_directory(&parent).context("sync campaign artifact parent")?;
        let snapshot = verified_file_snapshot(&file, maximum, "campaign artifact")?;
        anyhow::ensure!(
            snapshot.byte_length == expected_length,
            "retained campaign artifact length changed"
        );
        self.verify_root()?;
        let mut reopened =
            self.reopen_bound_artifact(&components, &name, parent_identity, snapshot, maximum)?;
        let retained_fingerprint = fingerprint_exact_source(&mut reopened, expected_length)?;
        anyhow::ensure!(
            retained_fingerprint == written_fingerprint,
            "retained campaign artifact changed"
        );
        ensure_file_unchanged(&reopened, snapshot, "campaign artifact")?;
        ensure_file_unchanged(&file, snapshot, "campaign artifact")?;
        self.verify_root()?;
        let final_reopen =
            self.reopen_bound_artifact(&components, &name, parent_identity, snapshot, maximum)?;
        self.verify_root()?;
        ensure_file_unchanged(&final_reopen, snapshot, "campaign artifact")?;
        anyhow::ensure!(
            verified_directory_identity(&parent, "campaign artifact parent")? == parent_identity,
            "campaign artifact parent changed"
        );
        Ok(BoundStreamedWrite {
            parent,
            parent_identity,
            file: final_reopen,
            snapshot,
            fingerprint: retained_fingerprint,
        })
    }

    fn reopen_bound_artifact(
        &self,
        components: &[OsString],
        name: &OsString,
        expected_parent_identity: FileIdentity,
        expected_snapshot: FileSnapshot,
        maximum: u64,
    ) -> Result<fs::File> {
        let parent = self.open_directory_components(components)?;
        anyhow::ensure!(
            verified_directory_identity(&parent, "campaign artifact parent")?
                == expected_parent_identity,
            "campaign artifact parent identity changed"
        );
        let opened = open_child_file(&parent, name, maximum, "campaign artifact")?;
        anyhow::ensure!(
            opened.snapshot == expected_snapshot,
            "campaign artifact path binding changed"
        );
        Ok(opened.file)
    }
}

struct ExactFingerprintWriter<W> {
    inner: W,
    expected_length: u64,
    written: u64,
    hasher: Sha256,
}

impl<W> ExactFingerprintWriter<W> {
    fn new(inner: W, expected_length: u64, maximum: u64) -> Result<Self> {
        anyhow::ensure!(
            expected_length <= maximum,
            "campaign artifact exceeds byte limit"
        );
        Ok(Self {
            inner,
            expected_length,
            written: 0,
            hasher: Sha256::new(),
        })
    }

    fn finish(self) -> Result<ArtifactFingerprint> {
        anyhow::ensure!(
            self.written == self.expected_length,
            "campaign artifact source was short"
        );
        Ok(ArtifactFingerprint {
            sha256: hex::encode_upper(self.hasher.finalize()),
            byte_length: self.written,
        })
    }
}

impl<W: Write> Write for ExactFingerprintWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| std::io::Error::other("campaign artifact length overflow"))?;
        let next = self
            .written
            .checked_add(length)
            .ok_or_else(|| std::io::Error::other("campaign artifact length overflow"))?;
        if next > self.expected_length {
            return Err(std::io::Error::other("campaign artifact source was long"));
        }
        let written = self.inner.write(bytes)?;
        if written > bytes.len() {
            return Err(std::io::Error::other(
                "campaign artifact writer violated the Write contract",
            ));
        }
        self.hasher.update(&bytes[..written]);
        self.written = self
            .written
            .checked_add(
                u64::try_from(written)
                    .map_err(|_| std::io::Error::other("campaign artifact length overflow"))?,
            )
            .ok_or_else(|| std::io::Error::other("campaign artifact length overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn copy_exact_source<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    expected_length: u64,
) -> Result<()> {
    let mut remaining = expected_length;
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(STREAM_BUFFER_BYTES as u64))
            .context("campaign artifact buffer length overflow")?;
        let read = loop {
            match reader.read(&mut buffer[..take]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => break result.context("read campaign artifact source")?,
            }
        };
        anyhow::ensure!(read != 0, "campaign artifact source was short");
        writer.write_all(&buffer[..read])?;
        remaining = remaining
            .checked_sub(u64::try_from(read).context("campaign artifact source length overflow")?)
            .context("campaign artifact source length overflow")?;
    }
    let mut trailing = [0_u8; 1];
    let trailing_length = loop {
        match reader.read(&mut trailing) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => break result.context("read campaign artifact source")?,
        }
    };
    anyhow::ensure!(trailing_length == 0, "campaign artifact source was long");
    Ok(())
}

pub(super) fn fingerprint_exact_source(
    reader: &mut (impl Read + Seek),
    expected_length: u64,
) -> Result<ArtifactFingerprint> {
    reader
        .seek(SeekFrom::Start(0))
        .context("rewind retained campaign artifact")?;
    let mut remaining = expected_length;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(STREAM_BUFFER_BYTES as u64))
            .context("retained campaign artifact buffer length overflow")?;
        let read = loop {
            match reader.read(&mut buffer[..take]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => break result.context("read retained campaign artifact")?,
            }
        };
        anyhow::ensure!(read != 0, "retained campaign artifact was short");
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).context("retained campaign artifact length overflow")?)
            .context("retained campaign artifact length overflow")?;
    }
    let mut trailing = [0_u8; 1];
    let trailing_length = loop {
        match reader.read(&mut trailing) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => break result.context("read retained campaign artifact")?,
        }
    };
    anyhow::ensure!(trailing_length == 0, "retained campaign artifact was long");
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(hasher.finalize()),
        byte_length: expected_length,
    })
}

struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: u64,
}

impl BoundedBytes {
    fn new(maximum: u64) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = u64::try_from(self.bytes.len())
            .ok()
            .and_then(|length| length.checked_add(u64::try_from(bytes.len()).ok()?))
            .ok_or_else(|| std::io::Error::other("campaign artifact length overflow"))?;
        if next > self.maximum {
            return Err(std::io::Error::other(
                "campaign artifact exceeds byte limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validated_components(path: &Path) -> Result<Vec<OsString>> {
    let display = path.to_string_lossy();
    anyhow::ensure!(
        !display.is_empty() && !display.contains('\\'),
        "invalid campaign-relative path"
    );
    path.components()
        .map(|component| match component {
            Component::Normal(value) if !value.is_empty() => Ok(value.to_os_string()),
            _ => Err(anyhow::anyhow!("invalid campaign-relative path")),
        })
        .collect()
}

#[cfg(not(windows))]
fn sync_directory(directory: &fs::File) -> Result<()> {
    directory.sync_all().context("sync directory")
}

#[cfg(windows)]
fn sync_directory(_directory: &fs::File) -> Result<()> {
    Err(anyhow::anyhow!(
        "campaign artifact store unavailable: durable directory synchronization is unsupported on Windows"
    ))
}

#[cfg(not(windows))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "uniform cross-platform activation gate preserves Windows fail-closed behavior"
)]
fn ensure_directory_durability_supported() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn ensure_directory_durability_supported() -> Result<()> {
    Err(anyhow::anyhow!(
        "campaign artifact store unavailable: durable directory synchronization is unsupported on Windows"
    ))
}

#[cfg(unix)]
fn set_private_directory_permissions(directory: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    directory
        .set_permissions(fs::Permissions::from_mode(0o700))
        .context("set private campaign directory permissions")
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "uniform cross-platform private-permissions boundary"
)]
fn set_private_directory_permissions(_directory: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("set private campaign artifact permissions")
}

#[cfg(unix)]
fn set_materialized_file_permissions(file: &fs::File, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o555 } else { 0o444 };
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("set materialized build-input permissions")
}

#[cfg(unix)]
fn set_materialized_directory_permissions(directory: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    directory
        .set_permissions(fs::Permissions::from_mode(0o555))
        .context("seal materialized input directory")
}

#[cfg(unix)]
fn verify_materialized_directory_permissions(directory: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    anyhow::ensure!(
        directory.metadata()?.permissions().mode() & 0o7777 == 0o555,
        "materialized input directory mode changed"
    );
    Ok(())
}

#[cfg(unix)]
fn verify_materialized_file_permissions(file: &fs::File, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let expected = if executable { 0o555 } else { 0o444 };
    anyhow::ensure!(
        file.metadata()?.permissions().mode() & 0o7777 == expected,
        "materialized build-input mode changed"
    );
    Ok(())
}

#[cfg(not(unix))]
fn set_materialized_file_permissions(file: &fs::File, _executable: bool) -> Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .context("set materialized build-input permissions")
}

#[cfg(not(unix))]
fn set_materialized_directory_permissions(directory: &fs::File) -> Result<()> {
    let mut permissions = directory.metadata()?.permissions();
    permissions.set_readonly(true);
    directory
        .set_permissions(permissions)
        .context("seal materialized input directory")
}

#[cfg(not(unix))]
fn verify_materialized_directory_permissions(directory: &fs::File) -> Result<()> {
    anyhow::ensure!(
        directory.metadata()?.permissions().readonly(),
        "materialized input directory mode changed"
    );
    Ok(())
}

#[cfg(not(unix))]
fn verify_materialized_file_permissions(file: &fs::File, _executable: bool) -> Result<()> {
    anyhow::ensure!(
        file.metadata()?.permissions().readonly(),
        "materialized build-input mode changed"
    );
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "uniform cross-platform private-permissions boundary"
)]
fn set_private_file_permissions(_file: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[cfg(not(windows))]
    use serde::ser::Error as _;

    use super::*;
    use crate::issuance_qualification::{
        fingerprint, plan_for_manifest, schedule::QualificationSchedule,
    };

    #[cfg(not(windows))]
    struct Broken;

    #[cfg(not(windows))]
    impl Read for Broken {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic read failure"))
        }
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct SyntheticReader {
        remaining: usize,
        maximum_requested: usize,
    }

    impl Read for SyntheticReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.maximum_requested = self.maximum_requested.max(buffer.len());
            let read = self.remaining.min(buffer.len());
            buffer[..read].fill(0x5a);
            self.remaining -= read;
            Ok(read)
        }
    }

    #[cfg(not(windows))]
    struct Unserializable;

    #[cfg(not(windows))]
    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("synthetic serialization failure"))
        }
    }

    fn schedule_inputs() -> (
        marty_perf_schema::SdJwtIssuanceQualificationManifest,
        marty_perf_schema::SdJwtIssuanceQualificationPlan,
    ) {
        let bytes =
            include_bytes!("../../tests/fixtures/sd-jwt-issuance-qualification-manifest-v1.json");
        let manifest = serde_json::from_slice(bytes).unwrap();
        let plan = plan_for_manifest(&manifest, bytes).unwrap();
        (manifest, plan)
    }

    #[test]
    fn bounded_pretty_serialization_rejects_body_and_line_feed_overflow() {
        let mut body = BoundedBytes::new(4);
        let mut serializer = serde_json::Serializer::pretty(&mut body);
        assert!("long".serialize(&mut serializer).is_err());
        assert!(body.bytes.len() <= 4);

        let mut line_feed = BoundedBytes::new(2);
        let mut serializer = serde_json::Serializer::pretty(&mut line_feed);
        "".serialize(&mut serializer).unwrap();
        assert_eq!(line_feed.bytes, b"\"\"");
        assert!(line_feed.write_all(b"\n").is_err());
        assert_eq!(line_feed.bytes, b"\"\"");
    }

    #[test]
    fn exact_fingerprinting_writer_is_chunk_independent_and_does_not_materialize_limit() {
        let expected = b"streamed campaign artifact";
        let mut output = Vec::new();
        let actual_fingerprint = {
            let mut writer = ExactFingerprintWriter::new(
                &mut output,
                u64::try_from(expected.len()).unwrap(),
                u64::try_from(expected.len()).unwrap(),
            )
            .unwrap();
            writer.write_all(&expected[..3]).unwrap();
            writer.write_all(&expected[3..11]).unwrap();
            writer.write_all(&expected[11..]).unwrap();
            writer.finish().unwrap()
        };
        assert_eq!(output, expected);
        assert_eq!(actual_fingerprint, fingerprint(expected).unwrap());

        let exact_limit = ExactFingerprintWriter::new(
            std::io::sink(),
            MAX_FIXED_BUILD_INPUT_BYTES,
            MAX_FIXED_BUILD_INPUT_BYTES,
        );
        assert!(exact_limit.is_ok());
        assert!(ExactFingerprintWriter::new(
            std::io::sink(),
            MAX_FIXED_BUILD_INPUT_BYTES + 1,
            MAX_FIXED_BUILD_INPUT_BYTES,
        )
        .is_err());
    }

    #[test]
    fn exact_fingerprinting_writer_rejects_short_overlong_and_broken_outputs() {
        let mut short_output = Vec::new();
        let mut short = ExactFingerprintWriter::new(&mut short_output, 3, 3).unwrap();
        short.write_all(b"12").unwrap();
        assert_eq!(
            short.finish().unwrap_err().to_string(),
            "campaign artifact source was short"
        );
        assert_eq!(short_output, b"12");

        let mut overlong_output = Vec::new();
        let mut overlong = ExactFingerprintWriter::new(&mut overlong_output, 2, 2).unwrap();
        overlong.write_all(b"12").unwrap();
        assert_eq!(
            overlong.write_all(b"3").unwrap_err().to_string(),
            "campaign artifact source was long"
        );
        assert_eq!(overlong_output, b"12");

        let mut broken = ExactFingerprintWriter::new(BrokenWriter, 1, 1).unwrap();
        assert_eq!(
            broken.write_all(b"x").unwrap_err().to_string(),
            "synthetic write failure"
        );
    }

    #[test]
    fn fixed_buffer_copy_requires_exact_source_eof() {
        let mut exact_output = Vec::new();
        copy_exact_source(&mut std::io::Cursor::new(b"exact"), &mut exact_output, 5).unwrap();
        assert_eq!(exact_output, b"exact");

        let mut short_output = Vec::new();
        assert_eq!(
            copy_exact_source(&mut std::io::Cursor::new(b"short"), &mut short_output, 6,)
                .unwrap_err()
                .to_string(),
            "campaign artifact source was short"
        );
        assert_eq!(short_output, b"short");

        let mut long_output = Vec::new();
        assert_eq!(
            copy_exact_source(&mut std::io::Cursor::new(b"long"), &mut long_output, 3,)
                .unwrap_err()
                .to_string(),
            "campaign artifact source was long"
        );
        assert_eq!(long_output, b"lon");

        let length = STREAM_BUFFER_BYTES * 3 + 17;
        let mut synthetic = SyntheticReader {
            remaining: length,
            maximum_requested: 0,
        };
        copy_exact_source(
            &mut synthetic,
            &mut std::io::sink(),
            u64::try_from(length).unwrap(),
        )
        .unwrap();
        assert_eq!(synthetic.remaining, 0);
        assert_eq!(synthetic.maximum_requested, STREAM_BUFFER_BYTES);

        let mut retained = std::io::Cursor::new(b"exact");
        assert_eq!(
            fingerprint_exact_source(&mut retained, 5).unwrap(),
            fingerprint(b"exact").unwrap()
        );
        let mut retained_short = std::io::Cursor::new(b"short");
        assert_eq!(
            fingerprint_exact_source(&mut retained_short, 6)
                .unwrap_err()
                .to_string(),
            "retained campaign artifact was short"
        );
        let mut retained_long = std::io::Cursor::new(b"long");
        assert_eq!(
            fingerprint_exact_source(&mut retained_long, 3)
                .unwrap_err()
                .to_string(),
            "retained campaign artifact was long"
        );
    }

    #[cfg(not(windows))]
    fn store() -> (tempfile::TempDir, CampaignArtifactStore) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("campaign");
        let store = CampaignArtifactStore::create_new(&root).unwrap();
        (temporary, store)
    }

    #[test]
    #[cfg(not(windows))]
    fn fixed_layout_is_exact_and_create_only() {
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        for relative in FIXED_DIRECTORIES {
            assert!(root.join(relative).is_dir(), "{relative}");
        }
        let mut actual = Vec::new();
        for top_level in fs::read_dir(&root).unwrap() {
            let top_level = top_level.unwrap();
            actual.push(top_level.file_name().to_string_lossy().into_owned());
        }
        actual.sort();
        let mut expected = FIXED_DIRECTORIES
            .iter()
            .filter(|value| !value.contains('/'))
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(actual, expected);
        assert!(store.initialize_fixed_layout().is_err());
        assert!(CampaignArtifactStore::create_new(&root).is_err());
    }

    #[test]
    fn every_process_role_path_is_unique_and_canonical() {
        let (manifest, plan) = schedule_inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let roles = [
            ArtifactRole::Invocation,
            ArtifactRole::CriterionHome,
            ArtifactRole::TemporaryDirectory,
            ArtifactRole::BarrierToken,
            ArtifactRole::BarrierReady,
            ArtifactRole::BarrierRelease,
            ArtifactRole::BarrierReceipt,
            ArtifactRole::InitialInventory,
            ArtifactRole::FinalInventory,
            ArtifactRole::Route,
            ArtifactRole::CriterionEstimate,
        ];
        for role in roles {
            let paths: BTreeSet<_> = schedule
                .iter()
                .map(|process| process.artifact_path(role).unwrap())
                .collect();
            assert_eq!(paths.len(), schedule.iter().len());
            assert!(paths
                .iter()
                .all(|path| validated_components(path.as_path()).is_ok()));
        }
        let first = schedule.iter().next().unwrap();
        let last = schedule.iter().last().unwrap();
        assert_eq!(
            first
                .artifact_path(ArtifactRole::Invocation)
                .unwrap()
                .as_path(),
            Path::new("invocations/r00_c00_e0.json")
        );
        assert_eq!(
            first.artifact_path(ArtifactRole::Route).unwrap().as_path(),
            Path::new("routes/r00_c00_e0.ndjson")
        );
        assert_eq!(
            last.artifact_path(ArtifactRole::FinalInventory)
                .unwrap()
                .as_path(),
            Path::new("inventories/r19_c65_e7-final.json")
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn process_directories_and_artifacts_are_create_only() {
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let (manifest, plan) = schedule_inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let process = schedule.iter().next().unwrap();
        let paths = store.prepare_process_directories(process).unwrap();
        assert!(temporary
            .path()
            .join("campaign")
            .join(paths.criterion_home.as_path())
            .is_dir());
        assert!(temporary
            .path()
            .join("campaign")
            .join(paths.temporary_directory.as_path())
            .is_dir());
        assert!(store.prepare_process_directories(process).is_err());
        let path = process.artifact_path(ArtifactRole::Invocation).unwrap();
        let expected = store.write_create_new_synced(&path, b"opaque", 6).unwrap();
        assert_eq!(expected, fingerprint(b"opaque").unwrap());
        assert!(store.write_create_new_synced(&path, b"changed", 7).is_err());
        assert_eq!(
            fs::read(temporary.path().join("campaign").join(path.as_path())).unwrap(),
            b"opaque"
        );
        let pretty_path = process.artifact_path(ArtifactRole::BarrierToken).unwrap();
        let pretty = store
            .write_canonical_pretty_create_new(
                &pretty_path,
                &serde_json::json!({"schema": "synthetic", "ordinal": 0}),
                1024,
            )
            .unwrap();
        let pretty_bytes = b"{\n  \"ordinal\": 0,\n  \"schema\": \"synthetic\"\n}\n";
        assert_eq!(pretty, fingerprint(pretty_bytes).unwrap());
        assert_eq!(
            fs::read(
                temporary
                    .path()
                    .join("campaign")
                    .join(pretty_path.as_path())
            )
            .unwrap(),
            pretty_bytes
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn bounded_short_erroring_and_serialization_sources_never_return_fingerprints() {
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let (manifest, plan) = schedule_inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let process = schedule.iter().next().unwrap();
        let too_large = process.artifact_path(ArtifactRole::Invocation).unwrap();
        assert!(store
            .write_create_new_synced(&too_large, b"123", 2)
            .is_err());
        let root = temporary.path().join("campaign");
        assert!(!root.join(too_large.as_path()).exists());
        let short = process.artifact_path(ArtifactRole::BarrierReady).unwrap();
        assert!(store
            .write_bounded_from(&short, std::io::Cursor::new(b"12"), 3, 3)
            .is_err());
        assert_eq!(fs::read(root.join(short.as_path())).unwrap(), b"12");
        let broken = process.artifact_path(ArtifactRole::BarrierRelease).unwrap();
        assert!(store.write_bounded_from(&broken, Broken, 1, 1).is_err());
        assert_eq!(fs::read(root.join(broken.as_path())).unwrap(), b"");
        let invalid = process.artifact_path(ArtifactRole::BarrierReceipt).unwrap();
        assert!(store
            .write_canonical_pretty_create_new(&invalid, &Unserializable, 1024)
            .is_err());
        assert!(!root.join(invalid.as_path()).exists());
        let over_limit = process
            .artifact_path(ArtifactRole::InitialInventory)
            .unwrap();
        assert!(store
            .write_canonical_pretty_create_new(&over_limit, &"x".repeat(1024), 16)
            .is_err());
        assert!(!root.join(over_limit.as_path()).exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn build_input_archive_stream_is_fixed_role_capped_and_create_only() {
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        let bytes = b"synthetic streamed build input bytes";
        let persisted = store
            .write_build_input_archive(u64::try_from(bytes.len()).unwrap(), |writer| {
                writer.write_all(&bytes[..9])?;
                writer.write_all(&bytes[9..])?;
                Ok(())
            })
            .unwrap();
        assert_eq!(persisted.fingerprint, fingerprint(bytes).unwrap());
        assert_eq!(persisted.root_identity, store.identity);
        assert_eq!(persisted.snapshot.byte_length, bytes.len() as u64);
        assert_eq!(
            fs::read(root.join(BUILD_INPUT_ARCHIVE_PATH)).unwrap(),
            bytes
        );
        assert!(store
            .write_build_input_archive(u64::try_from(bytes.len()).unwrap(), |writer| {
                writer.write_all(bytes)?;
                Ok(())
            })
            .is_err());

        let (temporary, second_store) = self::store();
        second_store.initialize_fixed_layout().unwrap();
        let invoked = std::cell::Cell::new(false);
        let Err(error) =
            second_store.write_build_input_archive(MAX_FIXED_BUILD_INPUT_BYTES + 1, |_writer| {
                invoked.set(true);
                Ok(())
            })
        else {
            panic!("an oversized archive must not issue a persistence capability");
        };
        assert_eq!(error.to_string(), "campaign artifact exceeds byte limit");
        assert!(!invoked.get());
        assert!(!temporary
            .path()
            .join("campaign")
            .join(BUILD_INPUT_ARCHIVE_PATH)
            .exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn failed_build_input_archive_streams_poison_the_create_only_campaign() {
        for (expected, emit, retained) in [
            (3, b"12".as_slice(), b"12".as_slice()),
            (2, b"123".as_slice(), b"12".as_slice()),
        ] {
            let (temporary, store) = store();
            store.initialize_fixed_layout().unwrap();
            assert!(store
                .write_build_input_archive(expected, |writer| {
                    copy_exact_source(&mut std::io::Cursor::new(emit), writer, expected)
                })
                .is_err());
            let path = temporary
                .path()
                .join("campaign")
                .join(BUILD_INPUT_ARCHIVE_PATH);
            assert_eq!(fs::read(path).unwrap(), retained);
            assert!(store
                .write_build_input_archive(expected, |_writer| Ok(()))
                .is_err());
        }

        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let Err(error) = store.write_build_input_archive(1, |writer| {
            writer.write_all(b"x")?;
            Err(anyhow::anyhow!("synthetic emitter failure"))
        }) else {
            panic!("a failed emitter must not issue a persistence capability");
        };
        assert_eq!(error.to_string(), "emit campaign artifact");
        assert_eq!(
            fs::read(
                temporary
                    .path()
                    .join("campaign")
                    .join(BUILD_INPUT_ARCHIVE_PATH)
            )
            .unwrap(),
            b"x"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn retained_archive_mutation_and_hardlink_insertion_issue_no_capability() {
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let path = temporary
            .path()
            .join("campaign")
            .join(BUILD_INPUT_ARCHIVE_PATH);
        assert!(store
            .write_build_input_archive(4, |writer| {
                writer.write_all(b"safe")?;
                let mut replacement = fs::OpenOptions::new().write(true).open(&path)?;
                replacement.write_all(b"evil")?;
                replacement.sync_all()?;
                Ok(())
            })
            .is_err());

        let (temporary, second_store) = self::store();
        second_store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        let path = root.join(BUILD_INPUT_ARCHIVE_PATH);
        assert!(second_store
            .write_build_input_archive(4, |writer| {
                writer.write_all(b"safe")?;
                fs::hard_link(&path, root.join("build/linked-input-files.bia"))?;
                Ok(())
            })
            .is_err());

        let (temporary, third_store) = self::store();
        third_store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        let path = root.join(BUILD_INPUT_ARCHIVE_PATH);
        assert!(third_store
            .write_build_input_archive(4, |writer| {
                writer.write_all(b"safe")?;
                fs::rename(&path, root.join("build/displaced-input-files.bia"))?;
                fs::write(&path, b"evil")?;
                Ok(())
            })
            .is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn archive_parent_and_campaign_root_replacement_issue_no_capability() {
        let (temporary, second_store) = self::store();
        second_store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        assert!(second_store
            .write_build_input_archive(4, |writer| {
                writer.write_all(b"safe")?;
                fs::rename(root.join("build"), root.join("moved-build"))?;
                fs::create_dir(root.join("build"))?;
                Ok(())
            })
            .is_err());

        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        assert!(store
            .write_build_input_archive(4, |writer| {
                writer.write_all(b"safe")?;
                fs::rename(&root, temporary.path().join("moved-campaign"))?;
                fs::create_dir(&root)?;
                fs::create_dir(root.join("build"))?;
                Ok(())
            })
            .is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn invalid_paths_collisions_and_hardlinks_fail_closed() {
        for invalid in [
            "",
            "../escape",
            "/absolute",
            "invocations\\escape.json",
            "invocations//escape.json",
        ] {
            assert!(
                ArtifactPath::canonical(invalid.into()).is_err(),
                "{invalid}"
            );
        }
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        fs::create_dir(root.join("invocations/collision.json")).unwrap();
        let collision = ArtifactPath::canonical("invocations/collision.json".into()).unwrap();
        assert!(store
            .write_create_new_synced(&collision, b"bytes", 5)
            .is_err());
        fs::write(root.join("source.bin"), b"sentinel").unwrap();
        fs::hard_link(root.join("source.bin"), root.join("invocations/hard.json")).unwrap();
        let hard = ArtifactPath::canonical("invocations/hard.json".into()).unwrap();
        assert!(store.write_create_new_synced(&hard, b"changed", 7).is_err());
        assert_eq!(fs::read(root.join("source.bin")).unwrap(), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_hardlinks_and_root_replacement_fail_closed() {
        use std::os::unix::fs::symlink;
        let (temporary, store) = store();
        store.initialize_fixed_layout().unwrap();
        let root = temporary.path().join("campaign");
        fs::write(root.join("outside"), b"sentinel").unwrap();
        symlink(root.join("outside"), root.join("invocations/link.json")).unwrap();
        let link = ArtifactPath::canonical("invocations/link.json".into()).unwrap();
        assert!(store.write_create_new_synced(&link, b"changed", 7).is_err());
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"sentinel");
        fs::hard_link(root.join("outside"), root.join("invocations/hard.json")).unwrap();
        let hard = ArtifactPath::canonical("invocations/hard.json".into()).unwrap();
        assert!(store.write_create_new_synced(&hard, b"changed", 7).is_err());
        fs::rename(&root, temporary.path().join("old-campaign")).unwrap();
        fs::create_dir(&root).unwrap();
        assert!(store.initialize_fixed_layout().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_fails_before_creation_when_directory_durability_is_unsupported() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("campaign");
        let Err(error) = CampaignArtifactStore::create_new(&root) else {
            panic!("Windows must not activate an unsupported durability contract");
        };
        assert_eq!(
            error.to_string(),
            "campaign artifact store unavailable: durable directory synchronization is unsupported on Windows"
        );
        assert!(!root.exists());
    }
}
