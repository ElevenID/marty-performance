//! Handle-relative, create-only storage for qualification campaign artifacts.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use fs_at::{OpenOptions as AtOpenOptions, OpenOptionsWriteMode};
use marty_perf_schema::ArtifactFingerprint;
use serde::Serialize;

use super::schedule::{ArtifactPath, ArtifactRole, ScheduledProcess};
use super::{
    ensure_file_unchanged, fingerprint, open_absolute_directory, verified_directory_identity,
    verified_file_snapshot, FileIdentity,
};

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
        sync_directory(&created).context("sync campaign root")?;
        sync_directory(&parent).context("sync campaign root parent")?;
        drop(created);
        let mut reopen = AtOpenOptions::default();
        reopen.read(true).follow(false);
        let root = reopen
            .open_dir_at(&parent, name)
            .context("reopen campaign root")?;
        let identity = verified_directory_identity(&root, "campaign root")?;
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
            let mut options = AtOpenOptions::default();
            options.read(true).follow(false);
            directory = options
                .open_dir_at(&directory, component)
                .context("open campaign directory")?;
            verified_directory_identity(&directory, "campaign directory")?;
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
        self.verify_root()?;
        anyhow::ensure!(
            expected_length <= maximum,
            "campaign artifact exceeds byte limit"
        );
        let mut components = validated_components(path.as_path())?;
        let name = components.pop().context("empty campaign artifact path")?;
        let parent = self.open_directory_components(&components)?;
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
        let mut retained = Vec::with_capacity(
            usize::try_from(expected_length).context("artifact allocation overflow")?,
        );
        let mut buffer = [0_u8; 8192];
        loop {
            let count = reader
                .read(&mut buffer)
                .context("read campaign artifact source")?;
            if count == 0 {
                break;
            }
            retained.extend_from_slice(&buffer[..count]);
            anyhow::ensure!(
                u64::try_from(retained.len()).context("artifact length overflow")? <= maximum,
                "campaign artifact exceeds byte limit"
            );
            file.write_all(&buffer[..count])
                .context("write campaign artifact")?;
        }
        anyhow::ensure!(
            u64::try_from(retained.len()).context("artifact length overflow")? == expected_length,
            "campaign artifact source was short"
        );
        file.flush().context("flush campaign artifact")?;
        file.sync_all().context("sync campaign artifact")?;
        sync_directory(&parent).context("sync campaign artifact parent")?;
        let snapshot = verified_file_snapshot(&file, maximum, "campaign artifact")?;
        file.seek(SeekFrom::Start(0))
            .context("rewind campaign artifact")?;
        let mut actual = Vec::with_capacity(retained.len());
        file.read_to_end(&mut actual)
            .context("read retained campaign artifact")?;
        anyhow::ensure!(actual == retained, "retained campaign artifact changed");
        ensure_file_unchanged(&file, snapshot, "campaign artifact")?;
        fingerprint(&actual)
    }
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
    use crate::issuance_qualification::{plan_for_manifest, schedule::QualificationSchedule};

    #[cfg(not(windows))]
    struct Broken;

    #[cfg(not(windows))]
    impl Read for Broken {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic read failure"))
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
