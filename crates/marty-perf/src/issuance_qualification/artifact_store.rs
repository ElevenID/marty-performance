//! Handle-relative, create-only storage for qualification campaign artifacts.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use fs_at::{OpenOptions as AtOpenOptions, OpenOptionsWriteMode};
use marty_perf_schema::ArtifactFingerprint;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::schedule::{ArtifactPath, ArtifactRole, ScheduledProcess};
use super::{
    ensure_file_unchanged, open_absolute_directory, verified_directory_identity,
    verified_file_snapshot, FileIdentity, FileSnapshot, MAX_FIXED_BUILD_INPUT_BYTES,
};

const BUILD_INPUT_ARCHIVE_PATH: &str = "build/input-files.bia";
const STREAM_BUFFER_BYTES: usize = 8 * 1024;

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

/// Store-bound proof that bytes were durably persisted at the fixed build-input archive role.
///
/// This capability attests only to persistence, identity, and fingerprinting. The later
/// build-input slice remains responsible for validating archive framing and member semantics.
pub(super) struct PersistedBuildInputArchiveBytes {
    root_identity: FileIdentity,
    snapshot: FileSnapshot,
    fingerprint: ArtifactFingerprint,
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
        let (snapshot, fingerprint) = self.write_streamed_create_new(
            &path,
            expected_length,
            MAX_FIXED_BUILD_INPUT_BYTES,
            emit,
        )?;
        Ok(PersistedBuildInputArchiveBytes {
            root_identity: self.identity,
            snapshot,
            fingerprint,
        })
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
        self.write_streamed_create_new(path, expected_length, maximum, |writer| {
            copy_exact_source(&mut reader, writer, expected_length)
        })
        .map(|(_, fingerprint)| fingerprint)
    }

    fn write_streamed_create_new(
        &self,
        path: &ArtifactPath,
        expected_length: u64,
        maximum: u64,
        emit: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<(FileSnapshot, ArtifactFingerprint)> {
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
        Ok((snapshot, retained_fingerprint))
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
        let mut options = AtOpenOptions::default();
        options.read(true).follow(false);
        let file = options
            .open_at(&parent, name)
            .context("reopen campaign artifact")?;
        anyhow::ensure!(
            verified_file_snapshot(&file, maximum, "campaign artifact")? == expected_snapshot,
            "campaign artifact path binding changed"
        );
        Ok(file)
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

fn fingerprint_exact_source(
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
