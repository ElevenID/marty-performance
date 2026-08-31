//! Approved, nonactivating retention of one exact source archive.

use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom};

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;

use super::artifact_store::{
    fingerprint_exact_source, CampaignArtifactStore, PersistedSourceArchiveBytes,
};
use super::{
    ensure_file_unchanged, fingerprint, valid_artifact_fingerprint, valid_campaign_id,
    validate_source_archive_bytes, OpenedInput, MAX_SOURCE_ARCHIVE_V1_BYTES,
};

const RETENTION_REJECTED: &str = "source archive retention rejected";
const SOURCE_READ_BUFFER_BYTES: usize = 8 * 1024;

/// One explicit in-memory controller decision authorizing source export for one campaign.
pub(super) struct SourceExportApproval {
    campaign_id: String,
    approved: bool,
}

impl SourceExportApproval {
    pub(super) fn new(campaign_id: String, approved: bool) -> Self {
        Self {
            campaign_id,
            approved,
        }
    }
}

/// Opaque, non-cloneable proof that an approved exact source archive was retained.
pub(super) struct RetainedSourceArchive {
    persisted: PersistedSourceArchiveBytes,
    campaign_id: String,
    source_commit: String,
    source_tree: String,
    cargo_lock_fingerprint: ArtifactFingerprint,
    committer_timestamp: u64,
}

impl fmt::Debug for RetainedSourceArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedSourceArchive")
            .finish_non_exhaustive()
    }
}

impl RetainedSourceArchive {
    pub(super) fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub(super) fn archive_fingerprint(&self) -> &ArtifactFingerprint {
        self.persisted.fingerprint()
    }

    pub(super) fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub(super) fn source_tree(&self) -> &str {
        &self.source_tree
    }

    pub(super) fn cargo_lock_fingerprint(&self) -> &ArtifactFingerprint {
        &self.cargo_lock_fingerprint
    }

    pub(super) fn committer_timestamp(&self) -> u64 {
        self.committer_timestamp
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        self.persisted
            .ensure_unchanged()
            .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))
    }
}

fn read_bounded_source_archive(reader: &mut (impl Read + ?Sized)) -> Result<Vec<u8>> {
    let limit = MAX_SOURCE_ARCHIVE_V1_BYTES
        .checked_add(1)
        .context(RETENTION_REJECTED)?;
    let mut remaining = limit;
    let mut bytes = Vec::with_capacity(64 * 1024);
    let mut buffer = [0_u8; SOURCE_READ_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(SOURCE_READ_BUFFER_BYTES as u64))
            .context(RETENTION_REJECTED)?;
        let read = loop {
            match reader.read(&mut buffer[..take]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => break result.map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?,
            }
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).context(RETENTION_REJECTED)?)
            .context(RETENTION_REJECTED)?;
    }
    anyhow::ensure!(
        u64::try_from(bytes.len()).is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_V1_BYTES),
        RETENTION_REJECTED
    );
    Ok(bytes)
}

fn retain_inner(
    store: &CampaignArtifactStore,
    campaign_id: &str,
    approval: SourceExportApproval,
    input: &mut OpenedInput,
    expected_outer_fingerprint: &ArtifactFingerprint,
    expected_cargo_lock_fingerprint: &ArtifactFingerprint,
    post_read: impl FnOnce(),
) -> Result<RetainedSourceArchive> {
    let SourceExportApproval {
        campaign_id: approved_campaign_id,
        approved,
    } = approval;
    anyhow::ensure!(
        approved
            && approved_campaign_id == campaign_id
            && valid_campaign_id(campaign_id)
            && valid_artifact_fingerprint(expected_outer_fingerprint)
            && valid_artifact_fingerprint(expected_cargo_lock_fingerprint)
            && input.snapshot.readonly
            && input.snapshot.link_count == 1
            && input.snapshot.byte_length <= MAX_SOURCE_ARCHIVE_V1_BYTES
            && input.snapshot.byte_length == expected_outer_fingerprint.byte_length,
        RETENTION_REJECTED
    );

    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    input
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    let bytes = read_bounded_source_archive(&mut input.file)?;
    anyhow::ensure!(
        u64::try_from(bytes.len()) == Ok(input.snapshot.byte_length),
        RETENTION_REJECTED
    );
    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;

    let actual_outer_fingerprint = fingerprint(&bytes).context(RETENTION_REJECTED)?;
    anyhow::ensure!(
        &actual_outer_fingerprint == expected_outer_fingerprint,
        RETENTION_REJECTED
    );

    post_read();
    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    let verification_fingerprint =
        fingerprint_exact_source(&mut input.file, input.snapshot.byte_length)
            .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    anyhow::ensure!(
        verification_fingerprint == actual_outer_fingerprint,
        RETENTION_REJECTED
    );
    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;

    let validated = validate_source_archive_bytes(
        &bytes,
        expected_outer_fingerprint,
        expected_cargo_lock_fingerprint,
    )
    .context(RETENTION_REJECTED)?;
    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;

    let mut retained_bytes = Cursor::new(bytes.as_slice());
    let persisted = store
        .write_source_archive(&mut retained_bytes, actual_outer_fingerprint.byte_length)
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    anyhow::ensure!(
        persisted.fingerprint() == expected_outer_fingerprint,
        RETENTION_REJECTED
    );

    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    let final_source_fingerprint =
        fingerprint_exact_source(&mut input.file, input.snapshot.byte_length)
            .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    anyhow::ensure!(
        final_source_fingerprint == actual_outer_fingerprint,
        RETENTION_REJECTED
    );
    ensure_file_unchanged(&input.file, input.snapshot, "source archive")
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;
    persisted
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))?;

    Ok(RetainedSourceArchive {
        persisted,
        campaign_id: campaign_id.to_owned(),
        source_commit: validated.manifest.source_commit,
        source_tree: validated.manifest.source_tree,
        cargo_lock_fingerprint: expected_cargo_lock_fingerprint.clone(),
        committer_timestamp: validated.committer_timestamp,
    })
}

pub(super) fn retain_approved_source_archive(
    store: &CampaignArtifactStore,
    campaign_id: &str,
    approval: SourceExportApproval,
    input: &mut OpenedInput,
    expected_outer_fingerprint: &ArtifactFingerprint,
    expected_cargo_lock_fingerprint: &ArtifactFingerprint,
) -> Result<RetainedSourceArchive> {
    retain_inner(
        store,
        campaign_id,
        approval,
        input,
        expected_outer_fingerprint,
        expected_cargo_lock_fingerprint,
        || {},
    )
    .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))
}

#[cfg(test)]
fn retain_with_post_read_hook(
    store: &CampaignArtifactStore,
    campaign_id: &str,
    approval: SourceExportApproval,
    input: &mut OpenedInput,
    expected_outer_fingerprint: &ArtifactFingerprint,
    expected_cargo_lock_fingerprint: &ArtifactFingerprint,
    post_read: impl FnOnce(),
) -> Result<RetainedSourceArchive> {
    retain_inner(
        store,
        campaign_id,
        approval,
        input,
        expected_outer_fingerprint,
        expected_cargo_lock_fingerprint,
        post_read,
    )
    .map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::{self, Cursor, Read};
    #[cfg(not(windows))]
    use std::io::{Seek, SeekFrom};
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use super::*;
    #[cfg(not(windows))]
    use crate::issuance_qualification::artifact_store::SOURCE_ARCHIVE_PATH;
    #[cfg(not(windows))]
    use crate::issuance_qualification::MAX_SOURCE_ARCHIVE_V1_BYTES;
    use crate::issuance_qualification::{
        git_object_id as production_git_object_id, open_absolute_file, reconstructed_source_tree,
        SourceArchiveEntryWire, SourceArchiveManifestWire, SOURCE_ARCHIVE_MAGIC,
    };

    const CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const OTHER_CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174001";

    struct Fixture {
        archive: Vec<u8>,
        archive_fingerprint: ArtifactFingerprint,
        cargo_lock_fingerprint: ArtifactFingerprint,
        source_commit: String,
        source_tree: String,
    }

    fn fingerprint(bytes: &[u8]) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: hex::encode_upper(Sha256::digest(bytes)),
            byte_length: u64::try_from(bytes.len()).unwrap(),
        }
    }

    fn fixture() -> Fixture {
        let contents = [b"lock\n".as_slice(), b"pub fn fixture() {}\n".as_slice()];
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
                    git_object_id: hex::encode(production_git_object_id("blob", contents[0])),
                    artifact_fingerprint: fingerprint(contents[0]),
                },
                SourceArchiveEntryWire {
                    repository_relative_path: "src/lib.rs".to_owned(),
                    git_mode: "100644".to_owned(),
                    git_object_id: hex::encode(production_git_object_id("blob", contents[1])),
                    artifact_fingerprint: fingerprint(contents[1]),
                },
            ],
        };
        manifest.source_tree =
            hex::encode(reconstructed_source_tree(&manifest.entries, &contents).unwrap());
        let commit = format!(
            "tree {}\nauthor Marty Fixture <fixture@example.invalid> 1700000000 -0700\ncommitter Marty Fixture <fixture@example.invalid> 1700000123 +0530\n\nfixture\n",
            manifest.source_tree
        )
        .into_bytes();
        manifest.source_commit = hex::encode(production_git_object_id("commit", &commit));
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        manifest_bytes.push(b'\n');
        let mut archive = SOURCE_ARCHIVE_MAGIC.to_vec();
        archive.extend_from_slice(&u64::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
        archive.extend_from_slice(&manifest_bytes);
        archive.extend_from_slice(&u64::try_from(commit.len()).unwrap().to_be_bytes());
        archive.extend_from_slice(&commit);
        for content in contents {
            archive.extend_from_slice(&u64::try_from(content.len()).unwrap().to_be_bytes());
            archive.extend_from_slice(content);
        }
        Fixture {
            archive_fingerprint: fingerprint(&archive),
            cargo_lock_fingerprint: fingerprint(contents[0]),
            source_commit: manifest.source_commit,
            source_tree: manifest.source_tree,
            archive,
        }
    }

    #[cfg(not(windows))]
    fn store() -> (tempfile::TempDir, CampaignArtifactStore) {
        let temporary = tempfile::tempdir().unwrap();
        let store = CampaignArtifactStore::create_new(&temporary.path().join("campaign")).unwrap();
        store.initialize_fixed_layout().unwrap();
        (temporary, store)
    }

    fn set_readonly(path: &Path, readonly: bool) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(readonly);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn source_input(
        directory: &Path,
        name: &str,
        bytes: &[u8],
        readonly: bool,
        maximum: u64,
    ) -> (PathBuf, OpenedInput) {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        set_readonly(&path, readonly);
        let input = open_absolute_file(&path, maximum, None, "source archive").unwrap();
        (path, input)
    }

    fn approval(campaign_id: &str, approved: bool) -> SourceExportApproval {
        SourceExportApproval::new(campaign_id.to_owned(), approved)
    }

    fn assert_redacted(error: &anyhow::Error) {
        let rendered = error.to_string();
        assert_eq!(rendered, RETENTION_REJECTED);
        assert!(!rendered.contains(CAMPAIGN_ID));
        assert!(!rendered.contains("exact-tree.sar"));
        assert!(!rendered.contains("Cargo.lock"));
    }

    #[test]
    #[cfg(not(windows))]
    fn approved_archive_retains_exact_bytes_and_golden_metadata() {
        let fixture = fixture();
        assert_eq!(
            fixture.archive_fingerprint,
            ArtifactFingerprint {
                sha256: "3135A38DA0213D5639724160B757A319DDB5C9D685D16298B5754EA13EBD18F1"
                    .to_owned(),
                byte_length: 1_162,
            }
        );
        assert_eq!(
            fixture.cargo_lock_fingerprint.sha256,
            "D8C9F2728AA278EBCD33CCEDF3AD309A866870AD5FB93A03526B4B7655C9E911"
        );
        assert_eq!(fixture.cargo_lock_fingerprint.byte_length, 5);
        assert_eq!(
            fixture.source_tree,
            "a8cad0707387a1afbdb5f57738d607d6fde4ab45"
        );
        assert_eq!(
            fixture.source_commit,
            "9b9421c2c50f037a66f2cb2f22819289437c35b2"
        );
        let (temporary, store) = store();
        let inputs = tempfile::tempdir().unwrap();
        let (_path, mut input) = source_input(
            inputs.path(),
            "approved.sar",
            &fixture.archive,
            true,
            MAX_SOURCE_ARCHIVE_V1_BYTES,
        );
        let retained = retain_approved_source_archive(
            &store,
            CAMPAIGN_ID,
            approval(CAMPAIGN_ID, true),
            &mut input,
            &fixture.archive_fingerprint,
            &fixture.cargo_lock_fingerprint,
        )
        .unwrap();

        assert_eq!(retained.campaign_id(), CAMPAIGN_ID);
        assert_eq!(retained.archive_fingerprint(), &fixture.archive_fingerprint);
        assert_eq!(
            retained.cargo_lock_fingerprint(),
            &fixture.cargo_lock_fingerprint
        );
        assert_eq!(retained.source_commit(), fixture.source_commit);
        assert_eq!(retained.source_tree(), fixture.source_tree);
        assert_eq!(retained.committer_timestamp(), 1_700_000_123);
        assert_eq!(
            fs::read(temporary.path().join("campaign").join(SOURCE_ARCHIVE_PATH)).unwrap(),
            fixture.archive
        );
        store
            .write_first_quiet_window(&serde_json::json!({ "synthetic": true }), 1_024)
            .unwrap();
        retained.ensure_unchanged().unwrap();
    }

    #[test]
    #[cfg(not(windows))]
    fn approval_and_campaign_mismatch_precede_reads_and_creation() {
        for (approved, approval_campaign) in [(false, CAMPAIGN_ID), (true, OTHER_CAMPAIGN_ID)] {
            let fixture = fixture();
            let (temporary, store) = store();
            let inputs = tempfile::tempdir().unwrap();
            let (_path, mut input) = source_input(
                inputs.path(),
                "source.sar",
                &fixture.archive,
                true,
                MAX_SOURCE_ARCHIVE_V1_BYTES,
            );
            input.file.seek(SeekFrom::Start(3)).unwrap();
            let error = retain_approved_source_archive(
                &store,
                CAMPAIGN_ID,
                approval(approval_campaign, approved),
                &mut input,
                &fixture.archive_fingerprint,
                &fixture.cargo_lock_fingerprint,
            )
            .unwrap_err();
            assert_redacted(&error);
            assert_eq!(input.file.stream_position().unwrap(), 3);
            assert!(!temporary
                .path()
                .join("campaign")
                .join(SOURCE_ARCHIVE_PATH)
                .exists());
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn writable_multilink_and_oversize_inputs_issue_no_capability() {
        let fixture = fixture();
        for condition in ["writable", "multilink", "oversize"] {
            let (temporary, store) = store();
            let inputs = tempfile::tempdir().unwrap();
            let (path, mut input) = match condition {
                "writable" => source_input(
                    inputs.path(),
                    "source.sar",
                    &fixture.archive,
                    false,
                    MAX_SOURCE_ARCHIVE_V1_BYTES,
                ),
                "multilink" => {
                    let (path, input) = source_input(
                        inputs.path(),
                        "source.sar",
                        &fixture.archive,
                        true,
                        MAX_SOURCE_ARCHIVE_V1_BYTES,
                    );
                    fs::hard_link(&path, inputs.path().join("alias.sar")).unwrap();
                    (path, input)
                }
                "oversize" => {
                    let path = inputs.path().join("source.sar");
                    let file = fs::File::create(&path).unwrap();
                    file.set_len(MAX_SOURCE_ARCHIVE_V1_BYTES + 1).unwrap();
                    drop(file);
                    set_readonly(&path, true);
                    let input = open_absolute_file(
                        &path,
                        MAX_SOURCE_ARCHIVE_V1_BYTES + 1,
                        None,
                        "source archive",
                    )
                    .unwrap();
                    (path, input)
                }
                _ => unreachable!(),
            };
            let error = retain_approved_source_archive(
                &store,
                CAMPAIGN_ID,
                approval(CAMPAIGN_ID, true),
                &mut input,
                &fixture.archive_fingerprint,
                &fixture.cargo_lock_fingerprint,
            )
            .unwrap_err();
            assert_redacted(&error);
            assert!(!temporary
                .path()
                .join("campaign")
                .join(SOURCE_ARCHIVE_PATH)
                .exists());
            set_readonly(&path, false);
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn outer_and_cargo_lock_mismatch_reject_before_persistence() {
        for mismatch in ["outer", "cargo-lock"] {
            let fixture = fixture();
            let (temporary, store) = store();
            let inputs = tempfile::tempdir().unwrap();
            let (_path, mut input) = source_input(
                inputs.path(),
                "source.sar",
                &fixture.archive,
                true,
                MAX_SOURCE_ARCHIVE_V1_BYTES,
            );
            let mut wrong_outer = fixture.archive_fingerprint.clone();
            wrong_outer.sha256.replace_range(..1, "0");
            if wrong_outer == fixture.archive_fingerprint {
                wrong_outer.sha256.replace_range(..1, "1");
            }
            let wrong_cargo_lock = fingerprint(b"wrong public source binding");
            let (outer, cargo_lock) = if mismatch == "outer" {
                (&wrong_outer, &fixture.cargo_lock_fingerprint)
            } else {
                (&fixture.archive_fingerprint, &wrong_cargo_lock)
            };
            let error = retain_approved_source_archive(
                &store,
                CAMPAIGN_ID,
                approval(CAMPAIGN_ID, true),
                &mut input,
                outer,
                cargo_lock,
            )
            .unwrap_err();
            assert_redacted(&error);
            assert!(!temporary
                .path()
                .join("campaign")
                .join(SOURCE_ARCHIVE_PATH)
                .exists());
        }
    }

    #[test]
    #[cfg(unix)]
    fn input_mutation_during_snapshot_sandwich_rejects_before_persistence() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture();
        let (temporary, store) = store();
        let inputs = tempfile::tempdir().unwrap();
        let (path, mut input) = source_input(
            inputs.path(),
            "source.sar",
            &fixture.archive,
            true,
            MAX_SOURCE_ARCHIVE_V1_BYTES,
        );
        let error = retain_with_post_read_hook(
            &store,
            CAMPAIGN_ID,
            approval(CAMPAIGN_ID, true),
            &mut input,
            &fixture.archive_fingerprint,
            &fixture.cargo_lock_fingerprint,
            || {
                let mut changed = fixture.archive.clone();
                *changed.last_mut().unwrap() ^= 1;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&path, changed).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            },
        )
        .unwrap_err();
        assert_redacted(&error);
        assert!(!temporary
            .path()
            .join("campaign")
            .join(SOURCE_ARCHIVE_PATH)
            .exists());
    }

    #[test]
    #[cfg(not(windows))]
    fn failed_stream_poisons_create_only_retry() {
        let fixture = fixture();
        let (temporary, store) = store();
        let mut short = Cursor::new(&fixture.archive[..fixture.archive.len() - 1]);
        assert!(store
            .write_source_archive(&mut short, fixture.archive_fingerprint.byte_length)
            .is_err());
        let retained_path = temporary.path().join("campaign").join(SOURCE_ARCHIVE_PATH);
        assert!(retained_path.exists());

        let inputs = tempfile::tempdir().unwrap();
        let (_path, mut input) = source_input(
            inputs.path(),
            "source.sar",
            &fixture.archive,
            true,
            MAX_SOURCE_ARCHIVE_V1_BYTES,
        );
        let error = retain_approved_source_archive(
            &store,
            CAMPAIGN_ID,
            approval(CAMPAIGN_ID, true),
            &mut input,
            &fixture.archive_fingerprint,
            &fixture.cargo_lock_fingerprint,
        )
        .unwrap_err();
        assert_redacted(&error);
    }

    #[test]
    #[cfg(unix)]
    fn post_write_source_directory_replacement_issues_no_store_capability() {
        let fixture = fixture();
        let (temporary, store) = store();
        let root = temporary.path().join("campaign");
        let original_source = root.join("original-source");
        let retained_path = root.join(SOURCE_ARCHIVE_PATH);
        let mut bytes = Cursor::new(fixture.archive.as_slice());

        let Err(error) = store.write_source_archive_with_post_write_hook(
            &mut bytes,
            fixture.archive_fingerprint.byte_length,
            || {
                fs::rename(root.join("source"), &original_source).unwrap();
                fs::create_dir(root.join("source")).unwrap();
                fs::rename(original_source.join("exact-tree.sar"), &retained_path).unwrap();
            },
        ) else {
            panic!("a replacement creation parent issued a source archive capability");
        };

        assert_eq!(
            error.to_string(),
            "source archive directory binding changed"
        );
        assert_eq!(fs::read(retained_path).unwrap(), fixture.archive);
    }

    #[test]
    #[cfg(unix)]
    fn retained_capability_rejects_root_directory_file_mode_link_and_byte_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        for mutation in ["root", "directory", "file", "mode", "link", "bytes"] {
            let fixture = fixture();
            let (temporary, store) = store();
            let inputs = tempfile::tempdir().unwrap();
            let (_path, mut input) = source_input(
                inputs.path(),
                "source.sar",
                &fixture.archive,
                true,
                MAX_SOURCE_ARCHIVE_V1_BYTES,
            );
            let retained = retain_approved_source_archive(
                &store,
                CAMPAIGN_ID,
                approval(CAMPAIGN_ID, true),
                &mut input,
                &fixture.archive_fingerprint,
                &fixture.cargo_lock_fingerprint,
            )
            .unwrap();
            let root = temporary.path().join("campaign");
            let archive = root.join(SOURCE_ARCHIVE_PATH);
            match mutation {
                "root" => {
                    fs::rename(&root, temporary.path().join("moved-campaign")).unwrap();
                    fs::create_dir(&root).unwrap();
                    fs::create_dir(root.join("source")).unwrap();
                    fs::write(root.join(SOURCE_ARCHIVE_PATH), &fixture.archive).unwrap();
                }
                "directory" => {
                    fs::rename(root.join("source"), root.join("original-source")).unwrap();
                    fs::create_dir(root.join("source")).unwrap();
                    fs::write(&archive, &fixture.archive).unwrap();
                }
                "file" => {
                    fs::rename(&archive, root.join("source/original.sar")).unwrap();
                    fs::write(&archive, &fixture.archive).unwrap();
                }
                "mode" => {
                    fs::set_permissions(&archive, fs::Permissions::from_mode(0o400)).unwrap();
                }
                "link" => {
                    fs::hard_link(&archive, root.join("source/alias.sar")).unwrap();
                }
                "bytes" => {
                    let mut changed = fixture.archive.clone();
                    *changed.last_mut().unwrap() ^= 1;
                    fs::write(&archive, changed).unwrap();
                }
                _ => unreachable!(),
            }
            let error = retained.ensure_unchanged().unwrap_err();
            assert_redacted(&error);
        }
    }

    struct ReadRequestTracker {
        inner: Cursor<Vec<u8>>,
        maximum_requested: Cell<usize>,
    }

    impl Read for ReadRequestTracker {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.maximum_requested
                .set(self.maximum_requested.get().max(buffer.len()));
            self.inner.read(buffer)
        }
    }

    #[test]
    fn retained_reads_never_request_more_than_eight_kibibytes() {
        let mut reader = ReadRequestTracker {
            inner: Cursor::new(vec![7_u8; SOURCE_READ_BUFFER_BYTES * 3 + 1]),
            maximum_requested: Cell::new(0),
        };
        assert_eq!(
            read_bounded_source_archive(&mut reader).unwrap().len(),
            SOURCE_READ_BUFFER_BYTES * 3 + 1
        );
        assert!(reader.maximum_requested.get() <= SOURCE_READ_BUFFER_BYTES);
    }

    #[test]
    fn bounded_reader_rejects_at_compiled_cap_plus_one() {
        let mut reader = std::io::repeat(7).take(MAX_SOURCE_ARCHIVE_V1_BYTES + 1);
        let error = read_bounded_source_archive(&mut reader).unwrap_err();
        assert_redacted(&error);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fifo_input_rejects_without_blocking_or_creation() {
        use rustix::fs::{mkfifoat, Mode};

        let (temporary, _store) = store();
        let inputs = tempfile::tempdir().unwrap();
        let directory = fs::File::open(inputs.path()).unwrap();
        mkfifoat(&directory, "source.sar", Mode::from_raw_mode(0o444)).unwrap();
        assert!(open_absolute_file(
            &inputs.path().join("source.sar"),
            MAX_SOURCE_ARCHIVE_V1_BYTES,
            None,
            "source archive",
        )
        .is_err());
        assert!(!temporary
            .path()
            .join("campaign")
            .join(SOURCE_ARCHIVE_PATH)
            .exists());
    }
}
