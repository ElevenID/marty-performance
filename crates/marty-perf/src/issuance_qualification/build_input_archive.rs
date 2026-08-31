//! Canonical, nonactivating fixed-build input archive emission.

use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;
use sha2::{Digest, Sha256};

use super::artifact_store::{CampaignArtifactStore, PersistedBuildInputArchiveBytes};
use super::{
    ensure_file_unchanged, valid_artifact_fingerprint, OpenedInput,
    FIXED_BUILD_INPUT_ARCHIVE_MAGIC, MAX_FIXED_BUILD_INPUT_BYTES, MAX_FIXED_BUILD_INPUT_ENTRIES,
};

const MEMBER_BUFFER_BYTES: usize = 8 * 1024;
const MEMBER_BUFFER_BYTES_U64: u64 = 8 * 1024;

/// One already-open, immutable archive member bound to its expected inventory fingerprint.
pub(super) struct BuildInputArchiveMember {
    input: OpenedInput,
    expected_fingerprint: ArtifactFingerprint,
}

impl BuildInputArchiveMember {
    /// Binds an open regular-file handle without reading or retaining its contents.
    pub(super) fn bind(
        input: OpenedInput,
        expected_fingerprint: ArtifactFingerprint,
    ) -> Result<Self> {
        anyhow::ensure!(
            valid_artifact_fingerprint(&expected_fingerprint),
            "invalid build-input archive member fingerprint"
        );
        anyhow::ensure!(
            input.snapshot.readonly
                && input.snapshot.link_count == 1
                && input.snapshot.byte_length == expected_fingerprint.byte_length,
            "invalid build-input archive member snapshot"
        );
        let member = Self {
            input,
            expected_fingerprint,
        };
        member.ensure_unchanged()?;
        Ok(member)
    }

    fn ensure_unchanged(&self) -> Result<()> {
        ensure_file_unchanged(
            &self.input.file,
            self.input.snapshot,
            "build-input archive member",
        )
    }
}

fn checked_archive_length(member_count: u64, total_member_bytes: u64) -> Result<u64> {
    let framing_bytes = member_count
        .checked_mul(8)
        .context("build-input archive member-count framing overflow")?;
    let archive_length = u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len())
        .context("build-input archive magic length overflow")?
        .checked_add(framing_bytes)
        .and_then(|length| length.checked_add(total_member_bytes))
        .context("build-input archive length overflow")?;
    anyhow::ensure!(
        (1..=u64::from(MAX_FIXED_BUILD_INPUT_ENTRIES)).contains(&member_count),
        "build-input archive member count is out of bounds"
    );
    anyhow::ensure!(
        archive_length <= MAX_FIXED_BUILD_INPUT_BYTES,
        "build-input archive exceeds byte limit"
    );
    Ok(archive_length)
}

fn copy_and_hash_exact_member<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    expected_length: u64,
) -> Result<ArtifactFingerprint> {
    let mut hasher = Sha256::new();
    let mut remaining = expected_length;
    let mut buffer = [0_u8; MEMBER_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(MEMBER_BUFFER_BYTES_U64))
            .context("build-input archive member buffer length overflow")?;
        let read = loop {
            match reader.read(&mut buffer[..take]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => break result.context("read build-input archive member")?,
            }
        };
        anyhow::ensure!(
            read <= take,
            "build-input archive member reader violated the Read contract"
        );
        anyhow::ensure!(read != 0, "build-input archive member was short");
        writer
            .write_all(&buffer[..read])
            .context("write build-input archive member")?;
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).context("build-input archive member length overflow")?)
            .context("build-input archive member length overflow")?;
    }
    let mut trailing = [0_u8; 1];
    let trailing_length = loop {
        match reader.read(&mut trailing) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => break result.context("read build-input archive member")?,
        }
    };
    anyhow::ensure!(trailing_length == 0, "build-input archive member was long");
    Ok(ArtifactFingerprint {
        sha256: hex::encode_upper(hasher.finalize()),
        byte_length: expected_length,
    })
}

/// Streams canonical archive framing and exact member bytes into the fixed create-only role.
pub(super) fn emit_build_input_archive(
    store: &CampaignArtifactStore,
    members: &mut [BuildInputArchiveMember],
) -> Result<PersistedBuildInputArchiveBytes> {
    let member_count =
        u64::try_from(members.len()).context("build-input archive member count overflow")?;
    let total_member_bytes = members.iter().try_fold(0_u64, |total, member| {
        total
            .checked_add(member.expected_fingerprint.byte_length)
            .context("build-input archive member length overflow")
    })?;
    let archive_length = checked_archive_length(member_count, total_member_bytes)?;
    for member in &*members {
        member.ensure_unchanged()?;
    }

    let persisted = store.write_build_input_archive(archive_length, |writer| {
        writer
            .write_all(FIXED_BUILD_INPUT_ARCHIVE_MAGIC)
            .context("write build-input archive magic")?;
        for member in &mut *members {
            member.ensure_unchanged()?;
            member
                .input
                .file
                .seek(SeekFrom::Start(0))
                .context("rewind build-input archive member")?;
            writer
                .write_all(&member.expected_fingerprint.byte_length.to_be_bytes())
                .context("write build-input archive member length")?;
            let actual = copy_and_hash_exact_member(
                &mut member.input.file,
                writer,
                member.expected_fingerprint.byte_length,
            )?;
            anyhow::ensure!(
                actual == member.expected_fingerprint,
                "build-input archive member fingerprint changed"
            );
            member.ensure_unchanged()?;
        }
        for member in &*members {
            member.ensure_unchanged()?;
        }
        Ok(())
    })?;

    for member in &*members {
        member.ensure_unchanged()?;
    }
    Ok(persisted)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    #[cfg(unix)]
    use std::fs;

    use super::*;
    #[cfg(unix)]
    use crate::issuance_qualification::artifact_store::CampaignArtifactStore;
    use crate::issuance_qualification::fingerprint;
    #[cfg(unix)]
    use crate::issuance_qualification::open_absolute_file;

    struct TrackingReader {
        bytes: io::Cursor<Vec<u8>>,
        maximum_requested: usize,
    }

    impl TrackingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes: io::Cursor::new(bytes),
                maximum_requested: 0,
            }
        }
    }

    impl Read for TrackingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.maximum_requested = self.maximum_requested.max(buffer.len());
            self.bytes.read(buffer)
        }
    }

    struct ErroringReader;

    impl Read for ErroringReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic member read failure"))
        }
    }

    #[test]
    fn exact_member_copy_accepts_zero_and_rejects_short_long_and_reader_error() {
        let mut zero_output = Vec::new();
        let zero =
            copy_and_hash_exact_member(&mut io::Cursor::new(Vec::<u8>::new()), &mut zero_output, 0)
                .unwrap();
        assert!(zero_output.is_empty());
        assert_eq!(zero, fingerprint(b"").unwrap());

        let mut short_output = Vec::new();
        assert_eq!(
            copy_and_hash_exact_member(&mut io::Cursor::new(b"12"), &mut short_output, 3,)
                .unwrap_err()
                .to_string(),
            "build-input archive member was short"
        );
        assert_eq!(short_output, b"12");

        let mut long_output = Vec::new();
        assert_eq!(
            copy_and_hash_exact_member(&mut io::Cursor::new(b"123"), &mut long_output, 2,)
                .unwrap_err()
                .to_string(),
            "build-input archive member was long"
        );
        assert_eq!(long_output, b"12");

        let mut error_output = Vec::new();
        assert_eq!(
            copy_and_hash_exact_member(&mut ErroringReader, &mut error_output, 1)
                .unwrap_err()
                .to_string(),
            "read build-input archive member"
        );
        assert!(error_output.is_empty());
    }

    #[test]
    fn exact_member_copy_never_requests_more_than_the_fixed_buffer() {
        let bytes = vec![0x5a; MEMBER_BUFFER_BYTES * 3 + 17];
        let expected = fingerprint(&bytes).unwrap();
        let mut reader = TrackingReader::new(bytes);
        let actual =
            copy_and_hash_exact_member(&mut reader, &mut io::sink(), expected.byte_length).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(reader.maximum_requested, MEMBER_BUFFER_BYTES);
    }

    #[test]
    fn framed_length_checks_zero_count_member_count_arithmetic_and_two_gib_cap() {
        assert!(checked_archive_length(0, 0).is_err());
        assert!(checked_archive_length(u64::MAX, 0).is_err());
        assert!(checked_archive_length(u64::from(MAX_FIXED_BUILD_INPUT_ENTRIES) + 1, 0).is_err());
        assert!(checked_archive_length(1, u64::MAX).is_err());

        let maximum_member = MAX_FIXED_BUILD_INPUT_BYTES
            - u64::try_from(FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len()).unwrap()
            - 8;
        assert_eq!(
            checked_archive_length(1, maximum_member).unwrap(),
            MAX_FIXED_BUILD_INPUT_BYTES
        );
        assert!(checked_archive_length(1, maximum_member + 1).is_err());
    }

    #[cfg(unix)]
    fn store() -> (tempfile::TempDir, CampaignArtifactStore) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("campaign");
        let store = CampaignArtifactStore::create_new(&root).unwrap();
        store.initialize_fixed_layout().unwrap();
        (temporary, store)
    }

    #[cfg(unix)]
    fn set_readonly(path: &std::path::Path, readonly: bool) {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        let mode = permissions.mode();
        permissions.set_mode(if readonly {
            mode & !0o222
        } else {
            mode | 0o200
        });
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn bound_member(
        directory: &std::path::Path,
        name: &str,
        bytes: &[u8],
    ) -> BuildInputArchiveMember {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        set_readonly(&path, true);
        BuildInputArchiveMember::bind(
            open_absolute_file(
                &path,
                MAX_FIXED_BUILD_INPUT_BYTES,
                None,
                "synthetic build-input archive member",
            )
            .unwrap(),
            fingerprint(bytes).unwrap(),
        )
        .unwrap()
    }

    #[test]
    #[cfg(unix)]
    fn archive_emission_matches_golden_framing_and_inventory_order() {
        let (temporary, store) = store();
        let members_root = tempfile::tempdir().unwrap();
        let mut members = vec![
            bound_member(members_root.path(), "first", b"first member"),
            bound_member(members_root.path(), "empty", b""),
            bound_member(members_root.path(), "third", b"third"),
        ];

        let persisted = emit_build_input_archive(&store, &mut members).unwrap();
        let mut expected = FIXED_BUILD_INPUT_ARCHIVE_MAGIC.to_vec();
        for bytes in [
            b"first member".as_slice(),
            b"".as_slice(),
            b"third".as_slice(),
        ] {
            expected.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(bytes);
        }
        assert_eq!(
            fs::read(temporary.path().join("campaign/build/input-files.bia")).unwrap(),
            expected
        );
        assert_eq!(persisted.fingerprint(), &fingerprint(&expected).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn mutated_swapped_mutable_and_multiply_linked_handles_issue_no_capability() {
        enum Change {
            Mutate,
            SwapHandle,
            MakeMutable,
            AddLink,
        }

        for change in [
            Change::Mutate,
            Change::SwapHandle,
            Change::MakeMutable,
            Change::AddLink,
        ] {
            let (temporary, store) = store();
            let members_root = tempfile::tempdir().unwrap();
            let path = members_root.path().join("member");
            let mut member = bound_member(members_root.path(), "member", b"safe");
            match change {
                Change::Mutate => {
                    set_readonly(&path, false);
                    fs::write(&path, b"evil").unwrap();
                    set_readonly(&path, true);
                }
                Change::SwapHandle => {
                    let replacement = members_root.path().join("replacement");
                    fs::write(&replacement, b"evil").unwrap();
                    set_readonly(&replacement, true);
                    member.input.file = fs::File::open(replacement).unwrap();
                }
                Change::MakeMutable => {
                    set_readonly(&path, false);
                }
                Change::AddLink => {
                    fs::hard_link(&path, members_root.path().join("member-link")).unwrap();
                }
            }
            let result = emit_build_input_archive(&store, std::slice::from_mut(&mut member));
            assert!(result.is_err());
            if !matches!(change, Change::Mutate) {
                assert!(!temporary
                    .path()
                    .join("campaign/build/input-files.bia")
                    .exists());
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn member_fault_poisons_create_only_archive_retry_without_issuing_capability() {
        let (temporary, store) = store();
        let members_root = tempfile::tempdir().unwrap();
        let path = members_root.path().join("member");
        fs::write(&path, b"safe").unwrap();
        set_readonly(&path, true);

        let wrong = fingerprint(b"evil").unwrap();
        let mut mismatched = BuildInputArchiveMember::bind(
            open_absolute_file(
                &path,
                MAX_FIXED_BUILD_INPUT_BYTES,
                None,
                "synthetic build-input archive member",
            )
            .unwrap(),
            wrong,
        )
        .unwrap();
        let first = emit_build_input_archive(&store, std::slice::from_mut(&mut mismatched));
        assert!(first.is_err());
        assert!(temporary
            .path()
            .join("campaign/build/input-files.bia")
            .exists());

        let mut correct = BuildInputArchiveMember::bind(
            open_absolute_file(
                &path,
                MAX_FIXED_BUILD_INPUT_BYTES,
                None,
                "synthetic build-input archive member",
            )
            .unwrap(),
            fingerprint(b"safe").unwrap(),
        )
        .unwrap();
        let retry = emit_build_input_archive(&store, std::slice::from_mut(&mut correct));
        assert!(retry.is_err());
    }
}
