//! Approved, nonactivating retention of one exact source archive.

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;

use super::artifact_store::{
    fingerprint_exact_source, CampaignArtifactStore, MaterializedInputParent,
    MaterializedInputStore, MaterializedInputStoreBuilder, PersistedSourceArchiveBytes,
};
use super::{
    canonical_unsigned_decimal, ensure_file_unchanged, fingerprint, git_object_id, handle_snapshot,
    open_absolute_directory, open_absolute_directory_excluding, open_child_directory,
    open_child_file, reconstructed_source_tree, source_archive_paths_are_materializable,
    valid_artifact_fingerprint, valid_campaign_id, valid_lowercase_hex, valid_source_archive_path,
    validate_source_archive_bytes, verified_directory_identity, verified_file_snapshot,
    FileIdentity, FileSnapshot, OpenedInput, SourceArchiveEntryWire, SourceArchiveExportReceipt,
    SourceArchiveExportRequest, SourceArchiveManifestWire, ValidatedSourceArchive,
    ValidatedSourceArchiveMemberRange, MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES,
    MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES, MAX_SOURCE_ARCHIVE_V1_BYTES,
    MAX_SOURCE_ARCHIVE_V1_ENTRIES, SOURCE_ARCHIVE_MAGIC,
};

const RETENTION_REJECTED: &str = "source archive retention rejected";
const MATERIALIZATION_REJECTED: &str = "source tree materialization rejected";
const EXPORT_REJECTED: &str = "source archive export rejected";
const SOURCE_READ_BUFFER_BYTES: usize = 8 * 1024;
const MAX_GIT_POLICY_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GIT_TREE_LISTING_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GIT_BATCH_OUTPUT_BYTES: u64 = MAX_SOURCE_ARCHIVE_V1_BYTES + MAX_GIT_TREE_LISTING_BYTES;
const MAX_GIT_OBJECT_INFO_ENTRIES: usize = 4_096;

#[derive(Clone, Debug)]
struct GitTreeMember {
    repository_relative_path: String,
    git_mode: String,
    git_object_id: String,
}

trait ExactGitSource {
    fn preflight(&mut self) -> Result<()>;
    fn read_commit(&mut self, source_commit: &str) -> Result<Vec<u8>>;
    fn read_tree(&mut self, source_tree: &str) -> Result<Vec<u8>>;
    fn read_blobs(&mut self, object_ids: &[String]) -> Result<Vec<Vec<u8>>>;
    fn postflight(&mut self) -> Result<()>;
}

struct LocalGitSource<'a> {
    repository: &'a Path,
    repository_handle: fs::File,
    repository_snapshot: FileSnapshot,
    git_handle: fs::File,
    git_snapshot: FileSnapshot,
    objects_handle: fs::File,
    objects_snapshot: FileSnapshot,
    objects_info_handle: fs::File,
    objects_info_snapshot: FileSnapshot,
}

fn is_git_environment_variable(variable: &OsStr) -> bool {
    variable
        .as_encoded_bytes()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"GIT_"))
}

fn scrub_git_environment<I>(command: &mut Command, variables: I)
where
    I: IntoIterator<Item = OsString>,
{
    for variable in variables {
        if is_git_environment_variable(&variable) {
            command.env_remove(variable);
        }
    }
}

fn is_alternate_object_store_name(name: &OsStr) -> bool {
    [b"alternates".as_slice(), b"http-alternates".as_slice()]
        .iter()
        .any(|reserved| name.as_encoded_bytes().eq_ignore_ascii_case(reserved))
}

impl<'a> LocalGitSource<'a> {
    fn open(repository: &'a Path) -> Result<Self> {
        let repository_handle = open_absolute_directory(repository, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let repository_snapshot = handle_snapshot(&repository_handle, true, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let git_handle = open_child_directory(
            &repository_handle,
            &OsString::from(".git"),
            "source repository",
        )
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let git_snapshot = handle_snapshot(&git_handle, true, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let objects_handle =
            open_child_directory(&git_handle, &OsString::from("objects"), "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let objects_snapshot = handle_snapshot(&objects_handle, true, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let objects_info_handle = open_child_directory(
            &objects_handle,
            &OsString::from("info"),
            "source repository",
        )
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let objects_info_snapshot =
            handle_snapshot(&objects_info_handle, true, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        Ok(Self {
            repository,
            repository_handle,
            repository_snapshot,
            git_handle,
            git_snapshot,
            objects_handle,
            objects_snapshot,
            objects_info_handle,
            objects_info_snapshot,
        })
    }

    fn root_identity(&self) -> FileIdentity {
        self.repository_snapshot.identity
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new("git");
        scrub_git_environment(
            &mut command,
            std::env::vars_os().map(|(variable, _)| variable),
        );
        command
            .arg("-C")
            .arg(self.repository)
            .arg("--no-pager")
            .arg("--no-replace-objects")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.untrackedCache=false")
            .args(arguments)
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C");
        command
    }

    fn ensure_no_alternate_object_store(&self) -> Result<()> {
        let before = handle_snapshot(&self.objects_info_handle, true, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(before == self.objects_info_snapshot, EXPORT_REJECTED);
        let mut listing = self
            .objects_info_handle
            .try_clone()
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let mut observed = 0_usize;
        for entry in fs_at::read_dir(&mut listing).map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))? {
            observed = observed.checked_add(1).context(EXPORT_REJECTED)?;
            anyhow::ensure!(observed <= MAX_GIT_OBJECT_INFO_ENTRIES, EXPORT_REJECTED);
            let entry = entry.map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
            let name = entry.name();
            if name == "." || name == ".." {
                continue;
            }
            anyhow::ensure!(!is_alternate_object_store_name(name), EXPORT_REJECTED);
        }
        anyhow::ensure!(
            handle_snapshot(&self.objects_info_handle, true, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == before
                && handle_snapshot(&listing, true, "source repository")
                    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                    == before,
            EXPORT_REJECTED
        );
        Ok(())
    }

    fn read_bounded_child_stdout(child: &mut Child, maximum_stdout_bytes: u64) -> Result<Vec<u8>> {
        let maximum = usize::try_from(maximum_stdout_bytes).context(EXPORT_REJECTED)?;
        let read_limit = maximum.checked_add(1).context(EXPORT_REJECTED)?;
        let stdout = child.stdout.take().context(EXPORT_REJECTED)?;
        let mut bounded = stdout.take(u64::try_from(read_limit).context(EXPORT_REJECTED)?);
        let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
        if bounded.read_to_end(&mut bytes).is_err() || bytes.len() > maximum {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(EXPORT_REJECTED);
        }
        let status = child.wait().map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(status.success(), EXPORT_REJECTED);
        Ok(bytes)
    }

    fn run_git(&self, arguments: &[&str], maximum_stdout_bytes: u64) -> Result<Vec<u8>> {
        let mut child = self
            .command(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        Self::read_bounded_child_stdout(&mut child, maximum_stdout_bytes)
    }

    fn run_git_with_input(
        &self,
        arguments: &[&str],
        input: Vec<u8>,
        maximum_stdout_bytes: u64,
    ) -> Result<Vec<u8>> {
        let mut child = self
            .command(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        let mut stdin = child.stdin.take().context(EXPORT_REJECTED)?;
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = Self::read_bounded_child_stdout(&mut child, maximum_stdout_bytes);
        let write_result = writer
            .join()
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        write_result.map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        output
    }

    fn ensure_policy(&self) -> Result<()> {
        anyhow::ensure!(
            self.run_git(&["rev-parse", "--is-inside-work-tree"], 16)? == b"true\n",
            EXPORT_REJECTED
        );
        anyhow::ensure!(
            self.run_git(&["rev-parse", "--git-dir"], 64)? == b".git\n",
            EXPORT_REJECTED
        );
        anyhow::ensure!(
            self.run_git(&["rev-parse", "--git-common-dir"], 64)? == b".git\n",
            EXPORT_REJECTED
        );
        self.ensure_no_alternate_object_store()?;
        anyhow::ensure!(
            self.run_git(&["rev-parse", "--show-object-format"], 16)? == b"sha1\n",
            EXPORT_REJECTED
        );
        anyhow::ensure!(
            self.run_git(
                &[
                    "status",
                    "--porcelain=v2",
                    "-z",
                    "--untracked-files=all",
                    "--ignored=matching",
                    "--ignore-submodules=none",
                ],
                MAX_GIT_POLICY_OUTPUT_BYTES,
            )?
            .is_empty(),
            EXPORT_REJECTED
        );
        Ok(())
    }

    fn ensure_handles_unchanged(&self) -> Result<()> {
        anyhow::ensure!(
            handle_snapshot(&self.repository_handle, true, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == self.repository_snapshot
                && handle_snapshot(&self.git_handle, true, "source repository")
                    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                    == self.git_snapshot
                && handle_snapshot(&self.objects_handle, true, "source repository")
                    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                    == self.objects_snapshot
                && handle_snapshot(&self.objects_info_handle, true, "source repository")
                    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                    == self.objects_info_snapshot,
            EXPORT_REJECTED
        );
        let reopened = open_absolute_directory(self.repository, "source repository")
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(
            verified_directory_identity(&reopened, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == self.repository_snapshot.identity,
            EXPORT_REJECTED
        );
        let reopened_git =
            open_child_directory(&reopened, &OsString::from(".git"), "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(
            verified_directory_identity(&reopened_git, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == self.git_snapshot.identity,
            EXPORT_REJECTED
        );
        let reopened_objects = open_child_directory(
            &reopened_git,
            &OsString::from("objects"),
            "source repository",
        )
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(
            verified_directory_identity(&reopened_objects, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == self.objects_snapshot.identity,
            EXPORT_REJECTED
        );
        let reopened_objects_info = open_child_directory(
            &reopened_objects,
            &OsString::from("info"),
            "source repository",
        )
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
        anyhow::ensure!(
            verified_directory_identity(&reopened_objects_info, "source repository")
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == self.objects_info_snapshot.identity,
            EXPORT_REJECTED
        );
        Ok(())
    }
}

impl ExactGitSource for LocalGitSource<'_> {
    fn preflight(&mut self) -> Result<()> {
        self.ensure_handles_unchanged()?;
        self.ensure_policy()?;
        self.ensure_handles_unchanged()
    }

    fn read_commit(&mut self, source_commit: &str) -> Result<Vec<u8>> {
        self.run_git(
            &["cat-file", "commit", source_commit],
            MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES,
        )
    }

    fn read_tree(&mut self, source_tree: &str) -> Result<Vec<u8>> {
        self.run_git(
            &["ls-tree", "-r", "-z", "--full-tree", source_tree],
            MAX_GIT_TREE_LISTING_BYTES,
        )
    }

    fn read_blobs(&mut self, object_ids: &[String]) -> Result<Vec<Vec<u8>>> {
        let mut input = Vec::new();
        for object_id in object_ids {
            anyhow::ensure!(valid_lowercase_hex(object_id, 40), EXPORT_REJECTED);
            input.extend_from_slice(object_id.as_bytes());
            input.push(b'\n');
            anyhow::ensure!(
                u64::try_from(input.len()).is_ok_and(|length| length <= MAX_GIT_TREE_LISTING_BYTES),
                EXPORT_REJECTED
            );
        }
        let output =
            self.run_git_with_input(&["cat-file", "--batch"], input, MAX_GIT_BATCH_OUTPUT_BYTES)?;
        parse_git_batch_blobs(&output, object_ids)
    }

    fn postflight(&mut self) -> Result<()> {
        self.ensure_handles_unchanged()?;
        self.ensure_policy()?;
        self.ensure_handles_unchanged()
    }
}

fn parse_git_batch_blobs(bytes: &[u8], object_ids: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut cursor = 0_usize;
    let mut blobs = Vec::with_capacity(object_ids.len());
    for expected_object_id in object_ids {
        let line_length = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .context(EXPORT_REJECTED)?;
        let line_end = cursor.checked_add(line_length).context(EXPORT_REJECTED)?;
        let header = std::str::from_utf8(&bytes[cursor..line_end]).context(EXPORT_REJECTED)?;
        cursor = line_end.checked_add(1).context(EXPORT_REJECTED)?;
        let mut fields = header.split(' ');
        let object_id = fields.next().context(EXPORT_REJECTED)?;
        let object_type = fields.next().context(EXPORT_REJECTED)?;
        let encoded_length = fields.next().context(EXPORT_REJECTED)?;
        let byte_length = canonical_unsigned_decimal(encoded_length.as_bytes())
            .and_then(|length| usize::try_from(length).ok())
            .context(EXPORT_REJECTED)?;
        anyhow::ensure!(
            fields.next().is_none()
                && object_id == expected_object_id
                && object_type == "blob"
                && u64::try_from(byte_length)
                    .is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_V1_BYTES),
            EXPORT_REJECTED
        );
        let content_end = cursor.checked_add(byte_length).context(EXPORT_REJECTED)?;
        let content = bytes.get(cursor..content_end).context(EXPORT_REJECTED)?;
        anyhow::ensure!(
            bytes.get(content_end) == Some(&b'\n')
                && hex::encode(git_object_id("blob", content)) == *expected_object_id,
            EXPORT_REJECTED
        );
        blobs.push(content.to_vec());
        cursor = content_end.checked_add(1).context(EXPORT_REJECTED)?;
    }
    anyhow::ensure!(cursor == bytes.len(), EXPORT_REJECTED);
    Ok(blobs)
}

fn parse_git_tree_listing(bytes: &[u8]) -> Result<Vec<GitTreeMember>> {
    anyhow::ensure!(!bytes.is_empty() && bytes.ends_with(&[0]), EXPORT_REJECTED);
    let mut members = Vec::new();
    for record in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        anyhow::ensure!(!record.is_empty(), EXPORT_REJECTED);
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context(EXPORT_REJECTED)?;
        let metadata = std::str::from_utf8(&record[..separator]).context(EXPORT_REJECTED)?;
        let path = std::str::from_utf8(&record[separator + 1..]).context(EXPORT_REJECTED)?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().context(EXPORT_REJECTED)?;
        let object_type = fields.next().context(EXPORT_REJECTED)?;
        let object_id = fields.next().context(EXPORT_REJECTED)?;
        anyhow::ensure!(
            fields.next().is_none()
                && matches!(mode, "100644" | "100755")
                && object_type == "blob"
                && valid_lowercase_hex(object_id, 40)
                && path.is_ascii()
                && valid_source_archive_path(path),
            EXPORT_REJECTED
        );
        members.push(GitTreeMember {
            repository_relative_path: path.to_owned(),
            git_mode: mode.to_owned(),
            git_object_id: object_id.to_owned(),
        });
        anyhow::ensure!(
            u32::try_from(members.len()).is_ok_and(|count| count <= MAX_SOURCE_ARCHIVE_V1_ENTRIES),
            EXPORT_REJECTED
        );
    }
    members.sort_by(|left, right| {
        left.repository_relative_path
            .as_bytes()
            .cmp(right.repository_relative_path.as_bytes())
    });
    anyhow::ensure!(
        !members.is_empty()
            && members.windows(2).all(|pair| {
                pair[0].repository_relative_path.as_bytes()
                    < pair[1].repository_relative_path.as_bytes()
            }),
        EXPORT_REJECTED
    );
    Ok(members)
}

#[derive(Debug)]
struct AssembledSourceArchive {
    bytes: Vec<u8>,
    archive_fingerprint: ArtifactFingerprint,
    cargo_lock_fingerprint: ArtifactFingerprint,
    entry_count: u32,
}

fn append_u64(bytes: &mut Vec<u8>, value: usize) -> Result<()> {
    bytes.extend_from_slice(&u64::try_from(value).context(EXPORT_REJECTED)?.to_be_bytes());
    Ok(())
}

fn encode_source_archive(
    manifest: &SourceArchiveManifestWire,
    commit: &[u8],
    contents: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut manifest_bytes = serde_json::to_vec_pretty(manifest).context(EXPORT_REJECTED)?;
    manifest_bytes.push(b'\n');
    anyhow::ensure!(
        u64::try_from(manifest_bytes.len())
            .is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES)
            && u64::try_from(commit.len())
                .is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES)
            && contents.len() == manifest.entries.len(),
        EXPORT_REJECTED
    );
    let mut total = SOURCE_ARCHIVE_MAGIC
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(manifest_bytes.len()))
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(commit.len()))
        .context(EXPORT_REJECTED)?;
    for content in contents {
        total = total
            .checked_add(8)
            .and_then(|value| value.checked_add(content.len()))
            .context(EXPORT_REJECTED)?;
    }
    anyhow::ensure!(
        u64::try_from(total).is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_V1_BYTES),
        EXPORT_REJECTED
    );
    let mut archive = Vec::with_capacity(total);
    archive.extend_from_slice(SOURCE_ARCHIVE_MAGIC);
    append_u64(&mut archive, manifest_bytes.len())?;
    archive.extend_from_slice(&manifest_bytes);
    append_u64(&mut archive, commit.len())?;
    archive.extend_from_slice(commit);
    for content in contents {
        append_u64(&mut archive, content.len())?;
        archive.extend_from_slice(content);
    }
    anyhow::ensure!(archive.len() == total, EXPORT_REJECTED);
    Ok(archive)
}

fn assemble_source_archive(
    source: &mut impl ExactGitSource,
    source_commit: &str,
    source_tree: &str,
) -> Result<AssembledSourceArchive> {
    anyhow::ensure!(
        valid_lowercase_hex(source_commit, 40) && valid_lowercase_hex(source_tree, 40),
        EXPORT_REJECTED
    );
    source.preflight()?;
    let commit = source.read_commit(source_commit)?;
    anyhow::ensure!(
        u64::try_from(commit.len())
            .is_ok_and(|length| length <= MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES)
            && hex::encode(git_object_id("commit", &commit)) == source_commit,
        EXPORT_REJECTED
    );
    let tree_listing = source.read_tree(source_tree)?;
    let members = parse_git_tree_listing(&tree_listing)?;
    let object_ids = members
        .iter()
        .map(|member| member.git_object_id.clone())
        .collect::<Vec<_>>();
    let source_contents = source.read_blobs(&object_ids)?;
    anyhow::ensure!(source_contents.len() == members.len(), EXPORT_REJECTED);
    let mut entries = Vec::with_capacity(members.len());
    let mut contents = Vec::with_capacity(members.len());
    let mut member_bytes = 0_u64;
    for (member, content) in members.into_iter().zip(source_contents) {
        let content_length = u64::try_from(content.len()).context(EXPORT_REJECTED)?;
        member_bytes = member_bytes
            .checked_add(content_length)
            .context(EXPORT_REJECTED)?;
        anyhow::ensure!(
            member_bytes <= MAX_SOURCE_ARCHIVE_V1_BYTES
                && hex::encode(git_object_id("blob", &content)) == member.git_object_id,
            EXPORT_REJECTED
        );
        entries.push(SourceArchiveEntryWire {
            repository_relative_path: member.repository_relative_path,
            git_mode: member.git_mode,
            git_object_id: member.git_object_id,
            artifact_fingerprint: fingerprint(&content).context(EXPORT_REJECTED)?,
        });
        contents.push(content);
    }
    anyhow::ensure!(
        source_archive_paths_are_materializable(&entries),
        EXPORT_REJECTED
    );
    let content_slices = contents.iter().map(Vec::as_slice).collect::<Vec<_>>();
    anyhow::ensure!(
        reconstructed_source_tree(&entries, &content_slices)
            .is_some_and(|tree| hex::encode(tree) == source_tree),
        EXPORT_REJECTED
    );
    let entry_count = u32::try_from(entries.len()).context(EXPORT_REJECTED)?;
    let manifest = SourceArchiveManifestWire {
        schema: "marty.performance/sd-jwt-issuance-source-archive-manifest/v1".to_owned(),
        git_object_format: "sha1".to_owned(),
        source_commit: source_commit.to_owned(),
        source_tree: source_tree.to_owned(),
        entry_count,
        entries,
    };
    let cargo_lock_fingerprint = manifest
        .entries
        .iter()
        .filter(|entry| entry.repository_relative_path == "Cargo.lock")
        .map(|entry| entry.artifact_fingerprint.clone())
        .collect::<Vec<_>>();
    let [cargo_lock_fingerprint] = cargo_lock_fingerprint.as_slice() else {
        anyhow::bail!(EXPORT_REJECTED)
    };
    let bytes = encode_source_archive(&manifest, &commit, &contents)?;
    let archive_fingerprint = fingerprint(&bytes).context(EXPORT_REJECTED)?;
    let validated =
        validate_source_archive_bytes(&bytes, &archive_fingerprint, cargo_lock_fingerprint)
            .context(EXPORT_REJECTED)?;
    anyhow::ensure!(
        validated.manifest.source_commit == source_commit
            && validated.manifest.source_tree == source_tree
            && validated.manifest.entry_count == entry_count
            && source.read_commit(source_commit)? == commit
            && source.read_tree(source_tree)? == tree_listing,
        EXPORT_REJECTED
    );
    source.postflight()?;
    Ok(AssembledSourceArchive {
        bytes,
        archive_fingerprint,
        cargo_lock_fingerprint: cargo_lock_fingerprint.clone(),
        entry_count,
    })
}

fn valid_export_output_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name() == Some(std::ffi::OsStr::new("exact-tree.sar"))
        && path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("source"))
}

fn verify_persisted_source_archive(
    output: &fs::File,
    parent_directory: &fs::File,
    parent: &Path,
    forbidden_repository: FileIdentity,
    parent_identity: FileIdentity,
    assembled: &AssembledSourceArchive,
) -> Result<()> {
    let output_snapshot = verified_file_snapshot(
        output,
        assembled.archive_fingerprint.byte_length,
        "source archive output",
    )
    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    anyhow::ensure!(
        output_snapshot.readonly
            && output_snapshot.byte_length == assembled.archive_fingerprint.byte_length,
        EXPORT_REJECTED
    );
    let mut retained = open_child_file(
        parent_directory,
        std::ffi::OsStr::new("exact-tree.sar"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "source archive output",
    )
    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    anyhow::ensure!(retained.snapshot == output_snapshot, EXPORT_REJECTED);
    let observed = fingerprint_exact_source(
        &mut retained.file,
        assembled.archive_fingerprint.byte_length,
    )
    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    ensure_file_unchanged(&retained.file, retained.snapshot, "source archive output")
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    anyhow::ensure!(
        observed == assembled.archive_fingerprint
            && verified_directory_identity(
                &open_absolute_directory_excluding(
                    parent,
                    Some(forbidden_repository),
                    "source archive output",
                )
                .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?,
                "source archive output",
            )
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
                == parent_identity,
        EXPORT_REJECTED
    );
    #[cfg(unix)]
    parent_directory
        .sync_all()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    Ok(())
}

fn persist_source_archive(
    output_path: &Path,
    forbidden_repository: FileIdentity,
    assembled: &AssembledSourceArchive,
) -> Result<()> {
    anyhow::ensure!(valid_export_output_path(output_path), EXPORT_REJECTED);
    let parent = output_path.parent().context(EXPORT_REJECTED)?;
    let parent_directory = open_absolute_directory_excluding(
        parent,
        Some(forbidden_repository),
        "source archive output",
    )
    .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    let parent_identity = verified_directory_identity(&parent_directory, "source archive output")
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    anyhow::ensure!(
        verified_directory_identity(
            &open_absolute_directory_excluding(
                parent,
                Some(forbidden_repository),
                "source archive output",
            )
            .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?,
            "source archive output",
        )
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
            == parent_identity,
        EXPORT_REJECTED
    );
    temporary
        .write_all(&assembled.bytes)
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    temporary
        .flush()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    let mut permissions = temporary
        .as_file()
        .metadata()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
        .permissions();
    permissions.set_readonly(true);
    temporary
        .as_file()
        .set_permissions(permissions)
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    let output = temporary
        .persist_noclobber(output_path)
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    let mut persisted_permissions = output
        .metadata()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?
        .permissions();
    persisted_permissions.set_readonly(true);
    output
        .set_permissions(persisted_permissions)
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    output
        .sync_all()
        .map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))?;
    verify_persisted_source_archive(
        &output,
        &parent_directory,
        parent,
        forbidden_repository,
        parent_identity,
        assembled,
    )
}

fn export_inner(request: &SourceArchiveExportRequest<'_>) -> Result<SourceArchiveExportReceipt> {
    anyhow::ensure!(
        request.source_export_approved
            && valid_lowercase_hex(request.source_commit, 40)
            && valid_lowercase_hex(request.source_tree, 40)
            && valid_export_output_path(request.output),
        EXPORT_REJECTED
    );
    let mut source = LocalGitSource::open(request.repository)?;
    let assembled =
        assemble_source_archive(&mut source, request.source_commit, request.source_tree)?;
    persist_source_archive(request.output, source.root_identity(), &assembled)?;
    source.postflight()?;
    Ok(SourceArchiveExportReceipt {
        archive_fingerprint: assembled.archive_fingerprint,
        source_commit: request.source_commit.to_owned(),
        source_tree: request.source_tree.to_owned(),
        cargo_lock_fingerprint: assembled.cargo_lock_fingerprint,
        entry_count: assembled.entry_count,
    })
}

pub(super) fn export_exact_source_archive(
    request: &SourceArchiveExportRequest<'_>,
) -> Result<SourceArchiveExportReceipt> {
    export_inner(request).map_err(|_| anyhow::anyhow!(EXPORT_REJECTED))
}

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
    members: Vec<RetainedSourceMember>,
    invalid: Cell<bool>,
}

struct RetainedSourceMember {
    relative_path: String,
    executable: bool,
    fingerprint: ArtifactFingerprint,
    range: ValidatedSourceArchiveMemberRange,
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

    pub(super) fn member_count(&self) -> usize {
        self.members.len()
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), RETENTION_REJECTED);
        let result = self.persisted.ensure_unchanged();
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!(RETENTION_REJECTED))
    }

    pub(super) fn ensure_materialization_preflight(&self) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), MATERIALIZATION_REJECTED);
        let result = (|| {
            anyhow::ensure!(valid_materialization_plan(self), MATERIALIZATION_REJECTED);
            self.ensure_unchanged()
        })();
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
    }
}

/// Opaque, non-cloneable proof that the retained archive and its exact source tree remain bound.
pub(super) struct MaterializedSourceTree {
    store: MaterializedInputStore,
    retained: RetainedSourceArchive,
    member_count: usize,
    invalid: Cell<bool>,
}

impl fmt::Debug for MaterializedSourceTree {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedSourceTree")
            .finish_non_exhaustive()
    }
}

impl MaterializedSourceTree {
    pub(super) fn store(&self) -> &MaterializedInputStore {
        &self.store
    }
    pub(super) fn absolute_root(&self) -> &Path {
        self.store.absolute_root()
    }

    pub(super) fn member_count(&self) -> usize {
        self.member_count
    }

    pub(super) fn campaign_id(&self) -> &str {
        self.retained.campaign_id()
    }

    pub(super) fn archive_fingerprint(&self) -> &ArtifactFingerprint {
        self.retained.archive_fingerprint()
    }

    pub(super) fn source_commit(&self) -> &str {
        self.retained.source_commit()
    }

    pub(super) fn source_tree(&self) -> &str {
        self.retained.source_tree()
    }

    pub(super) fn cargo_lock_fingerprint(&self) -> &ArtifactFingerprint {
        self.retained.cargo_lock_fingerprint()
    }

    pub(super) fn committer_timestamp(&self) -> u64 {
        self.retained.committer_timestamp()
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        anyhow::ensure!(!self.invalid.get(), MATERIALIZATION_REJECTED);
        let result = self.ensure_unchanged_inner();
        if result.is_err() {
            self.invalid.set(true);
        }
        result.map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
    }

    fn ensure_unchanged_inner(&self) -> Result<()> {
        self.retained.ensure_unchanged()?;
        self.store.verify_root()?;
        self.retained.ensure_unchanged()
    }

    /// Deliberately corrupts the retained archive for the fixed-build composition test.
    #[cfg(all(test, unix))]
    pub(super) fn overwrite_retained_archive_byte_for_test(&mut self, byte: u8) -> Result<u8> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = self.retained.persisted.absolute_path_for_test();
        let original_permissions = std::fs::metadata(&path)?.permissions();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(original_permissions.mode() | 0o200),
        )?;
        let mut archive = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        archive.seek(SeekFrom::Start(0))?;
        let mut original = [0_u8; 1];
        archive.read_exact(&mut original)?;
        archive.seek(SeekFrom::Start(0))?;
        archive.write_all(&[byte])?;
        archive.sync_all()?;
        std::fs::set_permissions(path, original_permissions)?;
        Ok(original[0])
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

fn copy_source_member(
    reader: &mut (impl Read + ?Sized),
    writer: &mut (impl Write + ?Sized),
    expected_length: u64,
) -> Result<()> {
    let mut remaining = expected_length;
    let mut buffer = [0_u8; SOURCE_READ_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(SOURCE_READ_BUFFER_BYTES as u64))
            .context(MATERIALIZATION_REJECTED)?;
        let read = loop {
            match reader.read(&mut buffer[..take]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => break result.map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?,
            }
        };
        anyhow::ensure!(read != 0, MATERIALIZATION_REJECTED);
        writer
            .write_all(&buffer[..read])
            .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?;
        remaining = remaining
            .checked_sub(u64::try_from(read).context(MATERIALIZATION_REJECTED)?)
            .context(MATERIALIZATION_REJECTED)?;
    }
    Ok(())
}

fn valid_materialization_plan(retained: &RetainedSourceArchive) -> bool {
    let Ok(member_count) = u32::try_from(retained.members.len()) else {
        return false;
    };
    if !(1..=MAX_SOURCE_ARCHIVE_V1_ENTRIES).contains(&member_count)
        || retained.archive_fingerprint().byte_length > MAX_SOURCE_ARCHIVE_V1_BYTES
    {
        return false;
    }
    let mut previous_end = 0_u64;
    let mut total_member_bytes = 0_u64;
    let mut cargo_lock_matches = 0_u32;
    for member in &retained.members {
        let Some(end) = member.range.offset.checked_add(member.range.byte_length) else {
            return false;
        };
        let Some(next_total) = total_member_bytes.checked_add(member.range.byte_length) else {
            return false;
        };
        if member.range.byte_length != member.fingerprint.byte_length
            || member.range.offset < previous_end
            || end > retained.archive_fingerprint().byte_length
            || next_total > MAX_SOURCE_ARCHIVE_V1_BYTES
        {
            return false;
        }
        if member.relative_path == "Cargo.lock" {
            if member.fingerprint != retained.cargo_lock_fingerprint {
                return false;
            }
            cargo_lock_matches = match cargo_lock_matches.checked_add(1) {
                Some(value) => value,
                None => return false,
            };
        }
        previous_end = end;
        total_member_bytes = next_total;
    }
    cargo_lock_matches == 1
}

fn retained_source_members(
    validated: &ValidatedSourceArchive,
) -> Result<Vec<RetainedSourceMember>> {
    let members = validated
        .manifest
        .entries
        .iter()
        .zip(&validated.member_ranges)
        .map(|(entry, range)| {
            if entry
                .repository_relative_path
                .split('/')
                .any(|component| component.eq_ignore_ascii_case(".cargo"))
            {
                return None;
            }
            let executable = match entry.git_mode.as_str() {
                "100644" => false,
                "100755" => true,
                _ => return None,
            };
            (range.byte_length == entry.artifact_fingerprint.byte_length).then(|| {
                RetainedSourceMember {
                    relative_path: entry.repository_relative_path.clone(),
                    executable,
                    fingerprint: entry.artifact_fingerprint.clone(),
                    range: *range,
                }
            })
        })
        .collect::<Option<Vec<_>>>()
        .context(RETENTION_REJECTED)?;
    anyhow::ensure!(
        members.len() == validated.manifest.entries.len()
            && usize::try_from(validated.manifest.entry_count) == Ok(members.len()),
        RETENTION_REJECTED
    );
    Ok(members)
}

#[cfg(test)]
fn create_source_tree_builder(
    absolute_destination: &Path,
    maximum_members: u32,
) -> Result<MaterializedInputStoreBuilder> {
    MaterializedInputStoreBuilder::create_new(
        absolute_destination,
        maximum_members,
        MAX_SOURCE_ARCHIVE_V1_BYTES,
    )
    .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
}

fn materialize_inner(
    mut retained: RetainedSourceArchive,
    mut store: MaterializedInputStoreBuilder,
    mut post_member: impl FnMut(usize),
) -> Result<MaterializedSourceTree> {
    ensure_materialization_preflight(&retained)?;
    let members = std::mem::take(&mut retained.members);
    let member_count = members.len();
    for (ordinal, member) in members.iter().enumerate() {
        let expected_end = member
            .range
            .offset
            .checked_add(member.range.byte_length)
            .context(MATERIALIZATION_REJECTED)?;
        let archive = retained.persisted.retained_file_mut();
        archive
            .seek(SeekFrom::Start(member.range.offset))
            .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?;
        let receipt = store
            .write_member(
                &member.relative_path,
                member.executable,
                &member.fingerprint,
                |writer| copy_source_member(archive, writer, member.range.byte_length),
            )
            .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?;
        anyhow::ensure!(
            receipt.fingerprint() == &member.fingerprint
                && archive
                    .stream_position()
                    .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?
                    == expected_end,
            MATERIALIZATION_REJECTED
        );
        post_member(ordinal);
    }
    retained.ensure_unchanged()?;
    let store = store
        .seal()
        .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))?;
    let materialized = MaterializedSourceTree {
        store,
        retained,
        member_count,
        invalid: Cell::new(false),
    };
    materialized.ensure_unchanged()?;
    Ok(materialized)
}

fn ensure_materialization_preflight(retained: &RetainedSourceArchive) -> Result<()> {
    retained.ensure_materialization_preflight()
}

/// Materializes every validated member into one new immutable source tree.
#[cfg(test)]
pub(super) fn materialize_retained_source_tree(
    retained: RetainedSourceArchive,
    absolute_destination: &Path,
) -> Result<MaterializedSourceTree> {
    ensure_materialization_preflight(&retained)?;
    let maximum_members =
        u32::try_from(retained.members.len()).context(MATERIALIZATION_REJECTED)?;
    let store = create_source_tree_builder(absolute_destination, maximum_members)?;
    materialize_inner(retained, store, |_| {})
        .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
}

pub(super) fn materialize_retained_source_tree_in_parent(
    retained: RetainedSourceArchive,
    parent: &MaterializedInputParent,
) -> Result<MaterializedSourceTree> {
    ensure_materialization_preflight(&retained)?;
    let maximum_members =
        u32::try_from(retained.members.len()).context(MATERIALIZATION_REJECTED)?;
    let store =
        parent.create_child_builder("worktree", maximum_members, MAX_SOURCE_ARCHIVE_V1_BYTES)?;
    materialize_inner(retained, store, |_| {})
        .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
}

#[cfg(test)]
fn materialize_with_post_member_hook(
    retained: RetainedSourceArchive,
    absolute_destination: &Path,
    post_member: impl FnMut(usize),
) -> Result<MaterializedSourceTree> {
    ensure_materialization_preflight(&retained)?;
    let maximum_members =
        u32::try_from(retained.members.len()).context(MATERIALIZATION_REJECTED)?;
    let store = create_source_tree_builder(absolute_destination, maximum_members)?;
    materialize_inner(retained, store, post_member)
        .map_err(|_| anyhow::anyhow!(MATERIALIZATION_REJECTED))
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
    let members = retained_source_members(&validated)?;
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
        members,
        invalid: Cell::new(false),
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
pub(crate) mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
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
        commit: Vec<u8>,
        contents: Vec<Vec<u8>>,
        entries: Vec<SourceArchiveEntryWire>,
    }

    fn fingerprint(bytes: &[u8]) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: hex::encode_upper(Sha256::digest(bytes)),
            byte_length: u64::try_from(bytes.len()).unwrap(),
        }
    }

    fn fixture() -> Fixture {
        fixture_with_lib_mode("100644")
    }

    fn fixture_with_lib_mode(lib_mode: &str) -> Fixture {
        fixture_with_lib_path_and_mode("src/lib.rs", lib_mode)
    }

    fn fixture_with_lib_path_and_mode(lib_path: &str, lib_mode: &str) -> Fixture {
        let contents = vec![b"lock\n".to_vec(), b"pub fn fixture() {}\n".to_vec()];
        let content_slices = contents.iter().map(Vec::as_slice).collect::<Vec<_>>();
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
                    git_object_id: hex::encode(production_git_object_id("blob", &contents[0])),
                    artifact_fingerprint: fingerprint(&contents[0]),
                },
                SourceArchiveEntryWire {
                    repository_relative_path: lib_path.to_owned(),
                    git_mode: lib_mode.to_owned(),
                    git_object_id: hex::encode(production_git_object_id("blob", &contents[1])),
                    artifact_fingerprint: fingerprint(&contents[1]),
                },
            ],
        };
        manifest.source_tree =
            hex::encode(reconstructed_source_tree(&manifest.entries, &content_slices).unwrap());
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
        for content in &contents {
            archive.extend_from_slice(&u64::try_from(content.len()).unwrap().to_be_bytes());
            archive.extend_from_slice(content);
        }
        Fixture {
            archive_fingerprint: fingerprint(&archive),
            cargo_lock_fingerprint: fingerprint(&contents[0]),
            source_commit: manifest.source_commit.clone(),
            source_tree: manifest.source_tree.clone(),
            commit,
            contents,
            entries: manifest.entries,
            archive,
        }
    }

    struct FakeGitSource {
        commit: Vec<u8>,
        tree_listing: Vec<u8>,
        blobs: BTreeMap<String, Vec<u8>>,
        commit_reads: usize,
        tree_reads: usize,
        changed_commit: Option<Vec<u8>>,
        changed_tree_listing: Option<Vec<u8>>,
        reject_preflight: bool,
        reject_postflight: bool,
    }

    impl FakeGitSource {
        fn from_fixture(fixture: &Fixture) -> Self {
            let mut tree_listing = Vec::new();
            for entry in fixture.entries.iter().rev() {
                tree_listing.extend_from_slice(entry.git_mode.as_bytes());
                tree_listing.extend_from_slice(b" blob ");
                tree_listing.extend_from_slice(entry.git_object_id.as_bytes());
                tree_listing.push(b'\t');
                tree_listing.extend_from_slice(entry.repository_relative_path.as_bytes());
                tree_listing.push(0);
            }
            let blobs = fixture
                .entries
                .iter()
                .zip(&fixture.contents)
                .map(|(entry, content)| (entry.git_object_id.clone(), content.clone()))
                .collect();
            Self {
                commit: fixture.commit.clone(),
                tree_listing,
                blobs,
                commit_reads: 0,
                tree_reads: 0,
                changed_commit: None,
                changed_tree_listing: None,
                reject_preflight: false,
                reject_postflight: false,
            }
        }

        fn append_tree_member(&mut self, mode: &str, path: &str, content: &[u8]) {
            let object_id = hex::encode(production_git_object_id("blob", content));
            self.tree_listing.extend_from_slice(mode.as_bytes());
            self.tree_listing.extend_from_slice(b" blob ");
            self.tree_listing.extend_from_slice(object_id.as_bytes());
            self.tree_listing.push(b'\t');
            self.tree_listing.extend_from_slice(path.as_bytes());
            self.tree_listing.push(0);
            self.blobs.insert(object_id, content.to_vec());
        }
    }

    impl ExactGitSource for FakeGitSource {
        fn preflight(&mut self) -> Result<()> {
            anyhow::ensure!(!self.reject_preflight, EXPORT_REJECTED);
            Ok(())
        }

        fn read_commit(&mut self, _source_commit: &str) -> Result<Vec<u8>> {
            self.commit_reads += 1;
            if self.commit_reads > 1 {
                if let Some(changed) = &self.changed_commit {
                    return Ok(changed.clone());
                }
            }
            Ok(self.commit.clone())
        }

        fn read_tree(&mut self, _source_tree: &str) -> Result<Vec<u8>> {
            self.tree_reads += 1;
            if self.tree_reads > 1 {
                if let Some(changed) = &self.changed_tree_listing {
                    return Ok(changed.clone());
                }
            }
            Ok(self.tree_listing.clone())
        }

        fn read_blobs(&mut self, object_ids: &[String]) -> Result<Vec<Vec<u8>>> {
            object_ids
                .iter()
                .map(|object_id| self.blobs.get(object_id).cloned().context(EXPORT_REJECTED))
                .collect()
        }

        fn postflight(&mut self) -> Result<()> {
            anyhow::ensure!(!self.reject_postflight, EXPORT_REJECTED);
            Ok(())
        }
    }

    fn assert_export_rejected(result: Result<AssembledSourceArchive>) {
        assert_eq!(result.unwrap_err().to_string(), EXPORT_REJECTED);
    }

    fn git_stdout(repository: &Path, arguments: &[&str]) -> Vec<u8> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn deterministic_git_fixture() -> (tempfile::TempDir, String, String) {
        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).unwrap();
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(&repository)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["config", "core.autocrlf", "false"])
            .status()
            .unwrap()
            .success());
        fs::create_dir(repository.join("src")).unwrap();
        fs::write(repository.join("Cargo.lock"), b"lock\n").unwrap();
        fs::write(repository.join("src/lib.rs"), b"pub fn fixture() {}\n").unwrap();
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["add", "--", "Cargo.lock", "src/lib.rs"])
            .status()
            .unwrap()
            .success());
        let source_tree = String::from_utf8(git_stdout(&repository, &["write-tree"]))
            .unwrap()
            .trim()
            .to_owned();
        let mut child = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["commit-tree", &source_tree])
            .env("GIT_AUTHOR_NAME", "Marty Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "1700000000 -0700")
            .env("GIT_COMMITTER_NAME", "Marty Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_DATE", "1700000123 +0530")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"fixture\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let source_commit = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["symbolic-ref", "HEAD", "refs/heads/main"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["update-ref", "refs/heads/main", &source_commit])
            .status()
            .unwrap()
            .success());
        (temporary, source_commit, source_tree)
    }

    #[test]
    fn exporter_reuses_the_validator_and_produces_the_existing_byte_golden() {
        let fixture = fixture();
        let mut source = FakeGitSource::from_fixture(&fixture);
        let assembled =
            assemble_source_archive(&mut source, &fixture.source_commit, &fixture.source_tree)
                .unwrap();

        assert_eq!(assembled.bytes, fixture.archive);
        assert_eq!(assembled.archive_fingerprint, fixture.archive_fingerprint);
        assert_eq!(
            assembled.cargo_lock_fingerprint,
            fixture.cargo_lock_fingerprint
        );
        assert_eq!(assembled.entry_count, 2);
        assert_eq!(source.commit_reads, 2);
        assert_eq!(source.tree_reads, 2);
        assert!(validate_source_archive_bytes(
            &assembled.bytes,
            &assembled.archive_fingerprint,
            &assembled.cargo_lock_fingerprint,
        )
        .is_some());

        let mut trailing = assembled.bytes.clone();
        trailing.push(0);
        assert!(validate_source_archive_bytes(
            &trailing,
            &fingerprint(&trailing),
            &assembled.cargo_lock_fingerprint,
        )
        .is_none());
    }

    #[test]
    fn batched_blob_protocol_rejects_type_length_order_and_trailing_data() {
        let fixture = fixture();
        let object_ids = fixture
            .entries
            .iter()
            .map(|entry| entry.git_object_id.clone())
            .collect::<Vec<_>>();
        let mut batch = Vec::new();
        for (entry, content) in fixture.entries.iter().zip(&fixture.contents) {
            batch.extend_from_slice(entry.git_object_id.as_bytes());
            batch.extend_from_slice(format!(" blob {}\n", content.len()).as_bytes());
            batch.extend_from_slice(content);
            batch.push(b'\n');
        }
        assert_eq!(
            parse_git_batch_blobs(&batch, &object_ids).unwrap(),
            fixture.contents
        );

        let blob_offset = batch
            .windows(6)
            .position(|value| value == b" blob ")
            .unwrap()
            + 1;
        let mut wrong_type = batch.clone();
        wrong_type[blob_offset..blob_offset + 4].copy_from_slice(b"tree");
        assert!(parse_git_batch_blobs(&wrong_type, &object_ids).is_err());

        let mut wrong_order = object_ids.clone();
        wrong_order.swap(0, 1);
        assert!(parse_git_batch_blobs(&batch, &wrong_order).is_err());

        let length_offset = batch.windows(3).position(|value| value == b" 5\n").unwrap() + 1;
        let mut wrong_length = batch.clone();
        wrong_length[length_offset] = b'6';
        assert!(parse_git_batch_blobs(&wrong_length, &object_ids).is_err());

        let mut trailing = batch;
        trailing.push(0);
        assert!(parse_git_batch_blobs(&trailing, &object_ids).is_err());
    }

    #[test]
    fn git_subprocess_environment_scrubs_every_ambient_git_control() {
        let mut command = Command::new("git");
        command
            .env("GIT_COMMON_DIR", "unverified-common-directory")
            .env("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=evil'")
            .env("Git_Trace2_Event", "unverified-trace-sink")
            .env("PATH", "preserved-path");
        scrub_git_environment(
            &mut command,
            [
                OsString::from("GIT_COMMON_DIR"),
                OsString::from("GIT_CONFIG_PARAMETERS"),
                OsString::from("Git_Trace2_Event"),
                OsString::from("PATH"),
            ],
        );
        let environment = command
            .get_envs()
            .map(|(name, value)| (name.to_os_string(), value.map(OsStr::to_os_string)))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(environment.get(OsStr::new("GIT_COMMON_DIR")), Some(&None));
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_PARAMETERS")),
            Some(&None)
        );
        assert_eq!(environment.get(OsStr::new("Git_Trace2_Event")), Some(&None));
        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&Some(OsString::from("preserved-path")))
        );
    }

    #[test]
    fn exporter_rejects_dirty_and_changed_source_views() {
        let fixture = fixture();

        let mut dirty = FakeGitSource::from_fixture(&fixture);
        dirty.reject_preflight = true;
        assert_export_rejected(assemble_source_archive(
            &mut dirty,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut changed_commit = FakeGitSource::from_fixture(&fixture);
        let mut replacement_commit = fixture.commit.clone();
        replacement_commit.push(b'!');
        changed_commit.changed_commit = Some(replacement_commit);
        assert_export_rejected(assemble_source_archive(
            &mut changed_commit,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut changed_tree = FakeGitSource::from_fixture(&fixture);
        let mut replacement_tree = changed_tree.tree_listing.clone();
        replacement_tree.extend_from_slice(b"unexpected");
        changed_tree.changed_tree_listing = Some(replacement_tree);
        assert_export_rejected(assemble_source_archive(
            &mut changed_tree,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut postflight = FakeGitSource::from_fixture(&fixture);
        postflight.reject_postflight = true;
        assert_export_rejected(assemble_source_archive(
            &mut postflight,
            &fixture.source_commit,
            &fixture.source_tree,
        ));
    }

    #[test]
    fn explicit_approval_exact_pins_and_fixed_output_role_precede_source_access() {
        let fixture = fixture();
        let temporary = tempfile::tempdir().unwrap();
        let source_parent = temporary.path().join("source");
        fs::create_dir(&source_parent).unwrap();
        let output = source_parent.join("exact-tree.sar");
        let missing_repository = temporary.path().join("missing-repository");
        let mut request = SourceArchiveExportRequest {
            repository: &missing_repository,
            source_commit: &fixture.source_commit,
            source_tree: &fixture.source_tree,
            output: &output,
            source_export_approved: false,
        };

        assert_eq!(
            export_exact_source_archive(&request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!output.exists());

        request.source_export_approved = true;
        request.source_commit = "9B9421C2C50F037A66F2CB2F22819289437C35B2";
        assert_eq!(
            export_exact_source_archive(&request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!output.exists());

        request.source_commit = &fixture.source_commit;
        let wrong_output = temporary.path().join("exact-tree.sar");
        request.output = &wrong_output;
        assert_eq!(
            export_exact_source_archive(&request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!wrong_output.exists());
    }

    #[test]
    fn exporter_rejects_links_paths_casefolds_duplicates_and_unexpected_members() {
        let fixture = fixture();

        let mut trailing = FakeGitSource::from_fixture(&fixture);
        trailing.tree_listing.push(b'x');
        assert_export_rejected(assemble_source_archive(
            &mut trailing,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut duplicate = FakeGitSource::from_fixture(&fixture);
        let duplicated = duplicate.tree_listing.clone();
        duplicate.tree_listing.extend_from_slice(&duplicated);
        assert_export_rejected(assemble_source_archive(
            &mut duplicate,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut symlink = FakeGitSource::from_fixture(&fixture);
        symlink.tree_listing[..6].copy_from_slice(b"120000");
        assert_export_rejected(assemble_source_archive(
            &mut symlink,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        for invalid_path in [
            ".CARGO/config.toml",
            "src\\escape.rs",
            "../escape.rs",
            "src/CON",
        ] {
            let mut invalid = FakeGitSource::from_fixture(&fixture);
            invalid.append_tree_member("100644", invalid_path, b"invalid\n");
            assert_export_rejected(assemble_source_archive(
                &mut invalid,
                &fixture.source_commit,
                &fixture.source_tree,
            ));
        }

        let mut casefold = FakeGitSource::from_fixture(&fixture);
        casefold.append_tree_member("100644", "SRC/lib.rs", b"case alias\n");
        assert_export_rejected(assemble_source_archive(
            &mut casefold,
            &fixture.source_commit,
            &fixture.source_tree,
        ));

        let mut unexpected = FakeGitSource::from_fixture(&fixture);
        unexpected.append_tree_member("100644", "README.md", b"unexpected\n");
        assert_export_rejected(assemble_source_archive(
            &mut unexpected,
            &fixture.source_commit,
            &fixture.source_tree,
        ));
    }

    #[test]
    fn persistence_is_create_new_and_rejects_aliases_and_repository_descendants() {
        let fixture = fixture();
        let mut source = FakeGitSource::from_fixture(&fixture);
        let assembled =
            assemble_source_archive(&mut source, &fixture.source_commit, &fixture.source_tree)
                .unwrap();
        let repository = tempfile::tempdir().unwrap();
        let repository_handle =
            open_absolute_directory(repository.path(), "source repository").unwrap();
        let repository_identity =
            verified_directory_identity(&repository_handle, "source repository").unwrap();
        let output_root = tempfile::tempdir().unwrap();
        let output_parent = output_root.path().join("source");
        fs::create_dir(&output_parent).unwrap();
        let output = output_parent.join("exact-tree.sar");
        let outside = output_root.path().join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        fs::hard_link(&outside, &output).unwrap();

        assert!(persist_source_archive(&output, repository_identity, &assembled).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
        assert_eq!(fs::read(&output).unwrap(), b"sentinel");

        let inside_parent = repository.path().join("source");
        fs::create_dir(&inside_parent).unwrap();
        assert!(persist_source_archive(
            &inside_parent.join("exact-tree.sar"),
            repository_identity,
            &assembled,
        )
        .is_err());
        assert!(!inside_parent.join("exact-tree.sar").exists());
        assert!(persist_source_archive(
            &output_parent.join("renamed.sar"),
            repository_identity,
            &assembled,
        )
        .is_err());
    }

    #[test]
    #[cfg(unix)]
    fn persistence_and_repository_open_reject_symlink_paths() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        let mut source = FakeGitSource::from_fixture(&fixture);
        let assembled =
            assemble_source_archive(&mut source, &fixture.source_commit, &fixture.source_tree)
                .unwrap();
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir(repository.path().join("real-git")).unwrap();
        symlink("real-git", repository.path().join(".git")).unwrap();
        assert!(LocalGitSource::open(repository.path()).is_err());

        let forbidden = tempfile::tempdir().unwrap();
        let forbidden_handle =
            open_absolute_directory(forbidden.path(), "source repository").unwrap();
        let forbidden_identity =
            verified_directory_identity(&forbidden_handle, "source repository").unwrap();
        let output_root = tempfile::tempdir().unwrap();
        let real_parent = output_root.path().join("real-source");
        fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, output_root.path().join("source")).unwrap();
        assert!(persist_source_archive(
            &output_root.path().join("source/exact-tree.sar"),
            forbidden_identity,
            &assembled,
        )
        .is_err());
        assert!(!real_parent.join("exact-tree.sar").exists());
    }

    #[test]
    fn real_git_export_matches_the_byte_golden_and_dirty_worktrees_reject() {
        let fixture = fixture();
        let (temporary, source_commit, source_tree) = deterministic_git_fixture();
        assert_eq!(source_commit, fixture.source_commit);
        assert_eq!(source_tree, fixture.source_tree);
        let repository = temporary.path().join("repository");
        let export_root = temporary.path().join("export");
        let output_parent = export_root.join("source");
        fs::create_dir_all(&output_parent).unwrap();
        let output = output_parent.join("exact-tree.sar");
        let request = SourceArchiveExportRequest {
            repository: &repository,
            source_commit: &source_commit,
            source_tree: &source_tree,
            output: &output,
            source_export_approved: true,
        };

        let receipt = export_exact_source_archive(&request).unwrap();
        assert_eq!(receipt.archive_fingerprint, fixture.archive_fingerprint);
        assert_eq!(
            receipt.cargo_lock_fingerprint,
            fixture.cargo_lock_fingerprint
        );
        assert_eq!(receipt.source_commit, fixture.source_commit);
        assert_eq!(receipt.source_tree, fixture.source_tree);
        assert_eq!(receipt.entry_count, 2);
        assert_eq!(fs::read(&output).unwrap(), fixture.archive);
        assert!(fs::metadata(&output).unwrap().permissions().readonly());
        assert_eq!(
            export_exact_source_archive(&request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );

        set_readonly(&output, false);
        fs::write(repository.join("untracked"), b"dirty\n").unwrap();
        let dirty_root = temporary.path().join("dirty-export");
        let dirty_parent = dirty_root.join("source");
        fs::create_dir_all(&dirty_parent).unwrap();
        let dirty_output = dirty_parent.join("exact-tree.sar");
        let dirty_request = SourceArchiveExportRequest {
            output: &dirty_output,
            ..request
        };
        assert_eq!(
            export_exact_source_archive(&dirty_request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!dirty_output.exists());

        fs::remove_file(repository.join("untracked")).unwrap();
        fs::write(repository.join(".git/info/exclude"), b"ignored\n").unwrap();
        fs::write(
            repository.join("ignored"),
            b"ignored but still unexpected\n",
        )
        .unwrap();
        let ignored_root = temporary.path().join("ignored-export");
        let ignored_parent = ignored_root.join("source");
        fs::create_dir_all(&ignored_parent).unwrap();
        let ignored_output = ignored_parent.join("exact-tree.sar");
        let ignored_request = SourceArchiveExportRequest {
            output: &ignored_output,
            ..dirty_request
        };
        assert_eq!(
            export_exact_source_archive(&ignored_request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!ignored_output.exists());
    }

    #[test]
    fn repository_policy_rejects_common_and_alternate_object_stores() {
        let (temporary, source_commit, source_tree) = deterministic_git_fixture();
        let repository = temporary.path().join("repository");
        let output_parent = temporary.path().join("export/source");
        fs::create_dir_all(&output_parent).unwrap();
        let output = output_parent.join("exact-tree.sar");
        let request = SourceArchiveExportRequest {
            repository: &repository,
            source_commit: &source_commit,
            source_tree: &source_tree,
            output: &output,
            source_export_approved: true,
        };

        fs::create_dir(repository.join("external-common")).unwrap();
        fs::write(repository.join(".git/commondir"), b"../external-common\n").unwrap();
        assert_eq!(
            export_exact_source_archive(&request)
                .unwrap_err()
                .to_string(),
            EXPORT_REJECTED
        );
        assert!(!output.exists());
        fs::remove_file(repository.join(".git/commondir")).unwrap();

        for name in ["alternates", "http-alternates"] {
            fs::write(
                repository.join(".git/objects/info").join(name),
                b"../../../external-objects\n",
            )
            .unwrap();
            assert_eq!(
                export_exact_source_archive(&request)
                    .unwrap_err()
                    .to_string(),
                EXPORT_REJECTED
            );
            assert!(!output.exists());
            fs::remove_file(repository.join(".git/objects/info").join(name)).unwrap();
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

    fn assert_materialization_redacted(error: &anyhow::Error) {
        let rendered = error.to_string();
        assert_eq!(rendered, MATERIALIZATION_REJECTED);
        assert!(!rendered.contains(CAMPAIGN_ID));
        assert!(!rendered.contains("exact-tree.sar"));
        assert!(!rendered.contains("Cargo.lock"));
        assert!(!rendered.contains("worktree"));
    }

    #[cfg(unix)]
    fn retained_fixture(fixture: &Fixture) -> (tempfile::TempDir, RetainedSourceArchive) {
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
        (temporary, retained)
    }

    #[cfg(unix)]
    pub(crate) fn retained_fixture_for_fixed_build_composition_test(
    ) -> (tempfile::TempDir, RetainedSourceArchive) {
        let fixture = fixture();
        retained_fixture(&fixture)
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
    #[cfg(unix)]
    fn approved_retained_archive_materializes_exact_tree_and_bound_metadata() {
        use std::collections::BTreeSet;
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture();
        let (_temporary, store) = store();
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
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("worktree");

        let materialized = materialize_retained_source_tree(retained, &destination).unwrap();

        assert_eq!(materialized.member_count(), 2);
        assert_eq!(materialized.campaign_id(), CAMPAIGN_ID);
        assert_eq!(
            materialized.archive_fingerprint(),
            &fixture.archive_fingerprint
        );
        assert_eq!(materialized.source_commit(), fixture.source_commit);
        assert_eq!(materialized.source_tree(), fixture.source_tree);
        assert_eq!(
            materialized.cargo_lock_fingerprint(),
            &fixture.cargo_lock_fingerprint
        );
        assert_eq!(materialized.committer_timestamp(), 1_700_000_123);
        assert_eq!(fs::read(destination.join("Cargo.lock")).unwrap(), b"lock\n");
        assert_eq!(
            fs::read(destination.join("src/lib.rs")).unwrap(),
            b"pub fn fixture() {}\n"
        );
        assert_eq!(
            fs::metadata(destination.join("Cargo.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(
            fs::metadata(destination.join("src/lib.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(
            fs::metadata(destination.join("src"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        let root_names = fs::read_dir(&destination)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            root_names,
            ["Cargo.lock".into(), "src".into()].into_iter().collect()
        );
        materialized.ensure_unchanged().unwrap();
    }

    #[test]
    fn validator_member_ranges_bind_the_exact_verified_blob_bytes() {
        let fixture = fixture();
        let validated = validate_source_archive_bytes(
            &fixture.archive,
            &fixture.archive_fingerprint,
            &fixture.cargo_lock_fingerprint,
        )
        .unwrap();
        let expected_contents = [b"lock\n".as_slice(), b"pub fn fixture() {}\n".as_slice()];

        assert_eq!(validated.member_ranges.len(), expected_contents.len());
        assert_eq!(
            validated.member_ranges.len(),
            validated.manifest.entries.len()
        );
        let mut previous_end = 0_u64;
        for ((entry, range), expected) in validated
            .manifest
            .entries
            .iter()
            .zip(&validated.member_ranges)
            .zip(expected_contents)
        {
            let end = range.offset.checked_add(range.byte_length).unwrap();
            assert!(range.offset >= previous_end);
            assert!(end <= fixture.archive_fingerprint.byte_length);
            let start = usize::try_from(range.offset).unwrap();
            let end = usize::try_from(end).unwrap();
            let ranged = &fixture.archive[start..end];
            assert_eq!(ranged, expected);
            assert_eq!(range.byte_length, entry.artifact_fingerprint.byte_length);
            assert_eq!(fingerprint(ranged), entry.artifact_fingerprint);
            assert_eq!(
                hex::encode(production_git_object_id("blob", ranged)),
                entry.git_object_id
            );
            previous_end = u64::try_from(end).unwrap();
        }
        let cargo_lock = validated
            .manifest
            .entries
            .iter()
            .zip(&validated.member_ranges)
            .find(|(entry, _)| entry.repository_relative_path == "Cargo.lock")
            .unwrap();
        assert_eq!(
            cargo_lock.0.artifact_fingerprint,
            fixture.cargo_lock_fingerprint
        );
    }

    #[test]
    #[cfg(unix)]
    fn source_materialization_preserves_executable_logical_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = fixture_with_lib_mode("100755");
        let (_temporary, retained) = retained_fixture(&fixture);
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("worktree");

        let materialized = materialize_retained_source_tree(retained, &destination).unwrap();

        assert_eq!(
            fs::metadata(destination.join("Cargo.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        assert_eq!(
            fs::metadata(destination.join("src/lib.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        materialized.ensure_unchanged().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn source_drift_rejects_before_destination_creation() {
        let fixture = fixture();
        let (temporary, retained) = retained_fixture(&fixture);
        let retained_path = temporary.path().join("campaign").join(SOURCE_ARCHIVE_PATH);
        let mut changed = fixture.archive.clone();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&retained_path, changed).unwrap();
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("worktree");

        let error = materialize_retained_source_tree(retained, &destination).unwrap_err();

        assert_materialization_redacted(&error);
        assert!(!destination.exists());
    }

    #[test]
    #[cfg(unix)]
    fn source_and_destination_races_issue_no_materialized_capability() {
        use std::os::unix::fs::PermissionsExt as _;

        for race in ["member", "framing", "destination"] {
            let fixture = fixture();
            let (temporary, retained) = retained_fixture(&fixture);
            let retained_path = temporary.path().join("campaign").join(SOURCE_ARCHIVE_PATH);
            let destination_parent = tempfile::tempdir().unwrap();
            let destination = destination_parent.path().join("worktree");
            let error =
                materialize_with_post_member_hook(retained, &destination, |ordinal| {
                    match (race, ordinal) {
                        ("member", 0) => {
                            let mut changed = fixture.archive.clone();
                            *changed.last_mut().unwrap() ^= 1;
                            fs::write(&retained_path, changed).unwrap();
                        }
                        ("framing", 1) => {
                            let mut changed = fixture.archive.clone();
                            changed[0] ^= 1;
                            fs::write(&retained_path, changed).unwrap();
                        }
                        ("destination", 1) => {
                            let cargo_lock = destination.join("Cargo.lock");
                            fs::set_permissions(&cargo_lock, fs::Permissions::from_mode(0o644))
                                .unwrap();
                            fs::write(&cargo_lock, b"evil\n").unwrap();
                            fs::set_permissions(&cargo_lock, fs::Permissions::from_mode(0o444))
                                .unwrap();
                        }
                        _ => {}
                    }
                })
                .unwrap_err();

            assert_materialization_redacted(&error);
            assert!(destination.exists(), "{race}");
            assert_eq!(
                fs::read(destination.join("Cargo.lock")).unwrap(),
                if race == "destination" {
                    b"evil\n"
                } else {
                    b"lock\n"
                }
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn materialized_capability_is_sticky_invalid_after_tree_or_archive_drift() {
        use std::os::unix::fs::PermissionsExt as _;

        for drift in ["tree", "archive"] {
            let fixture = fixture();
            let (temporary, retained) = retained_fixture(&fixture);
            let destination_parent = tempfile::tempdir().unwrap();
            let destination = destination_parent.path().join("worktree");
            let materialized = materialize_retained_source_tree(retained, &destination).unwrap();
            let (path, original, original_mode) = if drift == "tree" {
                (destination.join("Cargo.lock"), b"lock\n".to_vec(), 0o444)
            } else {
                (
                    temporary.path().join("campaign").join(SOURCE_ARCHIVE_PATH),
                    fixture.archive.clone(),
                    0o600,
                )
            };
            let mut changed = original.clone();
            *changed.last_mut().unwrap() ^= 1;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, changed).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(original_mode)).unwrap();

            let error = materialized.ensure_unchanged().unwrap_err();
            assert_materialization_redacted(&error);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&path, original).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(original_mode)).unwrap();
            assert_materialization_redacted(&materialized.ensure_unchanged().unwrap_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn invalid_member_count_and_ranges_reject_before_destination_creation() {
        for invalid in ["zero", "count", "range"] {
            let fixture = fixture();
            let (_temporary, mut retained) = retained_fixture(&fixture);
            match invalid {
                "zero" => retained.members.clear(),
                "count" => {
                    let range = retained.members[0].range;
                    let fingerprint = retained.members[0].fingerprint.clone();
                    while retained.members.len()
                        <= usize::try_from(MAX_SOURCE_ARCHIVE_V1_ENTRIES).unwrap()
                    {
                        retained.members.push(RetainedSourceMember {
                            relative_path: format!("overflow/{}", retained.members.len()),
                            executable: false,
                            fingerprint: fingerprint.clone(),
                            range,
                        });
                    }
                }
                "range" => {
                    retained.members[0].range.offset = fixture.archive_fingerprint.byte_length;
                }
                _ => unreachable!(),
            }
            let destination_parent = tempfile::tempdir().unwrap();
            let destination = destination_parent.path().join("worktree");

            let error = materialize_retained_source_tree(retained, &destination).unwrap_err();

            assert_materialization_redacted(&error);
            assert!(!destination.exists(), "{invalid}");
        }
    }

    #[test]
    #[cfg(windows)]
    fn source_materialization_boundary_fails_before_creation_without_directory_durability() {
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("worktree");

        let Err(error) = create_source_tree_builder(&destination, 1) else {
            panic!("unsupported directory durability issued a source-tree builder")
        };

        assert_materialization_redacted(&error);
        assert!(!destination.exists());
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

    #[test]
    #[cfg(unix)]
    fn retained_root_and_source_rename_restore_history_is_sticky() {
        for target in ["root", "source"] {
            for restore_before_first_check in [true, false] {
                let fixture = fixture();
                let (temporary, retained) = retained_fixture(&fixture);
                let root = temporary.path().join("campaign");
                let (original, displaced) = if target == "root" {
                    (root.clone(), temporary.path().join("displaced-campaign"))
                } else {
                    (root.join("source"), root.join("displaced-source"))
                };

                fs::rename(&original, &displaced).unwrap();
                if restore_before_first_check {
                    fs::rename(&displaced, &original).unwrap();
                }
                assert_redacted(&retained.ensure_unchanged().unwrap_err());
                if !restore_before_first_check {
                    fs::rename(&displaced, &original).unwrap();
                }
                assert_redacted(&retained.ensure_unchanged().unwrap_err());
            }
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
    fn materialized_member_reads_are_exact_and_never_exceed_eight_kibibytes() {
        let bytes = vec![7_u8; SOURCE_READ_BUFFER_BYTES * 3 + 1];
        let mut reader = ReadRequestTracker {
            inner: Cursor::new(bytes.clone()),
            maximum_requested: Cell::new(0),
        };
        let mut written = Vec::new();

        copy_source_member(
            &mut reader,
            &mut written,
            u64::try_from(bytes.len()).unwrap(),
        )
        .unwrap();

        assert_eq!(written, bytes);
        assert!(reader.maximum_requested.get() <= SOURCE_READ_BUFFER_BYTES);

        let error = copy_source_member(&mut Cursor::new(b"short"), &mut Vec::new(), 6).unwrap_err();
        assert_materialization_redacted(&error);
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
