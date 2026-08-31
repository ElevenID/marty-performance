//! Canonical, nonactivating fixed-build input archive emission.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};
use marty_perf_schema::ArtifactFingerprint;
use sha2::{Digest, Sha256};

use super::artifact_store::{
    CampaignArtifactStore, MaterializedInputStore, MaterializedInputStoreBuilder,
    PersistedBuildInputArchiveBytes, PersistedBuildInputInventoryBytes,
};
use super::{
    canonical_pretty_bytes, concrete_target_linker_environment_name, ensure_file_unchanged,
    fingerprint, valid_artifact_fingerprint, valid_build_input_inventory, valid_campaign_id,
    validate_build_input_archive_stream, BuildInputEntry, BuildInputInventory, OpenedInput,
    FIXED_BUILD_INPUT_ARCHIVE_MAGIC, MAX_FIXED_BUILD_INPUT_BYTES, MAX_FIXED_BUILD_INPUT_ENTRIES,
    MAX_SOURCE_ARCHIVE_V1_BYTES,
};

const MEMBER_BUFFER_BYTES: usize = 8 * 1024;
const MEMBER_BUFFER_BYTES_U64: u64 = 8 * 1024;

/// Closed roles for caller-approved public build inputs.
///
/// Cargo configuration is intentionally absent. A clean generated configuration must use the
/// separate `bind_generated_cargo_configuration` constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicBuildInputRole {
    CargoDependencySource,
    CargoExecutable,
    ExecutablePathInput,
    RustcExecutable,
    RustcSysrootFile,
    TargetArchiverExecutable,
    TargetLinkerExecutable,
    ToolDynamicDependency,
    WindowsRuntimeInput,
}

impl PublicBuildInputRole {
    fn wire_name(self) -> &'static str {
        match self {
            Self::CargoDependencySource => "cargo_dependency_source",
            Self::CargoExecutable => "cargo_executable",
            Self::ExecutablePathInput => "executable_path_input",
            Self::RustcExecutable => "rustc_executable",
            Self::RustcSysrootFile => "rustc_sysroot_file",
            Self::TargetArchiverExecutable => "target_archiver_executable",
            Self::TargetLinkerExecutable => "target_linker_executable",
            Self::ToolDynamicDependency => "tool_dynamic_dependency",
            Self::WindowsRuntimeInput => "windows_runtime_input",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovedPublicBuildInputRole {
    GeneratedCargoConfiguration,
    Public(PublicBuildInputRole),
}

impl ApprovedPublicBuildInputRole {
    fn wire_name(self) -> &'static str {
        match self {
            Self::GeneratedCargoConfiguration => "cargo_configuration",
            Self::Public(role) => role.wire_name(),
        }
    }
}

/// Portable logical mode retained by the inventory rather than a host ACL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LogicalBuildInputMode {
    Data,
    Executable,
}

impl LogicalBuildInputMode {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Data => "100644",
            Self::Executable => "100755",
        }
    }
}

/// Explicit caller approval for one public, already-open build input handle.
pub(super) struct ApprovedPublicBuildInput {
    role: ApprovedPublicBuildInputRole,
    relative_path: String,
    mode: LogicalBuildInputMode,
    input: OpenedInput,
}

impl ApprovedPublicBuildInput {
    /// Binds one non-configuration public input without reopening or discovering its path.
    pub(super) fn bind(
        role: PublicBuildInputRole,
        relative_path: String,
        mode: LogicalBuildInputMode,
        input: OpenedInput,
    ) -> Result<Self> {
        Self::bind_role(
            ApprovedPublicBuildInputRole::Public(role),
            relative_path,
            mode,
            input,
        )
    }

    /// Binds one explicitly generated, staged, clean public Cargo configuration.
    ///
    /// This is a provenance assertion by the trusted caller, not a heuristic secret scan. Live
    /// Cargo configuration and credentials have no generic role or constructor.
    pub(super) fn bind_generated_cargo_configuration(
        relative_path: String,
        input: OpenedInput,
    ) -> Result<Self> {
        Self::bind_role(
            ApprovedPublicBuildInputRole::GeneratedCargoConfiguration,
            relative_path,
            LogicalBuildInputMode::Data,
            input,
        )
    }

    fn bind_role(
        role: ApprovedPublicBuildInputRole,
        relative_path: String,
        mode: LogicalBuildInputMode,
        input: OpenedInput,
    ) -> Result<Self> {
        anyhow::ensure!(
            input.snapshot.readonly && input.snapshot.link_count == 1,
            "fixed build input capture rejected"
        );
        ensure_file_unchanged(&input.file, input.snapshot, "build-input archive member")?;
        Ok(Self {
            role,
            relative_path,
            mode,
            input,
        })
    }

    fn ensure_unchanged(&self) -> Result<()> {
        ensure_file_unchanged(
            &self.input.file,
            self.input.snapshot,
            "build-input archive member",
        )
    }
}

/// Joint persistence proof for one canonical inventory and its matching framed archive.
pub(super) struct PersistedFixedBuildInputs {
    inventory: PersistedBuildInputInventoryBytes,
    archive: PersistedBuildInputArchiveBytes,
}

impl PersistedFixedBuildInputs {
    /// Returns the retained canonical inventory fingerprint.
    pub(super) fn inventory_fingerprint(&self) -> &ArtifactFingerprint {
        self.inventory.fingerprint()
    }

    /// Returns the retained framed archive fingerprint.
    pub(super) fn archive_fingerprint(&self) -> &ArtifactFingerprint {
        self.archive.fingerprint()
    }
}

/// Proof that every verified archive member was published into one new immutable tree.
pub(super) struct MaterializedBuildInputTree {
    store: MaterializedInputStore,
    member_count: usize,
    aggregate_fingerprint: ArtifactFingerprint,
}

impl MaterializedBuildInputTree {
    pub(super) fn member_count(&self) -> usize {
        self.member_count
    }

    pub(super) fn aggregate_fingerprint(&self) -> &ArtifactFingerprint {
        &self.aggregate_fingerprint
    }

    pub(super) fn ensure_unchanged(&self) -> Result<()> {
        self.store.verify_root()
    }
}

struct HashingReader<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    hasher: Sha256,
    length: u64,
}

impl<R: Read + ?Sized> Read for HashingReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let take = bytes.len().min(MEMBER_BUFFER_BYTES);
        let read = self.inner.read(&mut bytes[..take])?;
        self.hasher.update(&bytes[..read]);
        self.length = self
            .length
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("materialization rejected"))?;
        if self.length > MAX_FIXED_BUILD_INPUT_BYTES {
            return Err(std::io::Error::other("materialization rejected"));
        }
        Ok(read)
    }
}

fn read_bounded_retained(reader: &mut impl Read, maximum: u64) -> Result<Vec<u8>> {
    let limit = maximum.checked_add(1).context("materialization rejected")?;
    let mut limited = reader.take(limit);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; MEMBER_BUFFER_BYTES];
    loop {
        let read = limited
            .read(&mut buffer)
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    anyhow::ensure!(
        u64::try_from(bytes.len()).is_ok_and(|length| length <= maximum),
        "materialization rejected"
    );
    Ok(bytes)
}

struct PreparedFixedBuildInputs {
    inventory_bytes: Vec<u8>,
    inventory_fingerprint: ArtifactFingerprint,
    archive_fingerprint: ArtifactFingerprint,
    members: Vec<BuildInputArchiveMember>,
}

struct DigestWriter<'a> {
    hasher: &'a mut Sha256,
}

impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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

fn inventory_from_entries(
    campaign_id: &str,
    target_triple: &str,
    entries: Vec<BuildInputEntry>,
    archive_fingerprint: ArtifactFingerprint,
) -> Result<BuildInputInventory> {
    let entry_count = u32::try_from(entries.len()).context("fixed build input capture rejected")?;
    let total_byte_length = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.fingerprint.byte_length)
            .context("fixed build input capture rejected")
    })?;
    Ok(BuildInputInventory {
        schema: "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2".to_owned(),
        campaign_id: campaign_id.to_owned(),
        target_triple: target_triple.to_owned(),
        entry_count,
        total_byte_length,
        archive_fingerprint,
        executable_path_directories: [
            "toolchain/bin",
            "tools/linker",
            "tools/archiver",
            "tools/runtime",
        ]
        .map(str::to_owned)
        .to_vec(),
        entries,
    })
}

fn projected_inventory_for_inputs(
    campaign_id: &str,
    target_triple: &str,
    inputs: &[ApprovedPublicBuildInput],
) -> Result<BuildInputInventory> {
    let member_count = u64::try_from(inputs.len()).context("fixed build input capture rejected")?;
    let total_member_bytes = inputs.iter().try_fold(0_u64, |total, input| {
        total
            .checked_add(input.input.snapshot.byte_length)
            .context("fixed build input capture rejected")
    })?;
    let archive_length = checked_archive_length(member_count, total_member_bytes)
        .context("fixed build input capture rejected")?;
    let placeholder = "0".repeat(64);
    let entries = inputs
        .iter()
        .map(|input| BuildInputEntry {
            role: input.role.wire_name().to_owned(),
            relative_path: input.relative_path.clone(),
            file_mode: input.mode.wire_name().to_owned(),
            fingerprint: ArtifactFingerprint {
                sha256: placeholder.clone(),
                byte_length: input.input.snapshot.byte_length,
            },
        })
        .collect::<Vec<_>>();
    inventory_from_entries(
        campaign_id,
        target_triple,
        entries,
        ArtifactFingerprint {
            sha256: placeholder,
            byte_length: archive_length,
        },
    )
}

fn fingerprint_sorted_inputs(
    inputs: &mut [ApprovedPublicBuildInput],
    archive_length: u64,
) -> Result<(Vec<BuildInputEntry>, ArtifactFingerprint)> {
    let mut archive_hasher = Sha256::new();
    archive_hasher.update(FIXED_BUILD_INPUT_ARCHIVE_MAGIC);
    let mut entries = Vec::with_capacity(inputs.len());
    for input in &mut *inputs {
        input.ensure_unchanged()?;
        input
            .input
            .file
            .seek(SeekFrom::Start(0))
            .context("fixed build input capture rejected")?;
        archive_hasher.update(input.input.snapshot.byte_length.to_be_bytes());
        let member_fingerprint = {
            let mut archive_writer = DigestWriter {
                hasher: &mut archive_hasher,
            };
            copy_and_hash_exact_member(
                &mut input.input.file,
                &mut archive_writer,
                input.input.snapshot.byte_length,
            )?
        };
        input.ensure_unchanged()?;
        entries.push(BuildInputEntry {
            role: input.role.wire_name().to_owned(),
            relative_path: input.relative_path.clone(),
            file_mode: input.mode.wire_name().to_owned(),
            fingerprint: member_fingerprint,
        });
    }
    for input in &*inputs {
        input.ensure_unchanged()?;
    }
    Ok((
        entries,
        ArtifactFingerprint {
            sha256: hex::encode_upper(archive_hasher.finalize()),
            byte_length: archive_length,
        },
    ))
}

fn prepare_fixed_build_inputs(
    campaign_id: &str,
    target_triple: &str,
    windows: bool,
    mut inputs: Vec<ApprovedPublicBuildInput>,
) -> Result<PreparedFixedBuildInputs> {
    anyhow::ensure!(
        valid_campaign_id(campaign_id)
            && concrete_target_linker_environment_name(target_triple).is_some()
            && target_triple
                .split('-')
                .any(|component| component == "windows")
                == windows,
        "fixed build input capture rejected"
    );
    inputs.sort_by(|left, right| {
        (
            left.role.wire_name().as_bytes(),
            left.relative_path.as_bytes(),
        )
            .cmp(&(
                right.role.wire_name().as_bytes(),
                right.relative_path.as_bytes(),
            ))
    });
    for input in &inputs {
        input.ensure_unchanged()?;
    }
    let projected_inventory = projected_inventory_for_inputs(campaign_id, target_triple, &inputs)?;
    anyhow::ensure!(
        valid_build_input_inventory(&projected_inventory, windows, target_triple, campaign_id,),
        "fixed build input capture rejected"
    );

    let (entries, archive_fingerprint) = fingerprint_sorted_inputs(
        &mut inputs,
        projected_inventory.archive_fingerprint.byte_length,
    )?;
    let inventory = inventory_from_entries(
        campaign_id,
        target_triple,
        entries,
        archive_fingerprint.clone(),
    )?;
    anyhow::ensure!(
        valid_build_input_inventory(&inventory, windows, target_triple, campaign_id),
        "fixed build input capture rejected"
    );
    let inventory_bytes =
        canonical_pretty_bytes(&inventory).context("fixed build input capture rejected")?;
    anyhow::ensure!(
        u64::try_from(inventory_bytes.len())
            .is_ok_and(|length| { length <= MAX_SOURCE_ARCHIVE_V1_BYTES }),
        "fixed build input capture rejected"
    );
    let inventory_fingerprint =
        fingerprint(&inventory_bytes).context("fixed build input capture rejected")?;
    let fingerprints = inventory
        .entries
        .iter()
        .map(|entry| entry.fingerprint.clone())
        .collect::<Vec<_>>();
    let members = inputs
        .into_iter()
        .zip(fingerprints)
        .map(|(input, expected)| BuildInputArchiveMember::bind(input.input, expected))
        .collect::<Result<Vec<_>>>()?;
    Ok(PreparedFixedBuildInputs {
        inventory_bytes,
        inventory_fingerprint,
        archive_fingerprint,
        members,
    })
}

fn persist_fixed_build_inputs(
    store: &CampaignArtifactStore,
    mut prepared: PreparedFixedBuildInputs,
) -> Result<PersistedFixedBuildInputs> {
    for member in &prepared.members {
        member.ensure_unchanged()?;
    }
    let inventory = store.write_build_input_inventory(&prepared.inventory_bytes)?;
    anyhow::ensure!(
        inventory.fingerprint() == &prepared.inventory_fingerprint,
        "fixed build input capture rejected"
    );
    for member in &prepared.members {
        member.ensure_unchanged()?;
    }
    let archive = emit_build_input_archive(store, &mut prepared.members)?;
    anyhow::ensure!(
        archive.fingerprint() == &prepared.archive_fingerprint
            && inventory.shares_store_with(&archive),
        "fixed build input capture rejected"
    );
    Ok(PersistedFixedBuildInputs { inventory, archive })
}

/// Captures one explicit public handle allowlist as a canonical inventory and matching BIA.
pub(super) fn capture_fixed_build_inventory(
    store: &CampaignArtifactStore,
    campaign_id: &str,
    target_triple: &str,
    windows: bool,
    inputs: Vec<ApprovedPublicBuildInput>,
) -> Result<PersistedFixedBuildInputs> {
    let prepared = prepare_fixed_build_inputs(campaign_id, target_triple, windows, inputs)?;
    persist_fixed_build_inputs(store, prepared)
}

fn read_verified_inventory(
    capability: &mut PersistedBuildInputInventoryBytes,
) -> Result<(BuildInputInventory, Vec<u8>)> {
    capability
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let bytes = {
        let file = capability.retained_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        read_bounded_retained(file, MAX_SOURCE_ARCHIVE_V1_BYTES)?
    };
    capability
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    anyhow::ensure!(
        fingerprint(&bytes).is_ok_and(|actual| &actual == capability.fingerprint()),
        "materialization rejected"
    );
    let inventory: BuildInputInventory =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let windows = inventory
        .target_triple
        .split('-')
        .any(|component| component == "windows");
    anyhow::ensure!(
        valid_build_input_inventory(
            &inventory,
            windows,
            &inventory.target_triple,
            &inventory.campaign_id,
        ) && canonical_pretty_bytes(&inventory).as_deref() == Some(bytes.as_slice()),
        "materialization rejected"
    );
    Ok((inventory, bytes))
}

fn validate_retained_archive(
    capability: &mut PersistedBuildInputArchiveBytes,
    inventory: &BuildInputInventory,
) -> Result<()> {
    capability
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let actual = {
        let file = capability.retained_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        let mut reader = HashingReader {
            inner: file,
            hasher: Sha256::new(),
            length: 0,
        };
        validate_build_input_archive_stream(&mut reader, inventory)
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        ArtifactFingerprint {
            sha256: hex::encode_upper(reader.hasher.finalize()),
            byte_length: reader.length,
        }
    };
    capability
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    anyhow::ensure!(
        &actual == capability.fingerprint() && actual == inventory.archive_fingerprint,
        "materialization rejected"
    );
    Ok(())
}

fn copy_archive_fragment(
    reader: &mut std::fs::File,
    writer: &mut dyn Write,
    expected_length: u64,
) -> Result<()> {
    let mut remaining = expected_length;
    let mut buffer = [0_u8; MEMBER_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(MEMBER_BUFFER_BYTES_U64))
            .context("materialization rejected")?;
        let read = reader
            .read(&mut buffer[..take])
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        anyhow::ensure!(read != 0, "materialization rejected");
        writer
            .write_all(&buffer[..read])
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        remaining = remaining
            .checked_sub(u64::try_from(read).context("materialization rejected")?)
            .context("materialization rejected")?;
    }
    Ok(())
}

fn materialized_aggregate(
    inventory_fingerprint: &ArtifactFingerprint,
    archive_fingerprint: &ArtifactFingerprint,
) -> Result<ArtifactFingerprint> {
    let preimage = format!(
        "MARTY-MATERIALIZED-BUILD-INPUT-TREE-V1\n{}\n{}\n{}\n{}\n",
        inventory_fingerprint.sha256,
        inventory_fingerprint.byte_length,
        archive_fingerprint.sha256,
        archive_fingerprint.byte_length,
    );
    fingerprint(preimage.as_bytes()).context("materialization rejected")
}

/// Materializes only the inventory-bound members from retained joint-capability handles.
pub(super) fn materialize_fixed_build_inputs(
    mut capability: PersistedFixedBuildInputs,
    absolute_destination: &Path,
) -> Result<MaterializedBuildInputTree> {
    let (inventory, inventory_bytes) = read_verified_inventory(&mut capability.inventory)?;
    validate_retained_archive(&mut capability.archive, &inventory)?;
    let inventory_fingerprint =
        fingerprint(&inventory_bytes).context("materialization rejected")?;
    let aggregate_fingerprint =
        materialized_aggregate(&inventory_fingerprint, &inventory.archive_fingerprint)?;

    let mut store = MaterializedInputStoreBuilder::create_new(
        absolute_destination,
        inventory.entry_count,
        MAX_FIXED_BUILD_INPUT_BYTES,
    )
    .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let archive = capability.archive.retained_file_mut();
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let mut magic = [0_u8; FIXED_BUILD_INPUT_ARCHIVE_MAGIC.len()];
    archive
        .read_exact(&mut magic)
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    anyhow::ensure!(
        magic == FIXED_BUILD_INPUT_ARCHIVE_MAGIC,
        "materialization rejected"
    );
    let member_count = inventory.entries.len();
    for entry in &inventory.entries {
        let mut encoded_length = [0_u8; 8];
        archive
            .read_exact(&mut encoded_length)
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        anyhow::ensure!(
            u64::from_be_bytes(encoded_length) == entry.fingerprint.byte_length,
            "materialization rejected"
        );
        let member = store
            .write_member(
                &entry.relative_path,
                entry.file_mode == "100755",
                &entry.fingerprint,
                |writer| copy_archive_fragment(archive, writer, entry.fingerprint.byte_length),
            )
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
        anyhow::ensure!(
            member.fingerprint() == &entry.fingerprint,
            "materialization rejected"
        );
    }
    let mut trailing = [0_u8; 1];
    anyhow::ensure!(
        archive
            .read(&mut trailing)
            .map_err(|_| anyhow::anyhow!("materialization rejected"))?
            == 0,
        "materialization rejected"
    );
    capability
        .archive
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    capability
        .inventory
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let store = store
        .seal()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    let materialized = MaterializedBuildInputTree {
        store,
        member_count,
        aggregate_fingerprint,
    };
    materialized
        .ensure_unchanged()
        .map_err(|_| anyhow::anyhow!("materialization rejected"))?;
    Ok(materialized)
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
    #[cfg(windows)]
    use crate::issuance_qualification::artifact_store::MaterializedInputStoreBuilder;
    #[cfg(unix)]
    use crate::issuance_qualification::artifact_store::{
        CampaignArtifactStore, MaterializedInputStoreBuilder,
    };
    use crate::issuance_qualification::fingerprint;
    #[cfg(unix)]
    use crate::issuance_qualification::{open_absolute_file, validate_build_input_archive_stream};

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
    fn every_materialization_reader_caps_requests_at_eight_kibibytes() {
        let bytes = vec![0x5a; MEMBER_BUFFER_BYTES * 3 + 17];
        let mut inventory_reader = TrackingReader::new(bytes.clone());
        assert_eq!(
            read_bounded_retained(&mut inventory_reader, bytes.len() as u64).unwrap(),
            bytes
        );
        assert_eq!(inventory_reader.maximum_requested, MEMBER_BUFFER_BYTES);

        let mut archive_reader = TrackingReader::new(vec![0x5a; MEMBER_BUFFER_BYTES * 2]);
        let mut hashing = HashingReader {
            inner: &mut archive_reader,
            hasher: Sha256::new(),
            length: 0,
        };
        let mut oversized = vec![0_u8; MEMBER_BUFFER_BYTES * 4];
        while hashing.read(&mut oversized).unwrap() != 0 {}
        assert_eq!(archive_reader.maximum_requested, MEMBER_BUFFER_BYTES);
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

    #[test]
    fn public_role_domain_has_no_generic_or_live_cargo_configuration_role() {
        let roles = [
            PublicBuildInputRole::CargoDependencySource,
            PublicBuildInputRole::CargoExecutable,
            PublicBuildInputRole::ExecutablePathInput,
            PublicBuildInputRole::RustcExecutable,
            PublicBuildInputRole::RustcSysrootFile,
            PublicBuildInputRole::TargetArchiverExecutable,
            PublicBuildInputRole::TargetLinkerExecutable,
            PublicBuildInputRole::ToolDynamicDependency,
            PublicBuildInputRole::WindowsRuntimeInput,
        ];
        assert!(roles
            .iter()
            .all(|role| role.wire_name() != "cargo_configuration"));
    }

    #[cfg(unix)]
    const CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    #[cfg(unix)]
    const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";

    #[cfg(unix)]
    fn opened_public_input(
        directory: &std::path::Path,
        physical_name: &str,
        bytes: &[u8],
    ) -> OpenedInput {
        let path = directory.join(physical_name);
        fs::write(&path, bytes).unwrap();
        set_readonly(&path, true);
        open_absolute_file(
            &path,
            MAX_FIXED_BUILD_INPUT_BYTES,
            None,
            "synthetic approved public build input",
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn approved_public_input(
        directory: &std::path::Path,
        physical_name: &str,
        role: PublicBuildInputRole,
        relative_path: &str,
        mode: LogicalBuildInputMode,
        bytes: &[u8],
    ) -> ApprovedPublicBuildInput {
        ApprovedPublicBuildInput::bind(
            role,
            relative_path.to_owned(),
            mode,
            opened_public_input(directory, physical_name, bytes),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn complete_public_inputs(directory: &std::path::Path) -> Vec<ApprovedPublicBuildInput> {
        let mut inputs = vec![
            ApprovedPublicBuildInput::bind_generated_cargo_configuration(
                "cargo-home/config.toml".to_owned(),
                opened_public_input(directory, "generated-config", b"[net]\noffline = true\n"),
            )
            .unwrap(),
            approved_public_input(
                directory,
                "dependency-source",
                PublicBuildInputRole::CargoDependencySource,
                "cargo-home/registry/src/synthetic/lib.rs",
                LogicalBuildInputMode::Data,
                b"pub const SYNTHETIC: bool = true;\n",
            ),
            approved_public_input(
                directory,
                "cargo",
                PublicBuildInputRole::CargoExecutable,
                "toolchain/bin/cargo",
                LogicalBuildInputMode::Executable,
                b"synthetic cargo executable",
            ),
            approved_public_input(
                directory,
                "runtime-tool",
                PublicBuildInputRole::ExecutablePathInput,
                "tools/runtime/synthetic-runner",
                LogicalBuildInputMode::Executable,
                b"synthetic runtime executable",
            ),
            approved_public_input(
                directory,
                "rustc",
                PublicBuildInputRole::RustcExecutable,
                "toolchain/bin/rustc",
                LogicalBuildInputMode::Executable,
                b"synthetic rustc executable",
            ),
            approved_public_input(
                directory,
                "sysroot",
                PublicBuildInputRole::RustcSysrootFile,
                "toolchain/lib/libsynthetic.rlib",
                LogicalBuildInputMode::Data,
                b"synthetic sysroot member",
            ),
            approved_public_input(
                directory,
                "archiver",
                PublicBuildInputRole::TargetArchiverExecutable,
                "tools/archiver/ar",
                LogicalBuildInputMode::Executable,
                b"synthetic archiver executable",
            ),
            approved_public_input(
                directory,
                "linker",
                PublicBuildInputRole::TargetLinkerExecutable,
                "tools/linker/ld",
                LogicalBuildInputMode::Executable,
                b"synthetic linker executable",
            ),
            approved_public_input(
                directory,
                "runtime-library",
                PublicBuildInputRole::ToolDynamicDependency,
                "tools/runtime/libsynthetic.so",
                LogicalBuildInputMode::Data,
                b"synthetic runtime library",
            ),
        ];
        inputs.reverse();
        inputs
    }

    #[test]
    #[cfg(unix)]
    fn explicit_allowlist_is_canonical_and_ignores_unlisted_files() {
        let (temporary, store) = store();
        let inputs_root = tempfile::tempdir().unwrap();
        fs::write(
            inputs_root.path().join("unlisted-credential-token"),
            b"synthetic unlisted secret sentinel",
        )
        .unwrap();
        let inputs = complete_public_inputs(inputs_root.path());

        let captured =
            capture_fixed_build_inventory(&store, CAMPAIGN_ID, TARGET_TRIPLE, false, inputs)
                .unwrap();
        let inventory_bytes =
            fs::read(temporary.path().join("campaign/build/input-inventory.json")).unwrap();
        let archive_bytes =
            fs::read(temporary.path().join("campaign/build/input-files.bia")).unwrap();
        let inventory: BuildInputInventory = serde_json::from_slice(&inventory_bytes).unwrap();
        assert!(valid_build_input_inventory(
            &inventory,
            false,
            TARGET_TRIPLE,
            CAMPAIGN_ID,
        ));
        assert_eq!(
            inventory
                .entries
                .iter()
                .map(|entry| entry.role.as_str())
                .collect::<Vec<_>>(),
            [
                "cargo_configuration",
                "cargo_dependency_source",
                "cargo_executable",
                "executable_path_input",
                "rustc_executable",
                "rustc_sysroot_file",
                "target_archiver_executable",
                "target_linker_executable",
                "tool_dynamic_dependency",
            ]
        );
        assert_eq!(canonical_pretty_bytes(&inventory).unwrap(), inventory_bytes);
        assert_eq!(
            captured.inventory_fingerprint(),
            &fingerprint(&inventory_bytes).unwrap()
        );
        assert_eq!(
            captured.archive_fingerprint(),
            &fingerprint(&archive_bytes).unwrap()
        );
        assert!(validate_build_input_archive_stream(
            &mut io::Cursor::new(&archive_bytes),
            &inventory,
        )
        .is_ok());
        assert!(!archive_bytes
            .windows(b"synthetic unlisted secret sentinel".len())
            .any(|window| window == b"synthetic unlisted secret sentinel"));
    }

    #[test]
    #[cfg(unix)]
    fn paths_aliases_duplicates_modes_and_live_cargo_config_fail_before_persistence() {
        enum Fault {
            Parent,
            Duplicate,
            CaseAlias,
            Mode,
            LiveCargoConfig,
        }

        for fault in [
            Fault::Parent,
            Fault::Duplicate,
            Fault::CaseAlias,
            Fault::Mode,
            Fault::LiveCargoConfig,
        ] {
            let (temporary, store) = store();
            let inputs_root = tempfile::tempdir().unwrap();
            let mut inputs = complete_public_inputs(inputs_root.path());
            match fault {
                Fault::Parent => inputs[0].relative_path = "../escape".to_owned(),
                Fault::Duplicate => inputs[0].relative_path = inputs[1].relative_path.clone(),
                Fault::CaseAlias => {
                    let alias = approved_public_input(
                        inputs_root.path(),
                        "case-alias",
                        PublicBuildInputRole::RustcSysrootFile,
                        "TOOLCHAIN/lib/libsynthetic.rlib",
                        LogicalBuildInputMode::Data,
                        b"synthetic alias",
                    );
                    inputs.push(alias);
                }
                Fault::Mode => {
                    inputs
                        .iter_mut()
                        .find(|input| input.role.wire_name() == "cargo_executable")
                        .unwrap()
                        .mode = LogicalBuildInputMode::Data;
                }
                Fault::LiveCargoConfig => {
                    let configuration = inputs
                        .iter_mut()
                        .find(|input| input.role.wire_name() == "cargo_configuration")
                        .unwrap();
                    configuration.relative_path = "cargo-home/credentials.toml".to_owned();
                }
            }
            let result =
                capture_fixed_build_inventory(&store, CAMPAIGN_ID, TARGET_TRIPLE, false, inputs);
            assert!(result.is_err());
            assert!(!temporary
                .path()
                .join("campaign/build/input-inventory.json")
                .exists());
            assert!(!temporary
                .path()
                .join("campaign/build/input-files.bia")
                .exists());
        }
    }

    #[test]
    #[cfg(unix)]
    fn snapshot_fingerprint_and_partial_faults_issue_no_combined_capability() {
        use std::os::unix::fs::PermissionsExt as _;

        let (temporary, store) = store();
        let inputs_root = tempfile::tempdir().unwrap();
        let inputs = complete_public_inputs(inputs_root.path());
        let prepared =
            prepare_fixed_build_inputs(CAMPAIGN_ID, TARGET_TRIPLE, false, inputs).unwrap();
        let mut permissions = prepared.members[0]
            .input
            .file
            .metadata()
            .unwrap()
            .permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        prepared.members[0]
            .input
            .file
            .set_permissions(permissions)
            .unwrap();
        assert!(persist_fixed_build_inputs(&store, prepared).is_err());
        assert!(!temporary
            .path()
            .join("campaign/build/input-inventory.json")
            .exists());

        let (temporary, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let inputs = complete_public_inputs(inputs_root.path());
        let mut prepared =
            prepare_fixed_build_inputs(CAMPAIGN_ID, TARGET_TRIPLE, false, inputs).unwrap();
        prepared.members[0].expected_fingerprint.sha256 = "F".repeat(64);
        assert!(persist_fixed_build_inputs(&store, prepared).is_err());
        assert!(temporary
            .path()
            .join("campaign/build/input-inventory.json")
            .exists());
        assert!(temporary
            .path()
            .join("campaign/build/input-files.bia")
            .exists());

        let (temporary, store) = self::store();
        store
            .write_build_input_archive(1, |writer| {
                writer.write_all(b"x")?;
                Ok(())
            })
            .unwrap();
        let inputs_root = tempfile::tempdir().unwrap();
        let result = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        );
        assert!(result.is_err());
        assert!(temporary
            .path()
            .join("campaign/build/input-inventory.json")
            .exists());
    }

    #[test]
    #[cfg(unix)]
    fn joint_capability_materializes_only_canonical_members_create_new() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_campaign, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let captured = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        )
        .unwrap();
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("inputs");
        let materialized = materialize_fixed_build_inputs(captured, &destination).unwrap();

        assert_eq!(materialized.member_count(), 9);
        assert!(materialized.aggregate_fingerprint().byte_length > 0);
        assert_eq!(
            fs::read(destination.join("cargo-home/config.toml")).unwrap(),
            b"[net]\noffline = true\n"
        );
        assert_eq!(
            fs::read(destination.join("toolchain/bin/rustc")).unwrap(),
            b"synthetic rustc executable"
        );
        let data_mode = fs::metadata(destination.join("cargo-home/config.toml"))
            .unwrap()
            .permissions()
            .mode();
        let executable_mode = fs::metadata(destination.join("toolchain/bin/rustc"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(data_mode & 0o777, 0o444);
        assert_eq!(executable_mode & 0o777, 0o555);
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 3);
        fs::set_permissions(
            destination.join("cargo-home/config.toml"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        assert!(materialized.ensure_unchanged().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn bulk_builder_retains_no_member_handles_and_scans_only_at_seal() {
        const MEMBER_COUNT: usize = 256;

        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let expected = fingerprint(b"").unwrap();
        let mut builder = MaterializedInputStoreBuilder::create_new(
            &destination,
            u32::try_from(MEMBER_COUNT).unwrap(),
            1,
        )
        .unwrap();

        for ordinal in 0..MEMBER_COUNT {
            let relative = format!("fanout/member-{ordinal:04}");
            let receipt = builder
                .write_member(&relative, false, &expected, |_writer| Ok(()))
                .unwrap();
            assert_eq!(receipt.fingerprint(), &expected);
            assert_eq!(builder.full_tree_scan_count_for_test(), 0);
            assert_eq!(builder.retained_member_handle_count_for_test(), 0);
        }

        let store = builder.seal().unwrap();
        assert_eq!(store.member_count_for_test(), MEMBER_COUNT);
        assert_eq!(store.retained_member_handle_count_for_test(), 0);
        assert_eq!(store.full_tree_scan_count_for_test(), 1);
        store.verify_root().unwrap();
        assert_eq!(store.full_tree_scan_count_for_test(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn failed_member_poisons_partial_tree_and_destination_reuse() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let stable = fingerprint(b"stable").unwrap();
        let expected = fingerprint(b"partial").unwrap();
        let mut builder = MaterializedInputStoreBuilder::create_new(&destination, 2, 16).unwrap();
        builder
            .write_member("stable", false, &stable, |writer| {
                writer.write_all(b"stable")?;
                Ok(())
            })
            .unwrap();

        let Err(error) = builder.write_member("partial", false, &expected, |writer| {
            writer.write_all(b"par")?;
            anyhow::bail!("synthetic writer failure")
        }) else {
            panic!("failed writer issued a member receipt")
        };
        assert_eq!(error.to_string(), "materialization rejected");
        assert_eq!(fs::read(destination.join("stable")).unwrap(), b"stable");
        assert_eq!(fs::read(destination.join("partial")).unwrap(), b"par");
        assert!(builder.is_poisoned_for_test());
        assert!(builder
            .write_member("later", false, &fingerprint(b"later").unwrap(), |writer| {
                writer.write_all(b"later")?;
                Ok(())
            })
            .is_err());
        assert!(builder.seal().is_err());
        assert!(MaterializedInputStoreBuilder::create_new(&destination, 2, 16).is_err());
        assert!(!destination.join("later").exists());
    }

    #[test]
    #[cfg(unix)]
    fn panicking_member_leaves_the_builder_poisoned_before_partial_mutation() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let expected = fingerprint(b"partial").unwrap();
        let mut builder = MaterializedInputStoreBuilder::create_new(&destination, 2, 16).unwrap();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = builder.write_member("partial", false, &expected, |writer| {
                writer.write_all(b"par")?;
                panic!("synthetic writer panic")
            });
        }));

        assert!(panic.is_err());
        assert_eq!(fs::read(destination.join("partial")).unwrap(), b"par");
        assert!(builder.is_poisoned_for_test());
        assert!(builder
            .write_member("later", false, &fingerprint(b"later").unwrap(), |writer| {
                writer.write_all(b"later")?;
                Ok(())
            })
            .is_err());
        assert!(!destination.join("later").exists());
        assert!(builder.seal().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn builder_limits_reject_before_creation_or_member_mutation() {
        let parent = tempfile::tempdir().unwrap();
        for (name, maximum_members, maximum_member_bytes) in [
            ("zero-members", 0, 1),
            ("too-many-members", MAX_FIXED_BUILD_INPUT_ENTRIES + 1, 1),
            ("oversized-member-limit", 1, MAX_FIXED_BUILD_INPUT_BYTES + 1),
        ] {
            let destination = parent.path().join(name);
            assert!(MaterializedInputStoreBuilder::create_new(
                &destination,
                maximum_members,
                maximum_member_bytes,
            )
            .is_err());
            assert!(!destination.exists(), "{name}");
        }

        let destination = parent.path().join("one-member");
        let expected = fingerprint(b"first").unwrap();
        let mut builder = MaterializedInputStoreBuilder::create_new(&destination, 1, 16).unwrap();
        builder
            .write_member("first", false, &expected, |writer| {
                writer.write_all(b"first")?;
                Ok(())
            })
            .unwrap();
        assert!(builder
            .write_member(
                "second",
                false,
                &fingerprint(b"second").unwrap(),
                |writer| {
                    writer.write_all(b"second")?;
                    Ok(())
                }
            )
            .is_err());
        assert_eq!(fs::read(destination.join("first")).unwrap(), b"first");
        assert!(!destination.join("second").exists());
        assert!(builder.is_poisoned_for_test());
        assert!(builder.seal().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn bulk_seal_rejects_untracked_entries_and_prior_member_drift() {
        use std::os::unix::fs::PermissionsExt as _;

        for drift in ["extra", "member"] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("inputs");
            let expected = fingerprint(b"original").unwrap();
            let mut builder =
                MaterializedInputStoreBuilder::create_new(&destination, 1, 16).unwrap();
            builder
                .write_member("tracked", false, &expected, |writer| {
                    writer.write_all(b"original")?;
                    Ok(())
                })
                .unwrap();

            match drift {
                "extra" => fs::write(destination.join("untracked"), b"poison").unwrap(),
                "member" => {
                    let member = destination.join("tracked");
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o644)).unwrap();
                    fs::write(&member, b"changed!").unwrap();
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o444)).unwrap();
                }
                _ => unreachable!(),
            }

            assert!(builder.seal().is_err(), "{drift}");
            assert!(destination.exists(), "{drift}");
            assert!(MaterializedInputStoreBuilder::create_new(&destination, 1, 16).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn materialization_rejects_archive_drift_without_a_capability() {
        use std::os::unix::fs::PermissionsExt as _;

        let (campaign, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let captured = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        )
        .unwrap();
        let archive = campaign.path().join("campaign/build/input-files.bia");
        let mut permissions = fs::metadata(&archive).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&archive, permissions).unwrap();
        fs::write(&archive, b"mutated archive").unwrap();
        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("inputs");

        assert!(materialize_fixed_build_inputs(captured, &destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    #[cfg(unix)]
    fn materialization_rejects_symlink_and_existing_destination_entries() {
        use std::os::unix::fs::symlink;

        for symlink_fault in [false, true] {
            let (_campaign, store) = self::store();
            let inputs_root = tempfile::tempdir().unwrap();
            let captured = capture_fixed_build_inventory(
                &store,
                CAMPAIGN_ID,
                TARGET_TRIPLE,
                false,
                complete_public_inputs(inputs_root.path()),
            )
            .unwrap();
            let destination_parent = tempfile::tempdir().unwrap();
            let destination = destination_parent.path().join("inputs");
            fs::create_dir(&destination).unwrap();
            if symlink_fault {
                let outside = tempfile::tempdir().unwrap();
                symlink(outside.path(), destination.join("toolchain")).unwrap();
            } else {
                fs::create_dir(destination.join("toolchain")).unwrap();
            }

            assert!(materialize_fixed_build_inputs(captured, &destination).is_err());
        }

        let destination_parent = tempfile::tempdir().unwrap();
        let destination = destination_parent.path().join("inputs");
        let mut destination_store =
            MaterializedInputStoreBuilder::create_new(&destination, 1, 64).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), destination.join("toolchain")).unwrap();
        let expected = fingerprint(b"synthetic member").unwrap();
        assert!(destination_store
            .write_member("toolchain/bin/tool", true, &expected, |writer| {
                writer.write_all(b"synthetic member")?;
                Ok(())
            })
            .is_err());
        assert!(!outside.path().join("bin/tool").exists());

        let corruption_parent = tempfile::tempdir().unwrap();
        let corruption_root = corruption_parent.path().join("inputs");
        let mut corruption_store =
            MaterializedInputStoreBuilder::create_new(&corruption_root, 1, 64).unwrap();
        let expected = fingerprint(b"original").unwrap();
        assert!(corruption_store
            .write_member("member", false, &expected, |writer| {
                writer.write_all(b"original")?;
                fs::write(corruption_root.join("member"), b"corrupt!")?;
                Ok(())
            })
            .is_err());
    }

    #[test]
    #[cfg(unix)]
    fn materialized_capability_rejects_recursive_tree_and_path_drift() {
        use std::os::unix::fs::PermissionsExt as _;

        enum Fault {
            SameLengthCorruption,
            RootReplacement,
            MemberReplacement,
            InjectedExtra,
            SpecialMode,
            RestoredDirectoryMode,
            ManyUnexpectedEntries,
            DirectoryFileReplacement,
        }
        for fault in [
            Fault::SameLengthCorruption,
            Fault::RootReplacement,
            Fault::MemberReplacement,
            Fault::InjectedExtra,
            Fault::SpecialMode,
            Fault::RestoredDirectoryMode,
            Fault::ManyUnexpectedEntries,
            Fault::DirectoryFileReplacement,
        ] {
            let (_campaign, store) = self::store();
            let inputs_root = tempfile::tempdir().unwrap();
            let captured = capture_fixed_build_inventory(
                &store,
                CAMPAIGN_ID,
                TARGET_TRIPLE,
                false,
                complete_public_inputs(inputs_root.path()),
            )
            .unwrap();
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("inputs");
            let materialized = materialize_fixed_build_inputs(captured, &destination).unwrap();
            let member = destination.join("cargo-home/config.toml");
            match fault {
                Fault::SameLengthCorruption => {
                    let mut bytes = fs::read(&member).unwrap();
                    bytes[0] ^= 1;
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o644)).unwrap();
                    fs::write(&member, bytes).unwrap();
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o444)).unwrap();
                }
                Fault::RootReplacement => {
                    fs::rename(&destination, parent.path().join("renamed-inputs")).unwrap();
                    fs::create_dir(&destination).unwrap();
                }
                Fault::MemberReplacement => {
                    fs::set_permissions(
                        destination.join("cargo-home"),
                        fs::Permissions::from_mode(0o755),
                    )
                    .unwrap();
                    fs::rename(&member, destination.join("cargo-home/original")).unwrap();
                    fs::write(&member, b"[net]\noffline = true\n").unwrap();
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o444)).unwrap();
                }
                Fault::InjectedExtra => {
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
                    fs::write(destination.join("extra"), b"synthetic extra").unwrap();
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o555)).unwrap();
                }
                Fault::SpecialMode => {
                    fs::set_permissions(&member, fs::Permissions::from_mode(0o2444)).unwrap();
                }
                Fault::RestoredDirectoryMode => {
                    let directory = destination.join("cargo-home");
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
                }
                Fault::ManyUnexpectedEntries => {
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
                    for index in 0..256 {
                        fs::write(destination.join(format!("unexpected-{index:03}")), b"x")
                            .unwrap();
                    }
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o555)).unwrap();
                    assert!(materialized.store.verify_exact_tree_for_test().is_err());
                }
                Fault::DirectoryFileReplacement => {
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
                    for relative in [
                        "cargo-home",
                        "cargo-home/registry",
                        "cargo-home/registry/src",
                        "cargo-home/registry/src/synthetic",
                    ] {
                        fs::set_permissions(
                            destination.join(relative),
                            fs::Permissions::from_mode(0o755),
                        )
                        .unwrap();
                    }
                    fs::remove_dir_all(destination.join("cargo-home")).unwrap();
                    fs::write(destination.join("cargo-home"), b"not a directory").unwrap();
                    assert!(materialized.store.verify_exact_tree_for_test().is_err());
                }
            }
            assert!(materialized.ensure_unchanged().is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fifo_member_substitution_rejects_without_blocking() {
        use rustix::fs::{mkfifoat, Mode};
        use std::os::unix::fs::PermissionsExt as _;

        let (_campaign, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let captured = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        )
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let materialized = materialize_fixed_build_inputs(captured, &destination).unwrap();
        let directory = destination.join("cargo-home");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(
            directory.join("config.toml"),
            parent.path().join("original-config"),
        )
        .unwrap();
        let handle = fs::File::open(&directory).unwrap();
        mkfifoat(&handle, "config.toml", Mode::from_raw_mode(0o444)).unwrap();
        assert!(materialized.store.verify_exact_tree_for_test().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn post_scan_path_replacement_is_caught_by_the_snapshot_sandwich() {
        let (_campaign, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let captured = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        )
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let materialized = materialize_fixed_build_inputs(captured, &destination).unwrap();
        assert!(materialized
            .store
            .verify_root_with_post_scan_hook(|| {
                fs::rename(&destination, parent.path().join("replaced-after-scan")).unwrap();
                fs::create_dir(&destination).unwrap();
            })
            .is_err());
    }

    #[test]
    #[cfg(unix)]
    fn post_scan_same_length_member_rewrite_is_caught_by_member_snapshot_sandwich() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_campaign, store) = self::store();
        let inputs_root = tempfile::tempdir().unwrap();
        let captured = capture_fixed_build_inventory(
            &store,
            CAMPAIGN_ID,
            TARGET_TRIPLE,
            false,
            complete_public_inputs(inputs_root.path()),
        )
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let materialized = materialize_fixed_build_inputs(captured, &destination).unwrap();
        let member = destination.join("cargo-home/config.toml");
        assert!(materialized
            .store
            .verify_root_with_post_scan_hook(|| {
                let mut bytes = fs::read(&member).unwrap();
                bytes[0] ^= 1;
                fs::set_permissions(&member, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&member, bytes).unwrap();
                fs::set_permissions(&member, fs::Permissions::from_mode(0o444)).unwrap();
            })
            .is_err());
    }

    #[test]
    #[cfg(windows)]
    fn materialized_builder_fails_before_creation_without_directory_durability() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("inputs");
        let Err(error) = MaterializedInputStoreBuilder::create_new(&destination, 1, 16) else {
            panic!("unsupported Windows directory durability issued a builder")
        };
        assert_eq!(error.to_string(), "materialization rejected");
        assert!(!destination.exists());
    }
}
