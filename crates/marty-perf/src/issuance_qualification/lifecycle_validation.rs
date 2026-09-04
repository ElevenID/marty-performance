//! Bounded, read-only replay of the retained validity-segment lifecycle.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;

use anyhow::{Context, Result};
use marty_perf_schema::{ArtifactFingerprint, SdJwtIssuanceQualificationPlan};

use super::first_quiet_window::{
    utc_nanos, validate_host_identity_bytes, validate_initial_test_window_bytes,
    validate_process_set_bytes, validate_test_window_bytes, validate_threshold_policy_bytes,
    HostObservation, ValidatedProcessSet, ValidatedTestWindow, ValidatedThresholdPolicy,
};
use super::schedule::{ProcessCoordinate, QualificationSchedule, TOTAL_PROCESS_COUNT};
use super::{
    fingerprint, inspect_campaign_segment_with_observer, monotonic_duration_within_seconds,
    parse_canonical_compact_line, read_campaign_input, valid_artifact_fingerprint,
    valid_uppercase_hex, AnalysisReadBudget, CampaignDirectory, CompletionAnchorWire,
    CompletionWire, ContinuationHeaderWire, GenesisHeaderWire, HardwareProfileWire,
    ProcessFinishRecordWire, ProcessIntentRecordWire, ProcessStartRecordWire, SegmentFooterWire,
    SegmentInspection, SegmentRecordEnvelope, TerminalObservationReceiptWire, ValiditySampleWire,
    MAX_SOURCE_ARCHIVE_V1_BYTES,
};

const MAXIMUM_TOTAL_RECORDS: u64 = 1_000_000;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Facts established by a complete embedded-lifecycle replay.
pub(super) struct ValidatedLifecycle {
    pub(super) host_identity_fingerprint: ArtifactFingerprint,
    pub(super) validity_thresholds_fingerprint: ArtifactFingerprint,
    pub(super) baseline_unrelated_process_set_fingerprint: ArtifactFingerprint,
    pub(super) ordered_segment_fingerprints: Vec<ArtifactFingerprint>,
    pub(super) ordered_test_window_attestation_fingerprints: Vec<ArtifactFingerprint>,
    pub(super) segment_count: u32,
    pub(super) segment_bytes: u64,
    pub(super) record_count: u64,
    pub(super) sample_count: u64,
    pub(super) lifecycle_event_count: u64,
    pub(super) process_intent_count: u32,
    pub(super) process_start_count: u32,
    pub(super) process_finish_count: u32,
    pub(super) attestation_transition_count: u32,
    pub(super) first_monotonic_nanoseconds: u64,
    pub(super) last_monotonic_nanoseconds: u64,
}

fn expected_profile_entries() -> BTreeSet<OsString> {
    [
        "baseline-unrelated-process-set.json",
        "hardware.json",
        "host-identity.json",
        "validity-thresholds.json",
    ]
    .map(OsString::from)
    .into_iter()
    .collect()
}

fn expected_attestation_entries(count: usize) -> Result<BTreeSet<OsString>> {
    let mut entries = BTreeSet::from([OsString::from("first-quiet-window.json")]);
    for ordinal in 0..count {
        anyhow::ensure!(ordinal < 16, "analysis rejected: attestation inventory");
        entries.insert(OsString::from(format!("timing-window-{ordinal:04}.json")));
    }
    Ok(entries)
}

fn expected_segment_entries(count: u32) -> BTreeSet<OsString> {
    (0..count)
        .map(|ordinal| OsString::from(format!("segment-{ordinal:04}.ndjson")))
        .collect()
}

fn load_test_windows(
    campaign: &CampaignDirectory,
    budget: &mut AnalysisReadBudget,
    completion: &CompletionWire,
) -> Result<Vec<ValidatedTestWindow>> {
    let expected = expected_attestation_entries(
        completion
            .ordered_test_window_attestation_fingerprints
            .len(),
    )?;
    campaign.validate_exact_directory_entries(
        Path::new("attestations"),
        &expected,
        "attestation inventory",
    )?;
    let mut windows: Vec<ValidatedTestWindow> = Vec::with_capacity(
        completion
            .ordered_test_window_attestation_fingerprints
            .len(),
    );
    for (ordinal, expected_fingerprint) in completion
        .ordered_test_window_attestation_fingerprints
        .iter()
        .enumerate()
    {
        let relative = format!("attestations/timing-window-{ordinal:04}.json");
        let bytes = read_campaign_input(
            budget,
            campaign,
            Path::new(&relative),
            MAX_SOURCE_ARCHIVE_V1_BYTES,
            "timing attestation",
        )?;
        let window = if let Some(first) = windows.first() {
            validate_test_window_bytes(
                &bytes,
                expected_fingerprint,
                &completion.campaign_id,
                first.target_role(),
                first.target_identity_pseudonym(),
                first.change_reference_pseudonym(),
            )
        } else {
            validate_initial_test_window_bytes(
                &bytes,
                expected_fingerprint,
                &completion.campaign_id,
            )
        }
        .map_err(|_| anyhow::anyhow!("analysis rejected: timing attestation"))?;
        if let Some(previous) = windows.last() {
            anyhow::ensure!(
                window.starts_at_utc_nanoseconds() <= previous.expires_at_utc_nanoseconds(),
                "analysis rejected: timing attestation chain"
            );
        }
        windows.push(window);
    }
    campaign.validate_exact_directory_entries(
        Path::new("attestations"),
        &expected,
        "attestation inventory",
    )?;
    Ok(windows)
}

struct GlobalPreimages {
    host_identity_fingerprint: ArtifactFingerprint,
    host_identity_pseudonym: String,
    thresholds: ValidatedThresholdPolicy,
    process_set: ValidatedProcessSet,
}

fn load_global_preimages(
    campaign: &CampaignDirectory,
    budget: &mut AnalysisReadBudget,
    genesis: &GenesisHeaderWire,
    hardware: &HardwareProfileWire,
) -> Result<GlobalPreimages> {
    let profiles = expected_profile_entries();
    campaign.validate_exact_directory_entries(
        Path::new("profiles"),
        &profiles,
        "profile inventory",
    )?;

    let host_bytes = read_campaign_input(
        budget,
        campaign,
        Path::new("profiles/host-identity.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "host identity",
    )?;
    let host = validate_host_identity_bytes(
        &host_bytes,
        &genesis.host_identity_fingerprint,
        &genesis.campaign_id,
        &genesis.boot_identity_pseudonym,
    )
    .map_err(|_| anyhow::anyhow!("analysis rejected: host identity"))?;

    let threshold_bytes = read_campaign_input(
        budget,
        campaign,
        Path::new("profiles/validity-thresholds.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "validity thresholds",
    )?;
    let thresholds = validate_threshold_policy_bytes(
        &threshold_bytes,
        &genesis.validity_thresholds_fingerprint,
        &genesis.campaign_id,
        hardware.total_memory_bytes,
    )
    .map_err(|_| anyhow::anyhow!("analysis rejected: validity thresholds"))?;

    let baseline_bytes = read_campaign_input(
        budget,
        campaign,
        Path::new("profiles/baseline-unrelated-process-set.json"),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "baseline unrelated process set",
    )?;
    let baseline = validate_process_set_bytes(
        &baseline_bytes,
        &genesis.baseline_unrelated_process_set_fingerprint,
        &genesis.campaign_id,
        host.boot_identity_pseudonym(),
        &thresholds,
    )
    .map_err(|_| anyhow::anyhow!("analysis rejected: baseline unrelated process set"))?;

    let content_name = format!(
        "{}.json",
        genesis.baseline_unrelated_process_set_fingerprint.sha256
    );
    let observed_entries = BTreeSet::from([OsString::from(&content_name)]);
    campaign.validate_exact_directory_entries(
        Path::new("observations/unrelated-process-sets"),
        &observed_entries,
        "unrelated process set inventory",
    )?;
    let content_relative = format!("observations/unrelated-process-sets/{content_name}");
    let content_bytes = read_campaign_input(
        budget,
        campaign,
        Path::new(&content_relative),
        MAX_SOURCE_ARCHIVE_V1_BYTES,
        "content-addressed unrelated process set",
    )?;
    anyhow::ensure!(
        content_bytes == baseline_bytes,
        "analysis rejected: exact baseline process set"
    );
    let content = validate_process_set_bytes(
        &content_bytes,
        &genesis.baseline_unrelated_process_set_fingerprint,
        &genesis.campaign_id,
        host.boot_identity_pseudonym(),
        &thresholds,
    )
    .map_err(|_| anyhow::anyhow!("analysis rejected: content-addressed unrelated process set"))?;
    anyhow::ensure!(
        content.fingerprint() == baseline.fingerprint()
            && content.process_identity_pseudonyms() == baseline.process_identity_pseudonyms(),
        "analysis rejected: exact baseline process set"
    );

    campaign.validate_exact_directory_entries(
        Path::new("observations/unrelated-process-sets"),
        &observed_entries,
        "unrelated process set inventory",
    )?;
    campaign.validate_exact_directory_entries(
        Path::new("profiles"),
        &profiles,
        "profile inventory",
    )?;
    Ok(GlobalPreimages {
        host_identity_fingerprint: host.fingerprint().clone(),
        host_identity_pseudonym: host.host_identity_pseudonym().to_owned(),
        thresholds,
        process_set: content,
    })
}

#[derive(Clone)]
struct IntentState {
    record: ProcessIntentRecordWire,
    fingerprint: ArtifactFingerprint,
}

#[derive(Clone)]
struct StartedState {
    intent: IntentState,
    record: ProcessStartRecordWire,
}

enum ProcessState {
    Idle,
    Intent(Box<IntentState>),
    Started(Box<StartedState>),
}

struct LifecycleReplay<'a> {
    schedule: &'a QualificationSchedule<'a>,
    completion: &'a CompletionWire,
    genesis: &'a GenesisHeaderWire,
    thresholds: &'a ValidatedThresholdPolicy,
    windows: &'a [ValidatedTestWindow],
    genesis_utc_nanoseconds: i128,
    active_window: usize,
    state: ProcessState,
    process_position: usize,
    expected_event_ordinal: u64,
    expected_sample_ordinal: u64,
    first_sample_monotonic_nanoseconds: Option<u64>,
    last_sample_monotonic_nanoseconds: Option<u64>,
    first_intent_monotonic_nanoseconds: Option<u64>,
    last_finish_monotonic_nanoseconds: Option<u64>,
    post_final_finish_sample_seen: bool,
    previous_segment_fingerprint: Option<ArtifactFingerprint>,
    previous_footer_monotonic_nanoseconds: Option<u64>,
    known_aliases: BTreeSet<String>,
    process_set_forbidden_aliases: BTreeSet<String>,
}

impl<'a> LifecycleReplay<'a> {
    #[allow(
        clippy::too_many_arguments,
        reason = "all values are independently authenticated campaign bindings"
    )]
    fn new(
        schedule: &'a QualificationSchedule<'a>,
        completion: &'a CompletionWire,
        genesis: &'a GenesisHeaderWire,
        thresholds: &'a ValidatedThresholdPolicy,
        windows: &'a [ValidatedTestWindow],
        host_identity_pseudonym: &str,
        terminal_challenge: &str,
        completion_challenge: &str,
    ) -> Result<Self> {
        let genesis_utc_nanoseconds = utc_nanos(&genesis.utc_rfc3339_nanoseconds)
            .map_err(|_| anyhow::anyhow!("analysis rejected: lifecycle clock"))?;
        let first_window = windows
            .first()
            .context("analysis rejected: timing attestation chain")?;
        anyhow::ensure!(
            first_window.fingerprint() == &genesis.initial_test_window_attestation_fingerprint,
            "analysis rejected: timing attestation chain"
        );
        let base_aliases = [
            host_identity_pseudonym,
            genesis.boot_identity_pseudonym.as_str(),
            first_window.target_identity_pseudonym(),
            first_window.change_reference_pseudonym(),
            terminal_challenge,
            completion_challenge,
        ];
        anyhow::ensure!(
            base_aliases
                .iter()
                .all(|value| valid_uppercase_hex(value, 64)),
            "analysis rejected: lifecycle alias uniqueness"
        );
        let globally_disjoint = [
            first_window.change_reference_pseudonym(),
            terminal_challenge,
            completion_challenge,
        ];
        for value in globally_disjoint {
            anyhow::ensure!(
                base_aliases.iter().filter(|other| **other == value).count() == 1,
                "analysis rejected: lifecycle alias uniqueness"
            );
        }
        let known_aliases = base_aliases
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let process_set_forbidden_aliases = globally_disjoint
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        Ok(Self {
            schedule,
            completion,
            genesis,
            thresholds,
            windows,
            genesis_utc_nanoseconds,
            active_window: 0,
            state: ProcessState::Idle,
            process_position: 0,
            expected_event_ordinal: 0,
            expected_sample_ordinal: 0,
            first_sample_monotonic_nanoseconds: None,
            last_sample_monotonic_nanoseconds: None,
            first_intent_monotonic_nanoseconds: None,
            last_finish_monotonic_nanoseconds: None,
            post_final_finish_sample_seen: false,
            previous_segment_fingerprint: None,
            previous_footer_monotonic_nanoseconds: None,
            known_aliases,
            process_set_forbidden_aliases,
        })
    }

    fn active_window(&self) -> Result<&ValidatedTestWindow> {
        self.windows
            .get(self.active_window)
            .context("analysis rejected: active timing attestation")
    }

    fn validate_clock(&self, utc: &str, monotonic: u64) -> Result<i128> {
        let actual_utc =
            utc_nanos(utc).map_err(|_| anyhow::anyhow!("analysis rejected: lifecycle clock"))?;
        let monotonic_delta = monotonic
            .checked_sub(self.genesis.monotonic_nanoseconds)
            .context("analysis rejected: lifecycle clock")?;
        let expected_utc = self
            .genesis_utc_nanoseconds
            .checked_add(i128::from(monotonic_delta))
            .context("analysis rejected: lifecycle clock")?;
        anyhow::ensure!(
            actual_utc == expected_utc,
            "analysis rejected: lifecycle clock"
        );
        Ok(actual_utc)
    }

    fn validate_clock_and_coverage(&self, utc: &str, monotonic: u64) -> Result<()> {
        let actual_utc = self.validate_clock(utc, monotonic)?;
        let window = self.active_window()?;
        anyhow::ensure!(
            window.starts_at_utc_nanoseconds() <= actual_utc
                && actual_utc < window.expires_at_utc_nanoseconds(),
            "analysis rejected: lifecycle attestation coverage"
        );
        Ok(())
    }

    fn validate_event_ordinal(&mut self, actual: u64) -> Result<()> {
        anyhow::ensure!(
            actual == self.expected_event_ordinal,
            "analysis rejected: lifecycle event ordinal"
        );
        self.expected_event_ordinal = self
            .expected_event_ordinal
            .checked_add(1)
            .context("analysis rejected: lifecycle event ordinal")?;
        Ok(())
    }

    fn expected_process(
        &self,
    ) -> Result<(
        &super::schedule::ScheduledProcess<'a>,
        &super::ProcessCompletionWire,
    )> {
        Ok((
            self.schedule
                .at(self.process_position)
                .context("analysis rejected: lifecycle process cardinality")?,
            self.completion
                .process_completions
                .get(self.process_position)
                .context("analysis rejected: lifecycle process cardinality")?,
        ))
    }

    fn process_coordinate_matches(
        coordinate: ProcessCoordinate,
        global_round: u32,
        cell: u32,
        expansion: u32,
    ) -> bool {
        coordinate.global_round == global_round
            && coordinate.cell == cell
            && coordinate.expansion == expansion
    }

    fn observe_line(&mut self, bytes: &[u8]) -> Result<()> {
        let body = bytes
            .strip_suffix(b"\n")
            .context("analysis rejected: lifecycle record")?;
        let envelope: SegmentRecordEnvelope = serde_json::from_slice(body)
            .map_err(|_| anyhow::anyhow!("analysis rejected: lifecycle record"))?;
        self.validate_clock_and_coverage(
            &envelope.utc_rfc3339_nanoseconds,
            envelope.monotonic_nanoseconds,
        )?;
        match envelope.schema.as_str() {
            "marty.performance/sd-jwt-issuance-validity-genesis/v1" => {
                anyhow::ensure!(
                    envelope.segment_ordinal == 0
                        && envelope.record_ordinal == 0
                        && fingerprint(bytes)? == self.completion.genesis_header_fingerprint,
                    "analysis rejected: lifecycle genesis"
                );
            }
            "marty.performance/sd-jwt-issuance-validity-continuation/v1" => {
                let record: ContinuationHeaderWire =
                    parse_canonical_compact_line(bytes, "lifecycle continuation")?;
                let previous_fingerprint = self
                    .previous_segment_fingerprint
                    .as_ref()
                    .context("analysis rejected: lifecycle continuation")?;
                let previous_monotonic = self
                    .previous_footer_monotonic_nanoseconds
                    .context("analysis rejected: lifecycle continuation")?;
                let gap = record
                    .monotonic_nanoseconds
                    .checked_sub(previous_monotonic)
                    .context("analysis rejected: lifecycle segment gap")?;
                anyhow::ensure!(
                    record.segment_ordinal > 0
                        && record.previous_segment_fingerprint == *previous_fingerprint
                        && record.genesis_header_fingerprint
                            == self.completion.genesis_header_fingerprint
                        && record.active_test_window_attestation_fingerprint
                            == *self.active_window()?.fingerprint()
                        && record.boot_identity_pseudonym == self.genesis.boot_identity_pseudonym
                        && (1..=10 * NANOSECONDS_PER_SECOND).contains(&gap),
                    "analysis rejected: lifecycle continuation"
                );
            }
            "marty.performance/sd-jwt-issuance-validity-sample/v1" => {
                let record: ValiditySampleWire =
                    parse_canonical_compact_line(bytes, "lifecycle sample")?;
                self.observe_sample(&record)?;
            }
            "marty.performance/sd-jwt-issuance-validity-process-intent/v1" => {
                let record: ProcessIntentRecordWire =
                    parse_canonical_compact_line(bytes, "lifecycle process intent")?;
                self.observe_intent(record, fingerprint(bytes)?)?;
            }
            "marty.performance/sd-jwt-issuance-validity-process-start/v1" => {
                let record: ProcessStartRecordWire =
                    parse_canonical_compact_line(bytes, "lifecycle process start")?;
                self.observe_start(record, &fingerprint(bytes)?)?;
            }
            "marty.performance/sd-jwt-issuance-validity-process-finish/v1" => {
                let record: ProcessFinishRecordWire =
                    parse_canonical_compact_line(bytes, "lifecycle process finish")?;
                self.observe_finish(&record, &fingerprint(bytes)?)?;
            }
            "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1" => {
                let record: super::AttestationTransitionWire =
                    parse_canonical_compact_line(bytes, "lifecycle attestation transition")?;
                self.observe_transition(&record)?;
            }
            _ => anyhow::bail!("analysis rejected: lifecycle record"),
        }
        Ok(())
    }

    fn observe_sample(&mut self, record: &ValiditySampleWire) -> Result<()> {
        anyhow::ensure!(
            record.sample_ordinal == self.expected_sample_ordinal
                && record.boot_identity_pseudonym == self.genesis.boot_identity_pseudonym
                && record.unrelated_process_set_fingerprint
                    == self.genesis.baseline_unrelated_process_set_fingerprint
                && record.active_test_window_attestation_fingerprint
                    == *self.active_window()?.fingerprint(),
            "analysis rejected: lifecycle sample binding"
        );
        if let Some(previous) = self.last_sample_monotonic_nanoseconds {
            let gap = record
                .monotonic_nanoseconds
                .checked_sub(previous)
                .context("analysis rejected: lifecycle sample cadence")?;
            anyhow::ensure!(
                (1..=10 * NANOSECONDS_PER_SECOND).contains(&gap),
                "analysis rejected: lifecycle sample cadence"
            );
        }
        match (&self.state, record.timing_state.as_str()) {
            (ProcessState::Idle, "idle") => anyhow::ensure!(
                record.global_round_ordinal.0.is_none()
                    && record.cell_ordinal.0.is_none()
                    && record.expansion_position.0.is_none()
                    && record.timing_process_id.0.is_none(),
                "analysis rejected: lifecycle sample state"
            ),
            (ProcessState::Intent(intent), "launching") => {
                let value = &intent.record;
                anyhow::ensure!(
                    record.global_round_ordinal.0 == Some(value.global_round_ordinal)
                        && record.cell_ordinal.0 == Some(value.cell_ordinal)
                        && record.expansion_position.0 == Some(value.expansion_position)
                        && record.timing_process_id.0.as_deref()
                            == Some(value.timing_process_id.as_str()),
                    "analysis rejected: lifecycle sample state"
                );
            }
            (ProcessState::Started(started), "process") => {
                let value = &started.record;
                anyhow::ensure!(
                    record.global_round_ordinal.0 == Some(value.global_round_ordinal)
                        && record.cell_ordinal.0 == Some(value.cell_ordinal)
                        && record.expansion_position.0 == Some(value.expansion_position)
                        && record.timing_process_id.0.as_deref()
                            == Some(value.timing_process_id.as_str()),
                    "analysis rejected: lifecycle sample state"
                );
            }
            _ => anyhow::bail!("analysis rejected: lifecycle sample state"),
        }
        self.thresholds
            .validate_observation(&HostObservation {
                total_cpu_percent: record.total_cpu_percent,
                monitor_cpu_percent: record.monitor_cpu_percent,
                benchmark_cpu_percent: record.benchmark_cpu_percent,
                unrelated_cpu_percent: record.unrelated_cpu_percent,
                available_memory_bytes: record.available_memory_bytes,
                cpu_frequency_hz: record.cpu_frequency_hz,
                maximum_temperature_millidegrees_celsius: record
                    .maximum_temperature_millidegrees_celsius,
                throttle_flags: &record.throttle_flags,
            })
            .map_err(|_| anyhow::anyhow!("analysis rejected: lifecycle sample observation"))?;
        self.first_sample_monotonic_nanoseconds
            .get_or_insert(record.monotonic_nanoseconds);
        self.last_sample_monotonic_nanoseconds = Some(record.monotonic_nanoseconds);
        if self.process_position == usize::try_from(TOTAL_PROCESS_COUNT)?
            && matches!(self.state, ProcessState::Idle)
        {
            self.post_final_finish_sample_seen = true;
        }
        self.expected_sample_ordinal = self
            .expected_sample_ordinal
            .checked_add(1)
            .context("analysis rejected: lifecycle sample ordinal")?;
        Ok(())
    }

    fn observe_intent(
        &mut self,
        record: ProcessIntentRecordWire,
        line_fingerprint: ArtifactFingerprint,
    ) -> Result<()> {
        anyhow::ensure!(
            matches!(self.state, ProcessState::Idle),
            "analysis rejected: lifecycle process overlap"
        );
        self.validate_event_ordinal(record.event_ordinal)?;
        let (expected, completion) = self.expected_process()?;
        anyhow::ensure!(
            Self::process_coordinate_matches(
                expected.coordinate,
                record.global_round_ordinal,
                record.cell_ordinal,
                record.expansion_position,
            ) && record.timing_process_id == expected.timing_process_id
                && record.full_benchmark_id == expected.full_benchmark_id
                && line_fingerprint == completion.process_intent_record_fingerprint
                && record.invocation_descriptor_fingerprint
                    == completion.invocation_descriptor_fingerprint
                && record.criterion_home_initial_inventory_fingerprint
                    == completion.criterion_home_initial_inventory_fingerprint
                && valid_artifact_fingerprint(&record.launch_barrier_token_fingerprint)
                && valid_artifact_fingerprint(&record.invocation_descriptor_fingerprint)
                && valid_artifact_fingerprint(&record.criterion_home_initial_inventory_fingerprint),
            "analysis rejected: lifecycle process intent"
        );
        self.first_intent_monotonic_nanoseconds
            .get_or_insert(record.monotonic_nanoseconds);
        self.state = ProcessState::Intent(Box::new(IntentState {
            record,
            fingerprint: line_fingerprint,
        }));
        Ok(())
    }

    fn observe_start(
        &mut self,
        record: ProcessStartRecordWire,
        line_fingerprint: &ArtifactFingerprint,
    ) -> Result<()> {
        self.validate_event_ordinal(record.event_ordinal)?;
        let ProcessState::Intent(intent) = &self.state else {
            anyhow::bail!("analysis rejected: lifecycle process start")
        };
        let (expected, completion) = self.expected_process()?;
        let spawn_to_ready = record
            .monotonic_nanoseconds
            .checked_sub(intent.record.monotonic_nanoseconds)
            .context("analysis rejected: lifecycle process start")?;
        anyhow::ensure!(
            Self::process_coordinate_matches(
                expected.coordinate,
                record.global_round_ordinal,
                record.cell_ordinal,
                record.expansion_position,
            ) && record.timing_process_id == intent.record.timing_process_id
                && record.full_benchmark_id == intent.record.full_benchmark_id
                && record.process_intent_record_fingerprint == intent.fingerprint
                && record.invocation_descriptor_fingerprint
                    == intent.record.invocation_descriptor_fingerprint
                && record.launch_barrier_token_fingerprint
                    == intent.record.launch_barrier_token_fingerprint
                && record.active_test_window_attestation_fingerprint
                    == *self.active_window()?.fingerprint()
                && *line_fingerprint == completion.process_start_record_fingerprint
                && valid_uppercase_hex(&record.process_identity_pseudonym, 64)
                && self
                    .known_aliases
                    .insert(record.process_identity_pseudonym.clone())
                && valid_artifact_fingerprint(&record.launch_barrier_ready_frame_fingerprint)
                && spawn_to_ready <= 30 * NANOSECONDS_PER_SECOND,
            "analysis rejected: lifecycle process start"
        );
        self.state = ProcessState::Started(Box::new(StartedState {
            intent: (**intent).clone(),
            record,
        }));
        Ok(())
    }

    fn observe_finish(
        &mut self,
        record: &ProcessFinishRecordWire,
        line_fingerprint: &ArtifactFingerprint,
    ) -> Result<()> {
        self.validate_event_ordinal(record.event_ordinal)?;
        let ProcessState::Started(started) = &self.state else {
            anyhow::bail!("analysis rejected: lifecycle process finish")
        };
        let (expected, completion) = self.expected_process()?;
        let elapsed = record
            .monotonic_nanoseconds
            .checked_sub(started.record.monotonic_nanoseconds)
            .context("analysis rejected: lifecycle process finish")?;
        let output = record
            .stdout_after_ready_bytes
            .checked_add(record.stderr_bytes)
            .context("analysis rejected: lifecycle process finish")?;
        anyhow::ensure!(
            Self::process_coordinate_matches(
                expected.coordinate,
                record.global_round_ordinal,
                record.cell_ordinal,
                record.expansion_position,
            ) && record.timing_process_id == started.record.timing_process_id
                && record.full_benchmark_id == started.record.full_benchmark_id
                && record.process_identity_pseudonym == started.record.process_identity_pseudonym
                && record.exit_code == 0
                && record.termination_reason == "exited"
                && record.elapsed_monotonic_nanoseconds == elapsed
                && (1..=300 * NANOSECONDS_PER_SECOND).contains(&elapsed)
                && output <= 1024 * 1024
                && *line_fingerprint == completion.process_finish_record_fingerprint
                && started.intent.fingerprint == completion.process_intent_record_fingerprint
                && record.launch_barrier_receipt_fingerprint
                    == completion.launch_barrier_receipt_fingerprint
                && record.criterion_home_final_inventory_fingerprint
                    == completion.criterion_home_final_inventory_fingerprint
                && record.criterion_artifact_fingerprint
                    == completion.criterion_artifact_fingerprint
                && record.route_artifact_fingerprint == completion.route_artifact_fingerprint
                && record.artifacts_flushed_and_synced,
            "analysis rejected: lifecycle process finish"
        );
        self.last_finish_monotonic_nanoseconds = Some(record.monotonic_nanoseconds);
        self.process_position = self
            .process_position
            .checked_add(1)
            .context("analysis rejected: lifecycle process cardinality")?;
        self.state = ProcessState::Idle;
        Ok(())
    }

    fn observe_transition(&mut self, record: &super::AttestationTransitionWire) -> Result<()> {
        self.validate_event_ordinal(record.event_ordinal)?;
        let transition_utc = utc_nanos(&record.utc_rfc3339_nanoseconds)
            .map_err(|_| anyhow::anyhow!("analysis rejected: lifecycle attestation transition"))?;
        let previous = self.active_window()?;
        let next = self
            .windows
            .get(self.active_window + 1)
            .context("analysis rejected: lifecycle attestation transition")?;
        anyhow::ensure!(
            record.previous_attestation_fingerprint == *previous.fingerprint()
                && record.next_attestation_fingerprint == *next.fingerprint()
                && utc_nanos(&record.next_starts_at_rfc3339_nanoseconds).ok()
                    == Some(next.starts_at_utc_nanoseconds())
                && utc_nanos(&record.next_expires_at_rfc3339_nanoseconds).ok()
                    == Some(next.expires_at_utc_nanoseconds())
                && next.starts_at_utc_nanoseconds() <= transition_utc,
            "analysis rejected: lifecycle attestation transition"
        );
        self.active_window += 1;
        Ok(())
    }

    fn observe_footer(&self, footer: &SegmentFooterWire) -> Result<()> {
        self.validate_clock_and_coverage(
            &footer.utc_rfc3339_nanoseconds,
            footer.monotonic_nanoseconds,
        )
    }

    fn seal_segment(&mut self, fingerprint: ArtifactFingerprint, footer_monotonic: u64) {
        self.previous_segment_fingerprint = Some(fingerprint);
        self.previous_footer_monotonic_nanoseconds = Some(footer_monotonic);
    }

    fn finish(
        self,
        process_set: &ValidatedProcessSet,
        terminal_request_monotonic_nanoseconds: u64,
        pre_timing_quiet_seconds: u64,
    ) -> Result<(u64, u64)> {
        anyhow::ensure!(
            matches!(self.state, ProcessState::Idle)
                && self.process_position == usize::try_from(TOTAL_PROCESS_COUNT)?
                && self.expected_sample_ordinal == self.completion.sample_count
                && self.post_final_finish_sample_seen
                && self.active_window + 1 == self.windows.len()
                && u32::try_from(self.windows.len() - 1)
                    == Ok(self.completion.attestation_transition_count),
            "analysis rejected: lifecycle completion"
        );
        let first_sample = self
            .first_sample_monotonic_nanoseconds
            .context("analysis rejected: lifecycle sample coverage")?;
        let last_sample = self
            .last_sample_monotonic_nanoseconds
            .context("analysis rejected: lifecycle sample coverage")?;
        let first_intent = self
            .first_intent_monotonic_nanoseconds
            .context("analysis rejected: lifecycle sample coverage")?;
        let last_finish = self
            .last_finish_monotonic_nanoseconds
            .context("analysis rejected: lifecycle sample coverage")?;
        let required_quiet = pre_timing_quiet_seconds
            .checked_mul(NANOSECONDS_PER_SECOND)
            .context("analysis rejected: lifecycle sample coverage")?;
        anyhow::ensure!(
            first_intent
                .checked_sub(first_sample)
                .is_some_and(|duration| duration >= required_quiet)
                && last_sample >= last_finish,
            "analysis rejected: lifecycle sample coverage"
        );
        self.validate_clock(
            &self.completion.created_at_utc_rfc3339_nanoseconds,
            self.completion.created_at_monotonic_nanoseconds,
        )?;
        self.validate_clock_and_coverage(
            &format_controller_utc(
                self.genesis_utc_nanoseconds,
                self.genesis.monotonic_nanoseconds,
                terminal_request_monotonic_nanoseconds,
            )?,
            terminal_request_monotonic_nanoseconds,
        )?;
        validate_process_set_aliases(
            process_set.process_identity_pseudonyms(),
            &self.process_set_forbidden_aliases,
        )?;
        Ok((self.expected_sample_ordinal, self.expected_event_ordinal))
    }
}

fn validate_process_set_aliases(
    process_set_aliases: &[String],
    globally_disjoint_aliases: &BTreeSet<String>,
) -> Result<()> {
    anyhow::ensure!(
        process_set_aliases
            .iter()
            .all(|value| !globally_disjoint_aliases.contains(value)),
        "analysis rejected: lifecycle alias uniqueness"
    );
    Ok(())
}

fn format_controller_utc(
    genesis_utc: i128,
    genesis_monotonic: u64,
    monotonic: u64,
) -> Result<String> {
    let delta = monotonic
        .checked_sub(genesis_monotonic)
        .context("analysis rejected: lifecycle clock")?;
    let nanoseconds = genesis_utc
        .checked_add(i128::from(delta))
        .context("analysis rejected: lifecycle clock")?;
    let seconds = i64::try_from(nanoseconds.div_euclid(i128::from(NANOSECONDS_PER_SECOND)))
        .context("analysis rejected: lifecycle clock")?;
    let nanos = u32::try_from(nanoseconds.rem_euclid(i128::from(NANOSECONDS_PER_SECOND)))
        .context("analysis rejected: lifecycle clock")?;
    let value = chrono::DateTime::from_timestamp(seconds, nanos)
        .context("analysis rejected: lifecycle clock")?;
    Ok(value.format("%Y-%m-%dT%H:%M:%S.%9fZ").to_string())
}

fn valid_footer(
    footer: &SegmentFooterWire,
    inspection: &SegmentInspection,
    campaign_id: &str,
    segment_ordinal: u32,
    terminal: bool,
    maximum_segment_seconds: u32,
) -> bool {
    footer.schema == "marty.performance/sd-jwt-issuance-validity-segment-footer/v1"
        && footer.campaign_id == campaign_id
        && footer.campaign_id == inspection.campaign_id
        && footer.segment_ordinal == segment_ordinal
        && footer.segment_ordinal == inspection.segment_ordinal
        && footer.record_ordinal == footer.records_before_footer
        && footer.records_before_footer == inspection.records_before_last
        && footer.bytes_before_footer == inspection.bytes_before_last
        && footer.records_before_footer_fingerprint == inspection.fingerprint_before_last
        && footer.first_monotonic_nanoseconds == inspection.header_monotonic_nanoseconds
        && inspection.last_record_monotonic_nanoseconds <= footer.monotonic_nanoseconds
        && monotonic_duration_within_seconds(
            footer.first_monotonic_nanoseconds,
            footer.monotonic_nanoseconds,
            maximum_segment_seconds,
        )
        && footer.last_monotonic_nanoseconds == footer.monotonic_nanoseconds
        && footer.sample_count == inspection.record_counts.sample
        && footer.process_intent_count == inspection.record_counts.process_intent
        && footer.process_start_count == inspection.record_counts.process_start
        && footer.process_finish_count == inspection.record_counts.process_finish
        && footer.attestation_transition_count == inspection.record_counts.attestation_transition
        && if terminal {
            footer.closed_reason == "campaign_complete"
        } else {
            matches!(
                footer.closed_reason.as_str(),
                "next_event_would_exceed_duration_limit"
                    | "next_record_would_exceed_byte_limit"
                    | "next_record_would_exceed_record_limit"
            )
        }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one ordered fail-closed replay keeps the complete authenticated chain visible"
)]
pub(super) fn validate_campaign_lifecycle(
    campaign: &CampaignDirectory,
    budget: &mut AnalysisReadBudget,
    schedule: &QualificationSchedule<'_>,
    completion: &CompletionWire,
    genesis: &GenesisHeaderWire,
    hardware: &HardwareProfileWire,
    plan: &SdJwtIssuanceQualificationPlan,
    terminal_receipt: &TerminalObservationReceiptWire,
    completion_anchor: &CompletionAnchorWire,
) -> Result<ValidatedLifecycle> {
    let preimages = load_global_preimages(campaign, budget, genesis, hardware)?;
    let windows = load_test_windows(campaign, budget, completion)?;
    let mut replay = LifecycleReplay::new(
        schedule,
        completion,
        genesis,
        &preimages.thresholds,
        &windows,
        &preimages.host_identity_pseudonym,
        &terminal_receipt.challenge_uppercase_hex_256,
        &completion_anchor.challenge_uppercase_hex_256,
    )?;

    let expected_segments = expected_segment_entries(completion.segment_count);
    campaign.validate_exact_directory_entries(
        Path::new("segments"),
        &expected_segments,
        "segment inventory",
    )?;
    let mut segment_bytes = 0_u64;
    let mut record_count = 0_u64;
    let mut aggregate_sample_count = 0_u64;
    let mut aggregate_intent_count = 0_u32;
    let mut aggregate_start_count = 0_u32;
    let mut aggregate_finish_count = 0_u32;
    let mut aggregate_transition_count = 0_u32;
    let mut ordered_segment_fingerprints = Vec::with_capacity(expected_segments.len());
    for ordinal in 0..completion.segment_count {
        let relative = format!("segments/segment-{ordinal:04}.ndjson");
        let inspection = inspect_campaign_segment_with_observer(
            budget,
            campaign,
            Path::new(&relative),
            "lifecycle segment",
            |line| replay.observe_line(line),
        )?;
        let footer: SegmentFooterWire =
            parse_canonical_compact_line(&inspection.last_line, "lifecycle footer")?;
        let terminal = ordinal + 1 == completion.segment_count;
        anyhow::ensure!(
            completion
                .ordered_segment_fingerprints
                .get(usize::try_from(ordinal)?)
                == Some(&inspection.fingerprint)
                && valid_footer(
                    &footer,
                    &inspection,
                    &completion.campaign_id,
                    ordinal,
                    terminal,
                    plan.global_rounds
                        .run_validity
                        .limits
                        .maximum_segment_seconds,
                )
                && (!terminal
                    || footer.monotonic_nanoseconds == completion.last_monotonic_nanoseconds),
            "analysis rejected: lifecycle segment footer"
        );
        replay.observe_footer(&footer)?;
        segment_bytes = segment_bytes
            .checked_add(inspection.fingerprint.byte_length)
            .context("analysis rejected: lifecycle segment bytes")?;
        record_count = record_count
            .checked_add(u64::from(inspection.records_before_last) + 1)
            .context("analysis rejected: lifecycle record count")?;
        anyhow::ensure!(
            record_count <= MAXIMUM_TOTAL_RECORDS,
            "analysis rejected: lifecycle record count"
        );
        aggregate_sample_count = aggregate_sample_count
            .checked_add(u64::from(inspection.record_counts.sample))
            .context("analysis rejected: lifecycle sample count")?;
        aggregate_intent_count = aggregate_intent_count
            .checked_add(inspection.record_counts.process_intent)
            .context("analysis rejected: lifecycle process count")?;
        aggregate_start_count = aggregate_start_count
            .checked_add(inspection.record_counts.process_start)
            .context("analysis rejected: lifecycle process count")?;
        aggregate_finish_count = aggregate_finish_count
            .checked_add(inspection.record_counts.process_finish)
            .context("analysis rejected: lifecycle process count")?;
        aggregate_transition_count = aggregate_transition_count
            .checked_add(inspection.record_counts.attestation_transition)
            .context("analysis rejected: lifecycle transition count")?;
        ordered_segment_fingerprints.push(inspection.fingerprint.clone());
        replay.seal_segment(inspection.fingerprint, footer.monotonic_nanoseconds);
    }
    campaign.validate_exact_directory_entries(
        Path::new("segments"),
        &expected_segments,
        "segment inventory",
    )?;
    anyhow::ensure!(
        aggregate_sample_count == completion.sample_count
            && aggregate_intent_count == completion.process_intent_count
            && aggregate_start_count == completion.process_start_count
            && aggregate_finish_count == completion.process_finish_count
            && aggregate_transition_count == completion.attestation_transition_count,
        "analysis rejected: lifecycle aggregate counts"
    );
    let (sample_count, lifecycle_event_count) = replay.finish(
        &preimages.process_set,
        terminal_receipt.controller_request_monotonic_nanoseconds,
        u64::from(plan.global_rounds.run_validity.pre_timing_quiet_seconds),
    )?;
    anyhow::ensure!(
        sample_count == aggregate_sample_count
            && lifecycle_event_count
                == u64::from(aggregate_intent_count)
                    + u64::from(aggregate_start_count)
                    + u64::from(aggregate_finish_count)
                    + u64::from(aggregate_transition_count),
        "analysis rejected: lifecycle aggregate counts"
    );
    Ok(ValidatedLifecycle {
        host_identity_fingerprint: preimages.host_identity_fingerprint,
        validity_thresholds_fingerprint: preimages.thresholds.fingerprint().clone(),
        baseline_unrelated_process_set_fingerprint: preimages.process_set.fingerprint().clone(),
        ordered_segment_fingerprints,
        ordered_test_window_attestation_fingerprints: completion
            .ordered_test_window_attestation_fingerprints
            .clone(),
        segment_count: completion.segment_count,
        segment_bytes,
        record_count,
        sample_count,
        lifecycle_event_count,
        process_intent_count: aggregate_intent_count,
        process_start_count: aggregate_start_count,
        process_finish_count: aggregate_finish_count,
        attestation_transition_count: aggregate_transition_count,
        first_monotonic_nanoseconds: completion.first_monotonic_nanoseconds,
        last_monotonic_nanoseconds: completion.last_monotonic_nanoseconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_perf_schema::SdJwtIssuanceQualificationManifest;
    use serde::Serialize;

    const CAMPAIGN_ID: &str = "123e4567-e89b-42d3-a456-426614174000";
    const BASE_UTC: &str = "2026-08-29T12:00:00.000000000Z";

    #[derive(Serialize)]
    struct TestWindowWire<'a> {
        schema: &'a str,
        campaign_id: &'a str,
        target_role: &'a str,
        target_identity_pseudonym: &'a str,
        starts_at_rfc3339_nanoseconds: String,
        expires_at_rfc3339_nanoseconds: String,
        change_reference_pseudonym: &'a str,
        production_traffic_drained: bool,
        public_ingress_disabled: bool,
        synthetic_data_only: bool,
    }

    #[derive(Serialize)]
    struct ThresholdWire<'a> {
        schema: &'a str,
        campaign_id: &'a str,
        maximum_total_cpu_percent: f64,
        maximum_monitor_cpu_percent: f64,
        maximum_unrelated_cpu_percent: f64,
        minimum_available_memory_bytes: u64,
        minimum_cpu_frequency_hz: u64,
        maximum_temperature_millidegrees_celsius: i64,
        forbidden_throttle_flags: Vec<String>,
        maximum_unrelated_process_count: u32,
        unrelated_process_set_policy: &'a str,
        require_all_observations: bool,
    }

    #[derive(Serialize)]
    struct ProcessSetWire<'a> {
        schema: &'a str,
        campaign_id: &'a str,
        boot_identity_pseudonym: &'a str,
        identity_scheme: &'a str,
        entry_count: u32,
        opaque_process_instances: Vec<ProcessSetEntryWire>,
    }

    #[derive(Serialize)]
    struct ProcessSetEntryWire {
        process_instance_pseudonym: String,
    }

    fn pretty<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).expect("pretty JSON");
        bytes.push(b'\n');
        bytes
    }

    fn compact<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).expect("compact JSON");
        bytes.push(b'\n');
        bytes
    }

    fn bound(role: &str, ordinal: usize) -> ArtifactFingerprint {
        fingerprint(format!("{role}:{ordinal}").as_bytes()).expect("fixture fingerprint")
    }

    fn manifest_and_plan() -> (
        SdJwtIssuanceQualificationManifest,
        SdJwtIssuanceQualificationPlan,
    ) {
        let bytes =
            include_bytes!("../../tests/fixtures/sd-jwt-issuance-qualification-manifest-v1.json");
        let manifest = serde_json::from_slice(bytes).expect("fixture manifest");
        let plan = super::super::plan_for_manifest(&manifest, bytes).expect("fixture plan");
        (manifest, plan)
    }

    fn timestamp(base: i128, monotonic: u64) -> String {
        format_controller_utc(base, 0, monotonic).expect("fixture timestamp")
    }

    fn test_windows(base: i128) -> (Vec<ValidatedTestWindow>, Vec<ArtifactFingerprint>) {
        let target = "A".repeat(64);
        let change = "B".repeat(64);
        let first_bytes = pretty(&TestWindowWire {
            schema: "marty.performance/sd-jwt-issuance-test-window/v1",
            campaign_id: CAMPAIGN_ID,
            target_role: "dedicated_performance_gateway",
            target_identity_pseudonym: &target,
            starts_at_rfc3339_nanoseconds: timestamp(base, 0),
            expires_at_rfc3339_nanoseconds: timestamp(base, 3_600 * NANOSECONDS_PER_SECOND),
            change_reference_pseudonym: &change,
            production_traffic_drained: true,
            public_ingress_disabled: true,
            synthetic_data_only: true,
        });
        let first_fingerprint = fingerprint(&first_bytes).expect("first window fingerprint");
        let first =
            validate_initial_test_window_bytes(&first_bytes, &first_fingerprint, CAMPAIGN_ID)
                .expect("first timing window");
        let second_bytes = pretty(&TestWindowWire {
            schema: "marty.performance/sd-jwt-issuance-test-window/v1",
            campaign_id: CAMPAIGN_ID,
            target_role: "dedicated_performance_gateway",
            target_identity_pseudonym: &target,
            starts_at_rfc3339_nanoseconds: timestamp(base, 100 * NANOSECONDS_PER_SECOND),
            expires_at_rfc3339_nanoseconds: timestamp(base, 43_000 * NANOSECONDS_PER_SECOND),
            change_reference_pseudonym: &change,
            production_traffic_drained: true,
            public_ingress_disabled: true,
            synthetic_data_only: true,
        });
        let second_fingerprint = fingerprint(&second_bytes).expect("second window fingerprint");
        let second = validate_test_window_bytes(
            &second_bytes,
            &second_fingerprint,
            CAMPAIGN_ID,
            first.target_role(),
            first.target_identity_pseudonym(),
            first.change_reference_pseudonym(),
        )
        .expect("second timing window");
        (
            vec![first, second],
            vec![first_fingerprint, second_fingerprint],
        )
    }

    fn threshold_policy() -> ValidatedThresholdPolicy {
        let bytes = pretty(&ThresholdWire {
            schema: "marty.performance/sd-jwt-issuance-validity-thresholds/v1",
            campaign_id: CAMPAIGN_ID,
            maximum_total_cpu_percent: 100.0,
            maximum_monitor_cpu_percent: 100.0,
            maximum_unrelated_cpu_percent: 100.0,
            minimum_available_memory_bytes: 0,
            minimum_cpu_frequency_hz: 0,
            maximum_temperature_millidegrees_celsius: 200_000,
            forbidden_throttle_flags: Vec::new(),
            maximum_unrelated_process_count: 0,
            unrelated_process_set_policy: "exact_baseline_match_v1",
            require_all_observations: true,
        });
        let fingerprint = fingerprint(&bytes).expect("threshold fingerprint");
        validate_threshold_policy_bytes(&bytes, &fingerprint, CAMPAIGN_ID, 16_000)
            .expect("threshold policy")
    }

    fn process_set(policy: &ValidatedThresholdPolicy) -> ValidatedProcessSet {
        let boot = "D".repeat(64);
        let bytes = pretty(&ProcessSetWire {
            schema: "marty.performance/sd-jwt-issuance-unrelated-process-set/v1",
            campaign_id: CAMPAIGN_ID,
            boot_identity_pseudonym: &boot,
            identity_scheme: "hmac_sha256_campaign_ephemeral_process_set_v1",
            entry_count: 0,
            opaque_process_instances: Vec::new(),
        });
        let fingerprint = fingerprint(&bytes).expect("process-set fingerprint");
        validate_process_set_bytes(&bytes, &fingerprint, CAMPAIGN_ID, &boot, policy)
            .expect("process set")
    }

    fn sample(
        base: i128,
        record_ordinal: u32,
        sample_ordinal: u64,
        monotonic: u64,
        process_set: &ArtifactFingerprint,
        active_window: &ArtifactFingerprint,
    ) -> ValiditySampleWire {
        ValiditySampleWire {
            schema: "marty.performance/sd-jwt-issuance-validity-sample/v1".to_owned(),
            campaign_id: CAMPAIGN_ID.to_owned(),
            segment_ordinal: 0,
            record_ordinal,
            sample_ordinal,
            utc_rfc3339_nanoseconds: timestamp(base, monotonic),
            monotonic_nanoseconds: monotonic,
            boot_identity_pseudonym: "D".repeat(64),
            timing_state: "idle".to_owned(),
            global_round_ordinal: super::super::RequiredNullable(None),
            cell_ordinal: super::super::RequiredNullable(None),
            expansion_position: super::super::RequiredNullable(None),
            timing_process_id: super::super::RequiredNullable(None),
            total_cpu_percent: 10.0,
            monitor_cpu_percent: 1.0,
            benchmark_cpu_percent: 2.0,
            unrelated_cpu_percent: 1.0,
            available_memory_bytes: 10_000,
            cpu_frequency_hz: 2_000,
            maximum_temperature_millidegrees_celsius: 40_000,
            throttle_flags: vec!["none".to_owned()],
            unrelated_process_set_fingerprint: process_set.clone(),
            active_test_window_attestation_fingerprint: active_window.clone(),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one synthetic replay keeps all 10,560 authenticated schedule bindings explicit"
    )]
    fn complete_matrix_replay_accepts_exact_schedule_and_coverage() {
        let (manifest, plan) = manifest_and_plan();
        let schedule = QualificationSchedule::new(&plan, &manifest).expect("schedule");
        let base = utc_nanos(BASE_UTC).expect("base UTC");
        let (windows, window_fingerprints) = test_windows(base);
        let thresholds = threshold_policy();
        let baseline = process_set(&thresholds);
        let first_sample = NANOSECONDS_PER_SECOND;
        let first_intent = first_sample + 2_700 * NANOSECONDS_PER_SECOND;
        let mut process_lines = Vec::with_capacity(usize::try_from(TOTAL_PROCESS_COUNT).unwrap());
        let mut completions = Vec::with_capacity(usize::try_from(TOTAL_PROCESS_COUNT).unwrap());
        for (position, expected) in schedule.iter().enumerate() {
            let event_base = 1 + u64::try_from(position).unwrap() * 3;
            let monotonic = first_intent + u64::try_from(position).unwrap() * 3;
            let record_base = 273 + u32::try_from(position).unwrap() * 3;
            let invocation = bound("invocation", position);
            let initial_inventory = bound("initial-inventory", position);
            let token = bound("token", position);
            let ready = bound("ready", position);
            let receipt = bound("receipt", position);
            let final_inventory = bound("final-inventory", position);
            let criterion = bound("criterion", position);
            let route = bound("route", position);
            let intent = ProcessIntentRecordWire {
                schema: "marty.performance/sd-jwt-issuance-validity-process-intent/v1".to_owned(),
                campaign_id: CAMPAIGN_ID.to_owned(),
                segment_ordinal: 0,
                record_ordinal: record_base,
                event_ordinal: event_base,
                utc_rfc3339_nanoseconds: timestamp(base, monotonic),
                monotonic_nanoseconds: monotonic,
                global_round_ordinal: expected.coordinate.global_round,
                cell_ordinal: expected.coordinate.cell,
                expansion_position: expected.coordinate.expansion,
                timing_process_id: expected.timing_process_id.clone(),
                full_benchmark_id: expected.full_benchmark_id.to_owned(),
                invocation_descriptor_fingerprint: invocation.clone(),
                criterion_home_initial_inventory_fingerprint: initial_inventory.clone(),
                launch_barrier_token_fingerprint: token.clone(),
            };
            let intent_bytes = compact(&intent);
            let intent_fingerprint = fingerprint(&intent_bytes).expect("intent fingerprint");
            let process_identity_pseudonym = format!("{:064X}", position + 1);
            let start = ProcessStartRecordWire {
                schema: "marty.performance/sd-jwt-issuance-validity-process-start/v1".to_owned(),
                campaign_id: CAMPAIGN_ID.to_owned(),
                segment_ordinal: 0,
                record_ordinal: record_base + 1,
                event_ordinal: event_base + 1,
                utc_rfc3339_nanoseconds: timestamp(base, monotonic + 1),
                monotonic_nanoseconds: monotonic + 1,
                global_round_ordinal: expected.coordinate.global_round,
                cell_ordinal: expected.coordinate.cell,
                expansion_position: expected.coordinate.expansion,
                timing_process_id: expected.timing_process_id.clone(),
                process_identity_pseudonym: process_identity_pseudonym.clone(),
                full_benchmark_id: expected.full_benchmark_id.to_owned(),
                process_intent_record_fingerprint: intent_fingerprint.clone(),
                invocation_descriptor_fingerprint: invocation.clone(),
                launch_barrier_token_fingerprint: token,
                launch_barrier_ready_frame_fingerprint: ready,
                active_test_window_attestation_fingerprint: window_fingerprints[1].clone(),
            };
            let start_bytes = compact(&start);
            let start_fingerprint = fingerprint(&start_bytes).expect("start fingerprint");
            let finish = ProcessFinishRecordWire {
                schema: "marty.performance/sd-jwt-issuance-validity-process-finish/v1".to_owned(),
                campaign_id: CAMPAIGN_ID.to_owned(),
                segment_ordinal: 0,
                record_ordinal: record_base + 2,
                event_ordinal: event_base + 2,
                utc_rfc3339_nanoseconds: timestamp(base, monotonic + 2),
                monotonic_nanoseconds: monotonic + 2,
                global_round_ordinal: expected.coordinate.global_round,
                cell_ordinal: expected.coordinate.cell,
                expansion_position: expected.coordinate.expansion,
                timing_process_id: expected.timing_process_id.clone(),
                process_identity_pseudonym,
                full_benchmark_id: expected.full_benchmark_id.to_owned(),
                exit_code: 0,
                termination_reason: "exited".to_owned(),
                elapsed_monotonic_nanoseconds: 1,
                stdout_after_ready_bytes: 0,
                stderr_bytes: 0,
                launch_barrier_receipt_fingerprint: receipt.clone(),
                criterion_home_final_inventory_fingerprint: final_inventory.clone(),
                criterion_artifact_fingerprint: criterion.clone(),
                route_artifact_fingerprint: route.clone(),
                artifacts_flushed_and_synced: true,
            };
            let finish_bytes = compact(&finish);
            let finish_fingerprint = fingerprint(&finish_bytes).expect("finish fingerprint");
            completions.push(super::super::ProcessCompletionWire {
                global_round_ordinal: expected.coordinate.global_round,
                cell_ordinal: expected.coordinate.cell,
                expansion_position: expected.coordinate.expansion,
                timing_process_id: expected.timing_process_id.clone(),
                full_benchmark_id: expected.full_benchmark_id.to_owned(),
                process_intent_record_fingerprint: intent_fingerprint,
                process_start_record_fingerprint: start_fingerprint,
                process_finish_record_fingerprint: finish_fingerprint,
                invocation_descriptor_fingerprint: invocation,
                launch_barrier_receipt_fingerprint: receipt,
                criterion_home_initial_inventory_fingerprint: initial_inventory,
                criterion_home_final_inventory_fingerprint: final_inventory,
                criterion_artifact_fingerprint: criterion,
                route_artifact_fingerprint: route,
            });
            process_lines.push((intent_bytes, start_bytes, finish_bytes));
        }
        assert_eq!(process_lines.len(), 10_560);

        let placeholder = bound("placeholder", 0);
        let genesis = GenesisHeaderWire {
            schema: "marty.performance/sd-jwt-issuance-validity-genesis/v1".to_owned(),
            campaign_id: CAMPAIGN_ID.to_owned(),
            segment_ordinal: 0,
            record_ordinal: 0,
            utc_rfc3339_nanoseconds: BASE_UTC.to_owned(),
            monotonic_nanoseconds: 0,
            plan_fingerprint: placeholder.clone(),
            manifest_fingerprint: placeholder.clone(),
            fixed_binary_fingerprint: placeholder.clone(),
            fixed_binary_build_receipt_fingerprint: placeholder.clone(),
            monitor_binary_fingerprint: placeholder.clone(),
            controller_binary_fingerprint: placeholder.clone(),
            controller_configuration_fingerprint: placeholder.clone(),
            monitor_configuration_fingerprint: placeholder.clone(),
            external_anchor_channel_configuration_fingerprint: placeholder.clone(),
            source_commit: "1".repeat(40),
            source_tree: "2".repeat(40),
            source_archive_fingerprint: placeholder.clone(),
            cargo_lock_fingerprint: placeholder.clone(),
            rustc_verbose_version: "rustc fixture\n".to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            build_profile: "bench".to_owned(),
            host_identity_fingerprint: placeholder.clone(),
            boot_identity_pseudonym: "D".repeat(64),
            hardware_profile_fingerprint: placeholder.clone(),
            validity_thresholds_fingerprint: thresholds.fingerprint().clone(),
            first_quiet_window_evidence_fingerprint: placeholder.clone(),
            initial_test_window_attestation_fingerprint: window_fingerprints[0].clone(),
            baseline_unrelated_process_set_fingerprint: baseline.fingerprint().clone(),
        };
        let genesis_bytes = compact(&genesis);
        let genesis_fingerprint = fingerprint(&genesis_bytes).expect("genesis fingerprint");
        let final_finish = first_intent + u64::from(TOTAL_PROCESS_COUNT) * 3 - 1;
        let post_sample = final_finish + 1;
        let completion = CompletionWire {
            schema: "marty.performance/sd-jwt-issuance-validity-completion/v1".to_owned(),
            campaign_id: CAMPAIGN_ID.to_owned(),
            created_at_utc_rfc3339_nanoseconds: timestamp(base, post_sample + 3),
            created_at_monotonic_nanoseconds: post_sample + 3,
            plan_fingerprint: placeholder.clone(),
            manifest_fingerprint: placeholder.clone(),
            external_anchor_channel_configuration_fingerprint: placeholder.clone(),
            genesis_header_fingerprint: genesis_fingerprint,
            ordered_segment_fingerprints: vec![placeholder.clone()],
            terminal_segment_fingerprint: placeholder.clone(),
            terminal_observation_evidence_fingerprint: placeholder.clone(),
            ordered_test_window_attestation_fingerprints: window_fingerprints.clone(),
            first_monotonic_nanoseconds: 0,
            last_monotonic_nanoseconds: post_sample + 1,
            segment_count: 1,
            sample_count: 272,
            process_intent_count: TOTAL_PROCESS_COUNT,
            process_start_count: TOTAL_PROCESS_COUNT,
            process_finish_count: TOTAL_PROCESS_COUNT,
            attestation_transition_count: 1,
            process_completions: completions,
            criterion_artifact_set_fingerprint: placeholder.clone(),
            route_artifact_set_fingerprint: placeholder.clone(),
            first_quiet_window_evidence_fingerprint: placeholder,
            invalidating_event_count: 0,
            validity_status: "valid".to_owned(),
        };
        let mut replay = LifecycleReplay::new(
            &schedule,
            &completion,
            &genesis,
            &thresholds,
            &windows,
            &"C".repeat(64),
            &"E".repeat(64),
            &"F".repeat(64),
        )
        .expect("replay");
        replay.observe_line(&genesis_bytes).expect("genesis");
        let transition_monotonic = 100 * NANOSECONDS_PER_SECOND;
        for ordinal in 0_u64..=270 {
            if ordinal == 10 {
                let transition = super::super::AttestationTransitionWire {
                    schema: "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1"
                        .to_owned(),
                    campaign_id: CAMPAIGN_ID.to_owned(),
                    segment_ordinal: 0,
                    record_ordinal: 11,
                    event_ordinal: 0,
                    utc_rfc3339_nanoseconds: timestamp(base, transition_monotonic),
                    monotonic_nanoseconds: transition_monotonic,
                    previous_attestation_fingerprint: window_fingerprints[0].clone(),
                    next_attestation_fingerprint: window_fingerprints[1].clone(),
                    next_starts_at_rfc3339_nanoseconds: timestamp(
                        base,
                        100 * NANOSECONDS_PER_SECOND,
                    ),
                    next_expires_at_rfc3339_nanoseconds: timestamp(
                        base,
                        43_000 * NANOSECONDS_PER_SECOND,
                    ),
                };
                replay
                    .observe_line(&compact(&transition))
                    .expect("attestation transition");
            }
            let active = if ordinal < 10 {
                &window_fingerprints[0]
            } else {
                &window_fingerprints[1]
            };
            let record = sample(
                base,
                u32::try_from(ordinal + 1).unwrap(),
                ordinal,
                first_sample + ordinal * 10 * NANOSECONDS_PER_SECOND,
                baseline.fingerprint(),
                active,
            );
            replay
                .observe_line(&compact(&record))
                .expect("pre-timing sample");
        }
        for (intent, start, finish) in &process_lines {
            replay.observe_line(intent).expect("process intent");
            replay.observe_line(start).expect("process start");
            replay.observe_line(finish).expect("process finish");
        }
        let final_sample = sample(
            base,
            40_000,
            271,
            post_sample,
            baseline.fingerprint(),
            &window_fingerprints[1],
        );
        replay
            .observe_line(&compact(&final_sample))
            .expect("post-finish sample");
        let counts = replay
            .finish(&baseline, post_sample + 1, 2_700)
            .expect("complete replay");
        assert_eq!(counts, (272, 31_681));
    }

    #[test]
    fn inventory_and_clock_boundaries_fail_closed() {
        assert_eq!(expected_segment_entries(3).len(), 3);
        assert!(expected_attestation_entries(16).is_ok());
        assert!(expected_attestation_entries(17).is_err());
        let base = utc_nanos(BASE_UTC).expect("base UTC");
        assert_eq!(
            timestamp(base, 10 * NANOSECONDS_PER_SECOND),
            "2026-08-29T12:00:10.000000000Z"
        );
        assert!(format_controller_utc(base, 10, 9).is_err());
    }

    #[test]
    fn process_set_alias_checks_follow_only_globally_disjoint_roles() {
        let target = "A".repeat(64);
        let timing_child = "B".repeat(64);
        let change_reference = "C".repeat(64);
        let terminal_challenge = "D".repeat(64);
        let completion_challenge = "E".repeat(64);
        let forbidden = [
            change_reference.clone(),
            terminal_challenge.clone(),
            completion_challenge.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();

        validate_process_set_aliases(&[target, timing_child], &forbidden)
            .expect("target and timing-child output collisions are not frozen rejections");
        for collision in [change_reference, terminal_challenge, completion_challenge] {
            assert_eq!(
                validate_process_set_aliases(&[collision], &forbidden)
                    .expect_err("globally disjoint alias must reject")
                    .to_string(),
                "analysis rejected: lifecycle alias uniqueness"
            );
        }
    }
}
