use std::fs;
use std::path::{Path, PathBuf};

use marty_perf_schema::{ArtifactFingerprint, SdJwtIssuanceLifecycleAnalysisReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;

const CAMPAIGN_ID: &str = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001";
const GENESIS_UTC: &str = "2026-08-29T12:35:00.000000000Z";
const GENESIS_MONOTONIC: u64 = 300;
const SECOND: u64 = 1_000_000_000;
const PROCESS_COUNT: usize = 10_560;
const SECOND_SEGMENT_PROCESS_LIMIT: usize = PROCESS_COUNT / 2;

#[derive(Serialize)]
struct HostIdentityFixture<'a> {
    schema: &'static str,
    campaign_id: &'static str,
    identity_scheme: &'static str,
    host_identity_pseudonym: &'a str,
    boot_identity_pseudonym: &'a str,
}

#[derive(Serialize)]
struct ThresholdFixture {
    schema: &'static str,
    campaign_id: &'static str,
    maximum_total_cpu_percent: f64,
    maximum_monitor_cpu_percent: f64,
    maximum_unrelated_cpu_percent: f64,
    minimum_available_memory_bytes: u64,
    minimum_cpu_frequency_hz: u64,
    maximum_temperature_millidegrees_celsius: i64,
    forbidden_throttle_flags: Vec<String>,
    maximum_unrelated_process_count: u32,
    unrelated_process_set_policy: &'static str,
    require_all_observations: bool,
}

#[derive(Serialize)]
struct ProcessSetFixture<'a> {
    schema: &'static str,
    campaign_id: &'static str,
    boot_identity_pseudonym: &'a str,
    identity_scheme: &'static str,
    entry_count: u32,
    opaque_process_instances: Vec<ProcessSetEntryFixture>,
}

#[derive(Serialize)]
struct ProcessSetEntryFixture {
    process_instance_pseudonym: String,
}

#[derive(Serialize)]
struct TestWindowFixture<'a> {
    schema: &'static str,
    campaign_id: &'static str,
    target_role: &'static str,
    target_identity_pseudonym: &'a str,
    starts_at_rfc3339_nanoseconds: String,
    expires_at_rfc3339_nanoseconds: String,
    change_reference_pseudonym: &'a str,
    production_traffic_drained: bool,
    public_ingress_disabled: bool,
    synthetic_data_only: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct MutableTestWindowFixture {
    schema: String,
    campaign_id: String,
    target_role: String,
    target_identity_pseudonym: String,
    starts_at_rfc3339_nanoseconds: String,
    expires_at_rfc3339_nanoseconds: String,
    change_reference_pseudonym: String,
    production_traffic_drained: bool,
    public_ingress_disabled: bool,
    synthetic_data_only: bool,
}

#[derive(Clone, Copy)]
enum SegmentRecordKind {
    Header,
    Sample,
    Intent,
    Start,
    Finish,
    Transition,
}

struct FixtureSegment {
    ordinal: u32,
    first_monotonic_nanoseconds: u64,
    bytes: Vec<u8>,
    next_record_ordinal: u32,
    sample_count: u32,
    process_intent_count: u32,
    process_start_count: u32,
    process_finish_count: u32,
    attestation_transition_count: u32,
}

impl FixtureSegment {
    fn with_header<T: Serialize>(ordinal: u32, monotonic: u64, header: &T) -> Self {
        let mut value = Self {
            ordinal,
            first_monotonic_nanoseconds: monotonic,
            bytes: Vec::new(),
            next_record_ordinal: 0,
            sample_count: 0,
            process_intent_count: 0,
            process_start_count: 0,
            process_finish_count: 0,
            attestation_transition_count: 0,
        };
        value.push(header, SegmentRecordKind::Header);
        value
    }

    fn record_ordinal(&self) -> u32 {
        self.next_record_ordinal
    }

    fn push<T: Serialize>(&mut self, record: &T, kind: SegmentRecordKind) -> ArtifactFingerprint {
        let fingerprint = append_fixture_segment_record(&mut self.bytes, record);
        self.next_record_ordinal = self
            .next_record_ordinal
            .checked_add(1)
            .expect("fixture record ordinal");
        match kind {
            SegmentRecordKind::Header => {}
            SegmentRecordKind::Sample => self.sample_count += 1,
            SegmentRecordKind::Intent => self.process_intent_count += 1,
            SegmentRecordKind::Start => self.process_start_count += 1,
            SegmentRecordKind::Finish => self.process_finish_count += 1,
            SegmentRecordKind::Transition => self.attestation_transition_count += 1,
        }
        fingerprint
    }

    fn finish(mut self, monotonic: u64, closed_reason: &str) -> Vec<u8> {
        let prefix = source_archive_fingerprint(&self.bytes);
        let footer = SegmentFooterWire {
            schema: "marty.performance/sd-jwt-issuance-validity-segment-footer/v1".to_owned(),
            campaign_id: CAMPAIGN_ID.to_owned(),
            segment_ordinal: self.ordinal,
            record_ordinal: self.next_record_ordinal,
            utc_rfc3339_nanoseconds: lifecycle_utc(monotonic),
            monotonic_nanoseconds: monotonic,
            records_before_footer: self.next_record_ordinal,
            bytes_before_footer: prefix.byte_length,
            records_before_footer_fingerprint: prefix,
            first_monotonic_nanoseconds: self.first_monotonic_nanoseconds,
            last_monotonic_nanoseconds: monotonic,
            sample_count: self.sample_count,
            process_intent_count: self.process_intent_count,
            process_start_count: self.process_start_count,
            process_finish_count: self.process_finish_count,
            attestation_transition_count: self.attestation_transition_count,
            closed_reason: closed_reason.to_owned(),
        };
        append_fixture_segment_record(&mut self.bytes, &footer);
        self.bytes
    }
}

fn lifecycle_utc(monotonic: u64) -> String {
    let base = chrono::DateTime::parse_from_rfc3339(GENESIS_UTC)
        .expect("fixture genesis UTC")
        .timestamp_nanos_opt()
        .expect("fixture timestamp");
    let delta = monotonic
        .checked_sub(GENESIS_MONOTONIC)
        .expect("fixture monotonic order");
    let nanoseconds = i128::from(base) + i128::from(delta);
    let seconds =
        i64::try_from(nanoseconds.div_euclid(i128::from(SECOND))).expect("fixture UTC seconds");
    let subsecond =
        u32::try_from(nanoseconds.rem_euclid(i128::from(SECOND))).expect("fixture UTC subsecond");
    chrono::DateTime::from_timestamp(seconds, subsecond)
        .expect("fixture UTC range")
        .format("%Y-%m-%dT%H:%M:%S.%9fZ")
        .to_string()
}

fn unique_binding(role: &str, ordinal: usize) -> ArtifactFingerprint {
    source_archive_fingerprint(format!("lifecycle fixture {role} {ordinal}").as_bytes())
}

fn lifecycle_sample(
    segment_ordinal: u32,
    record_ordinal: u32,
    sample_ordinal: u64,
    monotonic: u64,
    process_set: &ArtifactFingerprint,
    attestation: &ArtifactFingerprint,
) -> ValiditySampleWire {
    ValiditySampleWire {
        schema: "marty.performance/sd-jwt-issuance-validity-sample/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        segment_ordinal,
        record_ordinal,
        sample_ordinal,
        utc_rfc3339_nanoseconds: lifecycle_utc(monotonic),
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
        available_memory_bytes: 1024 * 1024 * 1024,
        cpu_frequency_hz: 2_000_000_000,
        maximum_temperature_millidegrees_celsius: 40_000,
        throttle_flags: vec!["none".to_owned()],
        unrelated_process_set_fingerprint: process_set.clone(),
        active_test_window_attestation_fingerprint: attestation.clone(),
    }
}

struct ProcessBindings {
    global_round: u32,
    cell: u32,
    expansion: u32,
    timing_process_id: String,
    full_benchmark_id: String,
    process_identity_pseudonym: String,
    invocation: ArtifactFingerprint,
    initial_inventory: ArtifactFingerprint,
    token: ArtifactFingerprint,
    ready: ArtifactFingerprint,
    receipt: ArtifactFingerprint,
    final_inventory: ArtifactFingerprint,
    criterion: ArtifactFingerprint,
    route: ArtifactFingerprint,
}

fn process_bindings(
    schedule: &schedule::QualificationSchedule<'_>,
    position: usize,
    selected_route: &ArtifactFingerprint,
) -> ProcessBindings {
    let expected = schedule.at(position).expect("scheduled process");
    ProcessBindings {
        global_round: expected.coordinate.global_round,
        cell: expected.coordinate.cell,
        expansion: expected.coordinate.expansion,
        timing_process_id: expected.timing_process_id.clone(),
        full_benchmark_id: expected.full_benchmark_id.to_owned(),
        process_identity_pseudonym: unique_binding("process identity", position).sha256,
        invocation: unique_binding("invocation", position),
        // Every fresh Criterion home has the same canonical empty initial inventory.
        initial_inventory: source_archive_fingerprint(b"[]\n"),
        token: unique_binding("barrier token", position),
        ready: unique_binding("ready frame", position),
        receipt: unique_binding("barrier receipt", position),
        final_inventory: unique_binding("final inventory", position),
        criterion: unique_binding("criterion artifact", position),
        route: if position == 1 {
            selected_route.clone()
        } else {
            unique_binding("route artifact", position)
        },
    }
}

fn append_intent(
    segment: &mut FixtureSegment,
    bindings: &ProcessBindings,
    event_ordinal: u64,
    monotonic: u64,
) -> ArtifactFingerprint {
    let record = ProcessIntentRecordWire {
        schema: "marty.performance/sd-jwt-issuance-validity-process-intent/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        segment_ordinal: segment.ordinal,
        record_ordinal: segment.record_ordinal(),
        event_ordinal,
        utc_rfc3339_nanoseconds: lifecycle_utc(monotonic),
        monotonic_nanoseconds: monotonic,
        global_round_ordinal: bindings.global_round,
        cell_ordinal: bindings.cell,
        expansion_position: bindings.expansion,
        timing_process_id: bindings.timing_process_id.clone(),
        full_benchmark_id: bindings.full_benchmark_id.clone(),
        invocation_descriptor_fingerprint: bindings.invocation.clone(),
        criterion_home_initial_inventory_fingerprint: bindings.initial_inventory.clone(),
        launch_barrier_token_fingerprint: bindings.token.clone(),
    };
    segment.push(&record, SegmentRecordKind::Intent)
}

fn append_start(
    segment: &mut FixtureSegment,
    bindings: &ProcessBindings,
    intent_fingerprint: &ArtifactFingerprint,
    attestation: &ArtifactFingerprint,
    event_ordinal: u64,
    monotonic: u64,
) -> ArtifactFingerprint {
    let record = ProcessStartRecordWire {
        schema: "marty.performance/sd-jwt-issuance-validity-process-start/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        segment_ordinal: segment.ordinal,
        record_ordinal: segment.record_ordinal(),
        event_ordinal,
        utc_rfc3339_nanoseconds: lifecycle_utc(monotonic),
        monotonic_nanoseconds: monotonic,
        global_round_ordinal: bindings.global_round,
        cell_ordinal: bindings.cell,
        expansion_position: bindings.expansion,
        timing_process_id: bindings.timing_process_id.clone(),
        process_identity_pseudonym: bindings.process_identity_pseudonym.clone(),
        full_benchmark_id: bindings.full_benchmark_id.clone(),
        process_intent_record_fingerprint: intent_fingerprint.clone(),
        invocation_descriptor_fingerprint: bindings.invocation.clone(),
        launch_barrier_token_fingerprint: bindings.token.clone(),
        launch_barrier_ready_frame_fingerprint: bindings.ready.clone(),
        active_test_window_attestation_fingerprint: attestation.clone(),
    };
    segment.push(&record, SegmentRecordKind::Start)
}

fn append_finish(
    segment: &mut FixtureSegment,
    bindings: &ProcessBindings,
    event_ordinal: u64,
    started_at: u64,
    monotonic: u64,
) -> ArtifactFingerprint {
    let record = ProcessFinishRecordWire {
        schema: "marty.performance/sd-jwt-issuance-validity-process-finish/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        segment_ordinal: segment.ordinal,
        record_ordinal: segment.record_ordinal(),
        event_ordinal,
        utc_rfc3339_nanoseconds: lifecycle_utc(monotonic),
        monotonic_nanoseconds: monotonic,
        global_round_ordinal: bindings.global_round,
        cell_ordinal: bindings.cell,
        expansion_position: bindings.expansion,
        timing_process_id: bindings.timing_process_id.clone(),
        process_identity_pseudonym: bindings.process_identity_pseudonym.clone(),
        full_benchmark_id: bindings.full_benchmark_id.clone(),
        exit_code: 0,
        termination_reason: "exited".to_owned(),
        elapsed_monotonic_nanoseconds: monotonic - started_at,
        stdout_after_ready_bytes: 0,
        stderr_bytes: 0,
        launch_barrier_receipt_fingerprint: bindings.receipt.clone(),
        criterion_home_final_inventory_fingerprint: bindings.final_inventory.clone(),
        criterion_artifact_fingerprint: bindings.criterion.clone(),
        route_artifact_fingerprint: bindings.route.clone(),
        artifacts_flushed_and_synced: true,
    };
    segment.push(&record, SegmentRecordKind::Finish)
}

fn completion_for_process(
    bindings: ProcessBindings,
    intent: ArtifactFingerprint,
    start: ArtifactFingerprint,
    finish: ArtifactFingerprint,
) -> ProcessCompletionWire {
    ProcessCompletionWire {
        global_round_ordinal: bindings.global_round,
        cell_ordinal: bindings.cell,
        expansion_position: bindings.expansion,
        timing_process_id: bindings.timing_process_id,
        full_benchmark_id: bindings.full_benchmark_id,
        process_intent_record_fingerprint: intent,
        process_start_record_fingerprint: start,
        process_finish_record_fingerprint: finish,
        invocation_descriptor_fingerprint: bindings.invocation,
        launch_barrier_receipt_fingerprint: bindings.receipt,
        criterion_home_initial_inventory_fingerprint: bindings.initial_inventory,
        criterion_home_final_inventory_fingerprint: bindings.final_inventory,
        criterion_artifact_fingerprint: bindings.criterion,
        route_artifact_fingerprint: bindings.route,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one authenticated fixture makes all lifecycle boundaries explicit"
)]
fn lifecycle_campaign_fixture() -> AnalyzerCampaignFixture {
    let fixture = analyzer_campaign_fixture();
    let manifest = manifest();
    let manifest_bytes = canonical_manifest_bytes(&manifest);
    let plan = plan_for_manifest(&manifest, &manifest_bytes).expect("qualification plan");
    let schedule = schedule::QualificationSchedule::new(&plan, &manifest).expect("schedule");

    let host_identity_pseudonym = "C".repeat(64);
    let boot_identity_pseudonym = "D".repeat(64);
    let host_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "profiles/host-identity.json",
        &HostIdentityFixture {
            schema: "marty.performance/sd-jwt-issuance-host-identity/v1",
            campaign_id: CAMPAIGN_ID,
            identity_scheme: "campaign_random_256_v1",
            host_identity_pseudonym: &host_identity_pseudonym,
            boot_identity_pseudonym: &boot_identity_pseudonym,
        },
    );
    let host_fingerprint = source_archive_fingerprint(&host_bytes);
    let threshold_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "profiles/validity-thresholds.json",
        &ThresholdFixture {
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
        },
    );
    let threshold_fingerprint = source_archive_fingerprint(&threshold_bytes);
    let process_set_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "profiles/baseline-unrelated-process-set.json",
        &ProcessSetFixture {
            schema: "marty.performance/sd-jwt-issuance-unrelated-process-set/v1",
            campaign_id: CAMPAIGN_ID,
            boot_identity_pseudonym: &boot_identity_pseudonym,
            identity_scheme: "hmac_sha256_campaign_ephemeral_process_set_v1",
            entry_count: 0,
            opaque_process_instances: Vec::new(),
        },
    );
    let process_set_fingerprint = source_archive_fingerprint(&process_set_bytes);
    write_fixture_bytes(
        &fixture.campaign_root,
        &format!(
            "observations/unrelated-process-sets/{}.json",
            process_set_fingerprint.sha256
        ),
        &process_set_bytes,
    );

    let first_quiet_window_bytes = b"{\"fixture\":true}\n";
    write_fixture_bytes(
        &fixture.campaign_root,
        "attestations/first-quiet-window.json",
        first_quiet_window_bytes,
    );
    let first_quiet_window_fingerprint = source_archive_fingerprint(first_quiet_window_bytes);
    let target_identity = "E".repeat(64);
    let change_reference = "F".repeat(64);
    let first_window = TestWindowFixture {
        schema: "marty.performance/sd-jwt-issuance-test-window/v1",
        campaign_id: CAMPAIGN_ID,
        target_role: "dedicated_performance_gateway",
        target_identity_pseudonym: &target_identity,
        starts_at_rfc3339_nanoseconds: lifecycle_utc(GENESIS_MONOTONIC),
        expires_at_rfc3339_nanoseconds: lifecycle_utc(GENESIS_MONOTONIC + 3_600 * SECOND),
        change_reference_pseudonym: &change_reference,
        production_traffic_drained: true,
        public_ingress_disabled: true,
        synthetic_data_only: true,
    };
    let first_window_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "attestations/timing-window-0000.json",
        &first_window,
    );
    let first_window_fingerprint = source_archive_fingerprint(&first_window_bytes);
    let second_window = TestWindowFixture {
        schema: "marty.performance/sd-jwt-issuance-test-window/v1",
        campaign_id: CAMPAIGN_ID,
        target_role: "dedicated_performance_gateway",
        target_identity_pseudonym: &target_identity,
        starts_at_rfc3339_nanoseconds: lifecycle_utc(GENESIS_MONOTONIC + 100 * SECOND),
        expires_at_rfc3339_nanoseconds: lifecycle_utc(GENESIS_MONOTONIC + 7_200 * SECOND),
        change_reference_pseudonym: &change_reference,
        production_traffic_drained: true,
        public_ingress_disabled: true,
        synthetic_data_only: true,
    };
    let second_window_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "attestations/timing-window-0001.json",
        &second_window,
    );
    let second_window_fingerprint = source_archive_fingerprint(&second_window_bytes);

    let old_segment = fs::read(fixture.campaign_root.join("segments/segment-0000.ndjson"))
        .expect("old genesis segment");
    let genesis_end = old_segment
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .expect("genesis line");
    let mut genesis: GenesisHeaderWire =
        serde_json::from_slice(&old_segment[..genesis_end]).expect("genesis JSON");
    genesis.host_identity_fingerprint = host_fingerprint;
    genesis.validity_thresholds_fingerprint = threshold_fingerprint;
    genesis.first_quiet_window_evidence_fingerprint = first_quiet_window_fingerprint.clone();
    genesis.initial_test_window_attestation_fingerprint = first_window_fingerprint.clone();
    genesis.baseline_unrelated_process_set_fingerprint = process_set_fingerprint.clone();
    let genesis_line = compact_fixture_record(&genesis);
    let genesis_fingerprint = source_archive_fingerprint(&genesis_line);
    let mut segment = FixtureSegment::with_header(0, GENESIS_MONOTONIC, &genesis);

    let first_sample_monotonic = GENESIS_MONOTONIC + SECOND;
    let transition_monotonic = GENESIS_MONOTONIC + 100 * SECOND;
    let mut event_ordinal = 0_u64;
    for sample_ordinal in 0_u64..=270 {
        if sample_ordinal == 10 {
            let transition = AttestationTransitionWire {
                schema: "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1"
                    .to_owned(),
                campaign_id: CAMPAIGN_ID.to_owned(),
                segment_ordinal: segment.ordinal,
                record_ordinal: segment.record_ordinal(),
                event_ordinal,
                utc_rfc3339_nanoseconds: lifecycle_utc(transition_monotonic),
                monotonic_nanoseconds: transition_monotonic,
                previous_attestation_fingerprint: first_window_fingerprint.clone(),
                next_attestation_fingerprint: second_window_fingerprint.clone(),
                next_starts_at_rfc3339_nanoseconds: second_window
                    .starts_at_rfc3339_nanoseconds
                    .clone(),
                next_expires_at_rfc3339_nanoseconds: second_window
                    .expires_at_rfc3339_nanoseconds
                    .clone(),
            };
            segment.push(&transition, SegmentRecordKind::Transition);
            event_ordinal += 1;
        }
        let active_window = if sample_ordinal < 10 {
            &first_window_fingerprint
        } else {
            &second_window_fingerprint
        };
        let monotonic = first_sample_monotonic + sample_ordinal * 10 * SECOND;
        let sample = lifecycle_sample(
            segment.ordinal,
            segment.record_ordinal(),
            sample_ordinal,
            monotonic,
            &process_set_fingerprint,
            active_window,
        );
        segment.push(&sample, SegmentRecordKind::Sample);
    }

    let selected_route = source_archive_fingerprint(
        &fs::read(fixture.campaign_root.join("routes/r00_c00_e1.ndjson")).expect("selected route"),
    );
    let first_process = process_bindings(&schedule, 0, &selected_route);
    let first_intent_monotonic = first_sample_monotonic + 2_700 * SECOND;
    let first_intent = append_intent(
        &mut segment,
        &first_process,
        event_ordinal,
        first_intent_monotonic,
    );
    event_ordinal += 1;
    let first_start_monotonic = first_intent_monotonic;
    let first_start = append_start(
        &mut segment,
        &first_process,
        &first_intent,
        &second_window_fingerprint,
        event_ordinal,
        first_start_monotonic,
    );
    event_ordinal += 1;
    let first_footer_monotonic = first_start_monotonic;
    let segment_zero = segment.finish(
        first_footer_monotonic,
        "next_record_would_exceed_record_limit",
    );
    let segment_zero_fingerprint = source_archive_fingerprint(&segment_zero);

    // Exercise the inclusive maximum predecessor-to-successor gap.
    let first_continuation_monotonic = first_footer_monotonic + 10 * SECOND;
    let first_continuation = ContinuationHeaderWire {
        schema: "marty.performance/sd-jwt-issuance-validity-continuation/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        segment_ordinal: 1,
        record_ordinal: 0,
        utc_rfc3339_nanoseconds: lifecycle_utc(first_continuation_monotonic),
        monotonic_nanoseconds: first_continuation_monotonic,
        previous_segment_fingerprint: segment_zero_fingerprint.clone(),
        genesis_header_fingerprint: genesis_fingerprint.clone(),
        active_test_window_attestation_fingerprint: second_window_fingerprint.clone(),
        boot_identity_pseudonym: boot_identity_pseudonym.clone(),
    };
    let mut segment =
        FixtureSegment::with_header(1, first_continuation_monotonic, &first_continuation);
    let mut boundary_sample = lifecycle_sample(
        segment.ordinal,
        segment.record_ordinal(),
        271,
        first_continuation_monotonic,
        &process_set_fingerprint,
        &second_window_fingerprint,
    );
    boundary_sample.timing_state = "process".to_owned();
    boundary_sample.global_round_ordinal =
        super::super::RequiredNullable(Some(first_process.global_round));
    boundary_sample.cell_ordinal = super::super::RequiredNullable(Some(first_process.cell));
    boundary_sample.expansion_position =
        super::super::RequiredNullable(Some(first_process.expansion));
    boundary_sample.timing_process_id =
        super::super::RequiredNullable(Some(first_process.timing_process_id.clone()));
    segment.push(&boundary_sample, SegmentRecordKind::Sample);
    let first_finish_monotonic = first_continuation_monotonic + 1;
    let first_finish = append_finish(
        &mut segment,
        &first_process,
        event_ordinal,
        first_start_monotonic,
        first_finish_monotonic,
    );
    event_ordinal += 1;
    let mut process_completions = Vec::with_capacity(PROCESS_COUNT);
    process_completions.push(completion_for_process(
        first_process,
        first_intent,
        first_start,
        first_finish,
    ));
    let mut next_monotonic = first_finish_monotonic + 1;
    let mut segment_one = None;
    let mut segment_one_fingerprint = None;

    for position in 1..PROCESS_COUNT {
        if position == SECOND_SEGMENT_PROCESS_LIMIT {
            let completed = segment.finish(next_monotonic, "next_record_would_exceed_record_limit");
            let completed_fingerprint = source_archive_fingerprint(&completed);
            let continuation_monotonic = next_monotonic + 1;
            let continuation = ContinuationHeaderWire {
                schema: "marty.performance/sd-jwt-issuance-validity-continuation/v1".to_owned(),
                campaign_id: CAMPAIGN_ID.to_owned(),
                segment_ordinal: 2,
                record_ordinal: 0,
                utc_rfc3339_nanoseconds: lifecycle_utc(continuation_monotonic),
                monotonic_nanoseconds: continuation_monotonic,
                previous_segment_fingerprint: completed_fingerprint.clone(),
                genesis_header_fingerprint: genesis_fingerprint.clone(),
                active_test_window_attestation_fingerprint: second_window_fingerprint.clone(),
                boot_identity_pseudonym: boot_identity_pseudonym.clone(),
            };
            segment_one = Some(completed);
            segment_one_fingerprint = Some(completed_fingerprint);
            segment = FixtureSegment::with_header(2, continuation_monotonic, &continuation);
            next_monotonic = continuation_monotonic + 1;
        }

        let bindings = process_bindings(&schedule, position, &selected_route);
        let intent_monotonic = next_monotonic;
        let intent = append_intent(&mut segment, &bindings, event_ordinal, intent_monotonic);
        event_ordinal += 1;
        let start_monotonic = intent_monotonic + 1;
        let start = append_start(
            &mut segment,
            &bindings,
            &intent,
            &second_window_fingerprint,
            event_ordinal,
            start_monotonic,
        );
        event_ordinal += 1;
        let finish_monotonic = start_monotonic + 1;
        let finish = append_finish(
            &mut segment,
            &bindings,
            event_ordinal,
            start_monotonic,
            finish_monotonic,
        );
        event_ordinal += 1;
        process_completions.push(completion_for_process(bindings, intent, start, finish));
        next_monotonic = finish_monotonic + 1;
    }
    assert_eq!(process_completions.len(), PROCESS_COUNT);
    assert_eq!(event_ordinal, 31_681);

    let final_sample = lifecycle_sample(
        segment.ordinal,
        segment.record_ordinal(),
        272,
        next_monotonic,
        &process_set_fingerprint,
        &second_window_fingerprint,
    );
    segment.push(&final_sample, SegmentRecordKind::Sample);
    let terminal_footer_monotonic = next_monotonic + 1;
    let segment_two = segment.finish(terminal_footer_monotonic, "campaign_complete");
    let segment_two_fingerprint = source_archive_fingerprint(&segment_two);
    let segment_one = segment_one.expect("second fixture segment");
    let segment_one_fingerprint = segment_one_fingerprint.expect("second segment fingerprint");
    for (ordinal, bytes) in [&segment_zero, &segment_one, &segment_two]
        .into_iter()
        .enumerate()
    {
        write_fixture_bytes(
            &fixture.campaign_root,
            &format!("segments/segment-{ordinal:04}.ndjson"),
            bytes,
        );
    }

    let terminal_receipt_path = fixture
        .campaign_root
        .join("anchors/terminal-observation-receipt.json");
    let mut terminal_receipt: TerminalObservationReceiptWire =
        serde_json::from_slice(&fs::read(&terminal_receipt_path).expect("terminal receipt"))
            .expect("terminal receipt JSON");
    terminal_receipt.terminal_segment_fingerprint = segment_two_fingerprint.clone();
    terminal_receipt.terminal_footer_monotonic_nanoseconds = terminal_footer_monotonic;
    terminal_receipt.controller_request_monotonic_nanoseconds = terminal_footer_monotonic + 10;
    terminal_receipt.channel_monotonic_nanoseconds = 1_000;
    resign_terminal_receipt(&mut terminal_receipt, &fixture.signing_key);
    let terminal_receipt_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/terminal-observation-receipt.json",
        &terminal_receipt,
    );
    let terminal_receipt_fingerprint = source_archive_fingerprint(&terminal_receipt_bytes);
    let terminal_evidence = TerminalObservationEvidenceWire {
        schema: "marty.performance/sd-jwt-issuance-terminal-observation-evidence/v1".to_owned(),
        campaign_id: CAMPAIGN_ID.to_owned(),
        terminal_observation_receipt_fingerprint: terminal_receipt_fingerprint,
        controller_receipt_observed_monotonic_nanoseconds: terminal_footer_monotonic + 20,
    };
    let terminal_evidence_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/terminal-observation-evidence.json",
        &terminal_evidence,
    );
    let terminal_evidence_fingerprint = source_archive_fingerprint(&terminal_evidence_bytes);

    let completion_path = fixture.campaign_root.join("completion.json");
    let mut completion: CompletionWire =
        serde_json::from_slice(&fs::read(&completion_path).expect("old completion"))
            .expect("old completion JSON");
    completion.created_at_monotonic_nanoseconds = terminal_footer_monotonic + 30;
    completion.created_at_utc_rfc3339_nanoseconds =
        lifecycle_utc(completion.created_at_monotonic_nanoseconds);
    completion.genesis_header_fingerprint = genesis_fingerprint;
    completion.ordered_segment_fingerprints = vec![
        segment_zero_fingerprint,
        segment_one_fingerprint,
        segment_two_fingerprint.clone(),
    ];
    completion.terminal_segment_fingerprint = segment_two_fingerprint.clone();
    completion.terminal_observation_evidence_fingerprint = terminal_evidence_fingerprint.clone();
    completion.ordered_test_window_attestation_fingerprints =
        vec![first_window_fingerprint, second_window_fingerprint];
    completion.first_monotonic_nanoseconds = GENESIS_MONOTONIC;
    completion.last_monotonic_nanoseconds = terminal_footer_monotonic;
    completion.segment_count = 3;
    completion.sample_count = 273;
    completion.process_intent_count = schedule::TOTAL_PROCESS_COUNT;
    completion.process_start_count = schedule::TOTAL_PROCESS_COUNT;
    completion.process_finish_count = schedule::TOTAL_PROCESS_COUNT;
    completion.attestation_transition_count = 1;
    completion.process_completions = process_completions;
    completion.first_quiet_window_evidence_fingerprint = first_quiet_window_fingerprint;
    let completion_bytes =
        write_fixture_pretty(&fixture.campaign_root, "completion.json", &completion);
    let completion_fingerprint = source_archive_fingerprint(&completion_bytes);

    let completion_anchor_path = fixture.campaign_root.join("anchors/completion-anchor.json");
    let mut completion_anchor: CompletionAnchorWire =
        serde_json::from_slice(&fs::read(&completion_anchor_path).expect("old completion anchor"))
            .expect("old completion anchor JSON");
    completion_anchor.completion_fingerprint = completion_fingerprint;
    completion_anchor.terminal_segment_fingerprint = segment_two_fingerprint;
    completion_anchor.terminal_observation_evidence_fingerprint = terminal_evidence_fingerprint;
    completion_anchor.channel_monotonic_nanoseconds = 1_100;
    resign_completion_anchor(&mut completion_anchor, &fixture.signing_key);
    write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/completion-anchor.json",
        &completion_anchor,
    );

    fixture
}

#[test]
fn lifecycle_analyzer_accepts_three_segments_and_publishes_exact_nonactivating_report() {
    let fixture = lifecycle_campaign_fixture();
    let output = fixture.output("lifecycle-analysis.json");
    analyze_lifecycle(&fixture.request(&output)).expect("complete lifecycle analysis");

    let bytes = fs::read(&output).expect("lifecycle report bytes");
    let report: SdJwtIssuanceLifecycleAnalysisReport =
        serde_json::from_slice(&bytes).expect("lifecycle report JSON");
    assert_eq!(bytes, canonical_pretty_bytes(&report));
    assert_eq!(
        report.schema,
        "marty.performance/sd-jwt-issuance-lifecycle-analysis/v1"
    );
    assert_eq!(
        report.analysis_scope,
        "complete_segment_chain_and_embedded_lifecycle_semantics_v1"
    );
    assert_eq!(report.segment_count, 3);
    assert_eq!(report.ordered_segment_fingerprints.len(), 3);
    assert_eq!(report.ordered_test_window_attestation_fingerprints.len(), 2);
    assert_eq!(report.sample_count, 273);
    assert_eq!(report.lifecycle_event_count, 31_681);
    assert_eq!(report.process_intent_count, schedule::TOTAL_PROCESS_COUNT);
    assert_eq!(report.process_start_count, schedule::TOTAL_PROCESS_COUNT);
    assert_eq!(report.process_finish_count, schedule::TOTAL_PROCESS_COUNT);
    assert_eq!(report.attestation_transition_count, 1);
    assert_eq!(report.artifact_integrity_status, "valid");
    assert_eq!(report.embedded_lifecycle_semantics_status, "valid");
    assert_eq!(report.campaign_qualification_status, "not_evaluated");
    assert!(!report.production_threshold_activation);
    assert!(report.production_activation_separate);
    assert!(report.qualified_issuance_thresholds.is_none());
    assert!(report.limitations.iter().any(|value| {
        value == "first_quiet_window_evidence_content_and_build_order_not_analyzed"
    }));
    let actual_segment_bytes = (0..3_u32)
        .map(|ordinal| {
            fs::metadata(
                fixture
                    .campaign_root
                    .join(format!("segments/segment-{ordinal:04}.ndjson")),
            )
            .expect("segment metadata")
            .len()
        })
        .sum::<u64>();
    assert_eq!(report.segment_bytes, actual_segment_bytes);
    assert_eq!(report.record_count, 31_960);
    assert_eq!(
        hex::encode_upper(Sha256::digest(&bytes)),
        "B3DB6C5D55460D7FA079BE20CD228D1DE7284988851C782A47B7382ECD8E9FF1"
    );

    fixture.restore_writable_key_for_cleanup();
}

struct MutableCampaignSnapshot {
    files: Vec<(PathBuf, Vec<u8>)>,
}

fn sole_process_set_path(fixture: &AnalyzerCampaignFixture) -> PathBuf {
    let process_set_directory = fixture
        .campaign_root
        .join("observations/unrelated-process-sets");
    let mut process_set_entries = fs::read_dir(process_set_directory)
        .expect("process-set inventory")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("process-set entries");
    assert_eq!(
        process_set_entries.len(),
        1,
        "fixture has one content-addressed process set"
    );
    process_set_entries.pop().expect("process-set entry").path()
}

impl MutableCampaignSnapshot {
    fn capture(fixture: &AnalyzerCampaignFixture) -> Self {
        let relatives = [
            "segments/segment-0000.ndjson",
            "segments/segment-0001.ndjson",
            "segments/segment-0002.ndjson",
            "completion.json",
            "anchors/terminal-observation-receipt.json",
            "anchors/terminal-observation-evidence.json",
            "anchors/completion-anchor.json",
            "attestations/timing-window-0000.json",
            "attestations/timing-window-0001.json",
            "profiles/baseline-unrelated-process-set.json",
        ];
        let mut files = relatives
            .into_iter()
            .map(|relative| {
                let path = fixture.campaign_root.join(relative);
                let bytes = fs::read(&path).expect("snapshot fixture artifact");
                (path, bytes)
            })
            .collect::<Vec<_>>();
        let process_set_path = sole_process_set_path(fixture);
        files.push((
            process_set_path.clone(),
            fs::read(process_set_path).expect("content-addressed process set"),
        ));
        Self { files }
    }

    fn restore(&self) {
        for (path, bytes) in &self.files {
            fs::write(path, bytes).expect("restore fixture artifact");
        }
    }
}

fn segment_lines(path: &Path) -> Vec<Vec<u8>> {
    let bytes = fs::read(path).expect("segment bytes");
    assert!(bytes.ends_with(b"\n"));
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

fn first_record_with_schema(path: &Path, schema: &str) -> usize {
    nth_record_with_schema(path, schema, 0)
}

fn nth_record_with_schema(path: &Path, schema: &str, occurrence: usize) -> usize {
    segment_lines(path)
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            serde_json::from_slice::<SegmentRecordEnvelope>(line)
                .ok()
                .filter(|record| record.schema == schema)
                .map(|_| index)
        })
        .nth(occurrence)
        .expect("fixture schema")
}

fn assert_segment_structurally_valid(path: &Path, role: &'static str) {
    let input = open_absolute_file(path, 64 * 1024 * 1024, None, role)
        .expect("open structurally valid fixture segment");
    inspect_segment(input, role).expect("mutation must preserve structural segment validity");
}

fn rewrite_segment_record<T: Serialize>(
    path: &Path,
    record_index: usize,
    record: &T,
) -> ArtifactFingerprint {
    let mut lines = segment_lines(path);
    assert!(
        record_index + 1 < lines.len(),
        "footer is not a payload record"
    );
    lines[record_index] = compact_fixture_record(record);
    let mut prefix = lines[..lines.len() - 1].concat();
    let prefix_fingerprint = source_archive_fingerprint(&prefix);
    let mut footer: SegmentFooterWire =
        serde_json::from_slice(lines.last().expect("footer line")).expect("footer JSON");
    footer.bytes_before_footer = prefix_fingerprint.byte_length;
    footer.records_before_footer_fingerprint = prefix_fingerprint;
    if record_index == 0 {
        let header: SegmentRecordEnvelope =
            serde_json::from_slice(&lines[0]).expect("segment header envelope");
        footer.first_monotonic_nanoseconds = header.monotonic_nanoseconds;
    }
    append_fixture_segment_record(&mut prefix, &footer);
    fs::write(path, prefix).expect("rewrite segment");
    source_archive_fingerprint(&lines[record_index])
}

fn update_completion(fixture: &AnalyzerCampaignFixture, update: impl FnOnce(&mut CompletionWire)) {
    let path = fixture.campaign_root.join("completion.json");
    let mut completion: CompletionWire =
        serde_json::from_slice(&fs::read(&path).expect("completion bytes"))
            .expect("completion JSON");
    update(&mut completion);
    write_fixture_pretty(&fixture.campaign_root, "completion.json", &completion);
}

fn rewrite_timing_window(
    fixture: &AnalyzerCampaignFixture,
    ordinal: usize,
    update: impl FnOnce(&mut MutableTestWindowFixture),
) -> (MutableTestWindowFixture, ArtifactFingerprint) {
    let relative = format!("attestations/timing-window-{ordinal:04}.json");
    let path = fixture.campaign_root.join(&relative);
    let mut window: MutableTestWindowFixture =
        serde_json::from_slice(&fs::read(path).expect("timing-window bytes"))
            .expect("timing-window JSON");
    update(&mut window);
    let bytes = write_fixture_pretty(&fixture.campaign_root, &relative, &window);
    assert_eq!(bytes, canonical_pretty_bytes(&window));
    let window_fingerprint = source_archive_fingerprint(&bytes);
    update_completion(fixture, |completion| {
        completion.ordered_test_window_attestation_fingerprints[ordinal] =
            window_fingerprint.clone();
    });
    (window, window_fingerprint)
}

fn assert_successor_timing_window_individually_valid(
    fixture: &AnalyzerCampaignFixture,
    ordinal: usize,
    expected_fingerprint: &ArtifactFingerprint,
) {
    let first_bytes = fs::read(
        fixture
            .campaign_root
            .join("attestations/timing-window-0000.json"),
    )
    .expect("initial timing-window bytes");
    let first_fingerprint = source_archive_fingerprint(&first_bytes);
    let first = super::super::first_quiet_window::validate_initial_test_window_bytes(
        &first_bytes,
        &first_fingerprint,
        CAMPAIGN_ID,
    )
    .expect("initial timing window remains valid");
    let successor_bytes = fs::read(
        fixture
            .campaign_root
            .join(format!("attestations/timing-window-{ordinal:04}.json")),
    )
    .expect("successor timing-window bytes");
    super::super::first_quiet_window::validate_test_window_bytes(
        &successor_bytes,
        expected_fingerprint,
        CAMPAIGN_ID,
        first.target_role(),
        first.target_identity_pseudonym(),
        first.change_reference_pseudonym(),
    )
    .expect("successor timing window remains individually valid");
}

fn rebind_outer_lifecycle_artifacts(fixture: &AnalyzerCampaignFixture) {
    rebind_outer_lifecycle_artifacts_preserving_predecessor(fixture, None);
}

fn rebind_outer_lifecycle_artifacts_preserving_predecessor(
    fixture: &AnalyzerCampaignFixture,
    preserve_predecessor_in_segment: Option<u32>,
) {
    let first_path = fixture.campaign_root.join("segments/segment-0000.ndjson");
    let mut segment_fingerprints = vec![source_archive_fingerprint(
        &fs::read(&first_path).expect("first segment bytes"),
    )];
    for ordinal in 1..3_u32 {
        let path = fixture
            .campaign_root
            .join(format!("segments/segment-{ordinal:04}.ndjson"));
        if preserve_predecessor_in_segment != Some(ordinal) {
            let mut continuation: ContinuationHeaderWire =
                serde_json::from_slice(&segment_lines(&path)[0]).expect("continuation JSON");
            continuation.previous_segment_fingerprint = segment_fingerprints
                .last()
                .expect("predecessor fingerprint")
                .clone();
            rewrite_segment_record(&path, 0, &continuation);
        }
        segment_fingerprints.push(source_archive_fingerprint(
            &fs::read(&path).expect("chained segment bytes"),
        ));
    }
    let terminal_path = fixture.campaign_root.join("segments/segment-0002.ndjson");
    let terminal_lines = segment_lines(&terminal_path);
    let terminal_footer: SegmentFooterWire =
        serde_json::from_slice(terminal_lines.last().expect("terminal footer"))
            .expect("terminal footer JSON");

    let receipt_path = fixture
        .campaign_root
        .join("anchors/terminal-observation-receipt.json");
    let mut receipt: TerminalObservationReceiptWire =
        serde_json::from_slice(&fs::read(&receipt_path).expect("terminal receipt"))
            .expect("terminal receipt JSON");
    receipt.terminal_segment_fingerprint = segment_fingerprints[2].clone();
    receipt.terminal_footer_monotonic_nanoseconds = terminal_footer.monotonic_nanoseconds;
    resign_terminal_receipt(&mut receipt, &fixture.signing_key);
    let receipt_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/terminal-observation-receipt.json",
        &receipt,
    );

    let evidence_path = fixture
        .campaign_root
        .join("anchors/terminal-observation-evidence.json");
    let mut evidence: TerminalObservationEvidenceWire =
        serde_json::from_slice(&fs::read(&evidence_path).expect("terminal evidence"))
            .expect("terminal evidence JSON");
    evidence.terminal_observation_receipt_fingerprint = source_archive_fingerprint(&receipt_bytes);
    let evidence_bytes = write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/terminal-observation-evidence.json",
        &evidence,
    );
    let evidence_fingerprint = source_archive_fingerprint(&evidence_bytes);

    let completion_path = fixture.campaign_root.join("completion.json");
    let mut completion: CompletionWire =
        serde_json::from_slice(&fs::read(&completion_path).expect("completion"))
            .expect("completion JSON");
    completion.ordered_segment_fingerprints = segment_fingerprints.clone();
    completion.terminal_segment_fingerprint = segment_fingerprints[2].clone();
    completion.terminal_observation_evidence_fingerprint = evidence_fingerprint.clone();
    let completion_bytes =
        write_fixture_pretty(&fixture.campaign_root, "completion.json", &completion);

    let anchor_path = fixture.campaign_root.join("anchors/completion-anchor.json");
    let mut anchor: CompletionAnchorWire =
        serde_json::from_slice(&fs::read(&anchor_path).expect("completion anchor"))
            .expect("completion anchor JSON");
    anchor.completion_fingerprint = source_archive_fingerprint(&completion_bytes);
    anchor.terminal_segment_fingerprint = segment_fingerprints[2].clone();
    anchor.terminal_observation_evidence_fingerprint = evidence_fingerprint;
    resign_completion_anchor(&mut anchor, &fixture.signing_key);
    write_fixture_pretty(
        &fixture.campaign_root,
        "anchors/completion-anchor.json",
        &anchor,
    );
}

fn assert_lifecycle_rejected(fixture: &AnalyzerCampaignFixture, output_name: &str) {
    let output = fixture.output(output_name);
    assert!(
        analyze_lifecycle(&fixture.request(&output)).is_err(),
        "mutation {output_name} must reject"
    );
    assert!(
        !output.exists(),
        "mutation {output_name} must not publish a report"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one restored authenticated campaign isolates each lifecycle invariant"
)]
fn lifecycle_analyzer_rejects_rebound_chain_ordinal_state_bound_attestation_and_process_set_mutations(
) {
    let fixture = lifecycle_campaign_fixture();
    let snapshot = MutableCampaignSnapshot::capture(&fixture);
    let segment_zero_path = fixture.campaign_root.join("segments/segment-0000.ndjson");
    let segment_one_path = fixture.campaign_root.join("segments/segment-0001.ndjson");

    let mut continuation: ContinuationHeaderWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[0]).expect("continuation JSON");
    continuation.previous_segment_fingerprint = unique_binding("wrong predecessor", 0);
    rewrite_segment_record(&segment_one_path, 0, &continuation);
    rebind_outer_lifecycle_artifacts_preserving_predecessor(&fixture, Some(1));
    assert_lifecycle_rejected(&fixture, "rejected-predecessor.json");

    snapshot.restore();
    let segment_zero_lines = segment_lines(&segment_zero_path);
    let footer: SegmentFooterWire =
        serde_json::from_slice(segment_zero_lines.last().expect("segment zero footer"))
            .expect("segment zero footer JSON");
    let mut continuation: ContinuationHeaderWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[0]).expect("continuation JSON");
    continuation.monotonic_nanoseconds = footer.monotonic_nanoseconds;
    continuation.utc_rfc3339_nanoseconds = lifecycle_utc(footer.monotonic_nanoseconds);
    rewrite_segment_record(&segment_one_path, 0, &continuation);
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-zero-segment-gap.json");

    snapshot.restore();
    let mut continuation: ContinuationHeaderWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[0]).expect("continuation JSON");
    continuation.monotonic_nanoseconds = footer.monotonic_nanoseconds + 10 * SECOND + 1;
    continuation.utc_rfc3339_nanoseconds = lifecycle_utc(continuation.monotonic_nanoseconds);
    rewrite_segment_record(&segment_one_path, 0, &continuation);
    let mut boundary_sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[1]).expect("boundary sample JSON");
    boundary_sample.monotonic_nanoseconds = continuation.monotonic_nanoseconds;
    boundary_sample.utc_rfc3339_nanoseconds = lifecycle_utc(boundary_sample.monotonic_nanoseconds);
    rewrite_segment_record(&segment_one_path, 1, &boundary_sample);
    let structurally_valid = open_absolute_file(
        &segment_one_path,
        64 * 1024 * 1024,
        None,
        "overlong-gap fixture segment",
    )
    .expect("open overlong-gap fixture segment");
    inspect_segment(structurally_valid, "overlong-gap fixture segment")
        .expect("overlong gap remains structurally valid");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-overlong-segment-gap.json");

    snapshot.restore();
    let intent_index = first_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-process-intent/v1",
    );
    let mut intent: ProcessIntentRecordWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[intent_index])
            .expect("intent JSON");
    intent.event_ordinal += 1;
    let intent_fingerprint = rewrite_segment_record(&segment_zero_path, intent_index, &intent);
    update_completion(&fixture, |completion| {
        completion.process_completions[0].process_intent_record_fingerprint = intent_fingerprint;
    });
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-global-event-ordinal.json");

    snapshot.restore();
    let mut intent: ProcessIntentRecordWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[intent_index])
            .expect("intent JSON");
    intent.cell_ordinal += 1;
    let intent_fingerprint = rewrite_segment_record(&segment_zero_path, intent_index, &intent);
    update_completion(&fixture, |completion| {
        completion.process_completions[0].process_intent_record_fingerprint = intent_fingerprint;
    });
    assert_segment_structurally_valid(&segment_zero_path, "coordinate fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-schedule-coordinate.json");

    snapshot.restore();
    let start_index = first_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-process-start/v1",
    );
    let start: ProcessStartRecordWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[start_index])
            .expect("start JSON");
    let mut overlapping_intent: ProcessIntentRecordWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[intent_index])
            .expect("intent JSON");
    overlapping_intent.record_ordinal = start.record_ordinal;
    overlapping_intent.event_ordinal = start.event_ordinal;
    overlapping_intent.utc_rfc3339_nanoseconds = start.utc_rfc3339_nanoseconds;
    overlapping_intent.monotonic_nanoseconds = start.monotonic_nanoseconds;
    rewrite_segment_record(&segment_zero_path, start_index, &overlapping_intent);
    assert_segment_structurally_valid(&segment_zero_path, "overlap fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-process-overlap.json");

    snapshot.restore();
    let sample_index = first_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-sample/v1",
    );
    let mut sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[sample_index])
            .expect("sample JSON");
    sample.sample_ordinal += 1;
    rewrite_segment_record(&segment_zero_path, sample_index, &sample);
    assert_segment_structurally_valid(&segment_zero_path, "sample-ordinal fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-sample-ordinal.json");

    snapshot.restore();
    let second_sample_index = nth_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-sample/v1",
        1,
    );
    let first_sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[sample_index])
            .expect("first sample JSON");
    let mut second_sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[second_sample_index])
            .expect("second sample JSON");
    second_sample.monotonic_nanoseconds += 1;
    second_sample.utc_rfc3339_nanoseconds = lifecycle_utc(second_sample.monotonic_nanoseconds);
    assert_eq!(
        second_sample.monotonic_nanoseconds - first_sample.monotonic_nanoseconds,
        10 * SECOND + 1
    );
    rewrite_segment_record(&segment_zero_path, second_sample_index, &second_sample);
    assert_segment_structurally_valid(&segment_zero_path, "sample-cadence fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-sample-cadence.json");

    snapshot.restore();
    let mut sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[sample_index])
            .expect("sample JSON");
    sample.timing_state = "process".to_owned();
    rewrite_segment_record(&segment_zero_path, sample_index, &sample);
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-sample-state.json");

    snapshot.restore();
    let finish_index = first_record_with_schema(
        &segment_one_path,
        "marty.performance/sd-jwt-issuance-validity-process-finish/v1",
    );
    let mut finish: ProcessFinishRecordWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[finish_index])
            .expect("finish JSON");
    finish.elapsed_monotonic_nanoseconds += 1;
    let finish_fingerprint = rewrite_segment_record(&segment_one_path, finish_index, &finish);
    update_completion(&fixture, |completion| {
        completion.process_completions[0].process_finish_record_fingerprint = finish_fingerprint;
    });
    assert_segment_structurally_valid(&segment_one_path, "elapsed fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-process-elapsed.json");

    snapshot.restore();
    let mut finish: ProcessFinishRecordWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[finish_index])
            .expect("finish JSON");
    finish.stdout_after_ready_bytes = u64::MAX;
    finish.stderr_bytes = 1;
    let finish_fingerprint = rewrite_segment_record(&segment_one_path, finish_index, &finish);
    update_completion(&fixture, |completion| {
        completion.process_completions[0].process_finish_record_fingerprint = finish_fingerprint;
    });
    assert_segment_structurally_valid(&segment_one_path, "output-overflow fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-process-output-overflow.json");

    snapshot.restore();
    let mut finish: ProcessFinishRecordWire =
        serde_json::from_slice(&segment_lines(&segment_one_path)[finish_index])
            .expect("finish JSON");
    finish.stderr_bytes = 1024 * 1024 + 1;
    let finish_fingerprint = rewrite_segment_record(&segment_one_path, finish_index, &finish);
    update_completion(&fixture, |completion| {
        completion.process_completions[0].process_finish_record_fingerprint = finish_fingerprint;
    });
    assert_segment_structurally_valid(&segment_one_path, "output-bound fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-process-output-bound.json");

    snapshot.restore();
    let transition_index = first_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1",
    );
    let mut transition: AttestationTransitionWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[transition_index])
            .expect("transition JSON");
    transition.next_attestation_fingerprint = unique_binding("wrong attestation", 0);
    rewrite_segment_record(&segment_zero_path, transition_index, &transition);
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-attestation-transition.json");

    snapshot.restore();
    let mut transition: AttestationTransitionWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[transition_index])
            .expect("transition JSON");
    transition.monotonic_nanoseconds -= 1;
    transition.utc_rfc3339_nanoseconds = lifecycle_utc(transition.monotonic_nanoseconds);
    assert!(
        transition.utc_rfc3339_nanoseconds < transition.next_starts_at_rfc3339_nanoseconds,
        "successor window is future-dated at the transition"
    );
    rewrite_segment_record(&segment_zero_path, transition_index, &transition);
    assert_segment_structurally_valid(&segment_zero_path, "future-window fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-future-attestation.json");

    snapshot.restore();
    let (expired_window, expired_window_fingerprint) =
        rewrite_timing_window(&fixture, 1, |window| {
            window.expires_at_rfc3339_nanoseconds = lifecycle_utc(GENESIS_MONOTONIC + 101 * SECOND);
        });
    assert_successor_timing_window_individually_valid(&fixture, 1, &expired_window_fingerprint);
    let mut transition: AttestationTransitionWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[transition_index])
            .expect("transition JSON");
    transition.next_attestation_fingerprint = expired_window_fingerprint;
    transition.next_starts_at_rfc3339_nanoseconds =
        expired_window.starts_at_rfc3339_nanoseconds.clone();
    transition.next_expires_at_rfc3339_nanoseconds =
        expired_window.expires_at_rfc3339_nanoseconds.clone();
    rewrite_segment_record(&segment_zero_path, transition_index, &transition);
    let first_post_transition_sample_index = nth_record_with_schema(
        &segment_zero_path,
        "marty.performance/sd-jwt-issuance-validity-sample/v1",
        10,
    );
    let first_post_transition_sample: ValiditySampleWire = serde_json::from_slice(
        &segment_lines(&segment_zero_path)[first_post_transition_sample_index],
    )
    .expect("first post-transition sample JSON");
    assert_eq!(
        first_post_transition_sample.utc_rfc3339_nanoseconds,
        expired_window.expires_at_rfc3339_nanoseconds,
        "first successor-covered record is exactly at the exclusive expiry"
    );
    assert_segment_structurally_valid(&segment_zero_path, "expired-window fixture segment");
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-expired-attestation.json");

    snapshot.restore();
    let first_window: MutableTestWindowFixture = serde_json::from_slice(
        &fs::read(
            fixture
                .campaign_root
                .join("attestations/timing-window-0000.json"),
        )
        .expect("initial timing-window bytes"),
    )
    .expect("initial timing-window JSON");
    let (gapped_window, gapped_window_fingerprint) = rewrite_timing_window(&fixture, 1, |window| {
        window.starts_at_rfc3339_nanoseconds =
            lifecycle_utc(GENESIS_MONOTONIC + 3_600 * SECOND + 1);
    });
    assert_successor_timing_window_individually_valid(&fixture, 1, &gapped_window_fingerprint);
    assert!(
        gapped_window.starts_at_rfc3339_nanoseconds > first_window.expires_at_rfc3339_nanoseconds,
        "successor starts after predecessor expiry"
    );
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-gapped-attestation.json");

    snapshot.restore();
    let mut sample: ValiditySampleWire =
        serde_json::from_slice(&segment_lines(&segment_zero_path)[sample_index])
            .expect("sample JSON");
    sample.unrelated_process_set_fingerprint = unique_binding("wrong process set", 0);
    rewrite_segment_record(&segment_zero_path, sample_index, &sample);
    rebind_outer_lifecycle_artifacts(&fixture);
    assert_lifecycle_rejected(&fixture, "rejected-process-set-binding.json");

    snapshot.restore();
    let process_set_path = sole_process_set_path(&fixture);
    let baseline_process_set = fs::read(
        fixture
            .campaign_root
            .join("profiles/baseline-unrelated-process-set.json"),
    )
    .expect("baseline process-set bytes");
    fs::write(&process_set_path, b"{}\n").expect("tamper content-addressed process set");
    assert_ne!(
        fs::read(&process_set_path).expect("tampered process-set bytes"),
        baseline_process_set,
        "expected SHA-named path now contains bytes unequal to the signed baseline"
    );
    assert_lifecycle_rejected(&fixture, "rejected-process-set-content.json");

    snapshot.restore();
    let extra_process_set = fixture
        .campaign_root
        .join("observations/unrelated-process-sets/EXTRA.json");
    fs::write(&extra_process_set, b"{}\n").expect("extra process-set entry");
    assert_lifecycle_rejected(&fixture, "rejected-process-set-inventory.json");
    fs::remove_file(extra_process_set).expect("remove extra process-set entry");

    snapshot.restore();
    fs::remove_file(&segment_one_path).expect("remove middle segment");
    assert!(!segment_one_path.exists());
    assert_lifecycle_rejected(&fixture, "rejected-missing-segment.json");

    snapshot.restore();
    let second_attestation_path = fixture
        .campaign_root
        .join("attestations/timing-window-0001.json");
    fs::remove_file(&second_attestation_path).expect("remove successor timing attestation");
    assert!(!second_attestation_path.exists());
    assert_lifecycle_rejected(&fixture, "rejected-missing-attestation.json");

    snapshot.restore();
    let process_set_path = sole_process_set_path(&fixture);
    fs::remove_file(&process_set_path).expect("remove content-addressed process set");
    assert!(!process_set_path.exists());
    assert_lifecycle_rejected(&fixture, "rejected-missing-process-set.json");

    snapshot.restore();

    fixture.restore_writable_key_for_cleanup();
}
