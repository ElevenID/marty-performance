//! Fail-closed validation of indexed issuance timing artifacts.

use anyhow::{Context, Result};
use marty_perf_schema::{
    ArtifactFingerprint, SdJwtIssuanceQualificationManifest, SdJwtIssuanceQualificationPlan,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::{
    fingerprint, parse_canonical_pretty, read_campaign_input,
    schedule::{ArtifactRole, QualificationSchedule, ScheduledProcess},
    statistics::criterion_median,
    valid_route_wire_bytes, AnalysisReadBudget, CampaignDirectory, CompletionWire,
    HardwareProfileWire,
};
const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_CRITERION_SUBTOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ROUTE_SUBTOTAL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum ArtifactKind {
    Criterion,
    Route,
}

impl ArtifactKind {
    fn schema(self) -> &'static str {
        match self {
            Self::Criterion => "marty.performance/sd-jwt-issuance-criterion-artifact-index/v1",
            Self::Route => "marty.performance/sd-jwt-issuance-route-artifact-index/v1",
        }
    }
    fn literal(self) -> &'static str {
        match self {
            Self::Criterion => "criterion_0_5_1_new_estimates_json",
            Self::Route => "sd_jwt_issuance_route_v2",
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactIndexEntry {
    pub(super) global_round_ordinal: u32,
    pub(super) cell_ordinal: u32,
    pub(super) expansion_position: u32,
    pub(super) timing_process_id: String,
    pub(super) full_benchmark_id: String,
    pub(super) relative_path: String,
    pub(super) fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactIndex {
    pub(super) schema: String,
    pub(super) campaign_id: String,
    pub(super) artifact_kind: String,
    pub(super) entry_count: u32,
    pub(super) entries: Vec<ArtifactIndexEntry>,
}

/// Bound timing values and index accounting from one exact ordered traversal.
pub(super) struct ValidatedTimingMatrix {
    pub(super) medians_nanoseconds: Vec<f64>,
    pub(super) criterion_index_fingerprint: ArtifactFingerprint,
    pub(super) criterion_artifact_count: u32,
    pub(super) criterion_artifact_bytes: u64,
    pub(super) route_index_fingerprint: ArtifactFingerprint,
    pub(super) route_artifact_count: u32,
    pub(super) route_artifact_bytes: u64,
}

fn charge_subtotal(current: &mut u64, bytes: usize, maximum: u64) -> Result<()> {
    *current = current
        .checked_add(u64::try_from(bytes)?)
        .context("evidence rejected: artifact subtotal overflow")?;
    anyhow::ensure!(*current <= maximum, "evidence rejected: artifact subtotal");
    Ok(())
}

fn validate_artifact_bytes(bytes: &[u8], expected: &ArtifactFingerprint) -> Result<()> {
    anyhow::ensure!(
        &fingerprint(bytes)? == expected,
        "evidence rejected: artifact fingerprint"
    );
    Ok(())
}

fn validate_index_envelope(
    index: &ArtifactIndex,
    kind: ArtifactKind,
    campaign_id: &str,
    schedule_len: usize,
) -> Result<()> {
    anyhow::ensure!(
        index.schema == kind.schema()
            && index.campaign_id == campaign_id
            && index.artifact_kind == kind.literal()
            && usize::try_from(index.entry_count) == Ok(schedule_len)
            && index.entries.len() == schedule_len,
        "evidence rejected: index envelope"
    );
    Ok(())
}

fn declared_artifact_total(index: &ArtifactIndex, maximum: u64) -> Result<u64> {
    let total = index.entries.iter().try_fold(0_u64, |total, entry| {
        anyhow::ensure!(
            super::valid_artifact_fingerprint(&entry.fingerprint)
                && entry.fingerprint.byte_length <= MAX_ARTIFACT_BYTES,
            "evidence rejected: artifact fingerprint"
        );
        total
            .checked_add(entry.fingerprint.byte_length)
            .context("evidence rejected: artifact subtotal overflow")
    })?;
    anyhow::ensure!(total <= maximum, "evidence rejected: artifact subtotal");
    Ok(total)
}

#[cfg(test)]
fn read_artifact_with_remaining(
    read_budget: &mut AnalysisReadBudget,
    campaign: &CampaignDirectory,
    relative_path: &Path,
    consumed: u64,
    subtotal_maximum: u64,
    label: &'static str,
) -> Result<Vec<u8>> {
    let remaining = subtotal_maximum
        .checked_sub(consumed)
        .context("evidence rejected: artifact subtotal")?;
    read_campaign_input(
        read_budget,
        campaign,
        relative_path,
        MAX_ARTIFACT_BYTES.min(remaining),
        label,
    )
}

fn validate_index_entry(
    index: &ArtifactIndex,
    kind: ArtifactKind,
    campaign_id: &str,
    position: usize,
    schedule_len: usize,
    process: &ScheduledProcess<'_>,
    bound: &ArtifactFingerprint,
) -> Result<()> {
    validate_index_envelope(index, kind, campaign_id, schedule_len)?;
    let entry = index
        .entries
        .get(position)
        .context("evidence rejected: index coverage")?;
    anyhow::ensure!(
        entry.global_round_ordinal == process.coordinate.global_round
            && entry.cell_ordinal == process.coordinate.cell
            && entry.expansion_position == process.coordinate.expansion
            && entry.timing_process_id == process.timing_process_id
            && entry.full_benchmark_id == process.full_benchmark_id
            && entry.relative_path
                == process.relative_path(match kind {
                    ArtifactKind::Route => ArtifactRole::Route,
                    ArtifactKind::Criterion => ArtifactRole::CriterionEstimate,
                })?
            && &entry.fingerprint == bound,
        "evidence rejected: index binding"
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered validation keeps every index, completion, and artifact binding in one auditable pipeline"
)]
fn validate_indexed_timing_artifacts_with_reader(
    manifest: &SdJwtIssuanceQualificationManifest,
    plan: &SdJwtIssuanceQualificationPlan,
    completion: &CompletionWire,
    hardware: &HardwareProfileWire,
    mut read: impl FnMut(&Path, u64, &'static str) -> Result<Vec<u8>>,
) -> Result<ValidatedTimingMatrix> {
    let schedule =
        QualificationSchedule::new(plan, manifest).context("evidence rejected: schedule")?;
    let criterion_index_bytes = read(
        Path::new("indexes/criterion-artifacts.json"),
        MAX_INDEX_BYTES,
        "criterion index",
    )?;
    let route_index_bytes = read(
        Path::new("indexes/route-artifacts.json"),
        MAX_INDEX_BYTES,
        "route index",
    )?;
    anyhow::ensure!(
        u64::try_from(criterion_index_bytes.len())? <= MAX_INDEX_BYTES
            && u64::try_from(route_index_bytes.len())? <= MAX_INDEX_BYTES,
        "evidence rejected: index bytes"
    );
    let criterion_index_fingerprint = fingerprint(&criterion_index_bytes)?;
    let route_index_fingerprint = fingerprint(&route_index_bytes)?;
    anyhow::ensure!(
        criterion_index_fingerprint == completion.criterion_artifact_set_fingerprint
            && route_index_fingerprint == completion.route_artifact_set_fingerprint,
        "evidence rejected: completion index fingerprint"
    );
    let criterion: ArtifactIndex =
        parse_canonical_pretty(&criterion_index_bytes, "criterion index")?;
    let route: ArtifactIndex = parse_canonical_pretty(&route_index_bytes, "route index")?;
    validate_index_envelope(
        &criterion,
        ArtifactKind::Criterion,
        &completion.campaign_id,
        schedule.iter().len(),
    )?;
    validate_index_envelope(
        &route,
        ArtifactKind::Route,
        &completion.campaign_id,
        schedule.iter().len(),
    )?;
    anyhow::ensure!(
        completion.process_completions.len() == schedule.iter().len(),
        "evidence rejected: completion coverage"
    );
    let declared_criterion_total =
        declared_artifact_total(&criterion, MAX_CRITERION_SUBTOTAL_BYTES)?;
    let declared_route_total = declared_artifact_total(&route, MAX_ROUTE_SUBTOTAL_BYTES)?;
    let mut criterion_total = 0_u64;
    let mut route_total = 0_u64;
    let mut medians_nanoseconds = Vec::with_capacity(schedule.iter().len());
    for (position, expected) in schedule.iter().enumerate() {
        let completion_entry = &completion.process_completions[position];
        let criterion_entry = criterion
            .entries
            .get(position)
            .context("evidence rejected: criterion coverage")?;
        let route_entry = route
            .entries
            .get(position)
            .context("evidence rejected: route coverage")?;
        anyhow::ensure!(
            completion_entry.global_round_ordinal == expected.coordinate.global_round
                && completion_entry.cell_ordinal == expected.coordinate.cell
                && completion_entry.expansion_position == expected.coordinate.expansion
                && completion_entry.timing_process_id == expected.timing_process_id
                && completion_entry.full_benchmark_id == expected.full_benchmark_id,
            "evidence rejected: completion coordinate"
        );
        for (kind, index, bound) in [
            (
                ArtifactKind::Criterion,
                &criterion,
                &completion_entry.criterion_artifact_fingerprint,
            ),
            (
                ArtifactKind::Route,
                &route,
                &completion_entry.route_artifact_fingerprint,
            ),
        ] {
            validate_index_entry(
                index,
                kind,
                &completion.campaign_id,
                position,
                schedule.iter().len(),
                expected,
                bound,
            )?;
        }
        let criterion_remaining = MAX_CRITERION_SUBTOTAL_BYTES
            .checked_sub(criterion_total)
            .context("evidence rejected: artifact subtotal")?;
        let criterion_bytes = read(
            Path::new(&criterion_entry.relative_path),
            MAX_ARTIFACT_BYTES.min(criterion_remaining),
            "criterion estimates",
        )?;
        let route_remaining = MAX_ROUTE_SUBTOTAL_BYTES
            .checked_sub(route_total)
            .context("evidence rejected: artifact subtotal")?;
        let route_bytes = read(
            Path::new(&route_entry.relative_path),
            MAX_ARTIFACT_BYTES.min(route_remaining),
            "route artifact",
        )?;
        charge_subtotal(
            &mut criterion_total,
            criterion_bytes.len(),
            MAX_CRITERION_SUBTOTAL_BYTES,
        )?;
        charge_subtotal(
            &mut route_total,
            route_bytes.len(),
            MAX_ROUTE_SUBTOTAL_BYTES,
        )?;
        validate_artifact_bytes(&criterion_bytes, &criterion_entry.fingerprint)?;
        validate_artifact_bytes(&route_bytes, &route_entry.fingerprint)?;
        anyhow::ensure!(
            valid_route_wire_bytes(
                &route_bytes,
                expected.full_benchmark_id,
                expected.fixture_id,
                expected.stage,
                expected.requested,
                u64::try_from(manifest.worker_cap).context("evidence rejected: worker cap")?,
                u64::from(hardware.host_available_parallelism)
            ),
            "evidence rejected: route semantics"
        );
        medians_nanoseconds.push(criterion_median(&criterion_bytes)?);
    }
    anyhow::ensure!(
        criterion_total == declared_criterion_total && route_total == declared_route_total,
        "evidence rejected: artifact subtotal binding"
    );
    Ok(ValidatedTimingMatrix {
        medians_nanoseconds,
        criterion_index_fingerprint,
        criterion_artifact_count: criterion.entry_count,
        criterion_artifact_bytes: criterion_total,
        route_index_fingerprint,
        route_artifact_count: route.entry_count,
        route_artifact_bytes: route_total,
    })
}

/// Traverse every canonical timing index entry with handle-bound campaign reads.
pub(super) fn validate_indexed_timing_artifacts(
    campaign: &CampaignDirectory,
    manifest: &SdJwtIssuanceQualificationManifest,
    plan: &SdJwtIssuanceQualificationPlan,
    completion: &CompletionWire,
    hardware: &HardwareProfileWire,
    read_budget: &mut AnalysisReadBudget,
) -> Result<ValidatedTimingMatrix> {
    validate_indexed_timing_artifacts_with_reader(
        manifest,
        plan,
        completion,
        hardware,
        |relative_path, maximum, label| {
            read_campaign_input(read_budget, campaign, relative_path, maximum, label)
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use super::*;
    use crate::issuance_qualification::{
        RequiredNullable, RouteBatchWire, RouteRecordWire, RouteStaticChunkWire, ROUTE_SCHEMA,
        STATIC_PARTITION_RULE_VERSION, WORK_ESTIMATOR_VERSION,
    };

    fn schedule_inputs() -> (
        SdJwtIssuanceQualificationManifest,
        SdJwtIssuanceQualificationPlan,
    ) {
        let bytes =
            include_bytes!("../../tests/fixtures/sd-jwt-issuance-qualification-manifest-v1.json");
        let manifest = serde_json::from_slice(bytes).unwrap();
        let plan = super::super::plan_for_manifest(&manifest, bytes).unwrap();
        (manifest, plan)
    }

    fn canonical_pretty<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn synthetic_hardware(campaign_id: &str) -> HardwareProfileWire {
        HardwareProfileWire {
            schema: "synthetic-test-only".to_owned(),
            campaign_id: campaign_id.to_owned(),
            operating_system_family: "linux".to_owned(),
            operating_system_version: None,
            kernel_version: None,
            architecture: "x86_64".to_owned(),
            cpu_vendor: None,
            cpu_model: None,
            physical_core_count: None,
            logical_cpu_count: 12,
            host_available_parallelism: 12,
            numa_node_count: None,
            total_memory_bytes: 8 * 1024 * 1024 * 1024,
            nominal_cpu_frequency_hz: None,
            virtualization_kind: "none".to_owned(),
            power_policy: "synthetic".to_owned(),
        }
    }

    fn route_bytes(process: &ScheduledProcess<'_>, worker_cap: u64) -> Vec<u8> {
        let adaptive = process.requested == "adaptive_candidate";
        let ready_batches = adaptive.then(|| {
            vec![RouteBatchWire {
                ordinal: 0,
                job_count: 5,
                estimated_work_bytes: RequiredNullable(Some(59)),
                work_estimate_status: "available".to_owned(),
                work_gate_evaluated: true,
                parallelism_gate_evaluated: true,
                budget_gate_evaluated: true,
                available_parallelism: RequiredNullable(Some(12)),
                selected_worker_count: RequiredNullable(Some(worker_cap)),
                leased_worker_count: RequiredNullable(Some(worker_cap)),
                budget_acquisition_result: "acquired".to_owned(),
                selected_mode: "native_parallel".to_owned(),
                selection_reason: "bounded_native".to_owned(),
                static_chunk_size: RequiredNullable(Some(2)),
                static_chunks: RequiredNullable(Some(vec![
                    RouteStaticChunkWire {
                        ordinal: 0,
                        job_count: 2,
                        estimated_work_bytes: 28,
                    },
                    RouteStaticChunkWire {
                        ordinal: 1,
                        job_count: 2,
                        estimated_work_bytes: 19,
                    },
                    RouteStaticChunkWire {
                        ordinal: 2,
                        job_count: 1,
                        estimated_work_bytes: 12,
                    },
                ])),
            }]
        });
        let wire = RouteRecordWire {
            schema: ROUTE_SCHEMA.to_owned(),
            benchmark_id: process.full_benchmark_id.to_owned(),
            fixture_id: process.fixture_id.to_owned(),
            stage: process.stage.to_owned(),
            requested: process.requested.to_owned(),
            effective: if adaptive {
                "bounded_native".to_owned()
            } else {
                "serial_oracle".to_owned()
            },
            executor_batches: RequiredNullable(adaptive.then_some(1)),
            serial_batches: RequiredNullable(adaptive.then_some(0)),
            native_batches: RequiredNullable(adaptive.then_some(1)),
            budget_fallback_batches: RequiredNullable(adaptive.then_some(0)),
            max_native_worker_count: if adaptive { worker_cap } else { 0 },
            worker_cap,
            host_available_parallelism: 12,
            work_estimator_version: WORK_ESTIMATOR_VERSION.to_owned(),
            static_partition_rule_version: STATIC_PARTITION_RULE_VERSION.to_owned(),
            ready_batches: RequiredNullable(ready_batches),
        };
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn placeholder_fingerprint() -> ArtifactFingerprint {
        fingerprint(b"synthetic bound placeholder").unwrap()
    }

    struct SyntheticIndexedFixture {
        manifest: SdJwtIssuanceQualificationManifest,
        plan: SdJwtIssuanceQualificationPlan,
        completion: CompletionWire,
        hardware: HardwareProfileWire,
        criterion_index: Vec<u8>,
        route_index: Vec<u8>,
        criterion: Vec<u8>,
        routes: BTreeMap<String, Vec<u8>>,
        criterion_paths: BTreeSet<String>,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one in-memory fixture binds all 10,560 indexed coordinate artifacts"
    )]
    fn synthetic_indexed_fixture() -> SyntheticIndexedFixture {
        let campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001";
        let (manifest, plan) = schedule_inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let criterion_bytes =
            include_bytes!("../../tests/fixtures/criterion-0.5.1/valid-estimates.json").to_vec();
        let criterion_fingerprint = fingerprint(&criterion_bytes).unwrap();
        let mut criterion_entries = Vec::with_capacity(schedule.iter().len());
        let mut route_entries = Vec::with_capacity(schedule.iter().len());
        let mut process_completions = Vec::with_capacity(schedule.iter().len());
        let mut routes = BTreeMap::new();
        let mut criterion_paths = BTreeSet::new();
        let placeholder = placeholder_fingerprint();
        for process in schedule.iter() {
            let criterion_path = process
                .relative_path(ArtifactRole::CriterionEstimate)
                .unwrap();
            let route_path = process.relative_path(ArtifactRole::Route).unwrap();
            let route_bytes = route_bytes(process, u64::try_from(manifest.worker_cap).unwrap());
            let route_fingerprint = fingerprint(&route_bytes).unwrap();
            criterion_paths.insert(criterion_path.clone());
            routes.insert(route_path.clone(), route_bytes);
            criterion_entries.push(ArtifactIndexEntry {
                global_round_ordinal: process.coordinate.global_round,
                cell_ordinal: process.coordinate.cell,
                expansion_position: process.coordinate.expansion,
                timing_process_id: process.timing_process_id.clone(),
                full_benchmark_id: process.full_benchmark_id.to_owned(),
                relative_path: criterion_path,
                fingerprint: criterion_fingerprint.clone(),
            });
            route_entries.push(ArtifactIndexEntry {
                global_round_ordinal: process.coordinate.global_round,
                cell_ordinal: process.coordinate.cell,
                expansion_position: process.coordinate.expansion,
                timing_process_id: process.timing_process_id.clone(),
                full_benchmark_id: process.full_benchmark_id.to_owned(),
                relative_path: route_path,
                fingerprint: route_fingerprint.clone(),
            });
            process_completions.push(super::super::ProcessCompletionWire {
                global_round_ordinal: process.coordinate.global_round,
                cell_ordinal: process.coordinate.cell,
                expansion_position: process.coordinate.expansion,
                timing_process_id: process.timing_process_id.clone(),
                full_benchmark_id: process.full_benchmark_id.to_owned(),
                process_intent_record_fingerprint: placeholder.clone(),
                process_start_record_fingerprint: placeholder.clone(),
                process_finish_record_fingerprint: placeholder.clone(),
                invocation_descriptor_fingerprint: placeholder.clone(),
                launch_barrier_receipt_fingerprint: placeholder.clone(),
                criterion_home_initial_inventory_fingerprint: placeholder.clone(),
                criterion_home_final_inventory_fingerprint: placeholder.clone(),
                criterion_artifact_fingerprint: criterion_fingerprint.clone(),
                route_artifact_fingerprint: route_fingerprint,
            });
        }
        let criterion_index = ArtifactIndex {
            schema: ArtifactKind::Criterion.schema().to_owned(),
            campaign_id: campaign_id.to_owned(),
            artifact_kind: ArtifactKind::Criterion.literal().to_owned(),
            entry_count: u32::try_from(criterion_entries.len()).unwrap(),
            entries: criterion_entries,
        };
        let route_index = ArtifactIndex {
            schema: ArtifactKind::Route.schema().to_owned(),
            campaign_id: campaign_id.to_owned(),
            artifact_kind: ArtifactKind::Route.literal().to_owned(),
            entry_count: u32::try_from(route_entries.len()).unwrap(),
            entries: route_entries,
        };
        let criterion_index_bytes = canonical_pretty(&criterion_index);
        let route_index_bytes = canonical_pretty(&route_index);
        let completion = CompletionWire {
            schema: "synthetic-test-only".to_owned(),
            campaign_id: campaign_id.to_owned(),
            created_at_utc_rfc3339_nanoseconds: "2026-08-29T12:34:56.123456789Z".to_owned(),
            created_at_monotonic_nanoseconds: 0,
            plan_fingerprint: placeholder.clone(),
            manifest_fingerprint: placeholder.clone(),
            external_anchor_channel_configuration_fingerprint: placeholder.clone(),
            genesis_header_fingerprint: placeholder.clone(),
            ordered_segment_fingerprints: vec![placeholder.clone()],
            terminal_segment_fingerprint: placeholder.clone(),
            terminal_observation_evidence_fingerprint: placeholder.clone(),
            ordered_test_window_attestation_fingerprints: vec![placeholder.clone()],
            first_monotonic_nanoseconds: 0,
            last_monotonic_nanoseconds: 0,
            segment_count: 1,
            sample_count: 0,
            process_intent_count: super::super::schedule::TOTAL_PROCESS_COUNT,
            process_start_count: super::super::schedule::TOTAL_PROCESS_COUNT,
            process_finish_count: super::super::schedule::TOTAL_PROCESS_COUNT,
            attestation_transition_count: 0,
            process_completions,
            criterion_artifact_set_fingerprint: fingerprint(&criterion_index_bytes).unwrap(),
            route_artifact_set_fingerprint: fingerprint(&route_index_bytes).unwrap(),
            first_quiet_window_evidence_fingerprint: placeholder,
            invalidating_event_count: 0,
            validity_status: "valid".to_owned(),
        };
        let hardware = synthetic_hardware(campaign_id);
        SyntheticIndexedFixture {
            manifest,
            plan,
            completion,
            hardware,
            criterion_index: criterion_index_bytes,
            route_index: route_index_bytes,
            criterion: criterion_bytes,
            routes,
            criterion_paths,
        }
    }

    #[test]
    fn synthetic_reader_traverses_all_10_560_indexed_timing_artifacts() {
        let SyntheticIndexedFixture {
            manifest,
            plan,
            completion,
            hardware,
            criterion_index: criterion_index_bytes,
            route_index: route_index_bytes,
            criterion: criterion_bytes,
            routes,
            criterion_paths,
        } = synthetic_indexed_fixture();
        let mut visited = BTreeSet::new();
        let matrix = validate_indexed_timing_artifacts_with_reader(
            &manifest,
            &plan,
            &completion,
            &hardware,
            |path, maximum, _| {
                let path = path.to_str().unwrap();
                visited.insert(path.to_owned());
                let bytes = match path {
                    "indexes/criterion-artifacts.json" => criterion_index_bytes.clone(),
                    "indexes/route-artifacts.json" => route_index_bytes.clone(),
                    _ if criterion_paths.contains(path) => criterion_bytes.clone(),
                    _ => routes
                        .get(path)
                        .cloned()
                        .context("unexpected synthetic path")?,
                };
                anyhow::ensure!(u64::try_from(bytes.len())? <= maximum);
                Ok(bytes)
            },
        )
        .unwrap();
        assert_eq!(matrix.medians_nanoseconds.len(), 10_560);
        assert_eq!(matrix.medians_nanoseconds.first(), Some(&100.0));
        assert_eq!(matrix.medians_nanoseconds.last(), Some(&100.0));
        assert_eq!(matrix.criterion_artifact_count, 10_560);
        assert_eq!(matrix.route_artifact_count, 10_560);
        assert_eq!(visited.len(), 21_122);
        assert_eq!(
            matrix.criterion_index_fingerprint,
            fingerprint(&criterion_index_bytes).unwrap()
        );
        assert_eq!(
            matrix.route_index_fingerprint,
            fingerprint(&route_index_bytes).unwrap()
        );
        assert_eq!(
            matrix.criterion_artifact_bytes,
            u64::try_from(criterion_bytes.len()).unwrap() * 10_560
        );
        assert_eq!(
            matrix.route_artifact_bytes,
            routes
                .values()
                .map(|bytes| u64::try_from(bytes.len()).unwrap())
                .sum::<u64>()
        );
    }

    #[test]
    fn subtotal_accounting_is_checked_and_fail_closed() {
        let mut total = MAX_ARTIFACT_BYTES;
        charge_subtotal(&mut total, 1, MAX_ARTIFACT_BYTES + 1).unwrap();
        assert_eq!(total, MAX_ARTIFACT_BYTES + 1);
        assert!(charge_subtotal(&mut total, 1, MAX_ARTIFACT_BYTES + 1).is_err());
        let mut overflow = u64::MAX;
        assert!(charge_subtotal(&mut overflow, 1, u64::MAX).is_err());

        let oversized_entry = ArtifactIndex {
            schema: String::new(),
            campaign_id: String::new(),
            artifact_kind: String::new(),
            entry_count: 1,
            entries: vec![ArtifactIndexEntry {
                global_round_ordinal: 0,
                cell_ordinal: 0,
                expansion_position: 0,
                timing_process_id: String::new(),
                full_benchmark_id: String::new(),
                relative_path: String::new(),
                fingerprint: ArtifactFingerprint {
                    sha256: "A".repeat(64),
                    byte_length: MAX_ARTIFACT_BYTES + 1,
                },
            }],
        };
        assert!(declared_artifact_total(&oversized_entry, u64::MAX).is_err());
        let aggregate = ArtifactIndex {
            entries: vec![
                ArtifactIndexEntry {
                    fingerprint: ArtifactFingerprint {
                        sha256: "A".repeat(64),
                        byte_length: MAX_ARTIFACT_BYTES,
                    },
                    ..oversized_entry.entries[0].clone()
                },
                ArtifactIndexEntry {
                    fingerprint: ArtifactFingerprint {
                        sha256: "B".repeat(64),
                        byte_length: 1,
                    },
                    ..oversized_entry.entries[0].clone()
                },
            ],
            entry_count: 2,
            ..oversized_entry
        };
        assert!(declared_artifact_total(&aggregate, MAX_ARTIFACT_BYTES).is_err());
    }

    #[test]
    fn valid_but_byte_different_criterion_rejects_a_stale_fingerprint() {
        let original = include_bytes!("../../tests/fixtures/criterion-0.5.1/valid-estimates.json");
        let expected = fingerprint(original).unwrap();
        let changed = String::from_utf8(original.to_vec())
            .unwrap()
            .replace("\"point_estimate\":100.0", "\"point_estimate\":101.0");
        assert!(criterion_median(changed.as_bytes()).is_ok());
        assert!(validate_artifact_bytes(changed.as_bytes(), &expected).is_err());
    }

    #[test]
    fn retained_reader_enforces_remaining_before_reading() {
        let temporary = tempfile::tempdir().unwrap();
        let campaign_path = temporary.path().join("campaign");
        fs::create_dir(&campaign_path).unwrap();
        fs::write(campaign_path.join("artifact.bin"), b"1234").unwrap();
        let campaign = CampaignDirectory::open(&campaign_path).unwrap();
        let mut budget = AnalysisReadBudget::default();
        assert_eq!(
            read_artifact_with_remaining(
                &mut budget,
                &campaign,
                Path::new("artifact.bin"),
                6,
                10,
                "test artifact"
            )
            .unwrap(),
            b"1234"
        );
        let mut budget = AnalysisReadBudget::default();
        assert!(read_artifact_with_remaining(
            &mut budget,
            &campaign,
            Path::new("artifact.bin"),
            7,
            10,
            "test artifact"
        )
        .is_err());
        let mut budget = AnalysisReadBudget::default();
        assert!(read_artifact_with_remaining(
            &mut budget,
            &campaign,
            Path::new("artifact.bin"),
            10,
            10,
            "test artifact"
        )
        .is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test enumerates each independent index mutation class"
    )]
    fn production_index_kernel_requires_exact_10_560_order_and_completion_binding() {
        let campaign_id = "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001";
        let bound = fingerprint(b"owned synthetic artifact").unwrap();
        let (manifest, plan) = schedule_inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let entries = schedule
            .iter()
            .map(|process| ArtifactIndexEntry {
                global_round_ordinal: process.coordinate.global_round,
                cell_ordinal: process.coordinate.cell,
                expansion_position: process.coordinate.expansion,
                timing_process_id: process.timing_process_id.clone(),
                full_benchmark_id: process.full_benchmark_id.to_owned(),
                relative_path: process
                    .relative_path(ArtifactRole::CriterionEstimate)
                    .unwrap(),
                fingerprint: bound.clone(),
            })
            .collect::<Vec<_>>();
        let valid = ArtifactIndex {
            schema: ArtifactKind::Criterion.schema().to_owned(),
            campaign_id: campaign_id.to_owned(),
            artifact_kind: ArtifactKind::Criterion.literal().to_owned(),
            entry_count: u32::try_from(schedule.iter().len()).unwrap(),
            entries,
        };
        for (position, process) in schedule.iter().enumerate() {
            validate_index_entry(
                &valid,
                ArtifactKind::Criterion,
                campaign_id,
                position,
                schedule.iter().len(),
                process,
                &bound,
            )
            .unwrap();
        }
        let mut missing = valid.clone();
        missing.entries.pop();
        assert!(validate_index_entry(
            &missing,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &bound
        )
        .is_err());
        let mut extra = valid.clone();
        extra.entries.push(extra.entries.last().unwrap().clone());
        extra.entry_count += 1;
        assert!(validate_index_entry(
            &extra,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &bound
        )
        .is_err());
        let mut reordered = valid.clone();
        reordered.entries.swap(1_642, 1_643);
        assert!(validate_index_entry(
            &reordered,
            ArtifactKind::Criterion,
            campaign_id,
            1_642,
            schedule.iter().len(),
            schedule.iter().nth(1_642).unwrap(),
            &bound
        )
        .is_err());
        let mut duplicate = valid.clone();
        duplicate.entries[1] = duplicate.entries[0].clone();
        assert!(validate_index_entry(
            &duplicate,
            ArtifactKind::Criterion,
            campaign_id,
            1,
            schedule.iter().len(),
            schedule.iter().nth(1).unwrap(),
            &bound
        )
        .is_err());
        let mut wrong_coordinate = valid.clone();
        wrong_coordinate.entries[0].cell_ordinal = 1;
        assert!(validate_index_entry(
            &wrong_coordinate,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &bound
        )
        .is_err());
        let mut wrong_path = valid.clone();
        wrong_path.entries[0].relative_path.push_str(".stale");
        assert!(validate_index_entry(
            &wrong_path,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &bound
        )
        .is_err());
        let mut wrong_id = valid.clone();
        wrong_id.entries[0].full_benchmark_id.push_str("/wrong");
        assert!(validate_index_entry(
            &wrong_id,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &bound
        )
        .is_err());
        let wrong_bound = fingerprint(b"other bytes").unwrap();
        assert!(validate_index_entry(
            &valid,
            ArtifactKind::Criterion,
            campaign_id,
            0,
            schedule.iter().len(),
            schedule.iter().next().unwrap(),
            &wrong_bound
        )
        .is_err());
    }
}
