//! Fail-closed validation of complete retained issuance measurement evidence.

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

#[allow(dead_code, reason = "consumed by the disconnected slice-C entrypoint")]
pub(super) struct ValidatedMedianMatrix {
    pub medians_nanoseconds: Vec<f64>,
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
    anyhow::ensure!(
        index.schema == kind.schema()
            && index.campaign_id == campaign_id
            && index.artifact_kind == kind.literal()
            && usize::try_from(index.entry_count) == Ok(schedule_len)
            && index.entries.len() == schedule_len,
        "evidence rejected: index envelope"
    );
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
    dead_code,
    clippy::too_many_lines,
    reason = "ordered streaming validation keeps every cross-artifact binding in one auditable pipeline"
)]
pub(super) fn validate_complete_campaign(
    campaign: &CampaignDirectory,
    manifest: &SdJwtIssuanceQualificationManifest,
    plan: &SdJwtIssuanceQualificationPlan,
    completion: &CompletionWire,
    hardware: &HardwareProfileWire,
    read_budget: &mut AnalysisReadBudget,
) -> Result<ValidatedMedianMatrix> {
    let schedule =
        QualificationSchedule::new(plan, manifest).context("evidence rejected: schedule")?;
    let criterion_index_bytes = read_campaign_input(
        read_budget,
        campaign,
        Path::new("indexes/criterion-artifacts.json"),
        MAX_INDEX_BYTES,
        "criterion index",
    )?;
    let route_index_bytes = read_campaign_input(
        read_budget,
        campaign,
        Path::new("indexes/route-artifacts.json"),
        MAX_INDEX_BYTES,
        "route index",
    )?;
    anyhow::ensure!(
        fingerprint(&criterion_index_bytes)? == completion.criterion_artifact_set_fingerprint
            && fingerprint(&route_index_bytes)? == completion.route_artifact_set_fingerprint,
        "evidence rejected: completion index fingerprint"
    );
    let criterion: ArtifactIndex =
        parse_canonical_pretty(&criterion_index_bytes, "criterion index")?;
    let route: ArtifactIndex = parse_canonical_pretty(&route_index_bytes, "route index")?;
    anyhow::ensure!(
        completion.process_completions.len() == schedule.iter().len(),
        "evidence rejected: completion coverage"
    );
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
        let criterion_bytes = read_artifact_with_remaining(
            read_budget,
            campaign,
            Path::new(&criterion_entry.relative_path),
            criterion_total,
            MAX_CRITERION_SUBTOTAL_BYTES,
            "criterion estimates",
        )?;
        let route_bytes = read_artifact_with_remaining(
            read_budget,
            campaign,
            Path::new(&route_entry.relative_path),
            route_total,
            MAX_ROUTE_SUBTOTAL_BYTES,
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
    Ok(ValidatedMedianMatrix {
        medians_nanoseconds,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

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

    #[test]
    fn subtotal_accounting_is_checked_and_fail_closed() {
        let mut total = MAX_ARTIFACT_BYTES;
        charge_subtotal(&mut total, 1, MAX_ARTIFACT_BYTES + 1).unwrap();
        assert_eq!(total, MAX_ARTIFACT_BYTES + 1);
        assert!(charge_subtotal(&mut total, 1, MAX_ARTIFACT_BYTES + 1).is_err());
        let mut overflow = u64::MAX;
        assert!(charge_subtotal(&mut overflow, 1, u64::MAX).is_err());
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
