//! Validated, canonical process schedule and artifact roles for qualification.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use marty_perf_schema::{SdJwtIssuanceQualificationManifest, SdJwtIssuanceQualificationPlan};

const EXECUTION_NESTING: &str = "global_round_then_manifest_cell_then_expansion_position";
const ORDINAL_ALIGNMENT: &str = "shared_campaign_cluster_across_all_cells";
const SERIAL_TIMING_PROCESSES: u32 = 1;
pub(super) const PAIRED_CELL_COUNT: usize = 66;
pub(super) const PROCESSES_PER_SUPERBLOCK: u32 = 8;
pub(super) const SUPERBLOCK_ORDERS: [&str; 20] = [
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
    "BAAB_FIRST",
    "ABBA_FIRST",
];
pub(super) const ABBA_EXPANSION: [&str; 8] = [
    "serial", "adaptive", "adaptive", "serial", "adaptive", "serial", "serial", "adaptive",
];
pub(super) const BAAB_EXPANSION: [&str; 8] = [
    "adaptive", "serial", "serial", "adaptive", "serial", "adaptive", "adaptive", "serial",
];
pub(super) const ROUND_COUNT: u32 = 20;
pub(super) const CELL_COUNT: u32 = 66;
pub(super) const EXPANSION_COUNT: u32 = PROCESSES_PER_SUPERBLOCK;
pub(super) const PROCESSES_PER_ROUND: u32 = CELL_COUNT * EXPANSION_COUNT;
pub(super) const TOTAL_PROCESS_COUNT: u32 = ROUND_COUNT * PROCESSES_PER_ROUND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessCoordinate {
    pub(super) global_round: u32,
    pub(super) cell: u32,
    pub(super) expansion: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ArtifactRole {
    Route,
    Criterion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScheduledProcess<'a> {
    pub(super) coordinate: ProcessCoordinate,
    pub(super) timing_process_id: String,
    pub(super) full_benchmark_id: &'a str,
    pub(super) fixture_id: &'a str,
    pub(super) stage: &'a str,
    pub(super) requested: &'static str,
}

impl ScheduledProcess<'_> {
    pub(super) fn relative_path(&self, role: ArtifactRole) -> Result<String> {
        let coordinate = self.coordinate;
        match role {
            ArtifactRole::Route => Ok(format!(
                "routes/r{:02}_c{:02}_e{}.ndjson",
                coordinate.global_round, coordinate.cell, coordinate.expansion
            )),
            ArtifactRole::Criterion => {
                let function_id = self
                    .full_benchmark_id
                    .strip_prefix("sd_jwt_issuance/")
                    .filter(|value| !value.is_empty())
                    .context("qualification schedule contains a noncanonical Criterion ID")?;
                Ok(format!(
                    "criterion/r{:02}_c{:02}_e{}/sd_jwt_issuance/{function_id}/new/estimates.json",
                    coordinate.global_round, coordinate.cell, coordinate.expansion
                ))
            }
        }
    }
}

pub(super) struct QualificationSchedule<'a> {
    processes: Vec<ScheduledProcess<'a>>,
}

impl<'a> QualificationSchedule<'a> {
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed constructor validates the entire contract before exposing iteration"
    )]
    pub(super) fn new(
        plan: &SdJwtIssuanceQualificationPlan,
        manifest: &'a SdJwtIssuanceQualificationManifest,
    ) -> Result<Self> {
        let processes_per_cell = ROUND_COUNT
            .checked_mul(EXPANSION_COUNT)
            .context("qualification schedule processes-per-cell overflow")?;

        anyhow::ensure!(
            manifest.paired_cell_count == PAIRED_CELL_COUNT
                && manifest.paired_cells.len() == PAIRED_CELL_COUNT
                && manifest.benchmark_id_count == PAIRED_CELL_COUNT * 2
                && manifest.criterion_ids.len() == PAIRED_CELL_COUNT * 2,
            "qualification schedule manifest cardinality mismatch"
        );
        anyhow::ensure!(
            plan.paired_cell_count == PAIRED_CELL_COUNT
                && plan.benchmark_id_count == PAIRED_CELL_COUNT * 2
                && plan.superblocks_per_cell == ROUND_COUNT
                && plan.processes_per_superblock == EXPANSION_COUNT
                && plan.processes_per_cell == processes_per_cell
                && plan.total_processes == TOTAL_PROCESS_COUNT
                && plan.global_rounds.cells_per_round == CELL_COUNT
                && plan.global_rounds.processes_per_round == PROCESSES_PER_ROUND,
            "qualification schedule plan cardinality mismatch"
        );
        anyhow::ensure!(
            plan.global_rounds.execution_nesting == EXECUTION_NESTING
                && plan.global_rounds.ordinal_alignment == ORDINAL_ALIGNMENT
                && plan.global_rounds.concurrent_timing_processes == SERIAL_TIMING_PROCESSES,
            "qualification schedule execution contract mismatch"
        );
        anyhow::ensure!(
            plan.superblock_orders == SUPERBLOCK_ORDERS.map(str::to_owned).to_vec()
                && plan.abba_expansion == ABBA_EXPANSION.map(str::to_owned).to_vec()
                && plan.baab_expansion == BAAB_EXPANSION.map(str::to_owned).to_vec(),
            "qualification schedule route expansion mismatch"
        );

        let criterion_ids: BTreeSet<&str> =
            manifest.criterion_ids.iter().map(String::as_str).collect();
        anyhow::ensure!(
            criterion_ids.len() == manifest.criterion_ids.len(),
            "qualification schedule contains duplicate Criterion IDs"
        );
        let paired_ids: BTreeSet<&str> = manifest
            .paired_cells
            .iter()
            .flat_map(|cell| [cell.serial_id.as_str(), cell.adaptive_id.as_str()])
            .collect();
        anyhow::ensure!(
            paired_ids.len() == PAIRED_CELL_COUNT * 2 && paired_ids == criterion_ids,
            "qualification schedule paired IDs are not unique and complete"
        );
        anyhow::ensure!(
            manifest.paired_cells.chunks_exact(2).all(|stages| {
                stages[0].fixture_id == stages[1].fixture_id
                    && stages[0].stage == "executor_assembly"
                    && stages[1].stage == "full_issuance"
            }),
            "qualification schedule manifest nesting mismatch"
        );

        let capacity = usize::try_from(TOTAL_PROCESS_COUNT)
            .context("qualification schedule capacity overflow")?;
        let mut processes = Vec::with_capacity(capacity);
        for (round, order) in SUPERBLOCK_ORDERS.iter().enumerate() {
            let expansion = match *order {
                "ABBA_FIRST" => &ABBA_EXPANSION,
                "BAAB_FIRST" => &BAAB_EXPANSION,
                _ => anyhow::bail!("qualification schedule contains an unknown order label"),
            };
            for (cell, paired) in manifest.paired_cells.iter().enumerate() {
                for (position, route) in expansion.iter().enumerate() {
                    let (full_benchmark_id, requested) = match *route {
                        "serial" => (paired.serial_id.as_str(), "serial_oracle"),
                        "adaptive" => (paired.adaptive_id.as_str(), "adaptive_candidate"),
                        _ => anyhow::bail!(
                            "qualification schedule contains an unknown route expansion"
                        ),
                    };
                    let coordinate = ProcessCoordinate {
                        global_round: u32::try_from(round)
                            .context("qualification schedule round overflow")?,
                        cell: u32::try_from(cell)
                            .context("qualification schedule cell overflow")?,
                        expansion: u32::try_from(position)
                            .context("qualification schedule expansion overflow")?,
                    };
                    processes.push(ScheduledProcess {
                        timing_process_id: format!(
                            "r{:02}-c{:02}-e{}",
                            coordinate.global_round, coordinate.cell, coordinate.expansion
                        ),
                        coordinate,
                        full_benchmark_id,
                        fixture_id: &paired.fixture_id,
                        stage: &paired.stage,
                        requested,
                    });
                }
            }
        }
        anyhow::ensure!(
            processes.len() == capacity,
            "qualification schedule did not expand to the exact total"
        );
        Ok(Self { processes })
    }

    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = &ScheduledProcess<'a>> {
        self.processes.iter()
    }

    pub(super) fn get(&self, coordinate: ProcessCoordinate) -> Option<&ScheduledProcess<'a>> {
        let cells = u32::try_from(PAIRED_CELL_COUNT).ok()?;
        let position = coordinate
            .global_round
            .checked_mul(cells.checked_mul(PROCESSES_PER_SUPERBLOCK)?)?
            .checked_add(coordinate.cell.checked_mul(PROCESSES_PER_SUPERBLOCK)?)?
            .checked_add(coordinate.expansion)?;
        let process = self.processes.get(usize::try_from(position).ok()?)?;
        (process.coordinate == coordinate).then_some(process)
    }

    pub(super) fn parse_route_path(path: &Path) -> Option<ProcessCoordinate> {
        let value = path.to_str()?;
        let coordinate = value.strip_prefix("routes/r")?.strip_suffix(".ndjson")?;
        let (round, rest) = coordinate.split_once("_c")?;
        let (cell, expansion) = rest.split_once("_e")?;
        if round.len() != 2
            || cell.len() != 2
            || expansion.len() != 1
            || !round
                .bytes()
                .chain(cell.bytes())
                .chain(expansion.bytes())
                .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let coordinate = ProcessCoordinate {
            global_round: round.parse().ok()?,
            cell: cell.parse().ok()?,
            expansion: expansion.parse().ok()?,
        };
        (coordinate.global_round < u32::try_from(SUPERBLOCK_ORDERS.len()).ok()?
            && coordinate.cell < u32::try_from(PAIRED_CELL_COUNT).ok()?
            && coordinate.expansion < PROCESSES_PER_SUPERBLOCK
            && value
                == format!(
                    "routes/r{:02}_c{:02}_e{}.ndjson",
                    coordinate.global_round, coordinate.cell, coordinate.expansion
                ))
        .then_some(coordinate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> (
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
    fn exact_size_order_endpoints_routes_ids_and_paths_are_canonical() {
        let (manifest, plan) = inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        assert_eq!(schedule.iter().len(), 10_560);
        let first = schedule.iter().next().unwrap();
        assert_eq!(
            first.coordinate,
            ProcessCoordinate {
                global_round: 0,
                cell: 0,
                expansion: 0
            }
        );
        assert_eq!(first.requested, "serial_oracle");
        assert_eq!(first.timing_process_id, "r00-c00-e0");
        assert_eq!(
            first.relative_path(ArtifactRole::Route).unwrap(),
            "routes/r00_c00_e0.ndjson"
        );
        assert!(first
            .relative_path(ArtifactRole::Criterion)
            .unwrap()
            .starts_with("criterion/r00_c00_e0/sd_jwt_issuance/"));
        let abba = schedule
            .get(ProcessCoordinate {
                global_round: 0,
                cell: 0,
                expansion: 1,
            })
            .unwrap();
        assert_eq!(abba.requested, "adaptive_candidate");
        let baab = schedule
            .get(ProcessCoordinate {
                global_round: 1,
                cell: 0,
                expansion: 0,
            })
            .unwrap();
        assert_eq!(baab.requested, "adaptive_candidate");
        let last = schedule.iter().last().unwrap();
        assert_eq!(
            last.coordinate,
            ProcessCoordinate {
                global_round: 19,
                cell: 65,
                expansion: 7
            }
        );
        assert_eq!(
            QualificationSchedule::parse_route_path(Path::new("routes/r19_c65_e7.ndjson")),
            Some(last.coordinate)
        );
        assert!(
            QualificationSchedule::parse_route_path(Path::new("routes/r20_c00_e0.ndjson"))
                .is_none()
        );
        assert!(schedule
            .get(ProcessCoordinate {
                global_round: 20,
                cell: 0,
                expansion: 0
            })
            .is_none());
    }

    #[test]
    fn all_cells_stages_and_expansions_are_covered() {
        let (manifest, plan) = inputs();
        let schedule = QualificationSchedule::new(&plan, &manifest).unwrap();
        let cells: BTreeSet<_> = schedule
            .iter()
            .map(|process| (process.coordinate.cell, process.stage))
            .collect();
        assert_eq!(cells.len(), 66);
        assert_eq!(
            schedule
                .iter()
                .filter(|process| process.coordinate.global_round == 0
                    && process.coordinate.expansion == 0
                    && process.stage == "executor_assembly")
                .count(),
            33
        );
        assert_eq!(
            schedule
                .iter()
                .filter(|process| process.coordinate.global_round == 0
                    && process.coordinate.expansion == 0
                    && process.stage == "full_issuance")
                .count(),
            33
        );
        for cell in 0..66 {
            for expansion in 0..8 {
                assert!(schedule
                    .get(ProcessCoordinate {
                        global_round: 0,
                        cell,
                        expansion
                    })
                    .is_some());
            }
        }
    }

    #[test]
    fn malformed_contracts_fail_before_an_iterator_exists() {
        let (manifest, plan) = inputs();
        let mut cases: Vec<(
            SdJwtIssuanceQualificationManifest,
            SdJwtIssuanceQualificationPlan,
        )> = Vec::new();
        let mut changed = plan.clone();
        changed.total_processes -= 1;
        cases.push((manifest.clone(), changed));
        let mut changed = plan.clone();
        changed.global_rounds.execution_nesting.push_str("_changed");
        cases.push((manifest.clone(), changed));
        let mut changed = plan.clone();
        changed.global_rounds.concurrent_timing_processes = 2;
        cases.push((manifest.clone(), changed));
        let mut changed = plan.clone();
        changed.superblock_orders[0] = "UNKNOWN".into();
        cases.push((manifest.clone(), changed));
        let mut changed = plan.clone();
        changed.abba_expansion.pop();
        cases.push((manifest.clone(), changed));
        let mut changed_manifest = manifest.clone();
        changed_manifest.paired_cells.pop();
        cases.push((changed_manifest, plan.clone()));
        let mut changed_manifest = manifest.clone();
        changed_manifest.criterion_ids.pop();
        cases.push((changed_manifest, plan.clone()));
        let mut changed_manifest = manifest.clone();
        changed_manifest.criterion_ids[1] = changed_manifest.criterion_ids[0].clone();
        cases.push((changed_manifest, plan.clone()));
        let mut changed_manifest = manifest.clone();
        changed_manifest.paired_cells.swap(1, 2);
        cases.push((changed_manifest, plan.clone()));
        for (manifest, plan) in cases {
            assert!(QualificationSchedule::new(&plan, &manifest).is_err());
        }
        let mut overflow = plan;
        overflow.superblocks_per_cell = u32::MAX;
        assert!(QualificationSchedule::new(&overflow, &manifest).is_err());
    }
}
