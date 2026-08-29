//! Frozen, deterministic planning for SD-JWT issuance qualification.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use marty_perf_schema::{
    ArtifactFingerprint, SdJwtIssuanceBootstrapProtocol, SdJwtIssuanceCriterionProtocol,
    SdJwtIssuanceDiscoveryProtocol, SdJwtIssuanceEffectProtocol,
    SdJwtIssuanceQualificationManifest, SdJwtIssuanceQualificationPlan,
};
use sha2::{Digest, Sha256};

const MANIFEST_SCHEMA: &str = "sd_jwt_issuance_qualification_manifest_v1";
const PLAN_SCHEMA: &str = "marty.performance/sd-jwt-issuance-plan/v2";
const BENCHMARK_GROUP_ID: &str = "sd_jwt_issuance";
const ROUTE_SCHEMA: &str = "sd_jwt_issuance_route_v2";
const WORK_ESTIMATOR_VERSION: &str = "issuance_work_bytes_v1";
const STATIC_PARTITION_RULE_VERSION: &str = "contiguous_ceil_chunks_v1";
const FIXTURE_CASE_COUNT: usize = 33;
const BENCHMARK_ID_COUNT: usize = 132;
const PAIRED_CELL_COUNT: usize = 66;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const QUIET_WINDOW_SECONDS: u64 = 45 * 60;
const PROCESSES_PER_SUPERBLOCK: u32 = 8;

const SUPERBLOCK_ORDERS: [&str; 20] = [
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
const ABBA_EXPANSION: [&str; 8] = [
    "serial", "adaptive", "adaptive", "serial", "adaptive", "serial", "serial", "adaptive",
];
const BAAB_EXPANSION: [&str; 8] = [
    "adaptive", "serial", "serial", "adaptive", "serial", "adaptive", "adaptive", "serial",
];

pub(crate) fn write_plan(manifest_path: &Path, output_path: &Path) -> Result<()> {
    anyhow::ensure!(
        output_path.is_absolute(),
        "qualification plan output path must be absolute"
    );
    let (manifest, manifest_bytes) = load_manifest(manifest_path)?;
    let plan = plan_for_manifest(&manifest, &manifest_bytes)?;
    let mut encoded = serde_json::to_vec_pretty(&plan).context("serialize qualification plan")?;
    encoded.push(b'\n');

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .with_context(|| format!("create qualification plan {}", output_path.display()))?;
    output
        .write_all(&encoded)
        .with_context(|| format!("write qualification plan {}", output_path.display()))?;
    output
        .flush()
        .with_context(|| format!("flush qualification plan {}", output_path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync qualification plan {}", output_path.display()))?;
    println!(
        "Frozen {} paired cells and {} fresh processes in {}.",
        plan.paired_cell_count,
        plan.total_processes,
        output_path.display()
    );
    Ok(())
}

fn load_manifest(path: &Path) -> Result<(SdJwtIssuanceQualificationManifest, Vec<u8>)> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect issuance qualification manifest {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "issuance qualification manifest must be a file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_MANIFEST_BYTES,
        "issuance qualification manifest exceeds {MAX_MANIFEST_BYTES} bytes"
    );
    let bytes = fs::read(path)
        .with_context(|| format!("read issuance qualification manifest {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).context("manifest byte length overflow")? <= MAX_MANIFEST_BYTES,
        "issuance qualification manifest changed beyond the size limit while reading"
    );
    validate_canonical_json_bytes(&bytes)?;
    let manifest: SdJwtIssuanceQualificationManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse issuance qualification manifest {}", path.display()))?;
    validate_manifest(&manifest)?;

    let mut canonical = serde_json::to_vec_pretty(&manifest)
        .context("serialize canonical qualification manifest")?;
    canonical.push(b'\n');
    anyhow::ensure!(
        bytes == canonical,
        "issuance qualification manifest is not the canonical v1 byte representation"
    );
    Ok((manifest, bytes))
}

fn validate_canonical_json_bytes(bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(!bytes.is_empty(), "qualification manifest is empty");
    anyhow::ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "qualification manifest must not contain a UTF-8 BOM"
    );
    anyhow::ensure!(
        std::str::from_utf8(bytes).is_ok(),
        "qualification manifest must be UTF-8"
    );
    anyhow::ensure!(
        !bytes.contains(&b'\r'),
        "qualification manifest must use LF line endings"
    );
    anyhow::ensure!(
        bytes.ends_with(b"\n") && !bytes.ends_with(b"\n\n"),
        "qualification manifest must end in exactly one LF"
    );
    Ok(())
}

fn validate_manifest(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    validate_manifest_contract(manifest)?;
    validate_cases(manifest)?;
    validate_paired_matrix(manifest)
}

fn validate_manifest_contract(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    anyhow::ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "unexpected manifest schema"
    );
    anyhow::ensure!(
        manifest.benchmark_group_id == BENCHMARK_GROUP_ID,
        "unexpected Criterion benchmark group"
    );
    anyhow::ensure!(
        manifest.fixture_case_count == FIXTURE_CASE_COUNT
            && manifest.cases.len() == FIXTURE_CASE_COUNT,
        "qualification manifest must contain exactly {FIXTURE_CASE_COUNT} cases"
    );
    anyhow::ensure!(
        manifest.benchmark_id_count == BENCHMARK_ID_COUNT
            && manifest.criterion_ids.len() == BENCHMARK_ID_COUNT,
        "qualification manifest must contain exactly {BENCHMARK_ID_COUNT} Criterion IDs"
    );
    anyhow::ensure!(
        manifest.paired_cell_count == PAIRED_CELL_COUNT
            && manifest.paired_cells.len() == PAIRED_CELL_COUNT,
        "qualification manifest must contain exactly {PAIRED_CELL_COUNT} paired cells"
    );
    anyhow::ensure!(
        manifest.route_schema == ROUTE_SCHEMA,
        "unexpected route schema"
    );
    anyhow::ensure!(
        manifest.work_estimator_version == WORK_ESTIMATOR_VERSION,
        "unexpected work-estimator version"
    );
    anyhow::ensure!(
        manifest.static_partition_rule_version == STATIC_PARTITION_RULE_VERSION,
        "unexpected static-partition version"
    );
    anyhow::ensure!(
        (1..=64).contains(&manifest.worker_cap),
        "worker cap is outside the supported qualification range"
    );
    anyhow::ensure!(
        manifest.mechanical_benchmark_thresholds.min_jobs == 2
            && manifest
                .mechanical_benchmark_thresholds
                .min_estimated_work_bytes
                == 1,
        "unexpected mechanical benchmark thresholds"
    );
    anyhow::ensure!(
        manifest.qualified_issuance_thresholds.is_none(),
        "production issuance thresholds must remain unqualified"
    );
    Ok(())
}

fn validate_cases(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    let mut fixture_ids = BTreeSet::new();
    for case in &manifest.cases {
        anyhow::ensure!(
            valid_identifier(&case.fixture_id),
            "invalid qualification fixture identifier"
        );
        anyhow::ensure!(
            fixture_ids.insert(case.fixture_id.as_str()),
            "duplicate qualification fixture identifier"
        );
        anyhow::ensure!(
            (1..=512).contains(&case.disclosure_count),
            "fixture disclosure count is outside the qualification matrix"
        );
    }
    Ok(())
}

fn validate_paired_matrix(manifest: &SdJwtIssuanceQualificationManifest) -> Result<()> {
    let criterion_prefix = format!("{}/", manifest.benchmark_group_id);
    let mut criterion_ids = BTreeSet::new();
    for id in &manifest.criterion_ids {
        anyhow::ensure!(
            id.starts_with(&criterion_prefix) && valid_criterion_id(id),
            "invalid full Criterion benchmark ID"
        );
        anyhow::ensure!(
            criterion_ids.insert(id.as_str()),
            "duplicate full Criterion benchmark ID"
        );
    }

    let mut paired_ids = BTreeSet::new();
    for (case_ordinal, case) in manifest.cases.iter().enumerate() {
        for (stage_ordinal, expected_stage) in ["executor_assembly", "full_issuance"]
            .into_iter()
            .enumerate()
        {
            let cell = &manifest.paired_cells[case_ordinal * 2 + stage_ordinal];
            anyhow::ensure!(
                cell.fixture_id == case.fixture_id && cell.stage == expected_stage,
                "paired cells must follow case order and executor/full stage order"
            );
            anyhow::ensure!(
                cell.serial_id.contains("__r_so__")
                    && cell.adaptive_id.contains("__r_ac__")
                    && cell.serial_id != cell.adaptive_id,
                "paired cell route identities are invalid"
            );
            anyhow::ensure!(
                criterion_ids.contains(cell.serial_id.as_str())
                    && criterion_ids.contains(cell.adaptive_id.as_str()),
                "paired cell references an unknown Criterion ID"
            );
            anyhow::ensure!(
                paired_ids.insert(cell.serial_id.as_str())
                    && paired_ids.insert(cell.adaptive_id.as_str()),
                "Criterion ID is reused across paired cells"
            );
        }
    }
    anyhow::ensure!(
        paired_ids == criterion_ids,
        "paired cells do not cover the complete Criterion ID set"
    );
    let expected_registration_order = manifest.paired_cells.chunks_exact(2).flat_map(|stages| {
        [
            stages[0].serial_id.as_str(),
            stages[1].serial_id.as_str(),
            stages[0].adaptive_id.as_str(),
            stages[1].adaptive_id.as_str(),
        ]
    });
    anyhow::ensure!(
        manifest
            .criterion_ids
            .iter()
            .map(String::as_str)
            .eq(expected_registration_order),
        "Criterion IDs do not follow canonical case, route, and stage registration order"
    );
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_criterion_id(value: &str) -> bool {
    (1..=512).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

fn plan_for_manifest(
    manifest: &SdJwtIssuanceQualificationManifest,
    manifest_bytes: &[u8],
) -> Result<SdJwtIssuanceQualificationPlan> {
    validate_manifest(manifest)?;
    let manifest_byte_length =
        u64::try_from(manifest_bytes.len()).context("manifest byte length overflow")?;
    let superblocks_per_cell =
        u32::try_from(SUPERBLOCK_ORDERS.len()).context("superblock count overflow")?;
    let processes_per_cell = superblocks_per_cell
        .checked_mul(PROCESSES_PER_SUPERBLOCK)
        .context("processes per cell overflow")?;
    let total_processes = processes_per_cell
        .checked_mul(u32::try_from(PAIRED_CELL_COUNT).context("paired cell count overflow")?)
        .context("total process count overflow")?;

    let plan = SdJwtIssuanceQualificationPlan {
        schema: PLAN_SCHEMA.to_owned(),
        manifest: ArtifactFingerprint {
            sha256: hex::encode_upper(Sha256::digest(manifest_bytes)),
            byte_length: manifest_byte_length,
        },
        manifest_schema: MANIFEST_SCHEMA.to_owned(),
        route_schema: manifest.route_schema.clone(),
        work_estimator_version: manifest.work_estimator_version.clone(),
        static_partition_rule_version: manifest.static_partition_rule_version.clone(),
        worker_cap: manifest.worker_cap,
        fixture_case_count: manifest.fixture_case_count,
        paired_cell_count: manifest.paired_cell_count,
        benchmark_id_count: manifest.benchmark_id_count,
        quiet_window_seconds: QUIET_WINDOW_SECONDS,
        quiet_windows: vec![
            "before_correctness_and_build".to_owned(),
            "after_fixed_binary_before_timing".to_owned(),
        ],
        fixed_binary_same_head: true,
        criterion: SdJwtIssuanceCriterionProtocol {
            sample_size: 50,
            warm_up_seconds: 15,
            measurement_seconds: 10,
            confidence_level: 0.95,
            no_plot: true,
            primary_statistic: "median.point_estimate".to_owned(),
        },
        superblock_orders: SUPERBLOCK_ORDERS.map(str::to_owned).to_vec(),
        abba_expansion: ABBA_EXPANSION.map(str::to_owned).to_vec(),
        baab_expansion: BAAB_EXPANSION.map(str::to_owned).to_vec(),
        superblocks_per_cell,
        processes_per_superblock: PROCESSES_PER_SUPERBLOCK,
        processes_per_cell,
        total_processes,
        bootstrap: SdJwtIssuanceBootstrapProtocol {
            replicates: 100_000,
            confidence_level: 0.95,
            rng: "splitmix64".to_owned(),
            seed: 2_453_812_215,
            quantile_method: "type_7".to_owned(),
            resampling_unit: "whole_superblock".to_owned(),
            simultaneous_band: "common_family_max_deviation_d_s_p".to_owned(),
        },
        effects: SdJwtIssuanceEffectProtocol {
            orientation: "ln(adaptive_median_ns)-ln(serial_median_ns)".to_owned(),
            abba_serial_first_pairs: vec![[1, 0], [7, 6]],
            abba_adaptive_first_pairs: vec![[2, 3], [4, 5]],
            baab_serial_first_pairs: vec![[3, 2], [5, 4]],
            baab_adaptive_first_pairs: vec![[0, 1], [6, 7]],
            s_definition: "mean(serial_first_pairs)".to_owned(),
            p_definition: "mean(adaptive_first_normalized_pairs)".to_owned(),
            d_definition: "(S+P)/2".to_owned(),
            o_definition: "S-P".to_owned(),
            primary_effects: vec!["D".to_owned(), "S".to_owned(), "P".to_owned()],
            disclosure_only_effects: vec!["O".to_owned()],
        },
        discovery: SdJwtIssuanceDiscoveryProtocol {
            required_ready_batch_count: 1,
            required_stages: vec!["executor_assembly".to_owned(), "full_issuance".to_owned()],
            percent_transform: "100.0 * (exp(effect) - 1.0)".to_owned(),
            d_upper_percent_less_than: -5.0,
            s_upper_percent_less_than: 0.0,
            p_upper_percent_less_than: 0.0,
            selection_rule: "unique_inclusion_maximal_else_none".to_owned(),
        },
        production_activation_separate: true,
    };
    validate_plan_schema(&plan)?;
    Ok(plan)
}

fn validate_plan_schema(plan: &SdJwtIssuanceQualificationPlan) -> Result<()> {
    anyhow::ensure!(
        plan.schema == PLAN_SCHEMA,
        "qualification plan schema must be the percent-domain v2 contract"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use marty_perf_schema::{
        SdJwtIssuanceQualificationCase, SdJwtIssuanceQualificationCell, SdJwtIssuanceThresholds,
    };

    use super::*;

    fn manifest() -> SdJwtIssuanceQualificationManifest {
        let cases = (0..FIXTURE_CASE_COUNT)
            .map(|ordinal| SdJwtIssuanceQualificationCase {
                fixture_id: format!("fixture_{ordinal:02}"),
                disclosure_count: 1 + ordinal,
            })
            .collect::<Vec<_>>();
        let mut criterion_ids = Vec::with_capacity(BENCHMARK_ID_COUNT);
        let mut paired_cells = Vec::with_capacity(PAIRED_CELL_COUNT);
        for case in &cases {
            let executor_serial = format!("sd_jwt_issuance/v2__s_ea__r_so__f_{}", case.fixture_id);
            let full_serial = format!("sd_jwt_issuance/v2__s_fi__r_so__f_{}", case.fixture_id);
            let executor_adaptive =
                format!("sd_jwt_issuance/v2__s_ea__r_ac__f_{}", case.fixture_id);
            let full_adaptive = format!("sd_jwt_issuance/v2__s_fi__r_ac__f_{}", case.fixture_id);
            criterion_ids.extend([
                executor_serial.clone(),
                full_serial.clone(),
                executor_adaptive.clone(),
                full_adaptive.clone(),
            ]);
            paired_cells.extend([
                SdJwtIssuanceQualificationCell {
                    fixture_id: case.fixture_id.clone(),
                    stage: "executor_assembly".to_owned(),
                    serial_id: executor_serial,
                    adaptive_id: executor_adaptive,
                },
                SdJwtIssuanceQualificationCell {
                    fixture_id: case.fixture_id.clone(),
                    stage: "full_issuance".to_owned(),
                    serial_id: full_serial,
                    adaptive_id: full_adaptive,
                },
            ]);
        }
        SdJwtIssuanceQualificationManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            benchmark_group_id: BENCHMARK_GROUP_ID.to_owned(),
            fixture_case_count: FIXTURE_CASE_COUNT,
            benchmark_id_count: BENCHMARK_ID_COUNT,
            paired_cell_count: PAIRED_CELL_COUNT,
            cases,
            criterion_ids,
            paired_cells,
            route_schema: ROUTE_SCHEMA.to_owned(),
            work_estimator_version: WORK_ESTIMATOR_VERSION.to_owned(),
            static_partition_rule_version: STATIC_PARTITION_RULE_VERSION.to_owned(),
            worker_cap: 4,
            mechanical_benchmark_thresholds: SdJwtIssuanceThresholds {
                min_jobs: 2,
                min_estimated_work_bytes: 1,
            },
            qualified_issuance_thresholds: None,
        }
    }

    fn canonical_manifest_bytes(value: &SdJwtIssuanceQualificationManifest) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).expect("manifest JSON");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn exact_protocol_schedule_and_effect_definitions_are_frozen() {
        let value = manifest();
        let bytes = canonical_manifest_bytes(&value);
        let plan = plan_for_manifest(&value, &bytes).expect("valid qualification plan");

        assert_eq!(plan.superblock_orders, SUPERBLOCK_ORDERS);
        assert_eq!(plan.abba_expansion, ABBA_EXPANSION);
        assert_eq!(plan.baab_expansion, BAAB_EXPANSION);
        assert_eq!(plan.processes_per_cell, 160);
        assert_eq!(plan.total_processes, 10_560);
        assert_eq!(plan.quiet_window_seconds, 2_700);
        assert_eq!(plan.bootstrap.replicates, 100_000);
        assert!((plan.bootstrap.confidence_level - 0.95).abs() < f64::EPSILON);
        assert_eq!(plan.bootstrap.seed, 2_453_812_215);
        assert_eq!(plan.effects.abba_serial_first_pairs, [[1, 0], [7, 6]]);
        assert_eq!(plan.effects.baab_adaptive_first_pairs, [[0, 1], [6, 7]]);
        assert_eq!(
            plan.discovery.percent_transform,
            "100.0 * (exp(effect) - 1.0)"
        );
        assert_eq!(
            plan.discovery.d_upper_percent_less_than.to_bits(),
            (-5.0_f64).to_bits()
        );
        assert_eq!(
            plan.discovery.s_upper_percent_less_than.to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(
            plan.discovery.p_upper_percent_less_than.to_bits(),
            0.0_f64.to_bits()
        );
        let encoded = String::from_utf8(
            serde_json::to_vec_pretty(&plan).expect("serialize qualification plan"),
        )
        .expect("qualification plan is UTF-8");
        assert!(encoded.contains("\"schema\": \"marty.performance/sd-jwt-issuance-plan/v2\""));
        assert!(encoded.contains("\"d_upper_percent_less_than\": -5.0"));
        assert!(!encoded.contains("\"d_upper_less_than\""));

        let plan_value = serde_json::to_value(&plan).expect("plan JSON value");
        let mut v1_with_v2_fields = plan_value.clone();
        v1_with_v2_fields["schema"] =
            serde_json::json!("marty.performance/sd-jwt-issuance-plan/v1");
        let parsed_v1_with_v2_fields =
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(v1_with_v2_fields)
                .expect("field shape is independently parseable");
        assert!(validate_plan_schema(&parsed_v1_with_v2_fields).is_err());

        let mut v2_with_v1_fields = plan_value;
        let legacy_discovery = v2_with_v1_fields["discovery"]
            .as_object_mut()
            .expect("discovery object");
        for effect in ["d", "s", "p"] {
            let percent_name = format!("{effect}_upper_percent_less_than");
            let legacy_name = format!("{effect}_upper_less_than");
            let value = legacy_discovery
                .remove(&percent_name)
                .expect("percent-domain bound");
            legacy_discovery.insert(legacy_name, value);
        }
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(v2_with_v1_fields.clone())
                .is_err(),
            "v2 must reject the incompatible v1 field shape"
        );

        let mut mixed_v2_fields = serde_json::to_value(&plan).expect("plan JSON value");
        mixed_v2_fields["discovery"]["d_upper_less_than"] = serde_json::json!(-0.05);
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(mixed_v2_fields).is_err(),
            "v2 must reject mixed legacy and percent-domain fields"
        );
        v2_with_v1_fields["schema"] =
            serde_json::json!("marty.performance/sd-jwt-issuance-plan/v1");
        assert!(
            serde_json::from_value::<SdJwtIssuanceQualificationPlan>(v2_with_v1_fields).is_err(),
            "v1 evidence must not be silently reinterpreted"
        );
        assert!(plan.production_activation_separate);
        assert_eq!(plan.manifest.byte_length, bytes.len() as u64);
        assert_eq!(plan.manifest.sha256.len(), 64);
        assert!(plan
            .manifest
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)));
    }

    #[test]
    fn manifest_validation_rejects_activation_drift_and_identity_gaps() {
        let mut activated = manifest();
        activated.qualified_issuance_thresholds = Some(SdJwtIssuanceThresholds {
            min_jobs: 8,
            min_estimated_work_bytes: 1_024,
        });
        assert!(validate_manifest(&activated).is_err());

        let mut missing = manifest();
        missing.paired_cells[0].serial_id = missing.paired_cells[1].serial_id.clone();
        assert!(validate_manifest(&missing).is_err());

        let mut reordered = manifest();
        reordered.paired_cells.swap(0, 1);
        assert!(validate_manifest(&reordered).is_err());

        let mut registration_order = manifest();
        registration_order.criterion_ids.swap(0, 1);
        assert!(validate_manifest(&registration_order).is_err());
    }

    #[test]
    fn plan_writer_requires_canonical_input_and_preserves_existing_output() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let manifest_path = temporary.path().join("manifest.json");
        let output_path = temporary.path().join("plan.json");
        let value = manifest();
        fs::write(&manifest_path, canonical_manifest_bytes(&value)).expect("write manifest");

        write_plan(&manifest_path, &output_path).expect("write plan");
        let first = fs::read(&output_path).expect("plan bytes");
        let parsed: SdJwtIssuanceQualificationPlan =
            serde_json::from_slice(&first).expect("plan JSON");
        assert_eq!(parsed.schema, PLAN_SCHEMA);
        assert_eq!(parsed.total_processes, 10_560);

        let error = write_plan(&manifest_path, &output_path).expect_err("refuse replacement");
        assert!(error.to_string().contains("create qualification plan"));
        assert_eq!(fs::read(&output_path).expect("preserved plan"), first);

        let compact_path = temporary.path().join("compact.json");
        fs::write(
            &compact_path,
            serde_json::to_vec(&value).expect("compact JSON"),
        )
        .expect("write compact manifest");
        assert!(load_manifest(&compact_path).is_err());
    }
}
