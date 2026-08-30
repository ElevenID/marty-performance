//! Descriptive-only issuance effect calculations.
//!
//! Criterion confidence intervals describe uncertainty in its median estimator;
//! they are deliberately never exposed as individual-operation tail latency.

use anyhow::{Context, Result};
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
struct ConfidenceInterval {
    confidence_level: serde_json::Number,
    lower_bound: f64,
    upper_bound: f64,
}

#[derive(Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "Criterion 0.5.1 uses point_estimate"
)]
struct Estimate {
    confidence_interval: ConfidenceInterval,
    point_estimate: f64,
    standard_error: f64,
}

#[derive(Debug)]
struct Estimates {
    mean: Estimate,
    median: Estimate,
    median_abs_dev: Estimate,
    slope: Option<Estimate>,
    std_dev: Estimate,
}

fn next_ordered<'de, A, T>(map: &mut A, expected: &'static str) -> Result<T, A::Error>
where
    A: MapAccess<'de>,
    T: Deserialize<'de>,
{
    match map.next_key::<String>()? {
        Some(key) if key == expected => map.next_value(),
        _ => Err(de::Error::custom("invalid ordered Criterion object")),
    }
}

impl<'de> Deserialize<'de> for ConfidenceInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = ConfidenceInterval;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an ordered Criterion confidence interval")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let value = ConfidenceInterval {
                    confidence_level: next_ordered(&mut map, "confidence_level")?,
                    lower_bound: next_ordered(&mut map, "lower_bound")?,
                    upper_bound: next_ordered(&mut map, "upper_bound")?,
                };
                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("invalid ordered Criterion object"));
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(OrderedVisitor)
    }
}

impl<'de> Deserialize<'de> for Estimate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = Estimate;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an ordered Criterion estimate")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let value = Estimate {
                    confidence_interval: next_ordered(&mut map, "confidence_interval")?,
                    point_estimate: next_ordered(&mut map, "point_estimate")?,
                    standard_error: next_ordered(&mut map, "standard_error")?,
                };
                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("invalid ordered Criterion object"));
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(OrderedVisitor)
    }
}

impl<'de> Deserialize<'de> for Estimates {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = Estimates;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("ordered Criterion 0.5.1 estimates")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let value = Estimates {
                    mean: next_ordered(&mut map, "mean")?,
                    median: next_ordered(&mut map, "median")?,
                    median_abs_dev: next_ordered(&mut map, "median_abs_dev")?,
                    slope: next_ordered(&mut map, "slope")?,
                    std_dev: next_ordered(&mut map, "std_dev")?,
                };
                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("invalid ordered Criterion object"));
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(OrderedVisitor)
    }
}

fn valid_estimate(value: &Estimate, require_positive: bool) -> bool {
    let ci = &value.confidence_interval;
    value.point_estimate.is_finite()
        && value.standard_error.is_finite()
        && value.standard_error >= 0.0
        && ci.confidence_level.to_string() == "0.95"
        && ci.confidence_level.as_f64().map(f64::to_bits) == Some(0.95_f64.to_bits())
        && ci.lower_bound.is_finite()
        && ci.upper_bound.is_finite()
        && ci.lower_bound <= value.point_estimate
        && value.point_estimate <= ci.upper_bound
        && (!require_positive
            || (value.point_estimate > 0.0 && ci.lower_bound > 0.0 && ci.upper_bound > 0.0))
}

pub(super) fn criterion_median(bytes: &[u8]) -> Result<f64> {
    let parsed: Estimates = serde_json::from_slice(bytes).context("invalid Criterion estimates")?;
    anyhow::ensure!(
        valid_estimate(&parsed.mean, false)
            && valid_estimate(&parsed.median, true)
            && valid_estimate(&parsed.median_abs_dev, false)
            && parsed
                .slope
                .as_ref()
                .is_none_or(|v| valid_estimate(v, false))
            && valid_estimate(&parsed.std_dev, false),
        "invalid Criterion estimate bounds"
    );
    Ok(parsed.median.point_estimate)
}

#[cfg(test)]
pub(super) fn round_effects(values: [f64; 8], order: &str) -> Result<[f64; 4]> {
    anyhow::ensure!(values.iter().all(|value| value.is_finite() && *value > 0.0));
    let logs = values.map(f64::ln);
    let pair = |adaptive: usize, serial: usize| logs[adaptive] - logs[serial];
    let (serial_first, adaptive_first) = match order {
        "ABBA_FIRST" => (
            f64::midpoint(pair(1, 0), pair(7, 6)),
            f64::midpoint(pair(2, 3), pair(4, 5)),
        ),
        "BAAB_FIRST" => (
            f64::midpoint(pair(3, 2), pair(5, 4)),
            f64::midpoint(pair(0, 1), pair(6, 7)),
        ),
        _ => anyhow::bail!("unknown superblock order"),
    };
    Ok([
        f64::midpoint(serial_first, adaptive_first),
        serial_first,
        adaptive_first,
        serial_first - adaptive_first,
    ])
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct EffectIntervals {
    pub observed: [f64; 4],
    pub lower: [f64; 4],
    pub upper: [f64; 4],
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct SplitMix64(u64);

#[cfg(test)]
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, upper: usize) -> Result<usize> {
        sample_index(upper, || self.next())
    }
}

#[cfg(test)]
fn sample_index(upper: usize, mut next: impl FnMut() -> u64) -> Result<usize> {
    anyhow::ensure!(upper > 0, "bootstrap requires rounds");
    let upper_u64 = u64::try_from(upper)?;
    let zone = u64::MAX - u64::MAX % upper_u64;
    loop {
        let value = next();
        if value < zone {
            return Ok(usize::try_from(value % upper_u64)?);
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "bounded bootstrap vector indices are exactly representable at campaign limits"
)]
#[cfg(test)]
fn type_7(values: &mut [f64], probability: f64) -> Result<f64> {
    anyhow::ensure!(!values.is_empty() && (0.0..=1.0).contains(&probability));
    anyhow::ensure!(values.iter().all(|value| value.is_finite()));
    values.sort_by(f64::total_cmp);
    let h = probability * (values.len() - 1) as f64;
    let lower = h.floor() as usize;
    let fraction = h - lower as f64;
    Ok(values[lower] + fraction * (values[h.ceil() as usize] - values[lower]))
}

#[allow(
    clippy::cast_precision_loss,
    reason = "validated campaign round counts are at most twenty"
)]
#[cfg(test)]
pub(super) fn bootstrap(
    cells: &[Vec<[f64; 4]>],
    replicates: usize,
    seed: u64,
) -> Result<Vec<EffectIntervals>> {
    anyhow::ensure!(!cells.is_empty() && replicates > 0);
    let rounds = cells[0].len();
    anyhow::ensure!(rounds > 0 && cells.iter().all(|cell| cell.len() == rounds));
    anyhow::ensure!(cells
        .iter()
        .flatten()
        .flatten()
        .all(|value| value.is_finite()));
    let observed: Vec<[f64; 4]> = cells
        .iter()
        .map(|cell| {
            let mut mean = [0.0; 4];
            for round in cell {
                for (target, value) in mean.iter_mut().zip(round) {
                    *target += value / rounds as f64;
                }
            }
            mean
        })
        .collect();
    let mut rng = SplitMix64(seed);
    let mut maxima = Vec::with_capacity(replicates);
    let mut diagnostic = vec![Vec::with_capacity(replicates); cells.len()];
    for _ in 0..replicates {
        let draws: Vec<usize> = (0..rounds)
            .map(|_| rng.index(rounds))
            .collect::<Result<_>>()?;
        let mut maximum = 0.0_f64;
        for (cell_ordinal, cell) in cells.iter().enumerate() {
            let mut mean = [0.0; 4];
            for draw in &draws {
                for (target, value) in mean.iter_mut().zip(cell[*draw]) {
                    *target += value / rounds as f64;
                }
            }
            for effect in 0..3 {
                maximum = maximum.max((mean[effect] - observed[cell_ordinal][effect]).abs());
            }
            diagnostic[cell_ordinal].push(mean[3]);
        }
        maxima.push(maximum);
    }
    let simultaneous_radius = type_7(&mut maxima, 0.95)?;
    observed
        .into_iter()
        .enumerate()
        .map(|(cell, point)| {
            let lower_o = type_7(&mut diagnostic[cell].clone(), 0.025)?;
            let upper_o = type_7(&mut diagnostic[cell], 0.975)?;
            Ok(EffectIntervals {
                observed: point,
                lower: [
                    point[0] - simultaneous_radius,
                    point[1] - simultaneous_radius,
                    point[2] - simultaneous_radius,
                    lower_o,
                ],
                upper: [
                    point[0] + simultaneous_radius,
                    point[1] + simultaneous_radius,
                    point[2] + simultaneous_radius,
                    upper_o,
                ],
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_criterion() -> String {
        String::from_utf8(
            include_bytes!("../../tests/fixtures/criterion-0.5.1/valid-estimates.json").to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn abba_and_baab_normalize_adaptive_over_serial_sign() {
        let abba =
            round_effects([1.0, 2.0, 32.0, 1.0, 128.0, 1.0, 1.0, 8.0], "ABBA_FIRST").unwrap();
        let baab =
            round_effects([32.0, 1.0, 1.0, 2.0, 1.0, 8.0, 128.0, 1.0], "BAAB_FIRST").unwrap();
        let unit = 2.0_f64.ln();
        let expected = [4.0 * unit, 2.0 * unit, 6.0 * unit, -4.0 * unit];
        for (actual, expected) in abba.iter().zip(expected) {
            assert!((*actual - expected).abs() < 1e-12);
        }
        assert!(abba
            .iter()
            .zip(baab)
            .all(|(left, right)| (*left - right).abs() < 1e-12));
    }

    #[test]
    fn criterion_95_percent_confidence_interval_is_not_p95_or_p99_latency() {
        let bytes = include_bytes!("../../tests/fixtures/criterion-0.5.1/valid-estimates.json");
        assert!((criterion_median(bytes).unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn criterion_confidence_level_accepts_legal_json_whitespace() {
        let spaced =
            valid_criterion().replace("\"confidence_level\":", "\"confidence_level\" \n : \t");
        assert!((criterion_median(spaced.as_bytes()).unwrap() - 100.0).abs() < f64::EPSILON);
        let normalized =
            valid_criterion().replace("\"confidence_level\":0.95", "\"confidence_level\":0.950");
        assert!((criterion_median(normalized.as_bytes()).unwrap() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn criterion_shape_rejects_unknown_fields() {
        let bytes = include_bytes!("../../tests/fixtures/criterion-0.5.1/unknown-field.json");
        assert!(criterion_median(bytes).is_err());
    }

    #[test]
    fn criterion_shape_rejects_reordered_duplicate_missing_and_unknown_fields() {
        let valid = valid_criterion();
        let cases = [
            valid.replace(
                "\"confidence_level\":0.95,\"lower_bound\":9.0",
                "\"lower_bound\":9.0,\"confidence_level\":0.95",
            ),
            valid.replace(
                "\"confidence_interval\":{\"confidence_level\":0.95,\"lower_bound\":9.0,\"upper_bound\":11.0},\"point_estimate\":10.0,\"standard_error\":1.0",
                "\"point_estimate\":10.0,\"confidence_interval\":{\"confidence_level\":0.95,\"lower_bound\":9.0,\"upper_bound\":11.0},\"standard_error\":1.0",
            ),
            valid.replace("\"mean\":", "\"unknown\":null,\"mean\":"),
            valid.replace("\"slope\":null,", ""),
            valid.replace("\"std_dev\":", "\"mean\":null,\"std_dev\":"),
            include_str!("../../tests/fixtures/criterion-0.5.1/reordered-top-level.json")
                .to_owned(),
        ];
        for case in cases {
            assert!(criterion_median(case.as_bytes()).is_err());
        }
    }

    #[test]
    fn criterion_projection_accepts_valid_slope_and_rejects_malformed_slope() {
        let valid = valid_criterion();
        let slope = "{\"confidence_interval\":{\"confidence_level\":0.95,\"lower_bound\":7.0,\"upper_bound\":9.0},\"point_estimate\":8.0,\"standard_error\":0.5}";
        let with_slope = valid.replace("\"slope\":null", &format!("\"slope\":{slope}"));
        assert!((criterion_median(with_slope.as_bytes()).unwrap() - 100.0).abs() < f64::EPSILON);
        let reordered = with_slope.replace(
            slope,
            "{\"point_estimate\":8.0,\"confidence_interval\":{\"confidence_level\":0.95,\"lower_bound\":7.0,\"upper_bound\":9.0},\"standard_error\":0.5}",
        );
        assert!(criterion_median(reordered.as_bytes()).is_err());
        let invalid = with_slope.replace("\"lower_bound\":7.0", "\"lower_bound\":9.5");
        assert!(criterion_median(invalid.as_bytes()).is_err());
    }

    #[test]
    fn criterion_median_rejects_invalid_numeric_contracts() {
        let valid = valid_criterion();
        for (index, case) in [
            valid.replace(
                "\"confidence_level\":0.95",
                "\"confidence_level\":0.9500000000000002",
            ),
            valid.replace("\"point_estimate\":100.0", "\"point_estimate\":0.0"),
            valid.replace("\"point_estimate\":100.0", "\"point_estimate\":-1.0"),
            valid.replace("\"lower_bound\":90.0", "\"lower_bound\":0.0"),
            valid.replace("\"lower_bound\":90.0", "\"lower_bound\":-1.0"),
            valid.replace("\"upper_bound\":110.0", "\"upper_bound\":-1.0"),
            valid.replace(
                "\"lower_bound\":90.0,\"upper_bound\":110.0",
                "\"lower_bound\":101.0,\"upper_bound\":110.0",
            ),
            valid.replace(
                "\"lower_bound\":90.0,\"upper_bound\":110.0",
                "\"lower_bound\":90.0,\"upper_bound\":99.0",
            ),
            valid.replace("\"standard_error\":2.0", "\"standard_error\":-1.0"),
            valid.replace("\"point_estimate\":100.0", "\"point_estimate\":1e999"),
            valid.replace("\"point_estimate\":10.0", "\"point_estimate\":1e999"),
            valid.replace("\"lower_bound\":9.0", "\"lower_bound\":12.0"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(criterion_median(case.as_bytes()).is_err(), "case {index}");
        }
    }

    #[test]
    fn splitmix64_rejection_sampling_discards_the_biased_tail() {
        let mut values = [u64::MAX, 5].into_iter();
        assert_eq!(sample_index(3, || values.next().unwrap()).unwrap(), 2);
    }

    #[test]
    fn splitmix64_stream_and_upper_20_indices_match_golden() {
        let mut raw = SplitMix64(2_453_812_215);
        assert_eq!(raw.next(), 17_694_892_751_657_379_964);
        let mut indexed = SplitMix64(2_453_812_215);
        assert_eq!(
            (0..8)
                .map(|_| indexed.index(20).unwrap())
                .collect::<Vec<_>>(),
            vec![4, 14, 15, 6, 3, 11, 7, 13]
        );
    }

    #[test]
    fn three_replicate_bootstrap_matches_stream_sensitive_golden() {
        let cells = vec![vec![
            [0.0, 0.0, 0.0, 0.0],
            [2.0, 4.0, 6.0, 8.0],
            [9.0, 12.0, 15.0, 18.0],
        ]];
        let result = bootstrap(&cells, 3, 2_453_812_215).unwrap();
        assert_eq!(
            result[0].lower.map(f64::to_bits),
            [
                -3.833_333_333_333_333_5,
                -2.166_666_666_666_667,
                -0.5,
                5.366_666_666_666_666
            ]
            .map(f64::to_bits)
        );
        assert_eq!(
            result[0].upper.map(f64::to_bits),
            [11.166_666_666_666_666, 12.833_333_333_333_332, 14.5, 17.4].map(f64::to_bits)
        );
    }

    #[test]
    fn type_7_quantiles_match_golden_cases() {
        let values = [0.0, 10.0, 20.0, 30.0, 40.0];
        for (probability, expected) in [
            (0.0, 0.0),
            (0.25, 10.0),
            (0.5, 20.0),
            (0.95, 38.0),
            (1.0, 40.0),
        ] {
            assert!((type_7(&mut values.clone(), probability).unwrap() - expected).abs() < 1e-12);
        }
    }

    #[test]
    fn bootstrap_is_deterministic_and_uses_common_round_draws() {
        let cells = vec![
            vec![[0.0, 0.0, 0.0, 1.0], [2.0, 2.0, 2.0, 3.0]],
            vec![[10.0, 10.0, 10.0, 11.0], [12.0, 12.0, 12.0, 13.0]],
        ];
        let first = bootstrap(&cells, 257, 2_453_812_215).unwrap();
        let second = bootstrap(&cells, 257, 2_453_812_215).unwrap();
        assert_eq!(first, second);
        let first_radius = first[0].lower[0] - first[0].observed[0];
        let second_radius = first[1].lower[0] - first[1].observed[0];
        assert!((first_radius - second_radius).abs() < f64::EPSILON);
    }

    #[test]
    #[allow(clippy::unreadable_literal, reason = "exact f64 bit-pattern golden")]
    fn common_round_draws_match_two_cell_exact_bit_golden() {
        let cells = vec![
            vec![
                [0.0, 1.0, 2.0, 3.0],
                [4.0, 8.0, 12.0, 16.0],
                [9.0, 18.0, 27.0, 36.0],
            ],
            vec![
                [100.0, 50.0, 25.0, 12.0],
                [80.0, 40.0, 20.0, 10.0],
                [20.0, 10.0, 5.0, 2.0],
            ],
        ];
        let result = bootstrap(&cells, 5, 2_453_812_215).unwrap();
        assert_eq!(
            result[0].lower.map(f64::to_bits),
            [
                13853776141233422335,
                13853119366287764138,
                13851852728892566185,
                4622757367511340373
            ]
        );
        assert_eq!(
            result[0].upper.map(f64::to_bits),
            [
                4631623829277726037,
                4632280604223384234,
                4632937379169042432,
                4629953744415909478
            ]
        );
        assert_eq!(
            result[1].lower.map(f64::to_bits),
            [
                4627823917092132184,
                13844065254536904696,
                13851008303962434217,
                4613187218303178070
            ]
        );
        assert_eq!(
            result[1].upper.map(f64::to_bits),
            [
                4637300241308057600,
                4634954616502135466,
                4633359591634108416,
                4622194417557919062
            ]
        );
    }

    #[test]
    fn bootstrap_100_000_replicates_matches_reduced_dimension_golden() {
        let cells = vec![vec![
            [0.0, 1.0, 2.0, 3.0],
            [2.0, 3.0, 4.0, 5.0],
            [8.0, 9.0, 10.0, 11.0],
        ]];
        let result = bootstrap(&cells, 100_000, 2_453_812_215).unwrap();
        assert_eq!(result.len(), 1);
        for (actual, expected) in
            result[0]
                .observed
                .iter()
                .zip([10.0 / 3.0, 13.0 / 3.0, 16.0 / 3.0, 19.0 / 3.0])
        {
            assert!((*actual - expected).abs() < 1e-12);
        }
        for (actual, expected) in result[0].lower.iter().zip([0.0, 1.0, 2.0, 3.0]) {
            assert!((*actual - expected).abs() < 1e-12);
        }
        for (actual, expected) in
            result[0]
                .upper
                .iter()
                .zip([20.0 / 3.0, 23.0 / 3.0, 26.0 / 3.0, 11.0])
        {
            assert!((*actual - expected).abs() < 1e-12);
        }
    }

    #[test]
    fn complete_schedule_has_exactly_10_560_coordinates() {
        let rounds = u32::try_from(super::super::SUPERBLOCK_ORDERS.len()).unwrap();
        let cells = u32::try_from(super::super::PAIRED_CELL_COUNT).unwrap();
        let expansions = super::super::PROCESSES_PER_SUPERBLOCK;
        let coordinates: Vec<_> = (0..rounds)
            .flat_map(|round| {
                (0..cells).flat_map(move |cell| {
                    (0..expansions).map(move |expansion| (round, cell, expansion))
                })
            })
            .collect();
        assert_eq!(rounds * cells * expansions, 10_560);
        assert_eq!(
            coordinates.len(),
            usize::try_from(rounds * cells * expansions).unwrap()
        );
        assert_eq!(coordinates.first(), Some(&(0, 0, 0)));
        assert_eq!(coordinates.last(), Some(&(19, 65, 7)));
        let unique: std::collections::BTreeSet<_> = coordinates.iter().copied().collect();
        assert_eq!(unique.len(), coordinates.len());
        for (ordinal, &(round, cell, expansion)) in coordinates.iter().enumerate() {
            let expected = round * cells * expansions + cell * expansions + expansion;
            assert_eq!(ordinal, usize::try_from(expected).unwrap());
            assert_eq!(
                (
                    expected / (cells * expansions),
                    (expected % (cells * expansions)) / expansions,
                    expected % expansions
                ),
                (round, cell, expansion)
            );
        }
    }
}
