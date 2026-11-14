//! Frozen protocol descriptions used to construct qualification plans.

use super::{
    schedule, Context, Result, SdJwtIssuanceArtifactIndexProtocol, SdJwtIssuanceBootstrapProtocol,
    SdJwtIssuanceCriterionHomeProtocol, SdJwtIssuanceCriterionProtocol,
    SdJwtIssuanceEvidenceFieldProtocol, SdJwtIssuanceEvidenceJsonType,
    SdJwtIssuanceEvidenceRecordProtocol, SdJwtIssuanceFirstQuietWindowProtocol,
    SdJwtIssuanceGlobalPreimageProtocol, SdJwtIssuanceGlobalRoundProtocol,
    SdJwtIssuanceInvocationDescriptorProtocol, SdJwtIssuanceLaunchBarrierProtocol,
    SdJwtIssuanceObservationBounds, SdJwtIssuanceRouteArtifactProtocol,
    SdJwtIssuanceRunValidityCompletionProtocol, SdJwtIssuanceRunValidityLimits,
    SdJwtIssuanceRunValidityProtocol, SdJwtIssuanceRunValidityRecordProtocols,
    FIXED_BUILD_ROOT_NON_WINDOWS, FIXED_BUILD_ROOT_WINDOWS, MAX_EXTERNAL_ANCHOR_V1_BYTES,
    MAX_FIXED_BUILD_INPUT_BYTES, MAX_FIXED_BUILD_INPUT_ENTRIES, MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
    MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES, MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
    MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES, MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES,
    MAX_SOURCE_ARCHIVE_PATH_SEGMENTS, MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES,
    MAX_SOURCE_ARCHIVE_PATH_V1_BYTES, MAX_SOURCE_ARCHIVE_V1_BYTES, MAX_SOURCE_ARCHIVE_V1_ENTRIES,
    MAX_TOTAL_EVIDENCE_BYTES, PAIRED_CELL_COUNT, PROCESSES_PER_SUPERBLOCK,
};

fn evidence_fields<const N: usize>(
    values: [(&str, SdJwtIssuanceEvidenceJsonType, bool); N],
) -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    values
        .map(
            |(name, json_type, nullable)| SdJwtIssuanceEvidenceFieldProtocol {
                name: name.to_owned(),
                json_type,
                nullable,
            },
        )
        .to_vec()
}

fn record_protocol(
    schema: &str,
    fields: Vec<SdJwtIssuanceEvidenceFieldProtocol>,
    cardinality: &str,
    semantic_rule: &str,
) -> SdJwtIssuanceEvidenceRecordProtocol {
    SdJwtIssuanceEvidenceRecordProtocol {
        schema: schema.to_owned(),
        fields,
        cardinality: cardinality.to_owned(),
        semantic_rule: semantic_rule.to_owned(),
    }
}

fn genesis_header_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-genesis/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
            (
                "fixed_binary_build_receipt_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("monitor_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_configuration_fingerprint", ArtifactFingerprint, false),
            ("monitor_configuration_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("host_identity_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
            ("hardware_profile_fingerprint", ArtifactFingerprint, false),
            ("validity_thresholds_fingerprint", ArtifactFingerprint, false),
            ("first_quiet_window_evidence_fingerprint", ArtifactFingerprint, false),
            ("initial_test_window_attestation_fingerprint", ArtifactFingerprint, false),
            ("baseline_unrelated_process_set_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_as_segment_0_record_0",
        "campaign_id_is_unique_uuid_v4_segment_ordinal_and_record_ordinal_are_0_all_fingerprints_resolve_through_fixed_role_paths_and_bind_create_new_actual_bytes_source_archive_reconstructs_exact_commit_and_tree_and_Cargo_lock_fixed_binary_build_receipt_cryptographically_links_the_installed_fixed_binary_to_those_source_toolchain_command_and_build_inputs_and_initial_timing_window_attestation_exists_after_shutdown_checks",
    )
}

fn continuation_header_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-continuation/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("previous_segment_fingerprint", ArtifactFingerprint, false),
            ("genesis_header_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
        ]),
        "exactly_one_as_record_0_of_each_segment_after_0",
        "same_campaign_genesis_and_boot_segment_ordinal_equals_predecessor_plus_1_previous_fingerprint_binds_entire_synced_predecessor",
    )
}

fn sample_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, String, StringArray, F64, I64, U32, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-sample/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("sample_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("boot_identity_pseudonym", String, false),
            ("timing_state", String, false),
            ("global_round_ordinal", U32, true),
            ("cell_ordinal", U32, true),
            ("expansion_position", U32, true),
            ("timing_process_id", String, true),
            ("total_cpu_percent", F64, false),
            ("monitor_cpu_percent", F64, false),
            ("benchmark_cpu_percent", F64, false),
            ("unrelated_cpu_percent", F64, false),
            ("available_memory_bytes", U64, false),
            ("cpu_frequency_hz", U64, false),
            ("maximum_temperature_millidegrees_celsius", I64, false),
            ("throttle_flags", StringArray, false),
            ("unrelated_process_set_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
        ]),
        "zero_based_sample_ordinal_contiguous_across_campaign_at_declared_cadence",
        "timing_state_is_exactly_idle_launching_or_process_idle_requires_all_four_process_context_fields_null_launching_requires_all_four_nonnull_and_matching_active_synced_intent_before_start_process_requires_all_four_nonnull_and_matching_active_start_and_remains_process_after_child_exit_through_route_Criterion_receipt_and_finish_sync_total_monitor_benchmark_and_unrelated_CPU_percent_are_finite_in_observation_bounds_each_subcategory_is_at_most_total_and_checked_finite_monitor_plus_benchmark_plus_unrelated_is_at_most_total_available_memory_is_at_most_bound_hardware_total_frequency_and_temperature_are_in_observation_bounds_throttle_flags_are_sorted_unique_protocol_literals_and_none_is_the_only_value_when_no_flag_is_active_every_sample_applies_the_bound_validity_thresholds_exactly_total_monitor_and_unrelated_CPU_are_at_most_their_declared_maxima_available_memory_is_at_least_the_enabled_nonzero_minimum_frequency_is_at_least_the_enabled_nonzero_minimum_temperature_is_at_most_the_declared_maximum_no_forbidden_throttle_flag_is_present_and_the_referenced_unrelated_process_set_entry_count_is_at_most_the_declared_maximum",
    )
}

fn process_intent_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-intent/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_before_creation_of_each_of_10560_scheduled_processes",
        "static_token_descriptor_and_empty_Criterion_home_inventory_are_create_new_synced_and_match_coordinate_controller_configuration_and_fixed_binary_token_fingerprint_is_bound_by_descriptor_and_intent_and_intent_record_is_flushed_and_durably_synced_before_spawn",
    )
}

fn process_start_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-start/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("full_benchmark_id", String, false),
            ("process_intent_record_fingerprint", ArtifactFingerprint, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_ready_frame_fingerprint", ArtifactFingerprint, false),
            ("active_test_window_attestation_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_after_spawned_child_reports_blocked_and_before_release_for_each_process",
        "same_coordinate_id_descriptor_token_and_full_benchmark_id_as_durably_synced_intent_process_identity_pseudonym_equals_the_exact_value_in_the_token_bound_by_intent_and_matching_ready_frame_controller_checks_actual_child_PID_only_in_memory_against_the_spawned_OS_handle_and_exclusive_pipes_without_retaining_it_child_validated_static_token_emitted_bounded_ready_frame_and_has_stdin_read_as_next_operation_controller_persisted_and_synced_exact_ready_bytes_checked_subtraction_of_start_monotonic_nanoseconds_minus_matching_intent_monotonic_nanoseconds_is_at_most_30000000000_which_conservatively_proves_spawn_to_ready_within_30_seconds_underflow_overflow_or_greater_delta_rejects_start_record_binds_ready_and_is_flushed_and_durably_synced_before_controller_persists_syncs_and_sends_release_no_second_start_before_matching_finish",
    )
}

fn process_finish_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, I32, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-process-finish/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("full_benchmark_id", String, false),
            ("exit_code", I32, false),
            ("termination_reason", String, false),
            ("elapsed_monotonic_nanoseconds", U64, false),
            ("stdout_after_ready_bytes", U64, false),
            ("stderr_bytes", U64, false),
            ("launch_barrier_receipt_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_final_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_artifact_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_fingerprint", ArtifactFingerprint, false),
            ("artifacts_flushed_and_synced", Boolean, false),
        ]),
        "exactly_one_after_each_matching_process_start",
        "same_coordinates_ids_process_identity_pseudonym_and_descriptor_as_intent_and_start_exit_code_0_termination_reason_exactly_exited_elapsed_monotonic_nanoseconds_equals_checked_finish_monotonic_nanoseconds_minus_matching_start_monotonic_nanoseconds_and_is_greater_than_0_and_at_most_300000000000_release_prepared_monotonic_is_between_matching_start_and_finish_inclusive_underflow_overflow_or_mismatch_rejects_controller_observed_stdout_after_ready_bytes_and_stderr_bytes_checked_add_without_overflow_and_sum_at_most_maximum_process_output_bytes_raw_output_was_drain_discarded_barrier_receipt_proves_release_after_synced_start_unique_home_was_empty_before_release_and_final_inventory_contains_one_fresh_matching_full_id_benchmark_object_with_new_benchmark_json_and_sibling_estimates_json_created_between_start_and_finish_no_unrelated_id_and_all_bound_artifacts_are_flushed_and_synced",
    )
}

fn attestation_transition_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-attestation-transition/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("event_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("previous_attestation_fingerprint", ArtifactFingerprint, false),
            ("next_attestation_fingerprint", ArtifactFingerprint, false),
            ("next_starts_at_rfc3339_nanoseconds", String, false),
            ("next_expires_at_rfc3339_nanoseconds", String, false),
        ]),
        "exactly_one_for_each_actual_attestation_after_the_genesis_attestation",
        "next_create_new_attestation_exists_and_was_created_after_shutdown_recheck_before_previous_expiry_same_target_and_conditions_no_time_gap_and_duration_at_most_43200_seconds",
    )
}

fn segment_footer_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-segment-footer/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("segment_ordinal", U32, false),
            ("record_ordinal", U32, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("records_before_footer", U32, false),
            ("bytes_before_footer", U64, false),
            ("records_before_footer_fingerprint", ArtifactFingerprint, false),
            ("first_monotonic_nanoseconds", U64, false),
            ("last_monotonic_nanoseconds", U64, false),
            ("sample_count", U32, false),
            ("process_intent_count", U32, false),
            ("process_start_count", U32, false),
            ("process_finish_count", U32, false),
            ("attestation_transition_count", U32, false),
            ("closed_reason", String, false),
        ]),
        "exactly_one_as_the_last_record_of_every_segment",
        "record_ordinal_equals_records_before_footer_counts_cover_every_prior_record_first_monotonic_equals_header_monotonic_last_monotonic_equals_footer_monotonic_closed_reason_is_one_protocol_literal_and_matches_the_exact_run_validity_segment_close_reason_rule_and_entire_segment_is_flushed_and_durably_synced_before_successor_or_completion",
    )
}

pub(super) fn record_protocols() -> SdJwtIssuanceRunValidityRecordProtocols {
    SdJwtIssuanceRunValidityRecordProtocols {
        genesis_header: genesis_header_protocol(),
        continuation_header: continuation_header_protocol(),
        sample: sample_protocol(),
        process_intent: process_intent_protocol(),
        process_start: process_start_protocol(),
        process_finish: process_finish_protocol(),
        attestation_transition: attestation_transition_protocol(),
        segment_footer: segment_footer_protocol(),
    }
}

fn first_quiet_window_protocol() -> SdJwtIssuanceFirstQuietWindowProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, QuietWindowSampleArray, String, StringArray, U32, U64,
    };
    SdJwtIssuanceFirstQuietWindowProtocol {
        schema: "marty.performance/sd-jwt-issuance-first-quiet-window/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_before_correctness_and_build"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("created_at_utc_rfc3339_nanoseconds", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            ("monitor_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("controller_configuration_fingerprint", ArtifactFingerprint, false),
            ("monitor_configuration_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("host_identity_fingerprint", ArtifactFingerprint, false),
            ("boot_identity_pseudonym", String, false),
            ("hardware_profile_fingerprint", ArtifactFingerprint, false),
            ("validity_thresholds_fingerprint", ArtifactFingerprint, false),
            (
                "first_quiet_window_attestation_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("baseline_unrelated_process_set_fingerprint", ArtifactFingerprint, false),
            ("started_at_utc_rfc3339_nanoseconds", String, false),
            ("started_at_monotonic_nanoseconds", U64, false),
            ("ended_at_utc_rfc3339_nanoseconds", String, false),
            ("ended_at_monotonic_nanoseconds", U64, false),
            ("sample_interval_seconds", U32, false),
            ("maximum_sample_gap_seconds", U32, false),
            ("samples", QuietWindowSampleArray, false),
            ("invalidating_events", StringArray, false),
            ("validity_status", String, false),
        ]),
        sample_fields: evidence_fields([
            ("sample_ordinal", U64, false),
            ("utc_rfc3339_nanoseconds", String, false),
            ("monotonic_nanoseconds", U64, false),
            ("boot_identity_pseudonym", String, false),
            ("total_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("monitor_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("unrelated_cpu_percent", SdJwtIssuanceEvidenceJsonType::F64, false),
            ("available_memory_bytes", U64, false),
            ("cpu_frequency_hz", U64, false),
            (
                "maximum_temperature_millidegrees_celsius",
                SdJwtIssuanceEvidenceJsonType::I64,
                false,
            ),
            ("throttle_flags", StringArray, false),
            ("unrelated_process_set_fingerprint", ArtifactFingerprint, false),
        ]),
        validity_rule: "campaign_plan_manifest_source_commit_tree_archive_Cargo_lock_host_and_boot_pseudonyms_hardware_monitor_controller_configuration_thresholds_and_first_window_target_pseudonym_and_conditions_match_genesis_except_the_first_window_attestation_has_its_own_disjoint_fixed_role_and_need_not_equal_the_initial_timing_window_attestation_the_first_window_attestation_start_is_at_or_before_the_first_window_start_and_its_expiry_is_strictly_after_every_first_window_sample_and_the_first_window_end_zero_based_samples_are_contiguous_controller_observed_target_5_second_cadence_no_gap_over_10_seconds_ended_minus_started_at_least_2700000000000_monotonic_nanoseconds_CPU_percent_memory_frequency_temperature_throttle_and_process_set_observations_satisfy_the_same_exact_observation_bounds_cross-field_rules_and_bound_validity_threshold_predicate_as_timing_samples_with_checked_finite_monitor_plus_unrelated_at_most_total_validity_status_exactly_valid_and_empty_invalidating_events".to_owned(),
    }
}

fn invocation_descriptor_protocol() -> SdJwtIssuanceInvocationDescriptorProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, NameValueArray, String, StringArray, U32,
    };
    SdJwtIssuanceInvocationDescriptorProtocol {
        schema: "marty.performance/sd-jwt-issuance-invocation/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_before_process_intent"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
            ("executable_relative_path", String, false),
            ("full_benchmark_id", String, false),
            ("argv", StringArray, false),
            ("standard_input_mode", String, false),
            ("standard_output_mode", String, false),
            ("standard_error_mode", String, false),
            ("environment", NameValueArray, false),
            ("working_directory", String, false),
            ("criterion_home", String, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_path", String, false),
            ("launch_barrier_token_fingerprint", ArtifactFingerprint, false),
        ]),
        environment_entry_fields: evidence_fields([
            ("name", String, false),
            ("value_kind", String, false),
            ("portable_value", String, true),
        ]),
        environment_allowlist: [
            "CRITERION_HOME",
            "MARTY_PERF_START_BARRIER",
            "NO_COLOR",
            "RUST_BACKTRACE",
            "SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID",
            "SD_JWT_ISSUANCE_ROUTE_NDJSON",
            "SystemRoot",
            "TEMP",
            "TMP",
            "WINDIR",
        ]
        .map(str::to_owned)
        .to_vec(),
        environment_value_kind_literals: [
            "literal",
            "campaign_relative_path",
            "windows_host_runtime_path",
        ]
        .map(str::to_owned)
        .to_vec(),
        environment_mapping_rule: "entries_are_in_allowlist_order_with_exact_table_CRITERION_HOME_campaign_relative_path_criterion/rNN_cNN_eN_MARTY_PERF_START_BARRIER_campaign_relative_path_barriers/rNN_cNN_eN.token_NO_COLOR_literal_1_RUST_BACKTRACE_literal_0_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_literal_exact_full_benchmark_id_SD_JWT_ISSUANCE_ROUTE_NDJSON_campaign_relative_path_routes/rNN_cNN_eN.ndjson_TEMP_campaign_relative_path_tmp/rNN_cNN_eN_TMP_campaign_relative_path_tmp/rNN_cNN_eN_and_on_windows_only_SystemRoot_and_WINDIR_windows_host_runtime_path_with_null_portable_value_non_windows_has_exactly_8_entries_and_windows_has_exactly_10_each_name_appears_once_no_other_name_kind_or_value_is_valid".to_owned(),
        semantic_rule: "descriptor_matches_controller_configuration_coordinate_fixed_binary_and_manifest_full_id_executable_relative_path_is_bin/fixed-benchmark_on_unix_or_bin/fixed-benchmark.exe_on_windows_selected_only_by_target_triple_argv_is_exact_ordered_Criterion_0.5.1_logical_vector_--bench_--exact_full_benchmark_id_--sample-size_50_--nresamples_100000_--warm-up-time_15_--measurement-time_10_--confidence-level_0.95_--save-baseline_base_--noplot_with_no_other_argument_standard_input_mode_is_controller_single_writer_release_frame_pipe_standard_output_mode_persists_only_exact_ready_frame_then_continuously_bounded_drains_and_discards_all_later_stdout_while_retaining_only_byte_count_standard_error_mode_concurrently_bounded_drains_and_discards_all_bytes_while_retaining_only_byte_count_working_directory_is_dot_for_campaign_root_parent_environment_is_cleared_then_only_explicit_allowlist_entries_are_added_in_protocol_order_case_fold_duplicates_forbidden_NO_COLOR_is_literal_1_RUST_BACKTRACE_is_literal_0_and_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_is_literal_exact_full_id_CRITERION_HOME_is_criterion/rNN_cNN_eN_MARTY_PERF_START_BARRIER_is_barriers/rNN_cNN_eN.token_SD_JWT_ISSUANCE_ROUTE_NDJSON_is_routes/rNN_cNN_eN.ndjson_TEMP_and_TMP_are_both_tmp/rNN_cNN_eN_SystemRoot_and_WINDIR_are_present_only_on_windows_as_host_role_with_null_portable_value_and_absent_on_non_windows_no_raw_absolute_inherited_digest_diagnostic_or_secret_value_is_retained_controller_derives_actual_absolute_campaign_paths_from_trusted_campaign_root_initial_inventory_is_canonical_empty_array".to_owned(),
        resolution_rule: "descriptor_at_invocations/rNN_cNN_eN.json_criterion_home_at_criterion/rNN_cNN_eN_token_at_barriers/rNN_cNN_eN.token_ready_at_barrier-ready/rNN_cNN_eN.json_release_at_barrier-releases/rNN_cNN_eN.json_receipt_at_barrier-receipts/rNN_cNN_eN.json_and_inventories_at_inventories/rNN_cNN_eN-initial.json_and_-final.json_under_campaign_root_compute_paths_from_coordinates_reject_absolute_parent_symlink_hardlink_or_reparse_escape_and_reject_missing_extra_or_mismatched_preimage".to_owned(),
    }
}

fn launch_barrier_protocol() -> SdJwtIssuanceLaunchBarrierProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U32, U64};
    SdJwtIssuanceLaunchBarrierProtocol {
        token_schema: "marty.performance/sd-jwt-issuance-launch-token/v1".to_owned(),
        token_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("nonce_uppercase_hex_256", String, false),
            ("process_identity_pseudonym", String, false),
        ]),
        nonce_rule: "exactly_64_ASCII_uppercase_hex_characters_from_an_independently_sampled_32_byte_CSPRNG_value_unique_across_all_10560_tokens_and_distinct_from_every_process_host_boot_target_change_and_anchor_challenge_pseudonym_or_nonce".to_owned(),
        process_identity_pseudonym_rule: "exactly_64_ASCII_uppercase_hex_characters_from_an_independently_sampled_32_byte_CSPRNG_value_unique_across_all_10560_processes_and_distinct_from_every_launch_nonce_host_boot_target_change_and_anchor_challenge_pseudonym_or_nonce".to_owned(),
        ready_frame_schema: "marty.performance/sd-jwt-issuance-launch-ready/v1".to_owned(),
        ready_frame_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        release_frame_schema: "marty.performance/sd-jwt-issuance-launch-release/v1".to_owned(),
        release_frame_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("ready_frame_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("prepared_at_utc_rfc3339_nanoseconds", String, false),
            ("prepared_at_monotonic_nanoseconds", U64, false),
        ]),
        receipt_schema: "marty.performance/sd-jwt-issuance-launch-receipt/v1".to_owned(),
        receipt_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("process_identity_pseudonym", String, false),
            ("launch_token_fingerprint", ArtifactFingerprint, false),
            ("ready_frame_fingerprint", ArtifactFingerprint, false),
            ("release_frame_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        artifact_format: "token_and_receipt_are_create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_ready_and_release_are_create_new_exact_canonical_compact_json_lf_frame_bytes_flush_and_durable_sync".to_owned(),
        transport_rule: "custom_benchmark_process_entry_before_any_Criterion_construction_validates_synced_token_then_writes_ready_as_exact_first_stdout_frame_plus_LF_flushes_and_makes_blocking_stdin_read_its_next_operation_controller_uses_one_bounded_reader_for_ready_and_all_later_stdout_and_concurrently_drains_bounded_stderr_persists_only_exact_ready_bytes_then_discards_later_stdout_and_all_stderr_while_retaining_only_separate_numeric_byte_counts_controller_checks_actual_child_PID_only_in_memory_against_spawned_handle_and_exclusive_pipe_ownership_controller_is_only_stdin_writer_all_duplicate_write_handles_are_closed_and_after_synced_release_artifact_uses_write_all_flush_close_child_reads_to_EOF_and_rejects_early_EOF_partial_extra_second_or_noncanonical_frame_and_does_not_enter_Criterion_on_any_error_broken_pipe_early_exit_conservative_intent_to_start_delta_over_30_seconds_or_output_over_limit_invalidates_campaign".to_owned(),
        semantic_rule: "controller_precomputes_canonical_token_identity_nonce_and_process_identity_pseudonym_under_their_exact_independent_random_grammar_uniqueness_and_nonreuse_rules_then_create_new_writes_flushes_and_durably_syncs_token_before_descriptor_and_intent_child_validates_token_emits_and_flushes_the_same_token_bound_pseudonym_in_ready_frame_then_waits_only_for_stdin_controller_create_new_persists_and_durably_syncs_exact_ready_frame_then_durably_syncs_matching_process_start_binding_ready_controller_create_new_persists_and_durably_syncs_release_frame_binding_token_ready_start_and_pseudonym_then_sends_same_exact_frame_child_validates_release_and_identity_then_create_new_writes_and_syncs_canonical_receipt_before_any_Criterion_construction_setup_or_timing_token_ready_start_release_receipt_and_finish_all_equal_the_same_pseudonym_causal_fingerprints_not_child_clocks_or_raw_PID_prove_order".to_owned(),
    }
}

fn criterion_home_protocol() -> SdJwtIssuanceCriterionHomeProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactInventoryEntryArray, String, U32, U64,
    };
    SdJwtIssuanceCriterionHomeProtocol {
        inventory_schema: "marty.performance/sd-jwt-issuance-criterion-home-inventory/v1"
            .to_owned(),
        inventory_fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("phase", String, false),
            ("collected_at_utc_rfc3339_nanoseconds", String, false),
            ("collected_at_monotonic_nanoseconds", U64, false),
            ("criterion_home", String, false),
            ("entries", ArtifactInventoryEntryArray, false),
        ]),
        entry_fields: evidence_fields([
            ("relative_path", String, false),
            ("file_kind", String, false),
            ("fingerprint", ArtifactFingerprint, false),
        ]),
        opaque_artifact_rule: "every_Criterion_owned_file_is_an_opaque_bounded_byte_string_hashed_exactly_as_written_without_Marty_canonical_byte_requirements_all_files_are_streamed_and_bound_by_the_final_inventory".to_owned(),
        benchmark_json_projection_rule: "parse_only_the_selected_new/benchmark.json_with_Criterion_0.5.1_shape_require_exact_ordered_keys_group_id_function_id_value_str_throughput_full_id_directory_name_title_throughput_is_exact_single_variant_Bytes_u64_object_and_require_group_function_full_id_directory_name_title_equal_manifest_selected_ID_mapping_reject_unknown_duplicate_missing_wrong_type_nonfinite_or_trailing_data".to_owned(),
        estimates_json_projection_rule: "parse_only_the_sibling_new/estimates.json_with_Criterion_0.5.1_Estimates_shape_exact_ordered_keys_mean_median_median_abs_dev_slope_std_dev_each_nonnull_estimate_has_exact_ordered_confidence_interval_point_estimate_standard_error_and_confidence_interval_has_exact_ordered_confidence_level_lower_bound_upper_bound_all_numbers_finite_each_interval_ordered_and_confidence_level_0.95_slope_is_nullable_and_when_nonnull_has_same_estimate_shape_selected_value_is_positive_median.point_estimate".to_owned(),
        freshness_rule: "controller_create_directory_fail_if_exists_at_unique_coordinate_home_reject_link_or_reparse_initial_inventory_phase_initial_is_synced_before_intent_and_has_zero_entries_final_inventory_phase_final_is_collected_after_successful_child_exit_in_ascending_utf8_relative_path_order_contains_exactly_eight_regular_files_for_one_manifest_matching_ID_base_and_new_each_have_benchmark.json_estimates.json_sample.json_tukey.json_corresponding_base_and_new_files_are_byte_equal_every_file_was_created_from_that_lifecycle_no_unrelated_benchmark_id_and_finish_binds_both_inventories_and_selected_new_artifacts".to_owned(),
    }
}

fn route_artifact_protocol() -> SdJwtIssuanceRouteArtifactProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        Boolean, RouteReadyBatchArray, RouteStaticChunkArray, String, U64,
    };
    SdJwtIssuanceRouteArtifactProtocol {
        record_schema: "sd_jwt_issuance_route_v2".to_owned(),
        artifact_format: "create_new_utf8_exactly_one_serde_json_1.0.151_canonical_compact_record_plus_one_LF_no_BOM_CR_or_extra_bytes_flush_and_durable_sync".to_owned(),
        record_fields: evidence_fields([
            ("schema", String, false),
            ("benchmark_id", String, false),
            ("fixture_id", String, false),
            ("stage", String, false),
            ("requested", String, false),
            ("effective", String, false),
            ("executor_batches", U64, true),
            ("serial_batches", U64, true),
            ("native_batches", U64, true),
            ("budget_fallback_batches", U64, true),
            ("max_native_worker_count", U64, false),
            ("worker_cap", U64, false),
            ("host_available_parallelism", U64, false),
            ("work_estimator_version", String, false),
            ("static_partition_rule_version", String, false),
            ("ready_batches", RouteReadyBatchArray, true),
        ]),
        ready_batch_fields: evidence_fields([
            ("ordinal", U64, false),
            ("job_count", U64, false),
            ("estimated_work_bytes", U64, true),
            ("work_estimate_status", String, false),
            ("work_gate_evaluated", Boolean, false),
            ("parallelism_gate_evaluated", Boolean, false),
            ("budget_gate_evaluated", Boolean, false),
            ("available_parallelism", U64, true),
            ("selected_worker_count", U64, true),
            ("leased_worker_count", U64, true),
            ("budget_acquisition_result", String, false),
            ("selected_mode", String, false),
            ("selection_reason", String, false),
            ("static_chunk_size", U64, true),
            ("static_chunks", RouteStaticChunkArray, true),
        ]),
        static_chunk_fields: evidence_fields([
            ("ordinal", U64, false),
            ("job_count", U64, false),
            ("estimated_work_bytes", U64, false),
        ]),
        stage_literals: ["executor_assembly", "full_issuance"]
            .map(str::to_owned)
            .to_vec(),
        requested_literals: ["serial_oracle", "adaptive_candidate"]
            .map(str::to_owned)
            .to_vec(),
        effective_literals: [
            "serial_oracle",
            "bounded_native",
            "mixed_native_and_serial",
            "ready_batch_serial_fallback",
            "budget_serial_fallback",
            "target_serial_fallback",
        ]
        .map(str::to_owned)
        .to_vec(),
        work_estimate_status_literals: ["not_evaluated", "available", "overflow"]
            .map(str::to_owned)
            .to_vec(),
        budget_acquisition_result_literals: ["not_evaluated", "acquired", "unavailable"]
            .map(str::to_owned)
            .to_vec(),
        selected_mode_literals: ["serial", "native_parallel"]
            .map(str::to_owned)
            .to_vec(),
        selection_reason_literals: [
            "below_min_jobs",
            "work_estimate_overflow",
            "below_min_estimated_work_bytes",
            "insufficient_available_parallelism",
            "worker_budget_unavailable",
            "bounded_native",
        ]
        .map(str::to_owned)
        .to_vec(),
        selected_record_rule: "fixed_binary_constructs_all_132_manifest_route_records_in_exact_registration_order_validates_the_full_unique_set_then_requires_SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID_equal_the_descriptor_and_exact_Criterion_filter_and_retains_only_that_one_matching_record_the_manifest_serial_ID_requires_requested_serial_oracle_and_the_manifest_adaptive_ID_requires_requested_adaptive_candidate_reject_missing_duplicate_extra_or_route-swapped_match".to_owned(),
        record_invariant_rule: "deny_unknown_duplicate_missing_wrong_type_nonfinite_checked_integer_overflow_or_trailing_data_schema_fixture_stage_and_benchmark_id_equal_the_exact_manifest_case_cell_and_full_ID_requested_is_exactly_serial_oracle_for_that_cell_serial_ID_or_adaptive_candidate_for_that_cell_adaptive_ID_versions_equal_issuance_work_bytes_v1_and_contiguous_ceil_chunks_v1_worker_cap_equals_manifest_and_locked_fixed_binary_host_available_parallelism_is_at_least_1_and_equals_bound_hardware_profile_serial_oracle_requires_effective_serial_oracle_all_four_batch_counts_and_ready_batches_null_and_max_native_worker_count_0_adaptive_target_fallback_requires_effective_target_serial_fallback_the_same_five_nullable_values_null_max_0_and_worker_cap_1_and_worker_cap_1_requires_this_exact_target_fallback_branch_other_adaptive_requires_worker_cap_at_least_2_ready_batches_array_and_four_nonnull_counts_let_E_equal_array_length_N_equal_count_selected_mode_native_parallel_S_equal_E_minus_N_F_equal_count selection_reason worker_budget_unavailable_and_M_equal_max_nonnull_leased_worker_count_or_0_require_executor_batches_E_native_batches_N_serial_batches_S_budget_fallback_batches_F_max_native_worker_count_M_E_equal_S_plus_N_F_at_most_S_and_M_at_most_worker_cap_effective_is_mixed_native_and_serial_if_N_positive_and_S_positive_else_bounded_native_if_N_positive_else_budget_serial_fallback_if_F_positive_else_ready_batch_serial_fallback_empty_array_is_ready_batch_serial_fallback_and_no_adaptive_record_may_use_serial_oracle".to_owned(),
        ready_batch_invariant_rule: "for_each_zero_based_ordinal_J_job_count_is_positive_X_is_estimated_work_bytes_A_is_available_parallelism_W_is_selected_worker_count_cap_is_record_worker_cap_and_thresholds_are_Jmin_2_and_Xmin_1_every_status_result_mode_and_reason_is_from_its_protocol_literal_array_and_only_exact_mode_reason_pairs_serial_below_min_jobs_serial_work_estimate_overflow_serial_below_min_estimated_work_bytes_serial_insufficient_available_parallelism_serial_worker_budget_unavailable_or_native_parallel_bounded_native_are_valid_below_min_jobs_iff_J_below_2_X_null_status_not_evaluated_work_gate_false_A_W_null_parallelism_gate_false_budget_gate_false_result_not_evaluated_mode_serial_lease_chunk_size_chunks_null_work_estimate_overflow_requires_J_at_least_2_X_null_status_overflow_work_gate_true_and_same_remaining_unevaluated_serial_fields_below_min_estimated_work_bytes_requires_J_at_least_2_X_present_below_1_status_available_work_gate_true_and_same_remaining_unevaluated_serial_fields_otherwise_X_at_least_1_status_available_work_gate_true_A_present_at_least_1_parallelism_gate_true_W_equals_min_A_cap_J_and_A_equals_record_host_available_parallelism_if_W_below_2_reason_insufficient_available_parallelism_budget_unevaluated_and_serial_static_null_if_W_at_least_2_and_acquisition_fails_reason_worker_budget_unavailable_budget_gate_true_result_unavailable_and_serial_lease_and_static_null_if_W_at_least_2_and_acquisition_succeeds_reason_bounded_native_budget_gate_true_result_acquired_mode_native_parallel_leased_worker_count_W_and_static_fields_present_equivalently_work_gate_iff_status_not_not_evaluated_X_present_iff_status_available_parallelism_gate_iff_A_and_W_present_budget_gate_iff_result_not_not_evaluated_native_parallel_iff_reason_bounded_native_and_lease_chunk_size_chunks_present_iff_native".to_owned(),
        static_chunk_invariant_rule: "native_only_with_J_job_count_W_selected_workers_X_estimated_work_bytes_C_equal_checked_ceil_J_div_W_and_K_equal_checked_ceil_J_div_C_static_chunk_size_equals_C_exactly_K_nonempty_chunks_K_at_most_W_ordinals_are_contiguous_0_through_K_minus_1_each_nonfinal_job_count_equals_C_final_job_count_equals_J_minus_C_times_K_minus_1_and_is_between_1_and_C_checked_sum_job_count_equals_J_checked_sum_estimated_work_bytes_equals_X_record_max_native_worker_count_uses_leased_W_not_K_analyzer_validation_is_limited_to_these_retained_count_ordinal_and_sum_equations_because_per_job_work_is_not_retained_while_locked_fixed_binary_source_tests_validate_each_chunk_estimate_against_its_exact_contiguous_job_slice_and_the_artifact_fingerprint_binds_the_emitted_values".to_owned(),
    }
}

fn artifact_index_protocol() -> SdJwtIssuanceArtifactIndexProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, CoordinateArtifactArray, String, U32,
    };
    SdJwtIssuanceArtifactIndexProtocol {
        criterion_schema: "marty.performance/sd-jwt-issuance-criterion-artifact-index/v1"
            .to_owned(),
        route_schema: "marty.performance/sd-jwt-issuance-route-artifact-index/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_JSON_plus_one_LF_flush_and_durable_sync_before_terminal_segment_footer"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("artifact_kind", String, false),
            ("entry_count", U32, false),
            ("entries", CoordinateArtifactArray, false),
        ]),
        entry_fields: evidence_fields([
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("relative_path", String, false),
            ("fingerprint", ArtifactFingerprint, false),
        ]),
        criterion_artifact_kind: "criterion_0_5_1_new_estimates_json".to_owned(),
        route_artifact_kind: "sd_jwt_issuance_route_v2".to_owned(),
        criterion_path_rule: "exact_ASCII_forward_slash_formatter_criterion/rRR_cCC_eE/sd_jwt_issuance/FUNCTION_ID/new/estimates.json_where_RR_is_two_digit_round_00_through_19_CC_is_two_digit_cell_00_through_65_E_is_one_digit_expansion_0_through_7_and_FUNCTION_ID_is_full_benchmark_id_after_removing_exactly_one_sd_jwt_issuance/ prefix_require_string_equality_to_formatter_and_reject_backslash_dot_or_dotdot_segment_absolute_path_alternate_padding_case_separator_escape_alias_or_extra_prefix".to_owned(),
        route_path_rule: "exact_ASCII_forward_slash_formatter_routes/rRR_cCC_eE.ndjson_with_the_same_coordinate_digits_require_string_equality_to_formatter_and_reject_backslash_dot_or_dotdot_segment_absolute_path_alternate_padding_case_separator_escape_alias_or_extra_suffix".to_owned(),
        validity_rule: "each_index_artifact_kind_equals_its_exact_protocol_literal_entry_count_is_10560_and_entries_are_exactly_unique_in_zero-based_array_position_order_array_position_equals_checked_formula_global_round_ordinal_times_66_plus_cell_ordinal_then_times_8_plus_expansion_position_with_round_0_through_19_cell_0_through_65_and_expansion_0_through_7_timing_process_id_equals_rRR-cCC-eE_full_benchmark_id_equals_the_schedule-selected_manifest_serial_or_adaptive_ID_relative_path_equals_the_kind-specific_exact_formatter_every_fingerprint_matches_process_completion_and_exact_opaque_Criterion_or_typed_route_file_bytes_and_completion_set_fingerprint_binds_the_entire_canonical_synced_index_artifact_reject_missing_extra_duplicate_gap_reorder_or_alias".to_owned(),
    }
}

fn terminal_observation_receipt_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        ("channel_id", String, false),
        ("log_id", String, false),
        ("campaign_append_ordinal", U64, false),
        ("channel_clock_session_id", String, false),
        ("channel_monotonic_nanoseconds", U64, false),
        ("observed_at_utc_rfc3339_nanoseconds", String, false),
        ("channel_receipt_id", String, false),
        ("challenge_uppercase_hex_256", String, false),
        ("terminal_segment_fingerprint", ArtifactFingerprint, false),
        ("terminal_footer_monotonic_nanoseconds", U64, false),
        ("controller_request_monotonic_nanoseconds", U64, false),
        ("signing_key_id", String, false),
        ("signature_uppercase_hex_512", String, false),
    ])
}

fn terminal_observation_evidence_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        (
            "terminal_observation_receipt_fingerprint",
            ArtifactFingerprint,
            false,
        ),
        (
            "controller_receipt_observed_monotonic_nanoseconds",
            U64,
            false,
        ),
    ])
}

fn completion_anchor_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    evidence_fields([
        ("schema", String, false),
        ("campaign_id", String, false),
        ("channel_id", String, false),
        ("log_id", String, false),
        ("campaign_append_ordinal", U64, false),
        ("channel_clock_session_id", String, false),
        ("channel_monotonic_nanoseconds", U64, false),
        ("published_at_utc_rfc3339_nanoseconds", String, false),
        ("channel_receipt_id", String, false),
        ("challenge_uppercase_hex_256", String, false),
        ("completion_fingerprint", ArtifactFingerprint, false),
        ("terminal_segment_fingerprint", ArtifactFingerprint, false),
        (
            "terminal_observation_evidence_fingerprint",
            ArtifactFingerprint,
            false,
        ),
        ("signing_key_id", String, false),
        ("signature_uppercase_hex_512", String, false),
    ])
}

fn external_anchor_channel_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-external-anchor-channel/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("channel_id", String, false),
            ("channel_kind", String, false),
            ("endpoint_role", String, false),
            ("log_id", String, false),
            ("connector_authentication_policy", String, false),
            ("receipt_verification_scheme", String, false),
            ("signing_key_id", String, false),
            ("trust_root_fingerprint", ArtifactFingerprint, false),
            ("clock_policy", String, false),
            ("maximum_receipt_bytes", U64, false),
        ]),
        "exactly_one_at_configuration/external-anchor-channel.json_and_bound_by_first_window_genesis_and_completion",
        "channel_id_equals_marty-sd-jwt-issuance-anchor-v1_channel_kind_equals_signed_create_only_log_v1_endpoint_role_equals_preconfigured_primary_anchor_connector_log_id_equals_sd-jwt-issuance-qualification-v1_connector_authentication_policy_equals_out_of_band_trust_root_authenticated_transport_v1_receipt_verification_scheme_equals_ed25519_rfc8032_canonical_json_v1_signing_key_id_equals_marty-sd-jwt-issuance-anchor-ed25519-v1_trust_root_fingerprint_has_byte_length_32_and_SHA256_of_exact_32_raw_Ed25519_public_key_bytes_resolved_only_by_exact_channel_log_and_key_ID_match_in_the_analyzer_out_of_band_preconfigured_read_only_trust_store_and_never_to_a_campaign_file_clock_policy_equals_signed_nonrollback_monotonic_session_si_nanoseconds_v1_under_which_one_session_ID_identifies_one_nonrestarting_channel_monotonic_origin_each_tick_is_one_SI_nanosecond_the_counter_never_rolls_back_or_slows_relative_to_elapsed_time_and_restart_changes_the_session_ID_maximum_receipt_bytes_is_exactly_16384_raw_endpoint_credentials_access_tokens_private_keys_and_transport_diagnostics_are_never_campaign_artifacts",
    )
}

pub(super) fn completion_protocol() -> SdJwtIssuanceRunValidityCompletionProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactFingerprintArray, ProcessCompletionArray, String, U32, U64,
    };
    SdJwtIssuanceRunValidityCompletionProtocol {
        schema: "marty.performance/sd-jwt-issuance-validity-completion/v1".to_owned(),
        artifact_format:
            "create_new_utf8_canonical_pretty_json_lf_flush_and_durable_sync_after_terminal_segment_sync"
                .to_owned(),
        fields: evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("created_at_utc_rfc3339_nanoseconds", String, false),
            ("created_at_monotonic_nanoseconds", U64, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("manifest_fingerprint", ArtifactFingerprint, false),
            (
                "external_anchor_channel_configuration_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("genesis_header_fingerprint", ArtifactFingerprint, false),
            ("ordered_segment_fingerprints", ArtifactFingerprintArray, false),
            ("terminal_segment_fingerprint", ArtifactFingerprint, false),
            (
                "terminal_observation_evidence_fingerprint",
                ArtifactFingerprint,
                false,
            ),
            ("ordered_test_window_attestation_fingerprints", ArtifactFingerprintArray, false),
            ("first_monotonic_nanoseconds", U64, false),
            ("last_monotonic_nanoseconds", U64, false),
            ("segment_count", U32, false),
            ("sample_count", U64, false),
            ("process_intent_count", U32, false),
            ("process_start_count", U32, false),
            ("process_finish_count", U32, false),
            ("attestation_transition_count", U32, false),
            ("process_completions", ProcessCompletionArray, false),
            ("criterion_artifact_set_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_set_fingerprint", ArtifactFingerprint, false),
            ("first_quiet_window_evidence_fingerprint", ArtifactFingerprint, false),
            ("invalidating_event_count", U32, false),
            ("validity_status", String, false),
        ]),
        process_completion_fields: evidence_fields([
            ("global_round_ordinal", U32, false),
            ("cell_ordinal", U32, false),
            ("expansion_position", U32, false),
            ("timing_process_id", String, false),
            ("full_benchmark_id", String, false),
            ("process_intent_record_fingerprint", ArtifactFingerprint, false),
            ("process_start_record_fingerprint", ArtifactFingerprint, false),
            ("process_finish_record_fingerprint", ArtifactFingerprint, false),
            ("invocation_descriptor_fingerprint", ArtifactFingerprint, false),
            ("launch_barrier_receipt_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_initial_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_home_final_inventory_fingerprint", ArtifactFingerprint, false),
            ("criterion_artifact_fingerprint", ArtifactFingerprint, false),
            ("route_artifact_fingerprint", ArtifactFingerprint, false),
        ]),
        validity_rule: "created_after_terminal_footer_and_signed_ordinal_0_terminal_observation_receipt_and_its_create_new_synced_controller_observation_wrapper_then_create_new_written_flushed_and_durably_synced_before_signed_ordinal_1_completion_anchor_and_within_total_campaign_limit_validity_status_exactly_valid_invalidating_event_count_0_external_anchor_channel_configuration_matches_genesis_and_typed_fixed_role_ordered_segments_are_complete_chain_terminal_equals_last_first_and_last_monotonic_equal_genesis_and_terminal_footer_genesis_fixed_binary_build_receipt_fingerprint_resolves_the_exact_v2_receipt_whose_inventory_and_archive_fingerprints_resolve_build/input-inventory.json_and_build/input-files.bia_and_the_inventory_archive_fingerprint_matches_so_every_member_byte_mode_and_path_is_offline_recomputable_terminal_observation_evidence_fingerprint_binds_the_exact_wrapper_and_signed_ordinal_0_receipt_attestations_are_complete_actual_chain_process_intent_start_finish_counts_each_10560_process_completions_have_exactly_10560_unique_round_major_cell_major_expansion_entries_with_matching_synced_intent_ready_start_release_receipt_successful_finish_fresh_home_and_artifacts_and_criterion_and_route_artifact_set_fingerprints_bind_the_exact_two_canonical_synced_index_artifacts_whose_entries_match_process_completions".to_owned(),
        terminal_observation_receipt_schema:
            "marty.performance/sd-jwt-issuance-terminal-observation-receipt/v1".to_owned(),
        terminal_observation_receipt_fields: terminal_observation_receipt_fields(),
        terminal_observation_evidence_schema:
            "marty.performance/sd-jwt-issuance-terminal-observation-evidence/v1".to_owned(),
        terminal_observation_evidence_fields: terminal_observation_evidence_fields(),
        external_anchor_schema: "marty.performance/sd-jwt-issuance-completion-anchor/v1".to_owned(),
        external_anchor_fields: completion_anchor_fields(),
        external_anchor_format: "two_offline_verifiable_Ed25519_signed_create-only_log_receipts_are_retained_at_anchors/terminal-observation-receipt.json_and_anchors/completion-anchor.json_as_utf8_canonical_pretty_JSON_plus_one_LF_with_the_Marty_owned_terminal_observation_wrapper_at_anchors/terminal-observation-evidence.json_each_create_new_flushed_and_durably_synced_and_each_signed_receipt_independently_verifiable_without_network_access".to_owned(),
        external_anchor_channel: external_anchor_channel_protocol(),
        external_anchor_channel_id: "marty-sd-jwt-issuance-anchor-v1".to_owned(),
        external_anchor_log_id: "sd-jwt-issuance-qualification-v1".to_owned(),
        external_anchor_connector_policy:
            "out_of_band_trust_root_authenticated_transport_v1".to_owned(),
        external_anchor_signature_scheme: "ed25519_rfc8032_canonical_json_v1".to_owned(),
        external_anchor_signing_key_id:
            "marty-sd-jwt-issuance-anchor-ed25519-v1".to_owned(),
        external_anchor_signed_preimage_rule: "strict_RFC8032_Ed25519_over_exact_ASCII_domain_then_u64_big_endian_unsigned_JSON_byte_length_then_canonical_compact_unsigned_JSON_without_LF_and_with_every_field_preceding_signature_in_protocol_order_terminal_domain_is_MARTY-SD-JWT-TERMINAL-OBSERVATION-V1_then_0x00_completion_domain_is_MARTY-SD-JWT-COMPLETION-ANCHOR-V1_then_0x00_signature_is_exactly_128_ASCII_uppercase_hex_characters_channel_clock_session_ID_is_exactly_64_ASCII_uppercase_hex_characters_unique_to_one_nonrestarting_channel_clock_session_challenge_is_an_independently_sampled_32_byte_CSPRNG_value_encoded_as_exactly_64_ASCII_uppercase_hex_characters_unique_across_both_receipts_and_all_other_campaign_nonces_or_pseudonyms_mutation_of_any_field_domain_length_key_or_signature_rejects".to_owned(),
        external_anchor_receipt_id_rule:
            "ASCII_[A-Za-z0-9._:-]_length_1_through_128_nonsecret_locator".to_owned(),
        external_anchor_replay_rule: "the_pinned_channel_create-only_uniqueness_and_non-equivocation_guarantee_for_each_exact_channel_id_log_id_campaign_id_campaign_append_ordinal_tuple_is_an_explicit_out-of-band_trusted-service_assumption_and_an_offline_bundle_cannot_discover_a_conflicting_receipt_withheld_by_that_trusted_channel_analyzer_rejects_every_same-tuple_pair_with_different_exact_canonical_signed_receipt_bytes_present_in_the_bundle_ordinals_are_exactly_0_for_terminal_observation_and_1_for_completion_only_exact_byte-for-byte_same_signed_receipt_retrieval_is_idempotent_same_locator_with_different_signed_bytes_is_a_conflict_both_ordinals_use_the_same_bound_channel_log_key_and_channel_clock_session_and_ordinal_1_binds_the_local_evidence_wrapper_whose_fingerprint_binds_ordinal_0_no_cross-log_channel_campaign_session_or_ordinal_replay_is_valid_and_no_one-time_downstream_activation_is_inferred".to_owned(),
        external_anchor_rule: "before_UTF8_or_JSON_parsing_analyzer_reads_each_signed_receipt_at_most_hardcoded_MAX_SD_JWT_ISSUANCE_COMPLETION_ANCHOR_V1_BYTES_16384_plus_one_and_rejects_larger_input_independently_of_plan_fields_then_offline_verifies_exact_canonical_bytes_signature_trust_root_channel_log_campaign_key_receipt_ID_challenge_channel_clock_session_and_ordinal_0_or_1_semantics_terminal_observation_receipt_terminal_fingerprint_and_footer_monotonic_match_the_synced_terminal_segment_controller_request_monotonic_is_between_terminal_footer_and_controller_receipt_observed_monotonic_inclusive_wrapper_binds_exact_ordinal_0_receipt_and_controller_observation_completion_binds_wrapper_and_is_durably_synced_before_ordinal_1_ordinal_1_binds_completion_terminal_and_wrapper_both_receipts_have_the_same_channel_clock_session_ID_and_ordinal_1_channel_monotonic_is_not_before_ordinal_0_timing_uses_only_same-clock_durations_A_is_checked_controller_receipt_observed_monotonic_minus_terminal_footer_monotonic_B_is_checked_ordinal_1_channel_monotonic_nanoseconds_minus_ordinal_0_channel_monotonic_nanoseconds_checked_A_plus_B_must_be_at_most_maximum_anchor_publication_delay_seconds_300000000000_nanoseconds_underflow_overflow_session_change_or_one_nanosecond_over_rejects_channel_UTC_is_retained_only_as_authenticated_audit_metadata_and_is_not_used_for_duration_controller_UTC_is_not_compared_to_channel_UTC_the_limit_proves_channel_publication_not_local_ordinal_1_receipt_delivery_or_sync_and_network_access_is_neither_used_nor_permitted_during_offline_analysis".to_owned(),
    }
}

fn controller_configuration_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-controller-config/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("artifact_layout_version", String, false),
            ("process_schedule_version", String, false),
            ("child_environment_policy_version", String, false),
            ("launch_transport_version", String, false),
            ("stdout_retention_policy", String, false),
            ("stderr_retention_policy", String, false),
            ("external_anchor_channel_id", String, false),
            ("external_anchor_policy_version", String, false),
            ("maximum_spawn_to_ready_seconds", U32, false),
            ("maximum_timing_process_seconds", U32, false),
            ("maximum_process_output_bytes", U64, false),
            ("maximum_anchor_publication_delay_seconds", U32, false),
            ("synthetic_data_only", Boolean, false),
            ("source_export_approved", Boolean, false),
        ]),
        "exactly_one_at_configuration/controller.json",
        "artifact_layout_version_equals_sd_jwt_issuance_artifact_layout_v1_process_schedule_version_equals_global_round_manifest_cell_expansion_v1_child_environment_policy_version_equals_cleared_allowlist_v1_launch_transport_version_equals_stdio_ready_release_v1_stdout_retention_policy_equals_persist_ready_only_drain_discard_rest_v1_stderr_retention_policy_equals_bounded_drain_discard_v1_external_anchor_channel_id_equals_marty-sd-jwt-issuance-anchor-v1_external_anchor_policy_version_equals_signed_offline_receipts_v1_all_limits_including_maximum_anchor_publication_delay_seconds_equal_the_plan_synthetic_data_only_and_source_export_approved_are_true_no_path_endpoint_credential_or_free_form_diagnostic_field_is_permitted",
    )
}

fn monitor_configuration_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, Boolean, String, U32};
    record_protocol(
        "marty.performance/sd-jwt-issuance-monitor-config/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("plan_fingerprint", ArtifactFingerprint, false),
            ("sample_interval_seconds", U32, false),
            ("maximum_sample_gap_seconds", U32, false),
            ("controller_clock_authoritative", Boolean, false),
            ("cpu_backend", String, false),
            ("memory_backend", String, false),
            ("frequency_backend", String, false),
            ("temperature_backend", String, false),
            ("throttle_backend", String, false),
            ("process_scope_policy", String, false),
            ("process_identity_scheme", String, false),
            ("process_identity_key_persisted", Boolean, false),
            ("raw_process_metadata_retained", Boolean, false),
        ]),
        "exactly_one_at_configuration/monitor.json",
        "intervals_equal_the_plan_controller_clock_authoritative_is_true_cpu_backend_equals_controller_observed_total_cpu_percent_v1_memory_backend_equals_controller_observed_available_memory_bytes_v1_frequency_backend_equals_controller_observed_cpu_frequency_hz_v1_temperature_backend_equals_controller_observed_maximum_temperature_millidegrees_celsius_v1_throttle_backend_equals_controller_observed_throttle_flags_v1_no_backend_value_is_a_device_or_filesystem_path_process_scope_policy_equals_exact_baseline_match_v1_process_identity_scheme_equals_hmac_sha256_campaign_ephemeral_process_set_v1_and_both_process_identity_key_persisted_and_raw_process_metadata_retained_are_false",
    )
}

fn host_identity_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::String;
    record_protocol(
        "marty.performance/sd-jwt-issuance-host-identity/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("identity_scheme", String, false),
            ("host_identity_pseudonym", String, false),
            ("boot_identity_pseudonym", String, false),
        ]),
        "exactly_one_at_profiles/host-identity.json",
        "identity_scheme_is_campaign_random_256_v1_each_pseudonym_is_an_independent_64_character_uppercase_hex_CSPRNG_value_unique_to_this_campaign_and_is_not_a_hostname_machine_or_boot_ID_serial_account_network_value_or_hash_of_any_guessable_identifier_controller_detects_underlying_host_or_boot_change_without_persisting_the_raw_values",
    )
}

fn hardware_profile_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{String, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-hardware-profile/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("operating_system_family", String, false),
            ("operating_system_version", String, true),
            ("kernel_version", String, true),
            ("architecture", String, false),
            ("cpu_vendor", String, true),
            ("cpu_model", String, true),
            ("physical_core_count", U32, true),
            ("logical_cpu_count", U32, false),
            ("host_available_parallelism", U32, false),
            ("numa_node_count", U32, true),
            ("total_memory_bytes", U64, false),
            ("nominal_cpu_frequency_hz", U64, true),
            ("virtualization_kind", String, false),
            ("power_policy", String, false),
        ]),
        "exactly_one_at_profiles/hardware.json",
        "operating_system_family_architecture_virtualization_kind_and_power_policy_each_equal_one_value_from_their_protocol_literal_array_operating_system_version_kernel_version_cpu_vendor_and_cpu_model_are_null_or_printable_ASCII_length_1_through_128_physical_core_count_and_numa_node_count_when_present_are_1_through_65536_logical_cpu_count_and_host_available_parallelism_are_1_through_observation_bounds_maximum_logical_cpu_count_and_host_available_parallelism_is_at_most_logical_cpu_count_total_memory_bytes_is_1_through_observation_bounds_maximum_total_memory_bytes_nominal_cpu_frequency_when_present_is_within_observation_bounds_frequency_range_hostname_username_IP_MAC_device_CPU_disk_or_cloud_instance_serial_and_filesystem_path_fields_are_forbidden",
    )
}

fn validity_thresholds_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{Boolean, String, StringArray, F64, I64, U32, U64};
    record_protocol(
        "marty.performance/sd-jwt-issuance-validity-thresholds/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("maximum_total_cpu_percent", F64, false),
            ("maximum_monitor_cpu_percent", F64, false),
            ("maximum_unrelated_cpu_percent", F64, false),
            ("minimum_available_memory_bytes", U64, false),
            ("minimum_cpu_frequency_hz", U64, false),
            ("maximum_temperature_millidegrees_celsius", I64, false),
            ("forbidden_throttle_flags", StringArray, false),
            ("maximum_unrelated_process_count", U32, false),
            ("unrelated_process_set_policy", String, false),
            ("require_all_observations", Boolean, false),
        ]),
        "exactly_one_at_profiles/validity-thresholds.json",
        "maximum_total_monitor_and_unrelated_CPU_percent_are_finite_in_inclusive_observation_bounds_and_monitor_and_unrelated_are_each_at_most_total_minimum_available_memory_bytes_is_0_to_bound_hardware_total_memory_where_0_disables_the_cutoff_minimum_cpu_frequency_hz_is_0_or_within_observation_bounds_frequency_range_where_0_disables_the_cutoff_maximum_temperature_millidegrees_celsius_is_0_through_observation_bounds_maximum_temperature_forbidden_throttle_flags_are_sorted_unique_values_from_the_protocol_throttle_flag_literals_and_must_not_include_none_maximum_unrelated_process_count_is_0_through_observation_bounds_maximum_unrelated_process_count_unrelated_process_set_policy_is_exact_baseline_match_v1_and_require_all_observations_is_true",
    )
}

fn unrelated_process_set_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{ProcessIdentityArray, String, U32};
    record_protocol(
        "marty.performance/sd-jwt-issuance-unrelated-process-set/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("boot_identity_pseudonym", String, false),
            ("identity_scheme", String, false),
            ("entry_count", U32, false),
            ("opaque_process_instances", ProcessIdentityArray, false),
        ]),
        "exactly_one_baseline_and_one_content_addressed_document_for_each_distinct_sampled_set",
        "identity_scheme_is_hmac_sha256_campaign_ephemeral_process_set_v1_entry_count_equals_array_length_and_is_at_most_4096_each_process_instance_pseudonym_is_exactly_64_ASCII_uppercase_hex_characters_entries_are_sorted_unique_and_match_the_baseline_under_exact_baseline_match_v1_controller_samples_one_independent_32_byte_CSPRNG_process_set_key_that_is_never_reused_as_any_target_or_other_key_and_derives_each_pseudonym_as_HMAC-SHA256_over_ASCII_marty.unrelated-process-instance.v1_then_0x00_then_u64_big_endian_total_tuple_byte_length_then_raw_tuple_bytes_where_the_tuple_is_u64be_operating_system_family_UTF8_byte_length_then_exact_operating_system_family_UTF8_then_u64be_PID_then_u64be_process_start_unix_nanoseconds_then_32_raw_SHA256_bytes_of_the_executable_file_controller_never_retains_the_key_tuple_PID_start_time_image_name_executable_path_or_digest_argv_environment_account_or_container_endpoint",
    )
}

fn test_window_attestation_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{Boolean, String};
    record_protocol(
        "marty.performance/sd-jwt-issuance-test-window/v1",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("target_role", String, false),
            ("target_identity_pseudonym", String, false),
            ("starts_at_rfc3339_nanoseconds", String, false),
            ("expires_at_rfc3339_nanoseconds", String, false),
            ("change_reference_pseudonym", String, false),
            ("production_traffic_drained", Boolean, false),
            ("public_ingress_disabled", Boolean, false),
            ("synthetic_data_only", Boolean, false),
        ]),
        "exactly_one_first_quiet_window_role_and_between_1_and_16_disjoint_actual_timing_window_roles",
        "target_role_is_one_of_the_protocol_literal_array_controller_samples_one_independent_32_byte_CSPRNG_target_key_never_reused_as_the_process_set_key_or_any_other_key_target_identity_pseudonym_is_exactly_64_ASCII_uppercase_hex_characters_of_HMAC-SHA256_over_ASCII_marty.test-window-target.v1_then_0x00_then_u64_big_endian_length_then_normalized_origin_UTF8_normalized_origin_is_the_RFC6454_ASCII_serialization_of_an_absolute_HTTPS_origin_with_lowercase_scheme_and_IDNA2008_A-label_host_RFC5952_bracketed_IPv6_default_port_443_removed_nondefault_port_in_unpadded_decimal_and_no_userinfo_path_beyond_slash_query_or_fragment_all_actual_attestations_match_the_same_target_pseudonym_and_conditions_times_use_the_plan_UTC_format_duration_is_positive_and_at_most_43200_seconds_change_reference_pseudonym_is_an_independently_sampled_32_byte_CSPRNG_value_encoded_as_exactly_64_ASCII_uppercase_hex_characters_unique_to_the_campaign_and_distinct_from_every_other_pseudonym_nonce_or_HMAC_output_all_three_condition_booleans_are_true_raw_target_origin_change_ticket_operator_identity_and_authorization_material_remain_outside_exportable_campaign_evidence_and_the_trusted_controller_is_the_only_authority_linking_those_raw_values_to_their_pseudonyms",
    )
}

fn fixed_binary_build_input_inventory_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, ArtifactInventoryEntryArray, String, StringArray, U32, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-fixed-build-input-inventory/v2",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("target_triple", String, false),
            ("entry_count", U32, false),
            ("total_byte_length", U64, false),
            ("archive_fingerprint", ArtifactFingerprint, false),
            ("executable_path_directories", StringArray, false),
            ("entries", ArtifactInventoryEntryArray, false),
        ]),
        "exactly_one_at_build/input-inventory.json_created_before_the_build_receipt",
        "entry_count_equals_entries_length_and_is_1_through_maximum_fixed_binary_build_input_entries_checked_sum_of_entry_fingerprint_byte_lengths_equals_total_byte_length_archive_fingerprint_byte_length_equals_checked_magic_length_plus_8_times_entry_count_plus_total_byte_length_and_is_at_most_maximum_build_input_bytes_every_role_path_mode_and_cardinality_matches_the_closed_rules_executable_path_directories_reconstructs_PATH_exactly_entries_are_strictly_sorted_unique_by_role_then_unsigned_ASCII_relative_path_and_completely_inventory_every_file_in_the_staged_read_only_Cargo_home_dependency_sources_and_configuration_fingerprinted_Cargo_and_rustc_distribution_target_linker_archiver_dynamic_tool_dependencies_Windows_runtime_tree_and_every_executable_PATH_directory_each_entry_fingerprint_matches_the_corresponding_retained_archive_member_bytes_no_unknown_role_alias_absolute_parent_backslash_case-fold_collision_link_device_reparse_uninventoried_config_or_extra_readable_build_input_is_permitted",
    )
}

fn fixed_binary_build_receipt_protocol() -> SdJwtIssuanceEvidenceRecordProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, Boolean, NameValueArray, String, StringArray, U64,
    };
    record_protocol(
        "marty.performance/sd-jwt-issuance-fixed-binary-build/v2",
        evidence_fields([
            ("schema", String, false),
            ("campaign_id", String, false),
            ("controller_binary_fingerprint", ArtifactFingerprint, false),
            ("source_archive_fingerprint", ArtifactFingerprint, false),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("cargo_lock_fingerprint", ArtifactFingerprint, false),
            ("cargo_binary_fingerprint", ArtifactFingerprint, false),
            ("cargo_verbose_version", String, false),
            ("rustc_binary_fingerprint", ArtifactFingerprint, false),
            ("rustc_verbose_version", String, false),
            ("rustc_reported_sysroot", String, false),
            ("build_input_inventory_fingerprint", ArtifactFingerprint, false),
            ("build_input_archive_fingerprint", ArtifactFingerprint, false),
            ("target_triple", String, false),
            ("build_profile", String, false),
            ("materialized_build_root", String, false),
            ("working_directory", String, false),
            ("logical_argv", StringArray, false),
            ("enabled_features", StringArray, false),
            ("build_environment_policy", String, false),
            ("build_environment", NameValueArray, false),
            ("offline_dependency_resolution_argv", StringArray, false),
            ("offline_dependency_resolution_succeeded", Boolean, false),
            ("build_started_monotonic_nanoseconds", U64, false),
            ("build_finished_monotonic_nanoseconds", U64, false),
            ("produced_binary_fingerprint", ArtifactFingerprint, false),
            ("installed_fixed_binary_fingerprint", ArtifactFingerprint, false),
        ]),
        "exactly_one_at_build/fixed-benchmark.json_created_after_first_quiet_window_and_before_genesis",
        "all_source_toolchain_target_controller_build_input_inventory_and_build_input_archive_values_are_transitively_bound_by_genesis_and_fixed_role_preimages_and_the_inventory_archive_fingerprints_equal_each_other_target_triple_has_ASCII_length_1_through_128_every_byte_is_alphanumeric_hyphen_underscore_or_dot_and_is_not_dot_dotdot_host-tuple_or_any_ASCII_case_fold_suffix_.json_build_profile_equals_bench_materialized_build_root_equals_the_exact_platform_canonical_root_working_directory_equals_ROOT/worktree_enabled_features_equals_exact_single_item_issuance_bench_cargo_and_rustc_verbose_versions_are_exact_command_stdout_valid_UTF8_at_most_4096_bytes_with_only_printable_ASCII_and_LF_and_no_endpoint_credential_or_diagnostic_suffix_rustc_reported_sysroot_equals_ROOT/inputs/toolchain_from_executing_the_inventoried_rustc_--print_sysroot_under_the_exact_cleared_build_environment_build_environment_policy_equals_trusted_controller_inventoried_inputs_cleared_offline_sandbox_v1_and_build_environment_equals_the_exact_platform_mapping_including_the_concrete_derived_target_linker_name_and_exact_SystemRoot_WINDIR_PATH_and_SOURCE_DATE_EPOCH_values_logical_argv_is_exactly_cargo_build_--frozen_--offline_--profile_bench_--no-default-features_--features_issuance_bench_--bench_sd_jwt_issuance_--target_target_triple_--message-format_json-render-diagnostics_with_the_record_target_triple_substituted_at_that_position_offline_dependency_resolution_argv_is_exactly_cargo_metadata_--frozen_--offline_--locked_--format-version_1_and_succeeded_is_true_for_a_real_prebuild_probe_under_the_same_materialized_tree_cleared_environment_and_read_sandbox_controller_mounts_one_private_create-new_campaign_directory_at_the_exact_canonical_root_securely_materializes_only_the_verified_source_archive_under_ROOT/worktree_and_the_verified_build_input_archive_under_ROOT/inputs_preserving_the_Rust_distribution_toolchain/bin_and_toolchain/lib_layout_clears_environment_then_adds_only_the_closed_table_disables_network_and_incremental_compilation_declares_only_execution_intent_for_the_fingerprinted_rustc_target_linker_archiver_sysroot_dependency_sources_Cargo_configuration_dynamic_tool_and_staged_Windows_runtime_inputs_and_does_not_attest_actual_child_resolution_rejects_RUSTC_WRAPPER_RUSTC_WORKSPACE_WRAPPER_RUSTFLAGS_CARGO_ENCODED_RUSTFLAGS_or_any_unlisted_variable_and_sandboxes_reads_to_worktree_and_inventoried_inputs_and_writes_to_ROOT/target_and_ROOT/tmp_all_Cargo_generated_absolute_environment_values_including_CARGO_MANIFEST_DIR_and_OUT_DIR_are_deterministically_derived_from_ROOT_source_target_profile_and_package_metadata_and_any_other_observed_generated_value_rejects_controller_runs_only_the_probes_and_build_command_accepts_exactly_one_Cargo_compiler-artifact_executable_for_bench_sd_jwt_issuance_hashes_it_before_installation_copies_it_create_new_to_the_target-selected_fixed_binary_path_and_requires_produced_installed_and_genesis_fixed_binary_fingerprints_equal_build_started_is_after_the_first_quiet_window_end_build_finished_equals_or_follows_start_and_precedes_genesis_monotonic_checked_subtraction_and_all_archive_member_tool_dependency_configuration_environment_path_source_and_binary_fingerprints_bind_actual_bytes",
    )
}

fn fixed_build_input_inventory_entry_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::{ArtifactFingerprint, String};
    evidence_fields([
        ("role", String, false),
        ("relative_path", String, false),
        ("file_mode", String, false),
        ("fingerprint", ArtifactFingerprint, false),
    ])
}

fn fixed_build_input_mode_literals() -> Vec<String> {
    ["100644", "100755"].map(str::to_owned).to_vec()
}

fn test_window_target_role_literals() -> Vec<String> {
    [
        "isolated_production_gateway",
        "dedicated_performance_gateway",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn fixed_build_input_role_literals() -> Vec<String> {
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
        "windows_runtime_input",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn fixed_build_environment_entry_fields() -> Vec<SdJwtIssuanceEvidenceFieldProtocol> {
    use SdJwtIssuanceEvidenceJsonType::String;
    evidence_fields([
        ("name", String, false),
        ("value_kind", String, false),
        ("resolved_value", String, false),
    ])
}

pub(super) fn fixed_build_environment_allowlist() -> Vec<String> {
    [
        "AR",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_<TARGET_TRIPLE_ENV>_LINKER",
        "PATH",
        "RUSTC",
        "SOURCE_DATE_EPOCH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "WINDIR",
    ]
    .map(str::to_owned)
    .to_vec()
}

pub(super) fn observation_bounds() -> SdJwtIssuanceObservationBounds {
    SdJwtIssuanceObservationBounds {
        minimum_cpu_percent: 0.0,
        maximum_cpu_percent: 100.0,
        minimum_cpu_frequency_hz: 1,
        maximum_cpu_frequency_hz: 10_000_000_000,
        minimum_temperature_millidegrees_celsius: -100_000,
        maximum_temperature_millidegrees_celsius: 200_000,
        maximum_total_memory_bytes: 1_152_921_504_606_846_976,
        maximum_logical_cpu_count: 65_536,
        maximum_unrelated_process_count: 4_096,
    }
}

fn global_preimage_protocol() -> SdJwtIssuanceGlobalPreimageProtocol {
    use SdJwtIssuanceEvidenceJsonType::{
        ArtifactFingerprint, SourceArchiveEntryArray, String, U32,
    };

    SdJwtIssuanceGlobalPreimageProtocol {
        artifact_format: "each_typed_preimage_is_create_new_utf8_canonical_pretty_JSON_plus_one_LF_flushed_and_durably_synced_before_its_first_fingerprint_reference_unknown_duplicate_missing_wrong_type_nonfinite_out_of_range_or_trailing_data_rejects".to_owned(),
        resolution_rule: "plan_manifest_and_Cargo_lock_resolve_inputs/qualification-plan.json_inputs/qualification-manifest.json_and_inputs/Cargo.lock_target_triple_selects_exactly_one_fixed-benchmark_fixed-benchmark.exe_controller_controller.exe_monitor_or_monitor.exe_under_bin_controller_monitor_and_external_anchor_channel_configurations_resolve_configuration/controller.json_configuration/monitor.json_and_configuration/external-anchor-channel.json_source_archive_resolves_source/exact-tree.sar_fixed_binary_build_receipt_complete_build_input_inventory_and_retained_build_input_archive_resolve_build/fixed-benchmark.json_build/input-inventory.json_and_build/input-files.bia_host_hardware_threshold_and_baseline_process_set_resolve_profiles/host-identity.json_profiles/hardware.json_profiles/validity-thresholds.json_and_profiles/baseline-unrelated-process-set.json_first_quiet_window_attestation_resolves_attestations/first-quiet-window.json_actual_timing_window_attestations_resolve_disjoint_attestations/timing-window-0000.json_through_timing-window-0015.json_and_each_observed_process_set_resolves_observations/unrelated-process-sets/UPPERCASE_SHA256.json_all_paths_are_fixed_roles_or_valid_ordinals_and_reject_absolute_parent_backslash_empty_link_hardlink_reparse_missing_duplicate_or_extra_resolution_trust_root_fingerprint_is_the_only_nonfile_reference_and_resolves_exclusively_against_the_analyzer_out_of_band_trust_store".to_owned(),
        controller_configuration: controller_configuration_protocol(),
        monitor_configuration: monitor_configuration_protocol(),
        host_identity: host_identity_protocol(),
        hardware_profile: hardware_profile_protocol(),
        observation_bounds: observation_bounds(),
        operating_system_family_literals: ["windows", "linux", "macos"]
            .map(str::to_owned)
            .to_vec(),
        architecture_literals: ["x86_64", "aarch64"]
            .map(str::to_owned)
            .to_vec(),
        virtualization_kind_literals: [
            "bare_metal",
            "virtual_machine",
            "containerized_host",
            "unknown",
        ]
        .map(str::to_owned)
        .to_vec(),
        power_policy_literals: [
            "performance",
            "balanced",
            "platform_default",
            "custom_locked",
        ]
        .map(str::to_owned)
        .to_vec(),
        throttle_flag_literals: [
            "none",
            "thermal",
            "power_limit",
            "frequency_cap",
            "platform_reported_unknown",
        ]
        .map(str::to_owned)
        .to_vec(),
        validity_thresholds: validity_thresholds_protocol(),
        unrelated_process_set: unrelated_process_set_protocol(),
        process_identity_fields: evidence_fields([(
            "process_instance_pseudonym",
            String,
            false,
        )]),
        test_window_attestation: test_window_attestation_protocol(),
        test_window_target_role_literals: test_window_target_role_literals(),
        fixed_binary_build_receipt: fixed_binary_build_receipt_protocol(),
        fixed_binary_build_input_inventory: fixed_binary_build_input_inventory_protocol(),
        fixed_binary_build_input_inventory_entry_fields:
            fixed_build_input_inventory_entry_fields(),
        fixed_binary_build_input_role_literals: fixed_build_input_role_literals(),
        fixed_binary_build_input_role_rule: "cargo_executable_and_rustc_executable_each_have_exactly_one_entry_at_toolchain/bin/cargo_or_cargo.exe_and_toolchain/bin/rustc_or_rustc.exe_rustc_sysroot_file_has_at_least_one_entry_under_toolchain_and_completes_the_same_distribution_whose_inventoried_rustc_reports_ROOT/inputs/toolchain_target_linker_executable_and_target_archiver_executable_each_have_exactly_one_entry_under_tools/linker_and_tools/archiver_cargo_dependency_source_has_at_least_one_entry_under_cargo-home/registry/src_or_cargo-home/git/checkouts_cargo_configuration_has_exactly_one_entry_at_cargo-home/config.toml_with_exact_bytes_[net]_LFoffline_space_equals_space_true_LF_and_no_other_table_or_field_source_archive_rejects_every_ASCII_case_fold_.cargo_component_executable_path_input_is_zero_or_more_under_one_declared_executable_path_directory_tool_dynamic_dependency_is_zero_or_more_beside_its_consuming_inventoried_tool_or_under_tools/runtime_windows_runtime_input_is_absent_on_non-Windows_and_at_least_one_under_windows-runtime/SystemRoot_on_Windows_every_file_read_by_the_build_has_exactly_one_entry_and_no_role_alias_cross-root_or_uninventoried_input_is_valid".to_owned(),
        fixed_binary_build_input_path_rule: "entry_relative_paths_use_the_same_portable_ASCII_segment_grammar_bounds_and_exact_ASCII-case-fold_.git_or_.cargo_component_prohibition_as_source_archive_paths_are_strictly_sorted_unique_by_role_then_unsigned_path_bytes_and_are_relative_to_the_canonical_materialized_build_ROOT/inputs_directory_executable_path_directories_is_the_exact_ordered_unique_array_toolchain/bin_tools/linker_tools/archiver_tools/runtime_each_directory_contains_an_inventoried_executable_PATH_is_reconstructed_by_joining_ROOT/inputs_to_these_entries_in_exact_array_order_CARGO_HOME_resolves_the_same_ROOT/inputs/cargo-home_tree_and_RUSTC_resolves_the_same_ROOT/inputs/toolchain/bin_member_whose_reported_sysroot_is_ROOT/inputs/toolchain_on_Windows_SystemRoot_and_WINDIR_resolve_the_same_staged_ROOT/inputs/windows-runtime/SystemRoot_tree_no_member_is_materialized_twice_and_unknown_absolute_parent_backslash_drive_ADS_device_case-fold_file-directory-prefix_or_target-filesystem_alias_paths_reject".to_owned(),
        fixed_binary_build_input_mode_literals: fixed_build_input_mode_literals(),
        fixed_binary_build_input_archive_format: "one_exact_build/input-files.bia_binary_stream_beginning_with_exact_ASCII_bytes_MARTY-SD-JWT-BUILD-INPUT-ARCHIVE-V1_plus_LF_then_for_each_build/input-inventory.json_entry_in_its_exact_canonical_order_one_unsigned_64_bit_big_endian_content_length_and_exact_file_bytes_then_immediate_EOF_no_paths_modes_alignment_padding_unused_metadata_or_trailing_byte_the_separate_inventory_is_the_only_manifest".to_owned(),
        fixed_binary_build_input_archive_rule: "controller_and_analyzer_open_the_archive_create-new_or_no-follow_read-only_verify_its_outer_SHA256_and_length_against_both_inventory.archive_fingerprint_and_build_receipt.build_input_archive_fingerprint_before_parsing_then_stream_a_second_pass_over_the_same_immutable_handle_without_buffering_the_archive_or_allocating_from_unverified_lengths_complete_archive_length_including_magic_and_framing_is_at_most_maximum_build_input_bytes_entry_count_is_at_most_maximum_fixed_binary_build_input_entries_every_length_equals_the_corresponding_inventory_fingerprint.byte_length_checked_member_SHA256_matches_that_fingerprint_checked_member_sum_equals_inventory.total_byte_length_file_mode_is_exactly_100644_or_100755_and_executed_tools_are_100755_members_and_inventory_are_one-to-one_in_identical_order_and_missing_extra_reordered_duplicate_link_device_or_trailing_members_reject_secure_materialization_preserves_portable_logical_mode_as_read-only_data_or_read-only_executable_without_host_ACL_metadata_and_all_build_reads_are_confined_to_the_verified_materialization".to_owned(),
        maximum_fixed_binary_build_input_entries: MAX_FIXED_BUILD_INPUT_ENTRIES,
        fixed_binary_build_environment_entry_fields: fixed_build_environment_entry_fields(),
        fixed_binary_build_environment_allowlist: fixed_build_environment_allowlist(),
        fixed_binary_build_environment_mapping_rule: "entries_are_in_allowlist_order_with_exact_name_value_kind_and_nonnull_resolved_value_AR_inventoried_absolute_path_is_the_unique_target_archiver_member_below_ROOT/inputs/tools/archiver_CARGO_HOME_canonical_absolute_path_ROOT/inputs/cargo-home_CARGO_INCREMENTAL_literal_0_CARGO_NET_OFFLINE_literal_true_CARGO_TARGET_DIR_canonical_absolute_path_ROOT/target_target_triple_has_ASCII_length_1_through_128_every_byte_is_alphanumeric_hyphen_underscore_or_dot_and_is_not_dot_dotdot_host-tuple_or_any_ASCII_case_fold_suffix_.json_the_wire_name_for_the_target_linker_is_the_concrete_CARGO_TARGET_plus_underscore_plus_target_triple_ASCII_uppercase_with_each_hyphen_underscore_or_dot_replaced_by_underscore_plus_underscore_LINKER_any_other_target_byte_and_any_template_brace_rejects_and_its_value_is_the_unique_inventoried_absolute_target_linker_member_below_ROOT/inputs/tools/linker_PATH_ordered_absolute_path_list_is_ROOT/inputs_joined_to_executable_path_directories_in_exact_inventory_order_RUSTC_inventoried_absolute_path_ROOT/inputs/toolchain/bin/RUSTC_FILE_SOURCE_DATE_EPOCH_literal_exact_canonical_unsigned_decimal_sole_validated_commit_committer_Unix_timestamp_TEMP_and_TMP_canonical_absolute_path_ROOT/tmp_and_on_Windows_only_SystemRoot_and_WINDIR_are_both_canonical_absolute_path_ROOT/inputs/windows-runtime/SystemRoot_non-Windows_has_exactly_11_entries_and_Windows_has_exactly_13_each_name_appears_once_ROOT_equals_the_exact_platform_fixed_binary_build_root_no_other_name_kind_value_duplicate_case-fold_alias_wrapper_flag_config_ambient_live_SystemRoot_or_unrecorded_resolved_path_is_valid".to_owned(),
        fixed_binary_build_root_windows: FIXED_BUILD_ROOT_WINDOWS.to_owned(),
        fixed_binary_build_root_non_windows: FIXED_BUILD_ROOT_NON_WINDOWS.to_owned(),
        fixed_binary_build_rule: "trusted_materialization_boundary_is_opaque_noncloneable_and_issued_only_after_controller_namespace_mount_and_process_isolation_excludes_untrusted_peers_controls_the_full_working_directory_ancestor_chain_through_filesystem_root_and_proves_every_ancestor_has_neither_.cargo/config_nor_.cargo/config.toml_same_effective_uid_and_CAP_DAC_OVERRIDE_peers_are_inside_the_controller_TCB_no_issuer_exists_in_this_preparation_phase_so_activation_is_unavailable_AR_linker_and_PATH_values_are_execution_intent_only_and_do_not_attest_actual_child_resolution_runtime_controller_and_receipt_must_attest_exact_cargo_--version_--verbose_and_every_compiler_wrapper_linker_archiver_host_script_proc_macro_child_identity_argv_and_environment_no_effective_configuration_closure_or_execution_claim_exists_in_this_phase_runtime_execution_and_tool_resolution_attestation_remain_controller_and_receipt_obligations_trusted_controller_receipt_complete_build_input_inventory_and_retained_build_input_archive_are_part_of_the_anchored_genesis_chain_and_are_the_only_v2_link_from_verified_source_archive_Cargo_lock_exact_retained_dependency_sources_Cargo_configuration_Rust_distribution_sysroot_Cargo_rustc_linker_archiver_dynamic_tool_and_staged_Windows_runtime_bytes_exact_canonical_materialized_build_root_generated_Cargo_environment_values_real_offline_dependency_probe_build_command_working_directory_sandbox_and_typed_cleared_offline_environment_to_the_actual_installed_fixed_binary_analyzer_reconstructs_the_exact_retained_tree_from_verified_archive_members_repeats_rustc_--print_sysroot_and_exact_cargo_metadata_--frozen_--offline_--locked_--format-version_1_under_the_same_typed_cleared_environment_working_directory_and_read_sandbox_and_requires_success_the_exact_reported_sysroot_and_the_same_resolved_dependency_graph_before_accepting_the_receipt_stale_extra_ambient_relocated_substituted_unretained_or_differently_built_binary_invalidates_the_campaign".to_owned(),
        source_archive_manifest_schema:
            "marty.performance/sd-jwt-issuance-source-archive-manifest/v1".to_owned(),
        source_archive_manifest_fields: evidence_fields([
            ("schema", String, false),
            ("git_object_format", String, false),
            ("source_commit", String, false),
            ("source_tree", String, false),
            ("entry_count", U32, false),
            ("entries", SourceArchiveEntryArray, false),
        ]),
        source_archive_entry_fields: evidence_fields([
            ("repository_relative_path", String, false),
            ("git_mode", String, false),
            ("git_object_id", String, false),
            ("artifact_fingerprint", ArtifactFingerprint, false),
        ]),
        maximum_source_archive_bytes: MAX_SOURCE_ARCHIVE_V1_BYTES,
        maximum_source_archive_manifest_bytes: MAX_SOURCE_ARCHIVE_MANIFEST_V1_BYTES,
        maximum_source_archive_commit_bytes: MAX_SOURCE_ARCHIVE_COMMIT_V1_BYTES,
        maximum_source_archive_entries: MAX_SOURCE_ARCHIVE_V1_ENTRIES,
        maximum_source_archive_path_bytes: MAX_SOURCE_ARCHIVE_PATH_V1_BYTES,
        maximum_source_archive_path_segment_bytes: MAX_SOURCE_ARCHIVE_PATH_SEGMENT_V1_BYTES,
        maximum_source_archive_path_segments: MAX_SOURCE_ARCHIVE_PATH_SEGMENTS,
        maximum_source_archive_derived_directory_nodes:
            MAX_SOURCE_ARCHIVE_DERIVED_DIRECTORY_NODES,
        maximum_source_archive_derived_component_bytes:
            MAX_SOURCE_ARCHIVE_DERIVED_COMPONENT_BYTES,
        source_archive_format: "one_exact_source/exact-tree.sar_binary_stream_beginning_with_exact_ASCII_bytes_MARTY-SD-JWT-SOURCE-ARCHIVE-V1_plus_LF_then_unsigned_64_bit_big_endian_manifest_byte_length_including_its_terminal_LF_then_exact_canonical_pretty_JSON_plus_LF_manifest_bytes_then_unsigned_64_bit_big_endian_raw_commit_content_length_then_exact_raw_Git_commit_content_then_for_each_manifest_entry_in_order_one_unsigned_64_bit_big_endian_content_length_and_exact_regular_file_bytes_then_immediate_EOF_no_alignment_padding_unused_header_metadata_or_trailing_byte_analyzer_reads_at_most_hardcoded_16777216_plus_one_into_one_bounded_immutable_buffer_verifies_the_outer_archive_fingerprint_before_any_UTF8_or_JSON_parse_then_parses_that_same_buffer_every_u64_length_uses_checked_conversion_and_subtraction_and_must_fit_remaining_bytes_and_its_4194304_manifest_1048576_commit_or_remaining_archive_cap_before_allocation".to_owned(),
        source_archive_rule: "manifest_schema_and_fields_are_exact_git_object_format_equals_sha1_source_commit_and_source_tree_are_40_lowercase_hex_entry_count_equals_entries_length_and_is_1_through_65536_repository_relative_paths_use_the_portable_ASCII_grammar_bytes_A_to_Z_a_to_z_0_to_9_dot_underscore_at_plus_hyphen_preserved_byte-for-byte_1_through_1024_bytes_with_1_through_256_forward-slash-separated_segments_each_1_through_255_bytes_no_component_ASCII-case-folds_to_exact_.git_or_.cargo_and_no_absolute_drive_ADS_empty_dot_dotdot_backslash_control_trailing_dot_or_Windows_reserved_device_segment_entries_are_strictly_ascending_by_unsigned_bytes_and_a_single_bounded_component_trie_rejects_file_or_directory_duplicates_ASCII_case-fold_aliases_at_every_component_and_file-directory_prefix_conflicts_derived_directory_node_count_is_at_most_131072_and_checked_sum_of_each_cloned_unique_directory_or_file_component_byte_length_is_at_most_4194304_secure_materialization_uses_create-new_directory-handle-relative_no-follow_opens_verifies_every_opened_handle_remains_beneath_the_empty_build_root_and_rejects_any_target-filesystem_lossy_round_trip_case_fold_normalization_or_other_alias_collision_git_mode_is_exactly_100644_or_100755_git_object_id_is_40_lowercase_hex_SHA1_and_matches_Git_blob_header_plus_the_corresponding_length-prefixed_file_bytes_each_SHA256_and_length_fingerprint_matches_those_file_bytes_archive_has_no_extra_duplicate_link_device_ref_reflog_config_remote_hook_credential_parent-commit_or_history-object_record_while_parent_identifiers_inside_the_retained_commit_are_allowed_analyzer_builds_the_bounded_parent-to-children_trie_in_one_path_pass_hashes_each_node_once_in_reverse_creation_order_using_canonical_Git_tree_entry_order_and_recomputes_every_intermediate_tree_and_root_source_tree_without_recursion_quadratic_prefix_scans_or_unbounded_derived_strings_parses_only_the_header_prefix_of_the_sole_raw_commit_bytewise_while_leaving_identity_encoding_headers_and_message_bytes_opaque_recomputes_the_complete_unchanged_raw_Git_object_ID_as_source_commit_requires_exactly_one_first_ASCII_tree_header_equal_source_tree_and_exactly_one_committer_header_whose_final_ASCII_tokens_are_a_nonnegative_no-leading-zero_u64_Unix_timestamp_and_valid_plus-or-minus_HHMM_offset_that_define_SOURCE_DATE_EPOCH_missing_duplicate_malformed_or_negative_committer_time_rejects_and_requires_inputs/Cargo.lock_bytes_equal_the_archive_entry_for_Cargo.lock_controller_configuration_source_export_approved_must_be_true".to_owned(),
        privacy_rule: "all_operational_typed_preimages_use_deny_unknown_fields_exact_literal_domains_and_bounded_string_grammars_and_retain_no_raw_or_unsalted_digest_of_hostname_machine_or_boot_ID_username_account_IP_MAC_serial_cloud_instance_ID_PID_process_start_time_image_name_executable_or_account_home_path_command_line_target_origin_endpoint_change_ticket_access_credential_secret_token_private_key_or_unbounded_or_untyped_free_form_diagnostic_text_campaign_ephemeral_identity_keys_and_raw_inputs_are_memory_only_and_destroyed_after_completion_the_fixed_nonpersonal_build_root_exact_staged_Windows_runtime_paths_bounded_typed_hardware_source_commit_toolchain_and_binary_fingerprints_anchor_channel_log_key_IDs_and_authenticated_timestamps_are_explicit_nonsecret_stable-metadata_exceptions_and_can_link_campaigns_the_retained_build_input_archive_is_a_separate_explicit_exception_limited_to_approved_public_dependency_Cargo_configuration_toolchain_linker_archiver_dynamic_runtime_and_staged_Windows_runtime_bytes_and_portable_nonpersonal_paths_and_must_contain_no_credential_private_source_secret_or_operational_capture_data_source_archive_bytes_are_another_explicit_exception_because_the_export_approved_exact_source_commit_can_intentionally_contain_repository_relative_paths_public_URLs_author_and_committer_metadata_and_timestamps_parent_identifiers_and_public_synthetic_test_key_material_but_no_extra_history_objects_or_operational_capture_data_child_output_after_ready_is_bounded_drained_and_discarded_and_only_counts_are_retained".to_owned(),
    }
}

fn run_validity_limits() -> SdJwtIssuanceRunValidityLimits {
    SdJwtIssuanceRunValidityLimits {
        maximum_plan_bytes: MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES,
        maximum_segment_seconds: 12 * 60 * 60,
        maximum_segment_bytes: 64 * 1024 * 1024,
        maximum_line_bytes: 64 * 1024,
        maximum_records_per_segment: 65_536,
        maximum_segment_count: 16,
        maximum_completion_manifest_bytes: 32 * 1024 * 1024,
        maximum_external_anchor_bytes: MAX_EXTERNAL_ANCHOR_V1_BYTES,
        maximum_auxiliary_preimage_bytes: MAX_SOURCE_ARCHIVE_V1_BYTES,
        maximum_route_artifact_bytes: 1024 * 1024,
        maximum_total_route_artifact_bytes: 128 * 1024 * 1024,
        maximum_criterion_home_bytes: 1024 * 1024,
        maximum_total_criterion_home_bytes: 512 * 1024 * 1024,
        maximum_build_input_bytes: MAX_FIXED_BUILD_INPUT_BYTES,
        maximum_launch_frame_bytes: 64 * 1024,
        maximum_spawn_to_ready_seconds: 30,
        maximum_process_output_bytes: 1024 * 1024,
        maximum_total_evidence_bytes: MAX_TOTAL_EVIDENCE_BYTES,
        maximum_total_records: 1_000_000,
        maximum_campaign_seconds: 7 * 24 * 60 * 60,
        maximum_timing_process_seconds: 5 * 60,
        maximum_anchor_publication_delay_seconds: 5 * 60,
        maximum_test_window_attestations: 16,
        exact_global_rounds: schedule::ROUND_COUNT,
        exact_cells_per_round: schedule::CELL_COUNT,
        exact_expansion_positions_per_cell: schedule::EXPANSION_COUNT,
        exact_timing_processes: schedule::TOTAL_PROCESS_COUNT,
        validation_rule: "before_UTF8_or_JSON_analyzer_opens_fixed_inputs/qualification-plan.json_without_following_links_reads_at_most_compiled_MAX_SD_JWT_ISSUANCE_PLAN_V3_BYTES_1048576_plus_one_rejects_larger_then_parses_exact_deny-unknown_V3_and_requires_canonical_pretty_JSON_plus_LF_before_using_any_plan-declared_limit_manifest_uses_its_independent_compiled_4194304_cap_stream_other_files_without_unbounded_buffering_check_each_declared_and_actual_size_before_allocation_or_hashing_the_build_input_archive_is_opened_without_following_links_outer-hashed_under_the_compiled_2147483648_byte_cap_then_rewound_on_the_same_immutable_handle_and_stream-framed_against_the_bound_inventory_without_member-sized_allocation_maximum_auxiliary_preimage_bytes_is_only_the_fallback_for_controller_monitor_anchor-channel_host-hardware-threshold-test-window-process-set-invocation-barrier-and-inventory_JSON_without_another_dedicated_cap_and_never_overrides_the_dedicated_segment_completion_anchor_route_Criterion_source-archive_or_build-input-archive_cap_each_dedicated_cap_has_precedence_route_Criterion_build-input-archive_segment_and_all_other_subtotals_are_part_of_total_evidence_bytes_and_reject_when_any_individual_subtotal_or_aggregate_limit_would_be_exceeded".to_owned(),
    }
}

pub(super) fn run_validity_protocol() -> SdJwtIssuanceRunValidityProtocol {
    SdJwtIssuanceRunValidityProtocol {
        schema: "marty.performance/sd-jwt-issuance-run-validity/v1".to_owned(),
        artifact_format: "create_new_utf8_ndjson_segments_one_compact_json_record_per_lf_line_keys_in_protocol_order_no_bom_no_cr_record_fingerprints_cover_exact_line_including_lf_each_segment_flushed_and_durably_synced_before_successor".to_owned(),
        canonicalization_rule: "for_Marty_owned_typed_JSON_only_deserialize_with_Cargo_lock_serde_json_1.0.151_into_exact_versioned_deny_unknown_struct_reject_duplicate_missing_unknown_wrong_type_nonfinite_and_trailing_data_then_require_byte_equality_with_serde_json_to_vec_for_segment_NDJSON_or_to_vec_pretty_two_space_indent_for_pretty_artifacts_plus_one_LF_nested_artifact_fingerprint_key_order_sha256_then_byte_length_route_bytes_follow_route_artifact_rule_Criterion_Cargo_lock_binary_source_archive_members_and_fixed_build_input_archive_members_are_opaque_and_only_stream_hashed_while_the_source_archive_manifest_and_fixed_build_input_inventory_are_typed".to_owned(),
        utc_format_rule: "exactly_30_ascii_bytes_yyyy-mm-ddThh:mm:ss.nnnnnnnnnZ_valid_utc_calendar_time_uppercase_T_and_Z_exactly_9_fractional_digits_no_offset_or_leap_second".to_owned(),
        monotonic_clock_rule: "one_nonrestarting_controller_process_creates_one_std_time_Instant_origin_before_campaign_genesis_and_authoritatively_observes_and_stamps_every_segment_first_window_monitor_child_and_completion_event_as_checked_u64_elapsed_nanoseconds_from_that_origin_monitor_and_child_never_supply_comparable_monotonic_values_controller_restart_origin_loss_overflow_or_detected_suspend_or_UTC_vs_monotonic_discontinuity_invalidates_campaign".to_owned(),
        artifact_inventory_rule: "create_new_campaign_root_has_fixed_role_inputs_bin_build_configuration_source_profiles_observations_tmp_segments_attestations_invocations_criterion_barriers_barrier-ready_barrier-releases_barrier-receipts_inventories_routes_indexes_and_anchors_directories_plus_first-quiet-window.json_and_completion.json_build_receipt_inventory_and_retained_input_archive_are_build/fixed-benchmark.json_build/input-inventory.json_and_build/input-files.bia_signed_anchor_receipts_and_wrapper_are_anchors/terminal-observation-receipt.json_anchors/terminal-observation-evidence.json_and_anchors/completion-anchor.json_process_paths_are_r00..19_c00..65_e0..7_with_token_ready_release_receipt_invocation_initial_and_final_inventory_unique_per_coordinate_route_suffix_ndjson_and_temp_directory_exactly_tmp/rNN_cNN_eN_segments_are_segment-0000..0015.ndjson_first_window_attestation_is_attestations/first-quiet-window.json_and_the_disjoint_actual_chain_is_attestations/timing-window-0000.json_through_timing-window-0015.json_indexes_are_criterion-artifacts.json_and_route-artifacts.json_all_paths_computed_only_from_fixed_roles_or_valid_ordinals_ordered_arrays_map_by_ordinal_and_validator_rejects_missing_extra_duplicate_absolute_parent_backslash_symlink_hardlink_or_reparse_escape_in_governed_paths".to_owned(),
        global_preimages: global_preimage_protocol(),
        threat_model: "trusted_nonrestarting_controller_and_create_new_filesystem_during_capture_controller_is_the_authority_that_checks_raw_operator_test_window_authorization_raw_target_origin_and_change_reference_then_exports_only_independent_domain-separated_pseudonyms_later_offline_analysis_proves_alias_continuity_but_intentionally_cannot_independently_recover_or_reauthenticate_those_raw_mappings_unkeyed_local_sha256_is_tamper_evidence_not_authenticity_terminal_and_completion_heads_are_authenticated_by_two_retained_strict_Ed25519_create-only-log_receipts_verified_offline_against_the_bound_out-of-band_public_key".to_owned(),
        coverage: "monitor_first_sample_at_or_before_second_quiet_window_start_through_after_last_criterion_and_route_artifact_sync".to_owned(),
        pre_timing_quiet_seconds: 2_700,
        sample_interval_seconds: 5,
        maximum_sample_gap_seconds: 10,
        limits: run_validity_limits(),
        segment_chain_rule: "exactly_one_genesis_segment_ordinal_0_without_predecessor_each_continuation_ordinal_equals_prior_plus_1_and_binds_entire_prior_segment_uppercase_sha256_and_byte_length_and_0_less_than_next_first_monotonic_minus_prior_last_monotonic_less_than_or_equal_10000000000_nanoseconds".to_owned(),
        record_ordinal_rule: "within_each_segment_header_is_record_0_every_following_record_ordinal_equals_prior_plus_1_and_footer_is_unique_last_record_without_gap_or_duplicate".to_owned(),
        event_ordinal_rule: "zero_based_contiguous_across_process_intent_process_start_process_finish_and_attestation_transition_records_in_physical_campaign_order".to_owned(),
        segment_close_reason_literals: [
            "next_event_would_exceed_duration_limit",
            "next_record_would_exceed_byte_limit",
            "next_record_would_exceed_record_limit",
            "campaign_complete",
        ]
        .map(str::to_owned)
        .to_vec(),
        segment_close_reason_rule: "before_each_non-footer_record_controller_canonically_encodes_the_candidate_and_checked-tests_it_plus_the_required_footer_against_duration_byte_and_record_limits_using_precedence_duration_then_bytes_then_records_if_a_limit_would_be_exceeded_controller_writes_no_candidate_and_closes_with_the_corresponding_exact_literal_campaign_complete_is_valid_only_after_all_10560_finishes_final_monitor_sample_and_required_attestation_transition_state_and_only_on_the_unique_terminal_segment_no_other_reason_or_early_close_is_valid".to_owned(),
        process_schedule_rule: "exactly_20_by_66_by_8_coordinates_in_zero_based_global_round_then_manifest_cell_then_expansion_order_each_has_create_new_synced_static_token_with_exact_unique_nonreused_64-uppercase-hex_nonce_and_process_identity_pseudonym_descriptor_and_empty_home_then_durably_synced_PID_free_intent_then_spawned_child_ready_and_blocked_before_any_Criterion_construction_controller_checks_raw_PID_only_in_memory_then_durably_synced_ready_artifact_and_pseudonymous_start_then_create_new_synced_release_artifact_and_exact_stdin_release_then_synced_receipt_Criterion_and_route_artifacts_and_one_matching_successful_finish_before_any_other_intent_no_overlap_skip_duplicate_retry_or_resume".to_owned(),
        attestation_chain_rule: "attestation_intervals_are_start_inclusive_and_expiry_exclusive_first_quiet_attestation_contains_the_entire_first_quiet_interval_initial_actual_attestation_starts_at_or_before_the_second_quiet_window_start_and_every_genesis_or_continuation_header_sample_process_intent_start_release_finish_artifact_sync_terminal_footer_and_terminal_observation_request_time_is_strictly_before_the_expiry_of_the_exact_referenced_active_attestation_genesis_binds_only_current_actual_attestation_each_renewal_is_create_new_after_shutdown_recheck_and_recorded_before_prior_expiry_with_predecessor_fingerprint_same_target_conditions_next_start_at_or_before_prior_expiry_so_no_one_nanosecond_gap_each_duration_is_positive_and_at_most_43200_seconds_expired_future_unreferenced_or_uncovered_attestation_rejects_completion_binds_ordered_actual_chain".to_owned(),
        first_quiet_window: first_quiet_window_protocol(),
        invocation_descriptor: invocation_descriptor_protocol(),
        launch_barrier: launch_barrier_protocol(),
        criterion_home: criterion_home_protocol(),
        route_artifact: route_artifact_protocol(),
        artifact_indexes: artifact_index_protocol(),
        records: record_protocols(),
        completion: completion_protocol(),
        invalidating_events: [
            "monitor_started_after_second_quiet_window_start_or_clean_pre_timing_coverage_under_2700_seconds",
            "monitor_restart_or_state_loss",
            "sample_gap_exceeds_maximum",
            "campaign_id_host_identity_or_boot_identity_change",
            "reboot_suspend_resume_or_monotonic_discontinuity",
            "hardware_toolchain_binary_controller_monitor_or_configuration_change",
            "first_quiet_window_missing_invalid_mismatched_or_under_2700_seconds",
            "invocation_descriptor_missing_noncanonical_unresolvable_or_not_allowlisted",
            "criterion_home_not_unique_create_new_empty_or_fresh_for_exact_process",
            "launch_token_ready_release_or_receipt_missing_reused_noncanonical_unsynced_oversize_out_of_order_or_mismatched",
            "launch_spawn_to_ready_timeout_pipe_ownership_EOF_broken_pipe_early_exit_or_output_bound_failure",
            "timing_process_overlap_chronology_coordinate_invocation_or_environment_mismatch",
            "timing_process_nonzero_exit_abnormal_termination_or_timeout",
            "criterion_home_or_selected_route_artifact_write_flush_sync_shape_size_or_coordinate_mismatch",
            "global_fingerprint_preimage_or_artifact_index_missing_invalid_or_mismatched",
            "validity_evidence_write_flush_or_sync_failure",
            "unexpected_process_set_or_predeclared_load_bound_exceeded",
            "operating_system_reported_thermal_or_power_throttle",
            "predeclared_temperature_frequency_or_memory_bound_exceeded",
            "test_window_attestation_missing_gap_condition_change_or_invalid_renewal",
            "record_missing_duplicate_out_of_order_unknown_or_noncanonical",
            "resource_cardinality_or_duration_bound_exceeded",
            "required_observation_unavailable_or_nonfinite",
            "completion_manifest_missing_invalid_unsynced_or_not_externally_anchored",
        ]
        .map(str::to_owned)
        .to_vec(),
        invalidation_rule: "any_event_gap_write_failure_or_missing_terminal_commitment_invalidates_entire_campaign_no_round_deletion_resume_or_partial_analysis".to_owned(),
    }
}

pub(super) fn global_round_protocol() -> Result<SdJwtIssuanceGlobalRoundProtocol> {
    let cells_per_round =
        u32::try_from(PAIRED_CELL_COUNT).context("global-round cell count overflow")?;
    let processes_per_round = cells_per_round
        .checked_mul(PROCESSES_PER_SUPERBLOCK)
        .context("global-round process count overflow")?;
    Ok(SdJwtIssuanceGlobalRoundProtocol {
        execution_nesting: "global_round_then_manifest_cell_then_expansion_position".to_owned(),
        ordinal_alignment: "shared_campaign_cluster_across_all_cells".to_owned(),
        cells_per_round,
        processes_per_round,
        concurrent_timing_processes: 1,
        run_validity: run_validity_protocol(),
    })
}

pub(super) fn bootstrap_protocol(draws_per_replicate: u32) -> SdJwtIssuanceBootstrapProtocol {
    SdJwtIssuanceBootstrapProtocol {
        replicates: 100_000,
        confidence_level: 0.95,
        rng: "splitmix64".to_owned(),
        seed: 2_453_812_215,
        seed_is_initial_state: true,
        rng_state_transition: "state=wrapping_add(state,0x9E3779B97F4A7C15);z=wrapping_mul(state^(state>>30),0xBF58476D1CE4E5B9);z=wrapping_mul(z^(z>>27),0x94D049BB133111EB);output=z^(z>>31)".to_owned(),
        draws_per_replicate,
        sampling_method: "with_replacement".to_owned(),
        uniform_index_rule: "accept_x_below_18446744073709551600_then_x_mod_20".to_owned(),
        stream_scope: "single_continuous_stream_across_all_replicates".to_owned(),
        consumption_order: "replicate_major_then_accepted_draw_major".to_owned(),
        rejected_output_rule: "rejected_output_consumes_state_and_retries_current_draw".to_owned(),
        quantile_method: "type_7".to_owned(),
        resampling_unit: "whole_global_round".to_owned(),
        common_index_scope: "all_paired_cells_and_effects_d_s_p_o".to_owned(),
        simultaneous_band: "type_7_q_0.95_of_replicate_max_abs_bootstrap_minus_observed_over_66_cells_d_s_p".to_owned(),
        primary_interval_rule: "observed_effect_plus_or_minus_common_critical_value".to_owned(),
        diagnostic_o_interval_rule:
            "type_7_marginal_q_0.025_and_q_0.975_of_bootstrap_o".to_owned(),
    }
}

pub(super) fn criterion_protocol() -> SdJwtIssuanceCriterionProtocol {
    SdJwtIssuanceCriterionProtocol {
        logical_argv: [
            "--bench",
            "--exact",
            "{full_benchmark_id}",
            "--sample-size",
            "50",
            "--nresamples",
            "100000",
            "--warm-up-time",
            "15",
            "--measurement-time",
            "10",
            "--confidence-level",
            "0.95",
            "--save-baseline",
            "base",
            "--noplot",
        ]
        .map(str::to_owned)
        .to_vec(),
        sample_size: 50,
        nresamples: 100_000,
        warm_up_seconds: 15,
        measurement_seconds: 10,
        confidence_level: 0.95,
        sampling_mode: "auto".to_owned(),
        baseline_mode: "save".to_owned(),
        baseline_name: "base".to_owned(),
        no_plot: true,
        primary_statistic: "median.point_estimate".to_owned(),
    }
}
