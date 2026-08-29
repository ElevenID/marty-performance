# Measurement Method

## Primary outputs

- End-to-end p50, p90, p95, p99, and maximum latency.
- Successful operations per second at a fixed offered load.
- Maximum sustainable throughput found during calibration.
- Error, timeout, and correctness-check rates.
- Per-container CPU, memory, throttling, storage, and network consumption.
- Per-service and dependency latency after shared instrumentation lands.

## Comparison campaign

Use interleaved repetitions to reduce time-dependent bias:

```text
baseline → candidate → baseline → candidate → baseline → candidate
```

The future comparison command will report confidence intervals, coefficient of
variation, and effect size. It must label changes inside the measured noise
floor as inconclusive rather than as a speedup or regression.

Calibration finds the highest offered load that preserves correctness and
avoids accumulating latency. Standard steady runs use approximately 60% of the
baseline's calibrated capacity. Latency comparisons use equal offered load;
throughput comparisons use equal correctness and saturation criteria.

## Run modes

- `comparable`: reduced logs, Prometheus/container metrics, fixed trace
  sampling, and no profiler.
- `diagnostic`: full traces or native profiling; never mixed into comparable
  statistics.

A separate no-telemetry control quantifies instrumentation cost.

## SD-JWT issuance qualification

The issuance microbenchmark uses a source-emitted canonical manifest rather
than rediscovering Criterion IDs from filesystem paths. Freeze its
pre-analysis protocol before building or timing:

    cargo run --locked -- qualification issuance plan \
      --manifest <canonical-manifest.json> \
      --output <absolute-new-plan.json>

The plan command rejects changed matrix cardinality, route or estimator
versions, noncanonical bytes, activated production thresholds, reused
benchmark IDs, and an existing output. The v2 plan fixes two independent
45-minute quiet windows, one same-HEAD executable, 20 eight-process
superblocks per paired cell, the Criterion process arguments, and the
whole-superblock simultaneous bootstrap. Its discovery gates use the exact
relative-percent transform `100.0 * (exp(effect) - 1.0)`. It describes 10,560
fresh timing processes but does not execute them or activate a production
threshold. Frozen v1 evidence must not be reinterpreted as v2.

## Test window

Contract-defined workloads require a time-bounded attestation that production
traffic is drained, public ingress is disabled, the authorized target matches
the requested gateway origin, and only synthetic data will be used. The harness
validates and binds this evidence but never performs the shutdown itself.

Smoke requests against local mocks do not require a test window. Smoke requests
against production hardware do.

## Invalid conditions

Reject or quarantine a run with response-check failures, unexpected runtime
fallbacks, OOMs, material CPU throttling, thermal instability, uncontrolled
background load, changed build/topology inputs, or incomplete evidence.
