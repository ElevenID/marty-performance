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

## Invalid conditions

Reject or quarantine a run with response-check failures, unexpected runtime
fallbacks, OOMs, material CPU throttling, thermal instability, uncontrolled
background load, changed build/topology inputs, or incomplete evidence.

