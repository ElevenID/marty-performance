# Marty Performance

Rust-first performance testing, profiling, and deployment evidence for the
public Marty stack. The repository measures released, digest-pinned stack
artifacts through the public gateway using synthetic workloads.

Performance findings are advisory. Correctness failures and invalid test
conditions fail a run; latency or throughput changes do not gate releases.

## Current milestone

The foundation milestone provides:

- `marty-perf doctor` for hardware and runtime evidence;
- `marty-perf stack prepare` for validating `marty.stack/v1` manifests and
  rendering digest-only Compose inputs;
- `marty-perf run smoke` for correctness-checked gateway health and readiness
  requests using k6;
- versioned workload contracts with smoke, calibration, steady, stress, burst,
  and soak execution profiles;
- deterministic Rust-generated lifecycle fixtures and an authenticated
  management-plane workload;
- frozen SD-JWT issuance planning plus bounded selected-route and indexed
  offline analyzers that use handle-bound inputs and do not claim campaign
  qualification, tail latency, throughput, or production thresholds;
- stable JSON artifacts suitable for later comparison and publication.

Broader lifecycle, issuance, verification, stress, burst, and soak scenarios
will build on these contracts. Results produced before the Rust migration's
final runtime inventory are labeled `migration-preview` and are not durable
baselines.

## Prerequisites

- Rust 1.95
- Docker Engine with a reachable Linux server
- A released `marty.stack/v1` manifest for stack preparation
- A running Marty gateway for the smoke scenario

A local k6 installation is optional and is used only when its version exactly
matches `config/tools.json`. Otherwise the runner falls back to the pinned
`grafana/k6` container.

To verify the runner without a Marty deployment, start the Rust mock gateway
in a separate terminal and target port 28080:

```console
cargo run -p marty-perf --example mock_gateway
cargo run -p marty-perf -- run smoke --base-url http://127.0.0.1:28080
```

## Quick start

```console
cargo run -p marty-perf -- doctor --output reports/doctor.json
cargo run -p marty-perf -- stack prepare \
  --manifest stack-manifest.json \
  --output-dir reports/prepared-stack
cargo run -p marty-perf -- run smoke \
  --base-url http://127.0.0.1:28000 \
  --output-dir reports/smoke
```

Before a `local-comparable` run, stop unrelated containers and require doctor
to qualify the machine. Bind both the doctor and prepared stack evidence into
the run:

```console
cargo run -p marty-perf -- doctor \
  --output reports/doctor.json \
  --require-comparable \
  --allow-container-prefix marty-performance-
cargo run -p marty-perf -- run smoke \
  --base-url http://127.0.0.1:28000 \
  --result-class local-comparable \
  --doctor-report reports/doctor.json \
  --stack-input reports/prepared-stack/stack-input.json
```

Repeat `--allow-container-prefix` for each intentionally running Compose
project. The accepted prefixes and counts are retained in `doctor.json`; a
prefix must contain at least four safe container-name characters.

The runner accepts loopback targets by default. An isolated remote test cluster
requires the explicit `--allow-remote-target` flag. That flag does not permit
production traffic or production personal data.

## Management lifecycle workload

Validate the versioned workload and generate a deterministic synthetic fixture:

```console
cargo run -p marty-perf -- scenario validate \
  --contract scenarios/management-lifecycle/contract.json
cargo run -p marty-perf -- fixture generate \
  --seed campaign-001 \
  --output reports/fixtures/management-lifecycle.json
```

The workload seeds one organization, trust profile, credential template,
presentation policy, and deployment profile through the gateway. Its measured
phase performs authenticated reads with fixed operation tags; teardown removes
the seeded resources in reverse order. The session ID is read from an ignored
file and is never copied into evidence or command arguments.

Every workload run requires an active test-window attestation. Create it only
after production traffic has been drained and public ingress has been disabled,
then run:

```console
cargo run -p marty-perf -- run workload \
  --contract scenarios/management-lifecycle/contract.json \
  --profile smoke \
  --fixture reports/fixtures/management-lifecycle.json \
  --session-file .secrets/gateway.session-id \
  --base-url http://127.0.0.1:28000 \
  --target-environment production \
  --test-window reports/test-window.json
```

See `docs/TEST-WINDOW.md` for the operational gate. The supplied load profile
rates are starting points for calibration, not capacity claims or service SLOs.

`stack prepare` requires exactly one image for each public stack role:
`ui`, `services`, `migrations`, and `marty-credentials-issuance`. Mutable OCI
tags are rejected.

## Result classes

- `migration-preview`: useful while runtime topology is still changing.
- `local-comparable`: accepted workstation measurements on a named profile.
- `diagnostic`: tracing or profiling enabled; not comparable to standard runs.
- `k8s-canonical`: production-shaped runs on declared Kubernetes hardware.

No production traffic or production personal data belongs in this repository.
