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

A local k6 installation is optional. The runner falls back to the pinned
`grafana/k6` container recorded in `config/tools.json`.

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
  --require-comparable
cargo run -p marty-perf -- run smoke \
  --base-url http://127.0.0.1:28000 \
  --result-class local-comparable \
  --doctor-report reports/doctor.json \
  --stack-input reports/prepared-stack/stack-input.json
```

`stack prepare` requires exactly one image for each public stack role:
`ui`, `services`, `migrations`, and `marty-credentials-issuance`. Mutable OCI
tags are rejected.

## Result classes

- `migration-preview`: useful while runtime topology is still changing.
- `local-comparable`: accepted workstation measurements on a named profile.
- `diagnostic`: tracing or profiling enabled; not comparable to standard runs.
- `k8s-canonical`: production-shaped runs on declared Kubernetes hardware.

No production traffic or production personal data belongs in this repository.
