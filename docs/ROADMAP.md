# Delivery Roadmap

Performance findings remain advisory throughout this roadmap. Correctness and
invalid evidence can fail a run; a measured regression produces a report for
review rather than a release gate.

## M1 — Foundation

- [x] Public repository and Rust 1.95 workspace.
- [x] Hardware and Docker doctor evidence.
- [x] Immutable public-stack preparation.
- [x] Pinned-container gateway smoke scenario.
- [x] Migration-preview versus comparable evidence classification.
- [x] Formatting, linting, tests, and pull-request CI.

Exit: the released v1.1.203 stack manifest validates, the mock gateway passes
all k6 checks, and an unbound comparable run is rejected.

## M2 — Workloads and calibration

- Synthetic organization, trust, template, policy, deployment, applicant, and
  flow lifecycle fixtures.
- SD-JWT VC, mdoc, JWT/VC issuance workloads.
- OID4VP verification, signing, status, and revocation workloads.
- Calibration, steady load, stress, burst, and soak executors.
- Deterministic reset and fixture isolation.

Exit: each journey proves correctness at smoke volume and emits stable
operation tags without identity data.

## M3 — Rust observability

- Extend `mmf-observability` with Axum, Tonic, Reqwest, SQLx, Redis, and
  messaging adapters.
- Adopt shared low-cardinality metrics across the Rust services.
- Keep OTLP traces optional and use fixed sampling in comparable mode.
- Quantify telemetry overhead with explicit control runs.

Exit: end-to-end latency can be decomposed across gateway, service, storage,
queue, and cryptographic stages.

## M4 — Native optimization loop

- Expand Criterion coverage in the owning Rust crates.
- Add service-level benchmarks for gateway and dependency boundaries.
- Capture Linux `perf` and flamegraphs only in diagnostic mode.
- Add repeated interleaved baseline/candidate comparison and noise analysis.

Exit: the report can distinguish an intentionally introduced slowdown from
normal workstation noise.

## M5 — Post-migration baseline

- Freeze the declared runtime inventory and stack topology.
- Run three accepted workstation campaigns.
- Publish the first `local-comparable` baseline after human review.
- Begin measured optimization experiments.

Exit: no fallback runtime is active and repeated baseline results remain inside
the accepted noise envelope.

## M6 — Kubernetes

- Dedicated, labeled performance node pools with recorded hardware.
- Isolated load-generator and telemetry nodes.
- Fixed replica/resource/placement profile for code comparisons.
- Separate HPA and recovery profile for deployment behavior.
- Production-shaped ingress, TLS, Postgres, Redis, secrets, and networking.

Exit: a reviewed `k8s-canonical` profile can be reproduced from immutable
artifacts without using production traffic or personal data.
