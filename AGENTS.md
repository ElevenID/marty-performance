# Repository Guidance

- Make every change on a task-scoped branch in a registered Git worktree.
  Never develop in the canonical checkout or push feature work directly to
  `main`.
- Prefer Rust for orchestration, evidence processing, fixtures, comparison,
  and reporting. JavaScript is limited to k6 workload definitions. Introduce
  another language only when an upstream tool contract requires it and record
  the reason.
- Use only synthetic workloads and data. Never target production traffic or
  commit credentials, private keys, personal data, or unsanitized traces.
- Preserve correctness checks. Performance deltas are advisory; correctness,
  immutable provenance, and run-validity failures are blocking.
- Do not compare runs across different hardware profiles, stack topology,
  telemetry modes, build profiles, or workload revisions.
- Keep generated reports under `reports/`; they are ignored unless explicitly
  sanitized and promoted through review.
- Before review, run `cargo fmt --all -- --check`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and
  `cargo test --locked --workspace --all-targets`.

