# Contributing

Use a task-scoped branch and isolated Git worktree. Do not develop in the
canonical checkout or push directly to `main`.

Before opening a pull request, run:

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

Performance changes must preserve correctness checks and disclose changes to
hardware, tool versions, workloads, telemetry, fixtures, build profiles, and
result classification. Never commit credentials, production personal data,
or raw traces containing identity attributes.

Performance thresholds are advisory unless a separately reviewed SLO adopts
them. A pull request must not weaken correctness or run-validity checks to
obtain a better result.

