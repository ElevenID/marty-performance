# Architecture

## Boundaries

The public gateway is the primary system boundary. A released
`marty.stack/v1` manifest identifies every immutable component used by a run.
The harness must not import application source to assemble a synthetic stack
that differs from a release.

The control plane, evidence contracts, comparison engine, fixture generators,
and future report generator are Rust crates. k6 workload files remain
JavaScript because k6 executes that contract directly.

## Evidence flow

```text
release stack manifest ──> stack prepare ──> stack-input.json
host + Docker state ─────> doctor ─────────> doctor.json
synthetic scenario ──────> run ────────────> run.json + k6 results
                                              │
accepted repeated runs ────────────────────────┴──> compare/report (next milestone)
```

Evidence is append-oriented. A failed runner invocation updates `run.json`
with its failure and retains stdout and stderr instead of presenting partial
results as successful.

## Comparability

A run is comparable only when it binds a qualifying doctor report and prepared
stack input. The comparison contract will additionally require matching:

- hardware profile and Docker resource envelope;
- workload revision, seed, dataset, rate, and duration;
- Rust target, compiler, release profile, allocator, and OCI architecture;
- service topology and immutable image roles;
- telemetry and profiling mode.

Migration-preview evidence may omit those bindings for fixture and early
cutover diagnostics, but it cannot be promoted as a durable baseline.

## Safety

The repository uses synthetic subjects, credentials, issuers, and keys.
Production traffic replay and production identity records are out of scope.
Route labels must use templates; metrics and reports must not retain tenant,
applicant, credential, issuer, or trace identifiers.

