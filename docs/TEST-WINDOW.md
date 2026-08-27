# Performance Test Window

The workload runner does not shut down production automatically. An operator
must establish the approved test window using the deployment's normal change
and recovery procedures before creating the attestation.

At minimum, confirm that:

- production traffic has drained from the hardware under test;
- public ingress is disabled and only the dedicated test path remains;
- background jobs that would create uncontrolled load are stopped or declared;
- the gateway session belongs to a synthetic performance-testing account;
- only synthetic organizations, credentials, and subjects will be created;
- rollback and public-service restoration are owned by the change procedure.

Create `reports/test-window.json` from
`examples/test-window.json.example`. The target must exactly match the
normalized `--base-url`, the current time must be inside the declared interval,
and a window may not exceed 12 hours. It must also remain active long enough for
the selected profile, setup, graceful stop, and teardown to finish. Create this
file only after the shutdown checks are true.

The runner hashes the complete attestation and records its digest, timestamps,
and change reference in `run.json`. It does not retain the gateway session ID.

After testing, inspect teardown results for correctness, reconcile any resource
whose `perf-` fixture name remains, and follow the deployment change procedure
to restore production service.
