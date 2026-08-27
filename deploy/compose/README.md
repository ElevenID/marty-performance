# Docker Compose Profile

The Docker profile will consume `stack.env` produced by `marty-perf stack
prepare` and the artifact-only public stack contract from
`marty-integration-tests`. It must not build application source or substitute
mutable tags for release digests.

Before the profile becomes comparable it will add explicit resource limits,
verified CPU partitions, isolated k6 and telemetry containers, Prometheus,
Grafana, and container-resource collection. A separate diagnostic overlay will
enable tracing or native profiling without changing the comparable profile.
