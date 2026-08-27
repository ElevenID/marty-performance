# Observability Integration

The shared implementation belongs in `marty-microservices-framework`.
`mmf-observability` already owns provider-neutral contracts, a
cardinality-limited metric registry, and Prometheus exposition. The next step
is reusable runtime middleware and exporter adapters, not service-specific
metric libraries.

Initial metric families will cover:

- Axum server and Reqwest client duration/count by route template and outcome;
- Tonic server/client duration and status;
- SQLx acquisition and operation duration;
- Redis operation duration and failure;
- queue/outbox depth, retry, delivery, and age;
- signing, verification, status-list, and policy-evaluation stages.

Allowed labels are bounded dimensions such as service, operation, route
template, method, status class, protocol, credential format, and outcome.
Identity and tenancy identifiers are forbidden.
