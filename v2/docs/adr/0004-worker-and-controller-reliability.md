# ADR 0004: Borrow worker and controller patterns, not DigitalOcean's queue stack

## Status

Accepted.

## Context

DigitalOcean publishes two useful bodies of operational code:

- [`go-workers2`](https://github.com/digitalocean/go-workers2) moves a job to a process-specific in-progress queue before execution, acknowledges it only after handling, identifies each worker process with a random nonce, emits TTL heartbeats with busy/concurrency data, drains on signals, and recovers in-progress work.
- [`csi-digitalocean`](https://github.com/digitalocean/csi-digitalocean) treats provider operations as idempotent controllers: observe before create/attach, reject an existing but incompatible object, treat an already-absent delete as success, distinguish retryable transitional conflicts from invalid requests, wait on asynchronous provider action IDs, and bound API rate and timeout behavior.

The failure lessons apply directly to Infractory. Their concrete infrastructure does not. `go-workers2` is a Redis/Sidekiq-compatible queue and would add a second durable service beside PostgreSQL. The CSI driver assumes Kubernetes owns reconciliation and resource identity, while Infractory deliberately uses fixed persisted operation steps and Pulumi state for managed AWS resources.

## Decision

Keep Graphile Worker as delivery over the same PostgreSQL cluster as product state. Keep operation and step rows as the workflow authority.

Adopt these patterns:

1. A delivered job is only a wake-up containing `operationId`; the persisted operation step is the in-progress record.
2. A worker has a random process identity and a TTL heartbeat so readiness can distinguish a healthy API from a dead execution plane.
3. Worker shutdown drains the current boundary and does not claim the next step.
4. Queue acknowledgement follows the durable step transition. A stale delivery re-reads state and safely becomes a no-op or resumes reconciliation.
5. Provider and agent actions observe actual state before deciding whether a requested mutation is already satisfied, incompatible, absent, or unknown.
6. An already-absent delete is success. An existing incompatible object is a conflict. An ambiguous mutation is `needs_reconciliation`, never an automatic retry.
7. Provider calls have bounded concurrency, deadlines, and explicit rate/backoff behavior. User-visible operations retain the provider correlation or action identifier when one exists.
8. Time-based leases use PostgreSQL/provider time where coordination depends on a shared clock; node clock skew remains an observed capability.

Do not adopt:

- Redis or Sidekiq compatibility
- generic retry middleware for infrastructure mutations
- an arbitrary job payload as workflow state
- Kubernetes/controller-runtime solely to obtain a reconcile loop
- a second worker dashboard that disagrees with operation history

## Consequences

Infractory gets the recovery and observability properties demonstrated by mature DigitalOcean components while retaining a single durable database and a small, inspectable operation engine. Queue statistics remain delivery diagnostics; the operator-facing truth remains the environment, operation, step, event, and observation records.
