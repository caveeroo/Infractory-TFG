# Operating Infractory v2

## Startup

Startup may validate configuration, connect to PostgreSQL, and verify the schema version. It must not call cloud APIs, alter hosts, enqueue repair operations, or seed external infrastructure.

## Runtime roles

- `api` serves `/api/v1`, `/agent/v1`, health endpoints, and operation event streams.
- `worker` advances one persisted operation step per job invocation.
- `migrate` applies forward-only database migrations under a PostgreSQL advisory lock.

Only one mutating operation can run for an environment. An ambiguous provider or agent outcome is reconciled before it is retried.

## Required production properties

- Stable HTTPS URL reachable by outbound agents.
- Persistent PostgreSQL storage.
- Stable application encryption key and Pulumi passphrase.
- AWS credentials supplied to the worker through the standard AWS credential chain.
- Pulumi CLI and provider plugins preinstalled in the worker image; runtime downloads are prohibited.

## Destroy and detach

Destroy first asks reachable agents to remove Infractory-owned workloads, secrets, and Nebula identity. It then destroys managed AWS resources through Pulumi and audits remaining ownership tags. Adopted hosts are detached, never terminated or rebooted. Unreachable adopted hosts produce an incomplete cleanup report rather than false success.
