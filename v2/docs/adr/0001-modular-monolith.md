# ADR 0001: A modular monolith with explicit state authorities

Status: accepted

## Context

Environment changes span cloud provisioning, host enrollment, an overlay network, and workload deployment. Those actions are long-running and can stop between any two observations. Splitting the first release into networked services would add partial failures without creating useful product isolation.

## Decision

The control plane is one TypeScript codebase with separate API and worker processes. PostgreSQL is the transaction boundary and durable record. Modules communicate through typed application interfaces, not a broker or an internal HTTP API.

State has one authority per concern:

- immutable environment revisions own intent;
- Pulumi state owns the managed AWS resource graph;
- operation and step rows own workflow progress;
- fresh agent observations own node and workload reality;
- Graphile Worker owns job delivery only.

Every operation kind has a closed, versioned step list. A worker invocation advances at most one persisted step. Ambiguous external mutations become `needs_reconciliation` and must be observed before another mutation is attempted.

## Consequences

The product can recover through one database transaction model and can be deployed by a single operator. Workflow steps remain deliberately repetitive and explicit. If independent scaling or ownership becomes necessary later, the existing module boundaries are extraction seams rather than promises of distributed behavior.
