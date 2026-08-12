# ADR 0003: Outbound, typed host control

Status: accepted

## Context

SSH-based orchestration requires inbound access, durable private keys, shell composition, and fragile assumptions about host state. Managed and adopted hosts also need to keep workloads running while the control plane is unavailable.

## Decision

A small root-owned Go service polls the control plane over HTTPS. Enrollment uses a short-lived one-use token; normal requests use a rotating, node-scoped device credential. The server stores only credential hashes.

The agent accepts a closed union of typed tasks. It has no inbound listener and no generic command task. Processes are executed as argument vectors. Mutating tasks are serialized, generation-checked, leased, deadline-bound, and recorded in a bounded atomic receipt journal so duplicate delivery can return the prior outcome.

The agent writes only below `/var/lib/infractory` and continues existing workloads during control-plane outages. Destructive instructions are rejected when stale.

## Consequences

Enrollment is an explicit product flow instead of a hidden server-side SSH action. Offline adopted hosts can be detached from control, but cleanup remains incomplete until observed or performed manually.
