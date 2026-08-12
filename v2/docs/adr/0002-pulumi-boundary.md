# ADR 0002: Pulumi owns managed AWS infrastructure only

Status: accepted

## Context

Using AWS SDK calls directly for VPCs, instances, security groups, IP addresses, and eventual networking features would require Infractory to implement its own resource dependency graph, adoption rules, refresh behavior, and ordered teardown.

## Decision

One Pulumi stack represents the managed AWS resources of one environment. The Pulumi program is versioned with the worker image and uses a dedicated PostgreSQL backend. CLI and provider artifacts are pinned and installed in that image.

The application database stores environment intent, operation history, sanitized stack outputs, and provider observations. It does not mirror every Pulumi resource. Adopted hosts, Nebula identities, and workloads are never Pulumi resources.

Tags allow residual audits and explicit recovery. They never authorize an automatic broad delete.

## Consequences

Plan and apply artifacts must record the program, provider, account, region, observation digest, and expiry. Backups must include both databases, the application encryption key, and the Pulumi passphrase. Repair always goes through a reviewed plan.
