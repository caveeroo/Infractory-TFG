# Infractory v2 architecture

Infractory v2 is a greenfield, self-hosted modular monolith. It shares no runtime, schema, API, or source dependency with the existing Java application.

## State ownership

| Concern | Authority |
| --- | --- |
| Desired environment and workload state | PostgreSQL environment revisions |
| AWS resource graph | One Pulumi stack per environment |
| Long-running progress | PostgreSQL operations, steps, and events |
| Job delivery | Graphile Worker |
| Node and workload reality | Fresh outbound-agent observations |

The control plane never promotes an accepted external request to success. AWS resources, agent enrollment, Nebula, and workload health must each be observed before an environment is ready.

## Processes

The TypeScript control plane produces two commands from one image: an HTTP API and a background worker. PostgreSQL is the only mandatory data service. Caddy terminates TLS and serves the compiled React application. The Go agent runs as a root-owned systemd service on managed and adopted nodes and makes outbound HTTPS requests only.

## Deliberate exclusions

There is no generic plugin system, workflow language, event bus, remote shell, resource mirror of Pulumi state, or automatic infrastructure repair. Docker Compose is the only workload runtime. V1 remains untouched.
