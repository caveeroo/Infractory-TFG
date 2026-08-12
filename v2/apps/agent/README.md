# Infractory node agent

`infractory-agent` is the outbound-only host component for Infractory v2. It
enrolls with a one-use token read from a root-only file or hidden prompt,
persists a node-scoped device credential, heartbeats every 15 seconds, and
long-polls for typed work. Host status is included in every heartbeat; the
heavier Docker/Nebula observation runs every 60 seconds and after each action.
It has no inbound listener and no generic shell task.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=0.1.0' ./cmd/infractory-agent
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' ./cmd/infractory-pki
go test ./...
```

The service requires Linux with systemd, `/dev/net/tun`, and one of Ubuntu
22.04, Ubuntu 24.04, or Debian 12 on `amd64` or `arm64`. Other hosts are
inspected and reported, but enrollment is refused. Docker Engine and Docker
Compose v2 are installed only through apt repositories and packages; the agent
never executes a downloaded installation script.

Mutating tasks require both host NTP synchronization and a measured
control-plane clock offset within five seconds. The offset is nullable until a
bounded HTTPS response supplies a valid `Date` header; an unknown offset is
never reported as zero, and measurements expire after two minutes. Inspect,
observation, log, and token-rotation tasks
remain available for diagnosis while the clock is unsafe.

Install the agent binary at `/var/lib/infractory/bin/infractory-agent`; this is
also its atomic self-upgrade target and the path used by the supplied systemd
unit. The operating root defaults to `/var/lib/infractory`. Override it only in tests
with `--state-dir`. Enrollment tokens are never accepted as command-line values.

The systemd service intentionally does not use `ProtectSystem` or a narrow
capability bounding set. The agent's declared duties include apt/dpkg package
installation, transient systemd unit management, Docker management, and atomic
self-upgrade; those settings would make those functions silently impossible.
It remains root-only, outbound-only, uses an empty stdin for subprocesses, and
never offers a generic command or shell-string task. Operators should isolate
the host and control-plane endpoint accordingly.

The sibling `infractory-pki` helper accepts one discriminated JSON request on
stdin and returns JSON on stdout. `createCa` accepts `name`, `network`,
`notBefore`, and `notAfter`, and returns `caCertificate`, `caPrivateKey`, and
`fingerprint`. `sign` accepts the CA certificate/key, optional `caPassphrase`,
host public key, name, `networks`, `groups`, `notBefore`, and `notAfter`, and
returns `certificate` and `fingerprint`. CA material is never placed in
arguments or temporary files.

Workload apply accepts only container, HTTP, and TCP health probes. The agent
persists the normalized probe definition with each immutable release, evaluates
it within the apply deadline, and emits a bounded structured failure list. An
unhealthy update triggers a best-effort reapply of the prior release and, when
recorded probes are available, verifies the rollback before reporting whether
recovery succeeded. Command probes are deliberately unsupported.

Docker Engine and Nebula come from signed distribution packages. Docker Compose
v2.39.1 is a pinned upstream static binary whose amd64/arm64 SHA-256 digest is
compiled into the agent; this keeps Debian 12 on Compose v2 without adding a
third-party apt repository. Other operating systems and architectures are
deliberately rejected. The agent does not support Docker Compose v1, rootless
Docker, Podman, non-systemd hosts, or hosts without `/dev/net/tun`.
