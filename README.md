# VPS Pilot

<p align="center">
  <img src="./extension/media/pilot-logo.png" alt="VPS Pilot logo" width="180">
</p>

VPS Pilot is a local Go MCP server and CLI, with a TypeScript extension for Visual Studio Code. The project is intended to help operators inspect and manage multi-service applications on VPS hosts through explicit, reviewable operations.

The product is being built for multiple hosts, environments, repositories, and services. The target workflow includes Docker Compose deployments, locally provisioned file-backed secrets, health checks, deployment history, and recovery plans. These capabilities are not all implemented yet.

## Current Status

The repository contains an early development implementation:

- The Go CLI provides `version` and starts an MCP stdio server with `mcp`.
- The MCP server exposes policy capabilities and a narrowly scoped, approval-gated stateless Compose executor; arbitrary SSH/shell commands are not exposed.
- SQLite local state is initialized with a versioned schema and restricted file permissions.
- SQLite uses the pure-Go `modernc.org/sqlite` driver, so Core builds do not require a C compiler or CGO.
- A strict SSH/SFTP connection manager foundation supports private keys, `ssh-agent`, pinned `known_hosts`, deadlines and connection reuse.
- SSH hosts persist in SQLite and can be managed through `vps-pilot host list|add|test`.
- MCP exposes read-only `hosts_list` and `host_connection_test`; host configuration remains a local CLI operation.
- Read-only `get_host_health` runs fixed uname/disk/systemd/Docker/Compose operations with output limits and secret/control-character sanitization.
- Strict local YAML application manifests support cycle-safe dependency graphs and Compose mappings.
- CLI `app validate|import|list|graph|plan|preflight|approve|deploy` and MCP release tools support immutable plans, read-only remote preflight, and approved execution.
- Release plans bind immutable image digests, explicit targets and SSH identity, policy/risk findings, and a diff against the previous locally planned version. Preflight binds bounded Compose configuration and runtime digests; a missing baseline is reported explicitly.
- `app approve` records a five-minute, terminal-confirmed approval bound to the exact preflighted plan and target identity. Execution revalidates the target, policy, Compose configuration and health.
- Execution currently denies stateful/managed services, secrets, environment values, host bind mounts, published ports and elevated container capabilities. It is not a complete deployment or secret-management workflow.
- The VS Code extension registers the configured local executable as an MCP server.
- The VS Code Explorer includes a VPS Pilot inventory view and a deployment workflow command.
- Secret bindings and rotation metadata are stored in local SQLite; MCP output and CLI records do not contain secret values or raw references.
- A local Docker Compose smoke test was executed successfully against PostgreSQL 17 on the Docker Desktop daemon.

The deployment executor and MCP/CLI entry points have automated fake-remote coverage, but have not been validated against a disposable VPS. VS Code plan/approval/progress UI, secret intake, stateful deployment, reconciliation and recovery remain incomplete. The journal and leases are local SQLite controls, not distributed coordination. Do not use this version to manage production infrastructure.

## Requirements

- Go 1.25 or newer
- Node.js 20 or newer and npm

## Build and Test

Run the Go checks from the repository root:

```sh
cd core
go test -p=1 ./...
go vet ./...
go build ./cmd/vps-pilot
```

Run the extension checks:

```sh
cd extension
npm ci
npm audit
npm test
npm run compile
```

Start the local MCP server from `core/`:

```sh
go run ./cmd/vps-pilot mcp
```

The server uses stdio for MCP. Its standard output is reserved for the protocol; diagnostics are written to standard error. The `mcp` command creates local state under the operating system's user configuration directory.

## Security Direction

The implementation is intended to keep credentials and secret values out of MCP arguments and responses. Planned operations will use verified SSH host keys, typed plans, local approval for production changes, and an auditable journal. These controls are not yet a complete deployment security boundary because deployment features are still under development.

Compose file-backed secrets are not encrypted at rest. Access to a rootful Docker socket or membership in the Docker group is generally equivalent to root access on the host. A deployment failure may leave partial changes, so recovery must be based on verified host state rather than an assumption of automatic rollback.

This project has not undergone an independent security audit and is not production-ready.
