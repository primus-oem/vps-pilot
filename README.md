# VPS Pilot

VPS Pilot is a local Go MCP server and CLI, with a TypeScript extension for Visual Studio Code. The project is intended to help operators inspect and manage multi-service applications on VPS hosts through explicit, reviewable operations.

The product is being built for multiple hosts, environments, repositories, and services. The target workflow includes Docker Compose deployments, locally provisioned file-backed secrets, health checks, deployment history, and recovery plans. These capabilities are not all implemented yet.

## Current Status

The repository currently contains an early development scaffold:

- The Go CLI provides `version` and starts an MCP stdio server with `mcp`.
- The MCP server exposes `get_policy_capabilities`. Mutating operations are disabled.
- SQLite local state is initialized with a versioned schema and restricted file permissions.
- SQLite uses the pure-Go `modernc.org/sqlite` driver, so Core builds do not require a C compiler or CGO.
- A strict SSH/SFTP connection manager foundation supports private keys, `ssh-agent`, pinned `known_hosts`, deadlines and connection reuse.
- SSH hosts persist in SQLite and can be managed through `vps-pilot host list|add|test`.
- MCP exposes `hosts_list` and `host_connection_test`; mutations remain disabled.
- Read-only `get_host_health` runs fixed uname/disk/systemd/Docker/Compose operations with output limits and secret/control-character sanitization.
- Strict local YAML application manifests support cycle-safe dependency graphs and Compose mappings.
- CLI `app validate|import|list|graph` and read-only MCP `apps_list|app_graph` provide imported application metadata.
- CLI `app plan` and MCP `plan_application_release` produce environment-scoped plans with immutable image digests, explicit host/path mappings, registry allowlists and a verifiable SHA-256 digest. Planning does not execute changes.
- The VS Code extension registers the configured local executable as an MCP server.

SSH host management, Compose import and deployment, secret intake, approvals, monitoring, and recovery are not yet complete. The SSH package is infrastructure only and is not exposed as a generic shell or unrestricted command interface. Do not use this version to manage production infrastructure.

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
