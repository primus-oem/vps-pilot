# Security Policy

VPS Pilot is an early development product and has not completed an independent security audit. Do not use it for production infrastructure.

## Supported Releases

Only the latest development release receives security fixes.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories for this repository. Include impact, reproduction steps, affected versions and logs with all secrets removed.

Do not open a public issue for credentials, private keys, secret values or active-host details.

## Security Boundaries

- MCP tools must not expose secret values or arbitrary shell execution.
- SSH host identity and keys must be explicitly pinned.
- Deployments require immutable plans and explicit local approval.
- Docker socket and Docker group access are treated as privileged host access.
- Compose files and remote output are untrusted input.
