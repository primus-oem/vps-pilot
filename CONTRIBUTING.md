# Contributing

## Setup

- Go 1.25 or newer
- Node.js 20 or newer
- Docker for Compose integration tests

## Validation

```sh
cd core
go test -race -p=1 ./...
go vet ./...

cd ../extension
npm ci
npm test
npm run compile
npm audit
```

## Rules

- Never add credentials or secret values to fixtures, logs, plans or tests.
- Keep policy and approval decisions outside MCP handlers and UI code.
- Use typed operations instead of arbitrary shell commands.
- Add a focused test for every security or deployment behavior change.
- Update documentation when public commands or MCP tools change.
