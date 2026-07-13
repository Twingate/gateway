# Twingate Gateway - AI Development Guide

## Project Overview

Zero-trust access gateway bridging Twingate with L7 resources such as Kubernetes API servers, HTTP services, and SSH servers. Authentication uses JWT + Proof-of-Possession.

- **License**: MPL-2.0
- **Repository**: <https://github.com/Twingate/gateway>
- **Language**: Go 1.26.5
- **Build**: goreleaser, Docker buildx, kind (testing)
- **Linting**: golangci-lint v2.11.1
- **Testing**: testify, helm-unittest

**Key Features**: TLS 1.3 mutual auth, K8s user impersonation, SSH certificate-based access, session recording, Prometheus metrics

**Core Dependencies**: k8s.io/client-go, golang.org/x/crypto/ssh, github.com/golang-jwt/jwt, go.uber.org/zap, prometheus/client_golang

## Architecture

### Startup Flow

```text
main.go → cmd/start.go → proxy.NewProxy() → proxy.Start()
  ├─> connect.NewListener() (TLS + protocol multiplexing)
  ├─> httphandler.NewProxy().Start() (K8s API proxy)
  ├─> sshhandler.NewProxy().Start() (SSH proxy)
  └─> metrics.Start() (Prometheus)
```

### Core Components

**`internal/proxy/proxy.go`** - Central orchestrator using errgroup for lifecycle management

**`internal/connect/`** - Connection handling:

- `listener.go`: Protocol multiplexer (HTTP/SSH based on handshake)
- `connect.go`: Validates CONNECT + JWT + Proof-of-Possession (EKM signature)
- `cert_reloader.go`: Hot-reloads TLS certs without restart

**`internal/httphandler/`** - Kubernetes proxy:

- Reverse proxy to K8s API with user impersonation headers
- Multiple upstreams (in-cluster or external with custom tokens)
- WebSocket support for kubectl exec/logs

**`internal/sshhandler/`** - SSH proxy:

- SSH server with CA-signed certificates (auto/manual/Vault)
- Bidirectional channel forwarding to upstreams
- Host certs (gateway→client) + User certs (gateway→upstream)

**`internal/token/`** - JWT validation:

- Fetches JWKS from Twingate
- Validates GAT claims (user, resource, client public key)
- Proof-of-Possession: client signs TLS EKM with private key

### Security Model

**Zero-Trust**: No stored credentials, per-connection JWT validation, TLS 1.3 mutual auth

**Token Validation Flow**:

1. Client sends CONNECT with `Proxy-Authorization: Bearer <JWT>` + `X-Token-Signature: <ECDSA_sig(TLS_EKM)>`
2. Gateway validates JWT signature via JWKS
3. Gateway verifies PoP signature using client public key from JWT
4. Gateway checks requested address matches token resource
5. Connection allowed, user identity extracted

**K8s Security**: Gateway uses impersonation headers (`Impersonate-User`, `Impersonate-Group`). K8s RBAC enforced at API server level. Gateway service account only needs impersonation permission.

**SSH Security**: Certificate-based auth. CA options: auto-generated (testing), manual (file), Vault (production). Separate CAs supported for gateway-host, gateway-user, and upstream verification.

## Directory Structure

```text
.
├── cmd/                    # CLI (Cobra)
├── internal/
│   ├── config/             # YAML config + validation
│   ├── connect/            # TLS + protocol multiplexing
│   ├── httphandler/        # K8s API proxy
│   ├── sshhandler/         # SSH proxy
│   ├── token/              # JWT validation
│   ├── sessionrecorder/    # Audit logs
│   ├── metrics/            # Prometheus
│   ├── log/                # Logging
│   └── version/
├── deploy/gateway/         # Helm chart
├── test/
│   ├── integration/        # Kind cluster tests
│   ├── e2e/                # End-to-end tests
│   └── data/               # Test fixtures
├── .github/workflows/      # CI/CD
├── main.go
├── Makefile
├── .goreleaser.yaml
├── .golangci.yml
└── go.mod
```

## Development Workflows

### Setup

```bash
asdf install golang 1.26.5
```

Versions tracked in `.tool-versions`.

### Commands

| Task | Command |
|------|---------|
| Build | `make build` |
| Test (Unit) | `make test` |
| Test (Integration) | `make test-integration` |
| Test (E2E) | `make test-e2e` |
| Test (Helm) | `make test-helm` |
| Lint Go | `make lint` |
| Lint Dockerfile | `make lint-dockerfile` |
| Lint Markdown | `make lint-markdown` |
| Version | `make version` |
| Cut Dev Release | `make cut-release-dev` |
| Cut Prod Release | `make cut-release-prod` |

### Before Committing

**IMPORTANT**: Run appropriate checks:

- **Go code** (`.go`): `make lint && make test`
- **Dockerfiles**: `make lint-dockerfile`
- **Markdown** (`*.md`): `make lint-markdown`
- **Helm charts**: `make test-helm`

**Full suite**: `make lint && make lint-dockerfile && make lint-markdown && make test && make test-integration && make test-helm`

### Testing

- **Unit**: `./cmd/...`, `./internal/...` - table-driven tests with testify
- **Integration**: `./test/integration/...` - requires kind cluster, tests full flows
- **E2E**: `./test/e2e/...` - full deployment scenario
  - **Prerequisite**: Caddy must be running (`caddy run` or `caddy start`)
  - Acts as reverse proxy for `acme.test` domain to simulate Twingate controller
- **Helm**: `deploy/gateway/tests/...` - snapshot tests

### Release Process

From `master` branch only:

- Dev: `make cut-release-dev` → `v1.2.3-dev-abc1234`
- Prod: `make cut-release-prod` → `v1.2.4`

Uses `svu` for version calculation based on conventional commits.

### CI/CD

Pipeline (`.github/workflows/ci.yaml`):

1. Lint (Go, Dockerfile, Markdown)
2. Unit tests + coverage
3. Integration tests (kind cluster)
4. Helm tests
5. E2E tests
6. CodeCov upload (unit and integration coverage with flags)

On tag: goreleaser builds multi-arch images (amd64/arm64) → Docker Hub

## Code Patterns

### Organization

- Internal packages only (`internal/` not importable)
- Package names: lowercase singular (`proxy`, not `proxies`)
- Interfaces in consumer packages
- Dependency injection via constructors (`NewXxx()`)

### Error Handling

```go
var ErrRequired = errors.New("required field is missing")  // Sentinel errors
return fmt.Errorf("context: %w", err)  // Error wrapping
```

### Configuration

- YAML via `config.Load(path)` in `internal/config/config.go`
- `Validate()` methods on all config structs
- Defaults in `newDefaultConfig()`
- Pointers for optional fields (`*KubernetesConfig`)

### Testing

```go
tests := []struct {
    name    string
    input   string
    want    string
    wantErr error
}{ /* cases */ }
```

Use `testify/assert` for assertions (keep going). Use `testify/require` only for preconditions where continuing would panic or be meaningless. Write mocks with `testify/mock`.

### Linting

Config: `.golangci.yml`

- All linters enabled except: cyclop, dupl, exhaustruct, funlen, varnamelen, wrapcheck
- Revive all rules except: cognitive-complexity, function-length, flag-parameter
- MPL-2.0 copyright header required
- Import ordering via gci

### Commits

Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `perf:`, `ci:`

## Critical Files

| Purpose | Path |
|---------|------|
| Entry Point | `main.go` |
| Start Command | `cmd/start.go` |
| Orchestrator | `internal/proxy/proxy.go` |
| Config | `internal/config/config.go` |
| Auth | `internal/connect/connect.go` |
| JWT | `internal/token/parser.go` |
| K8s Proxy | `internal/httphandler/http_proxy.go` |
| SSH Proxy | `internal/sshhandler/proxy.go` |
| Listener | `internal/connect/listener.go` |
| Helm | `deploy/gateway/` |

All paths relative to project root.

## Deployment

### Helm Chart (`deploy/gateway/`)

Resources: Deployment, Service, ServiceAccount, ClusterRole/Binding, Secret (TLS/SSH), ConfigMap

**HA Setup**: 3+ replicas with pod anti-affinity

**Monitoring**: Prometheus metrics at `:9090/metrics`

- `gateway_connections_total`: Connection counts by protocol/status
- `gateway_http_requests_total`: Request counts by upstream/method/status
- `gateway_http_request_duration_seconds`: Request latency
- `gateway_session_recordings_total`: Recording counts

**Secrets**: TLS cert/key, SSH CA key (manual mode), Vault token, upstream K8s tokens

## Troubleshooting

### Common Issues

**401 Unauthorized**:

- Token expired (check `exp` claim: `echo "<token>" | cut -d. -f2 | base64 -d | jq .`)
- JWKS endpoint unreachable
- PoP signature mismatch (ensure TLS 1.3)

**403 Forbidden (K8s)**:

- Gateway SA lacks impersonation: `kubectl auth can-i impersonate user/<email> --as=system:serviceaccount:<ns>:gateway`
- User has no RBAC bindings: `kubectl auth can-i get pods --as=<email>`

**SSH Connection Fails**:

- Certificate validation failure
- Upstream unreachable: `kubectl exec -it deployment/gateway -- nc -zv upstream.example.com 22`
- CA config mismatch (check Vault mount/role)

**Performance Issues**:

- Check resources: `kubectl top pod -l app=gateway`
- Check metrics: `curl http://localhost:9090/metrics | grep gateway_connections_active`
- Scale replicas or increase resource limits

### Debug Commands

```bash
export LOG_LEVEL=debug                                    # Enable debug logs
go test -v ./internal/proxy -run TestProxyStart          # Run specific test
go test -race ./...                                        # Race detector
```

## Notes for AI Assistants

1. **Use relative paths**: All paths relative to project root (e.g., `./internal/proxy/proxy.go`)
2. **Security critical**: Never bypass auth, token validation, or cert verification
3. **Run checks before committing**: See "Before Committing" section
4. **Update tests**: Add/update tests for any code changes
5. **Document config changes**: Update Helm values and this guide
6. **Backwards compatibility**: Avoid breaking config schema or API changes
7. **Conventional commits**: Required for automated versioning
8. **Multi-protocol**: Changes may affect both HTTP and SSH handlers
9. **Security review**: Auth/authz changes require careful review
10. **Follow patterns**: Table-driven tests, sentinel errors, struct validation
11. **PR Creation**: Titles must follow conventional commits (feat:, fix:, chore:, etc.). Descriptions should follow `.github/pull_request_template.md` structure (Related Tickets, Changes, Notes)
