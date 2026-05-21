# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Service Does

An **Envoy external authorization (ext-authz) plugin** implementing **RFC 8693 OAuth 2.0 Token Exchange**. It runs as a sidecar in a service mesh (typically Istio/Envoy), intercepts incoming requests via gRPC, matches them against operator-defined policies stored in Kubernetes ConfigMaps, exchanges the bearer token via an OAuth token endpoint, and rewrites the upstream `Authorization` header with the new token before returning an allow/deny decision to Envoy.

## Commands

```bash
# Build
go build ./cmd/...

# Run all tests
go test ./...

# Run a single test file or package
go test ./internal/policy/...

# Run with coverage
go test -coverprofile=coverage.out ./...

# Run service locally
GRPC_PORT=3001 go run ./cmd/ext-authz-token-exchange-service

# E2E tests (requires a running K8s cluster)
E2E_BASE_URL=https://httpbin.int.kube \
E2E_PLUGIN_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange:latest \
E2E_FAKE_TOKEN_ENDPOINT_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:latest \
go run github.com/onsi/ginkgo/v2/ginkgo -r -v ./test/e2e

# DevSpace (cluster-based dev)
devspace dev
devspace deploy -p local-test
devspace run test-e2e
```

## Architecture

### Request Flow

1. Envoy sends a gRPC `Check()` call to the service
2. `server.AuthzGRPCServer` extracts host, path, method, and bearer token from the Envoy `CheckRequest`
3. The policy `Store` returns the current immutable `Index`
4. `Index` matches against sorted entries (host → pathPrefix → methods)
5. On match with a token: `exchange.Client` performs RFC 8693 token exchange with the configured OAuth endpoint
6. Rewrite `Authorization` header with the new token and return OK to Envoy
7. On no match or error: return Deny or pass through, depending on `DefaultDenyUnmatched` and `ErrorPassthrough` config flags

### Key Packages

| Package | Responsibility |
|---|---|
| `cmd/ext-authz-token-exchange-service` | Main entrypoint — wires up gRPC server, policy store, exchange client |
| `internal/server` | Envoy ext-authz gRPC service (`Check()`) and structured logging interceptor |
| `internal/policy` | Policy YAML parsing, `Store` interface, `ConfigMapStore` (Kubernetes watcher), immutable `Index` |
| `internal/exchange` | RFC 8693 token exchange HTTP client |
| `internal/config` | Environment variable loading and validation |
| `internal/telemetry` | OpenTelemetry traces + Prometheus metrics |
| `cmd/fake-token-endpoint` | Demo/E2E OAuth token endpoint |
| `cmd/demo-scenario` | Terminal demo runner |
| `cmd/demo-dashboard` | Web UI for exploring policies |

### Policy System

**App-owned policies** live in Kubernetes ConfigMaps selected by label (`ext-authz-token-exchange.magneticflux.net/enabled=true`). The `ConfigMapStore` watches these via `cache.ListWatch` + `cache.Reflector` and rebuilds the immutable `Index` on every change.

**Operator-owned issuer profiles** are loaded at startup from a YAML file (path set via `TOKEN_EXCHANGE_ISSUER_PROFILES_FILE`).

ConfigMaps with invalid YAML or ambiguous (overlapping) policies are flagged as **unhealthy regions** — all traffic matching that region is denied (fail-closed). The `Index` is always fully rebuilt, never incrementally updated.

Policy YAML format (inside a ConfigMap):
```yaml
version: v1
entries:
  - match:
      host: api.example.com
      pathPrefix: /orders
      methods: ["GET", "POST"]
    action: exchange
    exchange:
      issuerRef: primary       # references an issuer profile
      scope: read:orders
      audiences:
        - orders-api
  - match:
      host: api.example.com
      pathPrefix: /admin
    action: deny
```

### Configuration

All runtime configuration is via environment variables. Key ones:

| Variable | Default | Purpose |
|---|---|---|
| `GRPC_PORT` | `3001` | gRPC listen port |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | — | Global OAuth credentials |
| `TOKEN_EXCHANGE_ISSUER_PROFILES_FILE` | — | Path to issuer profiles YAML |
| `TOKEN_ENDPOINT_AUTH_METHOD` | `client_secret_basic` | OAuth client auth method |
| `TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED` | false | Deny requests with no matching policy |
| `TOKEN_EXCHANGE_ERROR_PASSTHROUGH` | false | Pass upstream errors to client |
| `TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT` | false | Allow non-TLS token endpoints |
| `TOKEN_EXCHANGE_INSECURE_LOG_TOKENS` | false | Log tokens (demo only) |
| `CONFIGMAP_LABEL_SELECTOR` | `ext-authz-token-exchange.magneticflux.net/enabled=true` | Selects policy ConfigMaps |
| `CONFIGMAP_NAMESPACE_SELECTOR` | `ext-authz-token-exchange.magneticflux.net/policy=enabled` | Selects watched namespaces |
| `METRICS_ENABLED` | false | Enable Prometheus/OTel metrics |
| `TOKEN_ENDPOINT_REQUEST_TIMEOUT` | `750ms` | Timeout for token exchange requests |

### Testing Patterns

- Unit tests use table-driven tests with **Ginkgo/Gomega** (`onsi/ginkgo/v2`)
- `policy.StaticStore` is used in unit tests instead of `ConfigMapStore`
- E2E tests in `test/e2e/` use Ginkgo v2 and target a real Kubernetes cluster; can use either the fake token endpoint or a real Keycloak OIDC provider

### Observability

Diagnostic log messages use stable grep-able codes (`TXE-1001`, `TXE-2001`, etc.) for operational troubleshooting. Prometheus metrics include:
- `ext_authz_check_requests_total` / `ext_authz_check_duration_seconds` — by decision/result
- `ext_authz_token_exchange_requests_total` / `ext_authz_token_exchange_latency_seconds` — by endpoint/result/error

### Deployment

Multi-stage Docker build produces a distroless static binary. Helm charts in `charts/`:
- `ext-authz-token-exchange/` — production chart
- `ext-authz-token-exchange-e2e/` — E2E/demo chart with fake token endpoint and demo dashboard
- `keycloak/` — optional OIDC provider for local testing

Go module: `github.com/michaelw/ext-authz-token-exchange`
